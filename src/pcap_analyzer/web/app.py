"""Web interface. Pages use HTMX; tables and charts load JSON from /api."""
import base64
import binascii
import contextlib
import datetime
import ipaddress
import json
import logging
import os
import re
import shutil
import tempfile
import threading
from pathlib import Path

import jinja2
from fastapi import Depends, FastAPI, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import __version__, capture_guide, causes, compare, display_filters, engine, exports, knowledge, records, reports, services, split, stats, store, tshark, vault
from ..config import Settings
from . import directory, saved
from .auth import Auth
from .jobs import Jobs, QueueFull
from .users import MIN_PASSWORD, ROLES, Current, Users, password_problem

HERE = Path(__file__).parent
COOKIE = "pcap_session"
OPEN_PATHS = ("/login", "/language", "/healthz", "/static/")
CHANGE_PATHS = ("/password", "/logout")  # the only pages open until the first password is changed
SETUP_PATHS = ("/security", "/password", "/logout")  # and until the setup admin has set the master key
ADMIN_PATHS = ("/preferences", "/audit", "/tokens", "/users", "/security")
ANALYSIS_PATH = re.compile(r"/(?:a|export|api/a)/([^/]+)")
API_ANALYSIS_PATH = re.compile(r"/api/v1/analyses/([^/]+)")
JOB_PATH = re.compile(r"/jobs/([^/]+)")
API_JOB_PATH = re.compile(r"/api/v1/jobs/([^/]+)")
AUDIT_EVENTS = ("login", "login_failed", "logout", "password_changed", "upload", "delete", "export", "follow", "notes", "baseline", "thresholds",
                "token_created", "token_revoked", "api_upload", "api_delete", "expired", "user_added", "user_changed", "user_password", "user_deleted",
                "group_added", "group_changed", "group_deleted", "ldap_settings", "vault_set_up", "master_key_changed", "master_key_shown", "file_tampered")
CHUNK = 1 << 20
KEY_LIMIT = CHUNK
KEYLOG_LIMIT = 512 * CHUNK  # NetScaler writes the keys of every session it serves, about 60 MB in four busy minutes
FORM_OVERHEAD = KEYLOG_LIMIT + 2 * CHUNK  # key files and form fields on top of the capture
PURGE_INTERVAL_S = 3600
MAX_CAPTURE_S = 3600
TAB_LABELS = {"overview": "Overview", "issues": "Issues", "urls": "URLs", "connections": "Connections", "hosts": "Hosts", "backends": "Servers", "tls": "TLS", "stats": "Statistics"}
LANGUAGE_NAMES = {"tr": "Türkçe", "en": "English", "de": "Deutsch", "es": "Español"}
LANGUAGE_COOKIE = "pcap_language"
LANGUAGE_DAYS = 365
FORM_TOKEN_HEADER = "x-csrf-token"
FORM_TOKEN_FIELD = "csrf_token"
RECENT_CAPTURES = 12
API_PREFIX = "/api/v1/"
API_SECTIONS = ("overview", "urls", "connections", "hosts", "issues", "slowest")
CSP = ("default-src 'self'; img-src 'self' data:; font-src 'self' data:; style-src 'self' 'unsafe-inline'; object-src 'none'; "
       "base-uri 'none'; frame-ancestors 'none'; form-action 'self'")


def seconds(v):
    if v is None:
        return "–"
    return f"{v * 1000:.1f} ms" if v < 1 else f"{v:.2f} s"


def size(v):
    if v is None:
        return "–"
    for unit in ("B", "KB", "MB", "GB"):
        if v < 1024 or unit == "GB":
            return f"{v:.0f} {unit}" if unit == "B" else f"{v:.1f} {unit}"
        v /= 1024


def when(v):
    return datetime.datetime.fromtimestamp(v).strftime("%Y-%m-%d %H:%M:%S") if v else "–"


def day(v):
    return datetime.datetime.fromtimestamp(v).strftime("%Y-%m-%d")


def clock(v):
    return datetime.datetime.fromtimestamp(v).strftime("%H:%M")


SENTENCE_END = re.compile(r"(?<=[.!?])\s+(?=[A-ZÇĞİÖŞÜÁÉÍÓÚÑÄß0-9`(])")


def lead(text):
    """The first sentence of a text, and the rest of it, so a long explanation can open with one line."""
    parts = SENTENCE_END.split(text or "", maxsplit=1)
    return parts[0], parts[1] if len(parts) > 1 else ""


def _assets_stamp():
    """Version of app.css and app.js in their URLs: the release and the files' change time, so browsers fetch them again after every deployment."""
    stamp = max(int((HERE / "static" / name).stat().st_mtime) for name in ("app.css", "app.js"))
    return f"{__version__}.{_base36(stamp)}"


def _base36(n):
    digits = ""
    while True:
        n, d = divmod(n, 36)
        digits = "0123456789abcdefghijklmnopqrstuvwxyz"[d] + digits
        if not n:
            return digits


def _bad(message, code=400):
    raise HTTPException(code, message)


def _opt_int(v, name):
    if v in (None, ""):
        return None
    try:
        return int(v)
    except ValueError:
        _bad(knowledge.t("{name} must be a whole number", name=knowledge.t(name)))


def _opt_float(v):
    try:
        return float(v) if v not in (None, "") else None
    except ValueError:
        _bad(knowledge.t("Time is not valid: {value}", value=v))


def _offset_ms(v):
    """A clock difference in milliseconds, as seconds. A comma works as the decimal mark too."""
    v = (v or "").strip().replace(",", ".")
    if not v:
        return None
    try:
        return float(v) / 1000
    except ValueError:
        _bad(knowledge.t("The clock difference must be a number of milliseconds."))


def _ip(v, name):
    v = (v or "").strip()
    if not v:
        return None
    try:
        ipaddress.ip_network(v, strict=False)
    except ValueError:
        _bad(knowledge.t("{name} is not a valid IP address or network: {value}", name=knowledge.t(name), value=v))
    return v


def _epoch(v):
    if not v:
        return None
    try:
        return datetime.datetime.fromisoformat(v).timestamp()
    except ValueError:
        _bad(knowledge.t("Time is not valid: {value}", value=v))


async def _save(upload, path, limit, label):
    written = 0
    with open(path, "wb") as f:
        os.chmod(path, 0o600)
        while chunk := await upload.read(CHUNK):
            written += len(chunk)
            if written > limit:
                _bad(knowledge.t("{name} is too large", name=knowledge.t(label)), 413)
            f.write(chunk)
    return written


def _purge_loop(settings, stop):
    """Enforce retention even when nobody uses the app, and look for files changed by hand. Runs at startup, then every hour."""
    while True:
        try:
            engine.purge(settings)
        except OSError:
            logging.exception("Cleanup failed, trying again at the next interval")
        try:
            vault.of(settings.workdir).scan()
        except OSError:
            logging.exception("Checking the data folder failed, trying again at the next interval")
        if stop.wait(PURGE_INTERVAL_S):
            return


def needed_role(method, path):
    """The least role a request needs. Reading is open to every user; changing captures needs an analyst; settings, users, tokens,
    the activity log and encryption need an admin."""
    if path.startswith(ADMIN_PATHS):
        return "admin"
    if method in ("GET", "HEAD") or path in ("/language", "/password", "/logout"):
        return "viewer"
    return "analyst"


def named(path, query):
    """Analysis ids a request names, in its path or in the compare parameters, and the job ids."""
    ids = [m[1] for m in (ANALYSIS_PATH.match(path), API_ANALYSIS_PATH.match(path)) if m]
    ids += [query[k] for k in ("a", "b") if query.get(k)]
    jobs = [m[1] for m in (JOB_PATH.match(path), API_JOB_PATH.match(path)) if m]
    return ids, jobs


def create_app(settings=None, https=False):
    settings = settings or Settings()
    keys = vault.of(settings.workdir)
    people = Users(settings, settings.admin_user)
    auth = Auth(settings.admin_user, settings.admin_password, settings.admin_password_hash, settings.workdir / ".admin-password.json", vault=keys, users=people)
    jobs = Jobs(settings)
    safety_headers = {"Content-Security-Policy": CSP, "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"}
    if https:
        safety_headers["Strict-Transport-Security"] = f"max-age={settings.hsts_s}"

    async def from_this_session(request: Request):
        """Plain forms send the token as a field, and htmx sends it as a header."""
        if request.method in ("GET", "HEAD") or request.url.path.startswith(OPEN_PATHS + (API_PREFIX,)):
            return  # API calls carry a token that a browser never adds by itself
        sent = request.headers.get(FORM_TOKEN_HEADER)
        if sent is None:
            sent = (await request.form()).get(FORM_TOKEN_FIELD)
        if not auth.form_token_ok(request.cookies.get(COOKIE), sent):
            _bad(knowledge.t("This page is out of date. Reload it and try again."), 403)

    @contextlib.asynccontextmanager
    async def lifespan(_app):
        stop = threading.Event()
        threading.Thread(target=_purge_loop, args=(settings, stop), daemon=True, name="purge").start()
        yield
        stop.set()

    app = FastAPI(title="pcap-analyzer", version=__version__, docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan,
                  dependencies=[Depends(from_this_session)])
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=HERE / "templates")
    templates.env.filters.update(seconds=seconds, size=size, when=when, day=day, clock=clock, lead=lead)

    def me(request):
        return getattr(request.state, "who", None)

    def log(request, event, detail=""):
        who = me(request)
        records.audit(settings, event, request.client.host if request.client else "unknown", detail, who.name if who else "")

    words = re.findall(r'\bt\("([^"]+)"\)', (HERE / "static/app.js").read_text())
    templates.env.globals.update(version=__version__, assets=_assets_stamp(), display_filters=display_filters.PRESETS, tab_labels=TAB_LABELS, _=knowledge.t, warning_text=knowledge.warnings, lang=knowledge.language,
                                 languages=lambda: [(code, LANGUAGE_NAMES[code]) for code in knowledge.LANGUAGES],
                                 js_words=lambda: {w: knowledge.t(w) for w in words}, roles=ROLES, min_password=MIN_PASSWORD,
                                 role_labels=lambda: {"viewer": knowledge.t("Viewer"), "analyst": knowledge.t("Analyst"), "admin": knowledge.t("Admin")})

    @jinja2.pass_context
    def form_token(ctx):
        return auth.form_token(ctx["request"].cookies.get(COOKIE))

    def visible(who):
        """The analyses this user may see, newest first."""
        return [m for m in engine.list_analyses(settings) if who.sees(m.get("group"))]

    @jinja2.pass_context
    def recent_captures(ctx):
        """Error pages also reach people who have not signed in, and they must not see file names."""
        who = me(ctx["request"])
        if who is None or not keys.is_unlocked() and keys.is_set_up():
            return []
        try:
            return visible(who)[:RECENT_CAPTURES]
        except OSError:
            return []

    @jinja2.pass_context
    def current_user(ctx):
        return me(ctx["request"])

    @jinja2.pass_context
    def file_alerts(ctx):
        """Files changed by hand, for the notice admins see on every page."""
        who = me(ctx["request"])
        return keys.alerts() if who and who.can("admin") else []

    templates.env.globals.update(form_token=form_token, recent_captures=recent_captures, me=current_user, file_alerts=file_alerts)

    def page(request, name, status_code=200, **ctx):
        return templates.TemplateResponse(request, name, ctx, status_code=status_code)

    def capture_ctx(a, request=None):
        """What every capture page needs for its navigation."""
        with a.connect() as db:
            return dict(a=a, m=a.meta, notes=records.notes(settings, a.id), issue_count=sum(i["count"] for i in reports.issues(db, a.meta) if i["severity"] == 1))

    def is_htmx(request):
        return request.headers.get("hx-request") == "true"

    def opened(aid):
        try:
            return engine.open_analysis(aid, settings)
        except engine.NotFound:
            _bad(knowledge.t("This analysis does not exist. It may have passed its retention time."), 404)

    def waiting(request):
        """After a restart, or before the first setup is done, the data opens only when the setup admin signs in."""
        if request.url.path.startswith(API_PREFIX) or request.url.path.startswith("/api/"):
            return JSONResponse({"error": knowledge.t("The data is locked until the admin signs in. Try again in a few minutes.")}, 503, headers={"Retry-After": "60"})
        return templates.TemplateResponse(request, "waiting.html", {}, status_code=503, headers={"Retry-After": "60"})

    def api_identity(request):
        """A REST call carries an API token, or the name and password of a user (HTTP Basic). A token acts as an analyst of its group, or of every group."""
        sent = request.headers.get("authorization", "")
        client = request.client.host if request.client else "unknown"
        if sent[:7].lower() == "bearer ":
            if keys.is_set_up() and not keys.is_unlocked():
                return waiting(request)
            t = records.token_info(settings, sent[7:].strip())
            if t:
                return Current(f"token:{t['name'] or t['id']}", "analyst", group=t.get("group") or None, token=True)
        elif sent[:6].lower() == "basic ":
            if auth.blocked(client):
                return JSONResponse({"error": knowledge.t("Too many failed attempts. Try again in 5 minutes.")}, 429)
            try:
                user, _, password = base64.b64decode(sent[6:].strip(), validate=True).decode("utf-8").partition(":")
                who = auth.check(user, password)
            except vault.Locked:
                return waiting(request)
            except (ValueError, binascii.Error):
                who = None
            if who is not None and who.must_change:
                return JSONResponse({"error": knowledge.t("Change the first password before you go on.")}, 403)
            if who is not None and who.setup_admin and not keys.is_set_up():
                return JSONResponse({"error": knowledge.t("Set the master key first. Every file in the data folder is then encrypted.")}, 403)
            if who is not None:
                return who
            auth.failed(client)
            records.audit(settings, "login_failed", client, user if sent else "")
        return JSONResponse({"error": knowledge.t("A valid API token is required.")}, 401)

    def go(request, path):
        if request.headers.get("hx-request"):
            return Response(status_code=204, headers={"HX-Redirect": path})
        return RedirectResponse(path, 303)

    def forbidden(request, message, code=403):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"error": message}, code)
        if is_htmx(request):
            return HTMLResponse(f'<p class="error" role="alert">{_escape(message)}</p>', code)
        return templates.TemplateResponse(request, "error.html", dict(message=message), status_code=code)

    def refusal(request):
        """The answer to a request that must not reach a route."""
        path = request.url.path
        if request.method not in ("GET", "HEAD") and request.headers.get("sec-fetch-site") == "cross-site":
            return Response(knowledge.t("Cross-site request refused"), 403)
        if request.method == "POST" and path in ("/upload", API_PREFIX + "captures"):
            length = request.headers.get("content-length")
            if length is None or not length.isdigit():
                return Response(knowledge.t("Content-Length is required"), 411)
            if int(length) > settings.max_size_mb * CHUNK + FORM_OVERHEAD:
                return Response(knowledge.t("The capture is larger than the {n} MB limit.", n=settings.max_size_mb), 413)
        if path.startswith(API_PREFIX):
            who = api_identity(request)
            if isinstance(who, Response):
                return who
        elif path.startswith(OPEN_PATHS):
            return None
        else:
            who = auth.current(request.cookies.get(COOKIE))
            if who is None:
                if path.startswith("/api/"):
                    return JSONResponse({"error": knowledge.t("login required")}, 401)
                return go(request, "/login")
            if who.must_change and not path.startswith(CHANGE_PATHS):
                # the first sign-in, or a password an admin set: nothing but choosing a new password until it is done
                if path.startswith("/api/"):
                    return JSONResponse({"error": knowledge.t("Change the first password before you go on.")}, 403)
                return go(request, "/password")
            if who.setup_admin and not keys.is_set_up() and not path.startswith(SETUP_PATHS):
                # then the setup admin chooses the master key, and every file is encrypted with it
                if path.startswith("/api/"):
                    return JSONResponse({"error": knowledge.t("Set the master key first. Every file in the data folder is then encrypted.")}, 403)
                return go(request, "/security")
            if keys.is_set_up() and not keys.is_unlocked():
                return waiting(request)
        request.state.who = who
        if not who.can(needed_role(request.method, path)):
            return forbidden(request, knowledge.t("Your role cannot do this."))
        ids, job_ids = named(path, request.query_params)
        for aid in ids:
            try:
                a = engine.open_analysis(aid, settings)
            except engine.NotFound:
                continue  # the route answers with its own message
            except vault.Locked:
                return waiting(request)
            if not who.sees(a.meta.get("group")):
                return forbidden(request, knowledge.t("This analysis does not exist. It may have passed its retention time."), 404)
            engine.seen(aid, settings)
        for jid in job_ids:
            job = jobs.get(jid)
            if job is not None and not who.sees(job.group):
                return forbidden(request, knowledge.t("This analysis job is no longer known. Upload the capture again."), 404)
        return None

    @app.middleware("http")
    async def guard(request, call_next):
        knowledge.set_language(request.cookies.get(LANGUAGE_COOKIE))
        try:
            response = refusal(request) or await call_next(request)
        except vault.Locked:
            response = waiting(request)
        response.headers.update(safety_headers)
        response.headers["Cache-Control"] = "no-cache" if request.url.path.startswith("/static/") else "no-store"
        return response

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"error": exc.detail}, exc.status_code)
        if is_htmx(request):
            return HTMLResponse(f'<p class="error" role="alert">{_escape(exc.detail)}</p>', 200)
        return templates.TemplateResponse(request, "error.html", dict(message=exc.detail), status_code=exc.status_code)

    @app.exception_handler(vault.Locked)
    async def locked_error(request, exc):
        return waiting(request)

    @app.exception_handler(vault.Tampered)
    async def tampered_error(request, exc):
        return forbidden(request, knowledge.t("This file was changed by hand in the data folder, so it is not shown. The admin sees which on the Encryption page."), 409)

    @app.post("/language")
    def choose_language(language: str = Form(""), back: str = Form("/")):
        if language not in knowledge.LANGUAGES:
            _bad(knowledge.t("This language is not available."))
        resp = RedirectResponse(back if back.startswith("/") and not back.startswith(("//", "/\\")) else "/", 303)
        resp.set_cookie(LANGUAGE_COOKIE, language, httponly=True, samesite="lax", secure=https, max_age=LANGUAGE_DAYS * 86400)
        return resp

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "version": __version__}

    @app.get("/login", response_class=HTMLResponse)
    def login_form(request: Request):
        if auth.valid(request.cookies.get(COOKIE)):
            return RedirectResponse("/", 303)
        return page(request, "login.html", error=None)

    def first_page(who):
        if who.must_change:
            return "/password"
        if who.setup_admin and not keys.is_set_up():
            return "/security"
        return "/"

    @app.post("/login", response_class=HTMLResponse)
    def login(request: Request, username: str = Form(""), password: str = Form("")):
        client = request.client.host if request.client else "unknown"
        if auth.blocked(client):
            return page(request, "login.html", 429, error=knowledge.t("Too many failed attempts. Try again in 5 minutes."))
        try:
            token = auth.login(client, username, password)
        except vault.Locked:
            return waiting(request)
        if not token:
            records.audit(settings, "login_failed", client, username)
            return page(request, "login.html", 401, error=knowledge.t("The user name or password is wrong."))
        who = auth.current(token)
        records.audit(settings, "login", client, "", who.name)
        resp = RedirectResponse(first_page(who), 303)
        resp.set_cookie(COOKIE, token, httponly=True, samesite="strict", secure=https, max_age=12 * 3600)
        return resp

    @app.get("/password", response_class=HTMLResponse)
    def password_form(request: Request):
        who = me(request)
        return page(request, "password.html", section="password", error=None, first=who.must_change, ldap=who.source == "ldap", setup=who.setup_admin)

    @app.post("/password", response_class=HTMLResponse)
    def change_password(request: Request, current: str = Form(""), new: str = Form(""), again: str = Form("")):
        who = me(request)
        ctx = dict(first=who.must_change, ldap=who.source == "ldap", setup=who.setup_admin, section="password")
        if who.source == "ldap":
            return page(request, "password.html", 400, error=knowledge.t("An LDAP user's password is set in the directory."), **ctx)
        if who.setup_admin:
            problem = auth.change_password(current, new, again)
        elif people.verify(who.name, current) is None:
            problem = "The current password is wrong."
        elif new != again:
            problem = "The new passwords do not match."
        elif new == current:
            problem = "Choose a password other than the current one, admin or the user name."
        else:
            problem = password_problem(who.name, new)
        if problem:
            return page(request, "password.html", 400, error=knowledge.t(problem, n=MIN_PASSWORD), **ctx)
        if not who.setup_admin:
            people.set_own_password(who.name, new)
        log(request, "password_changed")
        return RedirectResponse("/security" if who.setup_admin and not keys.is_set_up() else "/", 303)

    @app.post("/logout")
    def logout(request: Request):
        log(request, "logout")
        auth.logout(request.cookies.get(COOKIE))
        resp = RedirectResponse("/login", 303)
        resp.delete_cookie(COOKIE)
        return resp

    @app.get("/", response_class=HTMLResponse)
    def home(request: Request, q: str = ""):
        who = me(request)
        return page(request, "home.html", section="captures", analyses=records.search(settings, visible(who), q), search=q, max_mb=settings.max_size_mb, ttl=settings.ttl_days)

    @app.post("/upload", response_class=HTMLResponse)
    async def upload(request: Request, capture: UploadFile, more: list[UploadFile] = (), keylog: list[UploadFile] = (), rsa_key: UploadFile | None = None,
                     host_a: str = Form(""), host_b: str = Form(""), port: str = Form(""), start: str = Form(""),
                     end: str = Form(""), display_filter: str = Form(""), decode_as: str = Form("")):
        job = await accept(me(request), capture, keylog, rsa_key, host_a, host_b, port, start, end, display_filter, more, decode_as)
        log(request, "upload", capture.filename)
        return page(request, "_job.html", job=job)

    async def accept(who, capture, keylogs, rsa_key, host_a, host_b, port, start, end, display_filter, more=(), decode_as=""):
        """The upload is kept in a private folder inside the data folder. The capture is encrypted there before the analysis reads it."""
        if not capture.filename:
            _bad(knowledge.t("Choose a capture file."))
        if not display_filters.is_preset(display_filter):
            _bad(knowledge.t("Choose a display filter from the list."))
        flt = tshark.Filter(_ip(host_a, "First host"), _ip(host_b, "Second host"), _opt_int(port, "Port"), _epoch(start), _epoch(end),
                            display_filter.strip() or None, tshark.decode_rules(decode_as))
        try:
            flt.decode_args()
        except tshark.TsharkError as e:
            _bad(str(e))
        settings.workdir.mkdir(parents=True, exist_ok=True)
        tmp = tempfile.mkdtemp(prefix=vault.IN_PROGRESS + "upload-", dir=settings.workdir)
        try:
            path = Path(tmp) / "capture"
            await _save(capture, path, settings.max_size_mb * CHUNK, "Capture")
            parts = [path]
            for i, extra in enumerate(p for p in more if p.filename):
                parts.append(Path(tmp) / f"part-{i}")
                await _save(extra, parts[-1], settings.max_size_mb * CHUNK, "Capture")
            name = capture.filename if len(parts) == 1 else knowledge.t("{name} and {n} more", name=capture.filename, n=len(parts) - 1)
            path = engine.join_parts(parts, tmp, settings)
            for part in parts:
                if part != path:
                    part.unlink(missing_ok=True)  # only the joined capture stays, and it is encrypted below
            kl = rk = None
            logs = []  # several key logs, such as one for each TLS leg on both sides of a NetScaler, are joined into one
            for i, keylog in enumerate(k for k in keylogs if k and k.filename):
                logs.append(Path(tmp) / f"keylog-{i}")
                await _save(keylog, logs[-1], KEYLOG_LIMIT - sum(p.stat().st_size for p in logs[:-1]), "Key log")
                engine.check_keylog(logs[-1])
            if logs:
                kl = logs[0] if len(logs) == 1 else Path(tmp) / "keylog"
                if len(logs) > 1:
                    engine.join_keylogs(logs, kl)
                    for one in logs:
                        one.unlink()
            if rsa_key and rsa_key.filename:
                rk = Path(tmp) / "rsa.pem"
                await _save(rsa_key, rk, KEY_LIMIT, "RSA key")
                engine.check_rsa_key(rk)
            keys.encrypt_in_place(path)
            job = jobs.submit(tmp, path, name.removesuffix(".gz"), kl, rk, flt, dict(user=who.name, group=who.upload_group))
        except (HTTPException, QueueFull, engine.CaptureTooLarge, engine.CompressedCapture, engine.WrongFile, tshark.TsharkError) as e:
            shutil.rmtree(tmp, ignore_errors=True)
            if isinstance(e, QueueFull):
                _bad(knowledge.t("Too many analyses are waiting. Try again in a moment."), 429)
            if not isinstance(e, HTTPException):
                _bad(str(e), 413 if isinstance(e, engine.CaptureTooLarge) else 400)
            raise
        return job

    @app.get("/jobs/{jid}", response_class=HTMLResponse)
    def job_status(request: Request, jid: str):
        job = jobs.get(jid)
        if job is None:
            _bad(knowledge.t("This analysis job is no longer known. Upload the capture again."), 404)
        if job.state == "done":
            return Response(status_code=200, headers={"HX-Redirect": f"/a/{job.analysis_id}"})
        return page(request, "_job.html", job=job)

    @app.post("/jobs/{jid}/cancel", response_class=HTMLResponse)
    def job_cancel(request: Request, jid: str):
        job = jobs.cancel(jid)
        if job is None:
            _bad(knowledge.t("This analysis job is no longer known. Upload the capture again."), 404)
        return page(request, "_job.html", job=job)

    def may_delete(request, aid):
        """Only the one who uploaded a capture, or an admin, may delete it."""
        try:
            meta = engine.open_analysis(aid, settings).meta
        except engine.NotFound:
            return True  # nothing to delete
        if not me(request).may_delete(meta):
            _bad(knowledge.t("Only the one who uploaded it, or an admin, can delete this capture."), 403)
        return True

    @app.post("/a/{aid}/delete")
    def delete(request: Request, aid: str):
        may_delete(request, aid)
        log(request, "delete", aid)
        engine.delete(aid, settings)
        return RedirectResponse("/", 303)

    def tab_context(a, tab, who):
        with a.connect() as db:
            if tab == "overview":
                ctx = dict(o=reports.overview(db, a.meta), budget=reports.time_budget(db), slow=reports.slowest(db, limit=5), quality=reports.quality(a.meta),
                           missed=reports.target_misses(db, records.thresholds(settings)["targets"]), base=None, drift=[])
                base_id = records.baseline(settings, who.upload_group)
                if base_id and base_id != a.id:
                    try:
                        base = engine.open_analysis(base_id, settings)
                    except engine.NotFound:
                        return ctx
                    if not who.sees(base.meta.get("group")):
                        return ctx
                    with base.connect() as bd:
                        ctx.update(base=base, drift=reports.drift(db, bd))
                return ctx
            if tab == "backends":
                return dict(backends=reports.backends(db))
            if tab == "issues":
                return dict(issues=reports.issues(db, a.meta))
            if tab == "tls":
                return dict(tls=reports.tls_health(db))
            if tab == "stats":
                return dict(http_load=stats.http_load(db), http_sequences=stats.http_sequences(db), quic=stats.quic(db))
        return {}

    @app.get("/a/{aid}", response_class=HTMLResponse)
    def analysis(request: Request, aid: str, tab: str = "overview"):
        if tab not in TAB_LABELS:
            _bad(knowledge.t("This view does not exist."), 404)
        a = opened(aid)
        who = me(request)
        name = "analysis.html" if not is_htmx(request) else f"_tab_{tab}.html"
        return page(request, name, tab=tab, baseline=records.baseline(settings, who.upload_group), deletable=who.may_delete(a.meta), **capture_ctx(a), **tab_context(a, tab, who))

    @app.post("/a/{aid}/notes")
    def save_notes(request: Request, aid: str, case: str = Form(""), tags: str = Form(""), note: str = Form("")):
        records.save_notes(settings, opened(aid).id, case, tags, note)
        log(request, "notes", aid)
        return RedirectResponse(f"/a/{aid}", 303)

    @app.post("/a/{aid}/baseline")
    def set_baseline(request: Request, aid: str):
        records.set_baseline(settings, opened(aid).id, me(request).upload_group)
        log(request, "baseline", aid)
        return RedirectResponse(f"/a/{aid}", 303)

    @app.get("/a/{aid}/issue/{key}", response_class=HTMLResponse)
    def issue(request: Request, aid: str, key: str):
        a = opened(aid)
        with a.connect() as db:
            d = reports.issue_detail(db, key)
        if d is None:
            _bad(knowledge.t("This issue does not exist."), 404)
        return page(request, "issue.html", d=d, **capture_ctx(a))

    @app.get("/a/{aid}/conn/{stream}", response_class=HTMLResponse)
    def connection(request: Request, aid: str, stream: int, percent: bool = False):
        a = opened(aid)
        with a.connect() as db:
            d = reports.connection_top(db, stream, percent)
            if d["conn"] is None:
                _bad(knowledge.t("This connection does not exist."), 404)
            d["top"] = [reports.describe(db, t) for t in d["top"]]
        return page(request, "connection.html", d=d, percent=percent, **capture_ctx(a))

    @app.get("/a/{aid}/txn/{tid}", response_class=HTMLResponse)
    def transaction(request: Request, aid: str, tid: int):
        a = opened(aid)
        with a.connect() as db:
            t = reports.transaction(db, tid)
        if t is None:
            _bad(knowledge.t("This request does not exist."), 404)
        return page(request, "transaction.html", t=t, **capture_ctx(a))

    def inspect_filter(q):
        size_of = q.get("size_of") or "total"
        if size_of not in reports.SIZE_SQL:
            _bad(knowledge.t("Size type is not valid."))
        return reports.Inspect((q.get("src") or "").strip() or None, (q.get("dst") or "").strip() or None, _opt_int(q.get("port"), "Port"),
                               q.get("kind") or None, (q.get("url") or "").strip() or None, _opt_int(q.get("min_size"), "Size"), size_of,
                               _opt_float(q.get("start")), _opt_float(q.get("end")), _opt_int(q.get("src_port"), "Source port"))

    def slow_filter(q):
        """The filter of the slowest requests list. A value that does not fit is left out, as an empty field is."""
        def ms(name):
            try:
                v = float((q.get(name) or "").strip().replace(",", "."))
            except ValueError:
                return None
            return v if 0 <= v < float("inf") else None
        status = q.get("slow_status") or None
        return reports.Slow((q.get("slow_q") or "").strip() or None, status if status in reports.SLOW_STATUSES else None, ms("slow_min_ms"), ms("slow_max_ms"))

    def page_number(q, name):
        v = (q.get(name) or "").strip()
        return int(v) if v.isdigit() and len(v) < 9 else 1

    @app.get("/a/{aid}/inspect", response_class=HTMLResponse)
    def inspect(request: Request, aid: str):
        a = opened(aid)
        q = dict(request.query_params)
        f = inspect_filter(q)
        with a.connect() as db:
            r = reports.inspect(db, f, slow_filter(q), page_number(q, "slow_page"))
            r["traffic"] = reports.all_traffic(db, f, page_number(q, "conn_page"))
            pairs = reports.rows(db, """SELECT DISTINCT client_ip, server_ip, server_port, kind, count(*) AS connections
                FROM tcp_connections GROUP BY ALL ORDER BY connections DESC LIMIT 200""")
            flows = reports.top_flows(db, f.start, f.end)
        phases = {p: knowledge.phase(p, 0)["label"] for p in causes.PHASES}
        url_chart = dict(labels=phases, bucket=r["bucket"], urls=[dict(title=f"{u['method']} {u['url']}", series=u["series"]) for u in r["urls"]])
        ctx = dict(r=r, q=q, flows=flows, query=str(request.url.query), pairs=pairs, phase_labels=phases, url_chart=url_chart, filter_fields=saved.FIELDS, kinds=sorted({p["kind"] for p in pairs}),
                   filters=saved.load(settings, filter_group(request)), **capture_ctx(a))
        return page(request, "_inspect_results.html" if is_htmx(request) else "inspect.html", **ctx)

    def filter_group(request):
        """Saved filters belong to the group they were saved in; admins see all of them."""
        who = me(request)
        return None if who.can("admin") else who.upload_group

    @app.post("/filters")
    async def filter_add(request: Request):
        form = await request.form()
        name = (form.get("name") or "").strip()
        back = form.get("back") or "/"
        if not back.startswith("/a/"):
            back = "/"
        if not name:
            _bad(knowledge.t("Give the filter a name."))
        saved.add(settings, name[:80], {k: form.get(k) for k in saved.FIELDS}, me(request).upload_group)
        return RedirectResponse(back, 303)

    @app.post("/filters/{fid}/delete")
    async def filter_delete(request: Request, fid: str):
        form = await request.form()
        saved.remove(settings, fid, filter_group(request))
        back = form.get("back") or "/"
        return RedirectResponse(back if back.startswith("/a/") else "/", 303)

    def side_filter(q, suffix):
        return inspect_filter({k: q.get(k + suffix) for k in saved.FIELDS})

    @app.get("/compare", response_class=HTMLResponse)
    def compare_page(request: Request):
        q = dict(request.query_params)
        ctx = dict(section="compare", q=q, analyses=visible(me(request)), result=None, points=None, a=None, b=None)
        if q.get("a") and q.get("b"):
            a, b = opened(q["a"]), opened(q["b"])
            ctx.update(a=a, b=b)
            with a.connect() as da, b.connect() as db:
                if q.get("mode") == "points":
                    ctx["points"] = compare.two_point(da, db, _offset_ms(q.get("offset_ms")))
                else:
                    fa = side_filter(q, "_a")
                    fb = side_filter({**{k[:-2] + "_b": v for k, v in q.items() if k.endswith("_a") and v}, **{k: v for k, v in q.items() if k.endswith("_b") and v}}, "_b")
                    ctx["result"] = compare.captures(da, db, fa, fb)
        return page(request, "compare.html", **ctx)

    @app.get("/trend", response_class=HTMLResponse)
    def trend_page(request: Request, url: str = ""):
        analyses = [engine.open_analysis(m["id"], settings) for m in visible(me(request))]
        return page(request, "trend.html", section="trend", url=url, names=reports.url_names(analyses), rows=reports.trend(analyses, url) if url else [])

    def preferences(request, **extra):
        limits = records.thresholds(settings)
        ctx = dict(new_token=None, error=None) | extra
        return page(request, "preferences.html", section="preferences", limits=limits, targets="\n".join(f"{t['pattern']} {t['seconds']:g}" for t in limits["targets"]),
                    tokens=records.tokens(settings), groups=people.groups(), **ctx)

    @app.get("/preferences", response_class=HTMLResponse)
    def preferences_page(request: Request):
        return preferences(request)

    @app.post("/preferences")
    def preferences_save(request: Request, slow: str = Form(""), targets: str = Form("")):
        try:
            value = float(slow)
        except ValueError:
            _bad(knowledge.t("Enter the slow request limit in seconds."))
        if value <= 0:
            _bad(knowledge.t("Enter the slow request limit in seconds."))
        parsed, bad = records.parse_targets(targets)
        if bad:
            _bad(knowledge.t("This line is not a URL pattern and seconds: {value}", value=bad[0]))
        records.save_thresholds(settings, value, parsed)
        log(request, "thresholds")
        return RedirectResponse("/preferences", 303)

    @app.post("/tokens", response_class=HTMLResponse)
    def token_add(request: Request, name: str = Form(""), group: str = Form("")):
        if group and group not in people.groups():
            _bad(knowledge.t("Choose one of the groups. An admin adds groups above."))
        token = records.new_token(settings, name, group or None)
        log(request, "token_created", f"{name} {group}".strip())
        return preferences(request, new_token=token)

    @app.post("/tokens/{tid}/delete")
    def token_delete(request: Request, tid: str):
        records.revoke_token(settings, tid)
        log(request, "token_revoked", tid)
        return RedirectResponse("/preferences", 303)

    @app.get("/audit", response_class=HTMLResponse)
    def audit_page(request: Request, event: str = ""):
        return page(request, "audit.html", section="audit", rows=records.read_audit(settings, event or None), event=event, events=AUDIT_EVENTS)

    @app.post(API_PREFIX + "captures", status_code=202)
    async def api_upload(request: Request, capture: UploadFile, keylog: list[UploadFile] = (), rsa_key: UploadFile | None = None,
                         host_a: str = Form(""), host_b: str = Form(""), port: str = Form(""), start: str = Form(""), end: str = Form(""), display_filter: str = Form(""),
                         decode_as: str = Form("")):
        job = await accept(me(request), capture, keylog, rsa_key, host_a, host_b, port, start, end, display_filter, (), decode_as)
        log(request, "api_upload", capture.filename)
        return dict(job=job.id, state=job.state)

    @app.get(API_PREFIX + "jobs/{jid}")
    def api_job(jid: str):
        job = jobs.get(jid)
        if job is None:
            _bad(knowledge.t("This analysis job is no longer known. Upload the capture again."), 404)
        return dict(job=job.id, state=job.state, analysis=job.analysis_id, error=job.error)

    @app.get(API_PREFIX + "analyses")
    def api_analyses(request: Request):
        return [{k: m.get(k) for k in ("id", "filename", "created", "size", "packets", "connections", "transactions", "group")} for m in visible(me(request))]

    @app.get(API_PREFIX + "analyses/{aid}")
    def api_analysis(aid: str):
        return opened(aid).meta

    @app.delete(API_PREFIX + "analyses/{aid}")
    def api_delete(request: Request, aid: str):
        a = opened(aid)
        may_delete(request, a.id)
        log(request, "api_delete", aid)
        engine.delete(a.id, settings)
        return dict(deleted=aid)

    @app.get(API_PREFIX + "analyses/{aid}/{section}")
    def api_section(aid: str, section: str):
        if section in ("services", "voip", "statistics"):  # these read the kept capture again
            a = opened(aid)
            return packet_view(lambda: {"services": services.response_times, "voip": services.voip, "statistics": stats.overview}[section](a, settings))
        if section not in API_SECTIONS:
            _bad(knowledge.t("Unknown data set."), 404)
        a = opened(aid)
        with a.connect() as db:
            return JSONResponse(json.loads(json.dumps({"overview": lambda: reports.overview(db, a.meta), "urls": lambda: reports.url_groups(db), "connections": lambda: reports.connections(db),
                                                       "hosts": lambda: reports.hosts(db), "issues": lambda: reports.issues(db, a.meta), "slowest": lambda: reports.slowest(db)}[section](), default=str)))

    @app.get("/capture-guide", response_class=HTMLResponse)
    def guide_page(request: Request):
        q = dict(request.query_params)
        server, client = _ip(q.get("server"), "Server"), _ip(q.get("client"), "Client")
        seconds = _opt_int(q.get("seconds"), "Seconds") or capture_guide.DEFAULT_SECONDS
        if not 1 <= seconds <= MAX_CAPTURE_S:
            _bad(knowledge.t("Seconds must be between 1 and {n}.", n=MAX_CAPTURE_S))
        names = {k: (q.get(k) or "").strip() or d for k, d in (("namespace", "default"), ("pod", "POD"), ("container", "CONTAINER"), ("interface", "any"), ("image", capture_guide.DEFAULT_IMAGE))}
        points = capture_guide.commands(server, _opt_int(q.get("port"), "Port"), client, seconds, settings.max_size_mb, **names)
        return page(request, "capture_guide.html", section="guide", q=q, points=points, seconds=seconds, max_mb=settings.max_size_mb)

    @app.get("/export/{aid}/report.html")
    def export_report(request: Request, aid: str):
        a = opened(aid)
        log(request, "export", f"{aid} report")
        with a.connect() as db:
            ctx = dict(a=a, m=a.meta, o=reports.overview(db, a.meta), budget=reports.time_budget(db), issues=reports.issues(db, a.meta), urls=reports.url_groups(db),
                       slow=reports.slowest(db), quality=reports.quality(a.meta), backends=reports.backends(db), notes=records.notes(settings, aid), css=(HERE / "static/app.css").read_text())
        html = templates.get_template("report.html").render(ctx)
        return Response(html, media_type="text/html; charset=utf-8", headers=_attachment(a, "report.html"))

    @app.get("/export/{aid}/requests.har")
    def export_har(request: Request, aid: str):
        a = opened(aid)
        log(request, "export", f"{aid} har")
        flt = inspect_filter(dict(request.query_params))
        return StreamingResponse(_streamed(a, lambda db: exports.har_chunks(db, flt)), media_type="application/json", headers=_attachment(a, "requests.har"))

    @app.get("/export/{aid}/{name}.{fmt}")
    def export_table(request: Request, aid: str, name: str, fmt: str):
        a = opened(aid)
        log(request, "export", f"{aid} {name}.{fmt}")
        if name not in exports.TABLES or fmt not in exports.FORMATS:
            _bad(knowledge.t("This export does not exist."), 404)
        return StreamingResponse(_streamed(a, lambda db: exports.render_chunks(exports.each_row(db, name, a.meta), fmt)), media_type=exports.FORMATS[fmt],
                                 headers=_attachment(a, f"{name}.{fmt}"))

    @app.get("/export/{aid}/conn/{stream}.pcapng")
    def export_stream(request: Request, aid: str, stream: int):
        a = opened(aid)
        log(request, "export", f"{aid} connection {stream}")
        capture = a.dir / "capture"
        if not capture.exists():
            _bad(knowledge.t("The original capture was not kept, so packets cannot be exported."), 404)
        with a.connect() as db:
            if not reports.one(db, "SELECT stream FROM tcp_connections WHERE stream = ?", [stream]):
                _bad(knowledge.t("This connection does not exist."), 404)
            where = reports.one(db, "SELECT part, part_stream FROM stream_parts WHERE stream = ?", [stream]) if a.meta.get("parts") else None
        feed, number = None, stream
        if where:  # a capture read in parts: only the part that holds this connection goes through tshark
            plan = split.plan(capture, a.meta["parts"])
            feed, number = (lambda: split.feed(capture, plan, where["part"])), where["part_stream"]
        with tempfile.TemporaryDirectory(prefix="pcap-export-", dir="/tmp") as tmp:
            out = Path(tmp) / "out.pcapng"
            try:
                tshark.extract_stream(capture, number, out, settings.tshark, feed)
            except tshark.TsharkError as e:
                _bad(str(e), 500)
            body = out.read_bytes()
        return Response(body, media_type="application/vnd.tcpdump.pcap", headers=_attachment(a, f"connection-{stream}.pcapng"))

    def packet_view(make):
        """Views that read the kept capture again. A missing capture or a filter tshark refuses gives a plain message."""
        try:
            return make()
        except stats.Unavailable as e:
            _bad(str(e), 404)
        except tshark.TsharkError as e:
            _bad(str(e))
        except tshark.Stopped:
            _bad(knowledge.t("Reading the capture passed its time limit of {n} seconds.", n=settings.analysis_timeout_s), 504)

    @app.get("/a/{aid}/stats/overview", response_class=HTMLResponse)
    def stats_overview(request: Request, aid: str):
        a = opened(aid)
        try:
            o = packet_view(lambda: stats.overview(a, settings))
        except HTTPException as e:
            return page(request, "_stats_overview.html", a=a, error=e.detail)
        return page(request, "_stats_overview.html", a=a, o=o)

    @app.get("/a/{aid}/stats/services", response_class=HTMLResponse)
    def stats_services(request: Request, aid: str):
        a = opened(aid)
        try:
            found = packet_view(lambda: services.response_times(a, settings))
        except HTTPException as e:
            return page(request, "_stats_services.html", a=a, error=e.detail)
        return page(request, "_stats_services.html", a=a, services=found)

    @app.get("/a/{aid}/stats/voip", response_class=HTMLResponse)
    def stats_voip(request: Request, aid: str):
        a = opened(aid)
        try:
            v = packet_view(lambda: services.voip(a, settings))
        except HTTPException as e:
            return page(request, "_stats_voip.html", a=a, error=e.detail)
        for c in v["calls"]:
            c["state_label"] = services.state_label(c["state"])
        return page(request, "_stats_voip.html", a=a, v=v)

    @app.get("/a/{aid}/stats/io", response_class=HTMLResponse)
    def stats_io(request: Request, aid: str, filter: str = ""):  # noqa: A002 - the name people see in the address
        a, flt = opened(aid), display_filters.allowed(filter)
        try:
            packet_view(lambda: stats.io_graph(a, settings, flt or None))
        except HTTPException as e:
            return page(request, "_io_graph.html", a=a, error=e.detail)
        return page(request, "_io_graph.html", a=a, flt=flt)

    @app.get("/api/a/{aid}/io")
    def api_io(aid: str, filter: str = ""):  # noqa: A002
        a, flt = opened(aid), display_filters.allowed(filter)
        return packet_view(lambda: stats.io_graph(a, settings, flt or None))

    @app.get("/api/a/{aid}/tcpgraph/{stream}")
    def api_tcpgraph(aid: str, stream: int):
        a = opened(aid)
        data = packet_view(lambda: stats.tcp_graphs(a, settings, stream))
        if data is None:
            _bad(knowledge.t("This connection does not exist."), 404)
        return data

    @app.get("/a/{aid}/flow", response_class=HTMLResponse)
    def flow(request: Request, aid: str, filter: str = "", stream: int | None = None):  # noqa: A002
        a, flt = opened(aid), display_filters.allowed(filter)
        f = packet_view(lambda: stats.flow_graph(a, settings, flt or None, stream))
        return page(request, "flow.html", f=f, flt=flt, stream=stream, **capture_ctx(a))

    @app.get("/a/{aid}/conn/{stream}/follow", response_class=HTMLResponse)
    def follow(request: Request, aid: str, stream: int, mode: str = "ascii"):
        a = opened(aid)
        if mode not in ("ascii", "hex", "http"):
            _bad(knowledge.t("This view does not exist."), 404)
        with a.connect() as db:
            if not reports.one(db, "SELECT stream FROM tcp_connections WHERE stream = ?", [stream]):
                _bad(knowledge.t("This connection does not exist."), 404)
            requests = reports.one(db, "SELECT count(*) AS n FROM http_transactions WHERE stream = ?", [stream])["n"]
            exchanges = stats.follow_http(db, stream) if mode == "http" else None
        log(request, "follow", f"{aid} connection {stream} {mode}")
        f = dict(mode="http", chunks=[]) if mode == "http" else packet_view(lambda: stats.follow(a, settings, stream, mode))
        return page(request, "follow.html", f=f, exchanges=exchanges, requests=requests, stream=stream, **capture_ctx(a))

    @app.get("/a/{aid}/txn/{tid}/packets", response_class=HTMLResponse)
    def transaction_packets(request: Request, aid: str, tid: int):
        a = opened(aid)
        with a.connect() as db:
            t = reports.one(db, "SELECT stream, req_frame, req_start, req_end, resp_end, new_conn FROM http_transactions WHERE id = ?", [tid])
        if t is None:
            _bad(knowledge.t("This request does not exist."), 404)
        try:
            found = packet_view(lambda: stats.request_packets(a, settings, t))
        except HTTPException as e:
            return page(request, "_conn_packets.html", a=a, error=e.detail)
        return page(request, "_conn_packets.html", a=a, p=found, stream=t["stream"])

    @app.get("/a/{aid}/conn/{stream}/packets", response_class=HTMLResponse)
    def connection_packets(request: Request, aid: str, stream: int):
        a = opened(aid)
        try:
            found = packet_view(lambda: stats.packets(a, settings, stream))
        except HTTPException as e:
            return page(request, "_conn_packets.html", a=a, error=e.detail)
        return page(request, "_conn_packets.html", a=a, p=found, stream=stream)

    @app.get("/a/{aid}/objects", response_class=HTMLResponse)
    def objects(request: Request, aid: str):
        a = opened(aid)
        found = packet_view(lambda: stats.objects(a, settings))
        return page(request, "objects.html", objects=found, **capture_ctx(a))

    @app.get("/export/{aid}/object/{name}")
    def export_object(request: Request, aid: str, name: str):
        a = opened(aid)
        path = stats.object_path(a, name)
        if path is None:
            _bad(knowledge.t("This file does not exist."), 404)
        log(request, "export", f"{aid} object {name}")
        return Response(vault.read_bytes(path), media_type="application/octet-stream", headers=_attachment(a, name))

    @app.get("/api/a/{aid}/waterfall/{stream}")
    def api_waterfall(aid: str, stream: int):
        a = opened(aid)
        with a.connect() as db:
            data = reports.waterfall(db, stream)
        if data is None:
            _bad(knowledge.t("This connection does not exist."), 404)
        return data

    @app.get("/api/a/{aid}/{what}")
    def api(aid: str, what: str):
        a = opened(aid)
        with a.connect() as db:
            if what == "urls":
                data = reports.url_groups(db)
            elif what == "connections":
                data = reports.connections(db)
            elif what == "hosts":
                data = reports.hosts(db)
            elif what == "histogram":
                data = reports.histogram(db)
            elif what == "statuses":
                data = reports.overview(db, a.meta)["statuses"]
            elif what == "timeline":
                data = reports.timeline(db)
            else:
                _bad(knowledge.t("Unknown data set."), 404)
        return data

    # ---- users, groups and LDAP: admins only, which the guard checks

    def users_page(request, message=None, error=None, status_code=None, test_ok=None):
        return page(request, "users.html", status_code or (400 if error else 200), section="users", users=people.list(), groups=people.group_list(),
                    setup_admin=settings.admin_user, ldap=directory.load(settings), ldap_ready=directory.configured(settings), message=message, error=error, test_ok=test_ok)

    @app.get("/users", response_class=HTMLResponse)
    def users_list(request: Request):
        return users_page(request)

    @app.post("/users/groups", response_class=HTMLResponse)
    def group_add(request: Request, group_name: str = Form(""), description: str = Form("")):
        name = group_name.strip().lower()
        problem = people.group_problem(name)
        if problem:
            return users_page(request, error=knowledge.t(problem))
        people.add_group(name, description)
        log(request, "group_added", name)
        return users_page(request, message=knowledge.t("Group {name} was added.", name=name))

    @app.post("/users/groups/{name}/update")
    def group_update(request: Request, name: str, description: str = Form("")):
        if not people.update_group(name, description):
            _bad(knowledge.t("This group does not exist."), 404)
        log(request, "group_changed", name)
        return RedirectResponse("/users", 303)

    @app.post("/users/groups/{name}/delete", response_class=HTMLResponse)
    def group_delete(request: Request, name: str):
        why = people.delete_group(name)
        if why == "missing":
            _bad(knowledge.t("This group does not exist."), 404)
        if why == "users":
            return users_page(request, error=knowledge.t("Group {name} still has users. Move them to another group first.", name=name))
        log(request, "group_deleted", name)
        return RedirectResponse("/users", 303)

    @app.post("/users/ldap", response_class=HTMLResponse)
    async def ldap_save(request: Request):
        form = await request.form()
        values = {f: str(form.get(f) or "").strip() for f in directory.FIELDS}
        problem = directory.problem(values)
        if problem:
            return users_page(request, error=knowledge.t(problem))
        directory.save(settings, values)
        log(request, "ldap_settings", values["url"])
        return users_page(request, message=knowledge.t("LDAP settings saved."))

    @app.post("/users/ldap/test", response_class=HTMLResponse)
    def ldap_test(request: Request, test_user: str = Form("")):
        line, ok = directory.test(settings, test_user)
        return users_page(request, message=line, test_ok=ok)

    def is_setup_admin_name(name):
        return name.lower() == settings.admin_user.lower()

    @app.post("/users", response_class=HTMLResponse)
    def user_add(request: Request, name: str = Form(""), full_name: str = Form(""), employee_id: str = Form(""), group: str = Form(""),
                 role: str = Form(""), source: str = Form("local"), password: str = Form("")):
        name, group, ldap = name.strip().lower(), group.strip().lower(), source == "ldap"
        if ldap and not directory.configured(settings):
            return users_page(request, error=knowledge.t("Set up LDAP below before adding LDAP users."))
        problem = people.problem(name, group, role, None if ldap else password, True)
        if not problem and not full_name.strip():
            problem = "Enter the person's full name."
        if problem:
            return users_page(request, error=knowledge.t(problem, n=MIN_PASSWORD))
        people.add(name, full_name, employee_id, group, role, None if ldap else password, ldap)
        log(request, "user_added", f"{name} {group} {role}")
        return users_page(request, message=knowledge.t("{name} was added.", name=name))

    def existing_user(name):
        if is_setup_admin_name(name):
            _bad(knowledge.t("The setup admin is set in the server settings and cannot be changed here."), 403)
        u = people.get(name)
        if u is None:
            _bad(knowledge.t("This user does not exist."), 404)
        return u

    @app.post("/users/{name}/update", response_class=HTMLResponse)
    def user_update(request: Request, name: str, full_name: str = Form(""), employee_id: str = Form(""), group: str = Form(""), role: str = Form("")):
        existing_user(name)
        group = group.strip().lower()
        problem = people.problem(name, group, role, None, False)
        if not problem and not full_name.strip():
            problem = "Enter the person's full name."
        if problem:
            return users_page(request, error=knowledge.t(problem))
        people.update(name, full_name, employee_id, group, role)
        log(request, "user_changed", f"{name} {group} {role}")
        return RedirectResponse("/users", 303)

    @app.post("/users/{name}/password", response_class=HTMLResponse)
    def user_password(request: Request, name: str, password: str = Form("")):
        u = existing_user(name)
        if u.get("source") == "ldap":
            return users_page(request, error=knowledge.t("An LDAP user's password is set in the directory."))
        problem = password_problem(name, password)
        if problem:
            return users_page(request, error=knowledge.t(problem, n=MIN_PASSWORD))
        people.update(name, password=password)
        log(request, "user_password", name)
        return users_page(request, message=knowledge.t("The password of {name} was reset. They choose a new one at the next sign-in.", name=name))

    @app.post("/users/{name}/delete")
    def user_delete(request: Request, name: str):
        existing_user(name)
        people.delete(name)
        log(request, "user_deleted", name)
        return RedirectResponse("/users", 303)

    # ---- encryption

    def security_page(request, message=None, error=None, shown=None):
        return page(request, "security.html", 400 if error else 200, section="security", set_up=keys.is_set_up(), alerts=keys.alerts(),
                    algorithm=[line if line.endswith(".") else line + "." for line in vault.ALGORITHM.split(". ")], native=store.NATIVE_ENCRYPTION,
                    message=message, error=error, shown=shown)

    @app.get("/security", response_class=HTMLResponse)
    def security(request: Request):
        return security_page(request)

    @app.post("/security", response_class=HTMLResponse)
    def security_save(request: Request, master: str = Form(""), again: str = Form(""), password: str = Form("")):
        """Set the master key the first time, which encrypts every file in the data folder, or change it later."""
        who = me(request)
        if not who.setup_admin:
            return security_page(request, error=knowledge.t("Only the setup admin can set the master key, since it is wrapped with that admin's password."))
        problem = vault.master_problem(master)
        if not problem and master != again:
            problem = "The two keys are not the same."
        if problem:
            return security_page(request, error=knowledge.t(problem))
        if not keys.is_set_up():
            if not auth.check(settings.admin_user, password):
                return security_page(request, error=knowledge.t("The current password is wrong."))
            keys.set_up(password, master)
            auth.encrypted_now()
            log(request, "vault_set_up")
            return security_page(request, message=knowledge.t("The master key is set. Every file in the data folder is now encrypted."))
        keys.change_master(master)
        log(request, "master_key_changed")
        return security_page(request, message=knowledge.t("The master key was changed."))

    @app.post("/security/reveal", response_class=HTMLResponse)
    def security_reveal(request: Request):
        if not me(request).setup_admin:
            _bad(knowledge.t("Only the setup admin can see the master key."), 403)
        log(request, "master_key_shown")
        return security_page(request, shown=keys.master_key())

    @app.post("/security/alerts/clear")
    def security_alerts_clear(request: Request):
        keys.clear_alerts()
        return RedirectResponse("/security", 303)

    return app


def _streamed(a, make):
    """An export written while it is read from the database, so a large analysis does not sit in memory."""
    with a.connect() as db:
        yield from make(db)


def _attachment(a, name):
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", a.meta["filename"])[:60]
    return {"Content-Disposition": f'attachment; filename="{stem}-{name}"'}


def _escape(text):
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
