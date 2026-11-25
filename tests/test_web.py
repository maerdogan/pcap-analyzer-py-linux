import gzip
import html
import os
import re
import time

import pytest
from fastapi.testclient import TestClient

from pcap_analyzer import engine
from pcap_analyzer.web.app import create_app
from pcap_analyzer.web.auth import FAIL_WINDOW_S, MAX_FAILS, MAX_TOTAL_FAILS, Auth, hash_password, verify_password
from conftest import sign_in

PW = "test-pass-for-unit-tests"


@pytest.fixture
def anon(settings):
    settings.admin_password = PW
    with TestClient(create_app(settings), follow_redirects=False, base_url="https://testserver") as c:
        yield c


@pytest.fixture
def client(anon):
    return sign_in(anon, password=PW)


def form_token(client):
    """The password page is open to everyone signed in, also before the master key is set."""
    return re.search(r'name="csrf_token" value="(\w+)"', client.get("/password").text)[1]


def upload(client, path, extra_files=None, **form):
    files = {"capture": (path.name, path.read_bytes())}
    for k, p in (extra_files or {}).items():
        files[k] = (p.name, p.read_bytes())
    r = client.post("/upload", files=files, data=form)
    assert r.status_code == 200, r.text
    jid = re.search(r"/jobs/([0-9a-f]+)", r.text)
    if not jid:
        return r.text
    for _ in range(300):
        s = client.get(f"/jobs/{jid[1]}")
        if "HX-Redirect" in s.headers:
            return s.headers["HX-Redirect"]
        if 'class="error"' in s.text:
            return s.text
        time.sleep(0.05)
    raise AssertionError("analysis did not finish")


def _first_login(settings, **kw):
    for k, v in kw.items():
        setattr(settings, k, v)
    c = TestClient(create_app(settings), follow_redirects=False, base_url="https://testserver")
    r = c.post("/login", data={"username": "admin", "password": "admin"})
    return c, r


@pytest.mark.parametrize("configured", [{}, {"admin_password": "admin"}, {"admin_password_hash": hash_password("admin")}])
def test_first_sign_in_is_admin_admin_and_must_change(settings, configured):
    c, r = _first_login(settings, **configured)
    with c:
        assert r.status_code == 303 and r.headers["location"] == "/password"
        for path in ("/", "/preferences", "/compare", "/a/0123456789abcdef0123/inspect"):
            assert c.get(path).headers.get("location") == "/password", path
        assert c.get("/", headers={"HX-Request": "true"}).headers["HX-Redirect"] == "/password"
        page = c.get("/password")
        assert page.status_code == 200 and "first sign-in with the default password" in page.text
        token = re.search(r'name="csrf_token" value="(\w+)"', page.text)[1]
        bad = {"current": "admin", "new": "short", "again": "short", "csrf_token": token}
        assert "at least 12 characters" in c.post("/password", data=bad).text
        assert "at least 12 characters" in c.post("/password", data={**bad, "new": "eleven-char", "again": "eleven-char"}).text
        assert "do not match" in c.post("/password", data={**bad, "new": "a-long-new-pass-1", "again": "other-long-pass-2"}).text
        assert "current password is wrong" in c.post("/password", data={**bad, "current": "nope", "new": "a-long-new-pass-1", "again": "a-long-new-pass-1"}).text
        assert c.post("/password", data={**bad, "new": "a-long-new-pass-1", "again": "a-long-new-pass-1"}).headers["location"] == "/security"
        assert c.get("/").headers["location"] == "/security"  # next the master key is set
        same = {**bad, "current": "a-long-new-pass-1", "new": "a-long-new-pass-1", "again": "a-long-new-pass-1"}
        assert "other than" in c.post("/password", data=same).text and "first sign-in" not in c.get("/password").text
    stored = settings.workdir / ".admin-password.json"
    assert stored.stat().st_mode & 0o777 == 0o600
    with TestClient(create_app(settings), follow_redirects=False, base_url="https://testserver") as again:  # a restart keeps the new password
        assert again.post("/login", data={"username": "admin", "password": "admin"}).status_code == 401
        r = again.post("/login", data={"username": "admin", "password": "a-long-new-pass-1"})
        assert r.status_code == 303 and r.headers["location"] == "/security"


def test_password_change_needs_the_form_token(settings):
    c, _ = _first_login(settings)
    with c:
        r = c.post("/password", data={"current": "admin", "new": "a-long-new-pass-1", "again": "a-long-new-pass-1"})
        assert r.status_code == 403 and not (settings.workdir / ".admin-password.json").exists()


def test_a_chosen_password_needs_no_change(anon):
    r = anon.post("/login", data={"username": "admin", "password": PW})
    assert r.headers["location"] == "/security"  # but the master key is set before anything else


def test_invalid_hash_is_refused(settings):
    settings.admin_password_hash = "PASTE_HASH_HERE"
    with pytest.raises(ValueError, match="not a valid hash"):
        create_app(settings)


def test_pages_need_login(anon):
    assert anon.get("/").headers["location"] == "/login"
    assert anon.get("/api/a/0/urls").status_code == 401
    assert anon.get("/a/00000000000000000000").status_code == 303
    assert anon.get("/healthz").json()["status"] == "ok"


def test_wrong_password_and_lockout(anon):
    for _ in range(5):
        assert anon.post("/login", data={"username": "admin", "password": "wrong"}).status_code == 401
    assert anon.post("/login", data={"username": "admin", "password": PW}).status_code == 429


def test_many_addresses_share_a_limit():
    a = Auth("admin", password="right")
    for i in range(MAX_TOTAL_FAILS):
        assert not a.blocked(f"client-{i}")
        assert a.login(f"client-{i}", "admin", "wrong") is None
    assert a.blocked("anyone-else")


def test_failed_logins_expire():
    a = Auth("admin", password="right")
    a.fails.extend((time.time() - FAIL_WINDOW_S - 1, "c") for _ in range(MAX_FAILS))
    assert not a.blocked("c") and not a.fails


def test_success_clears_only_that_client():
    a = Auth("admin", password="right")
    a.login("c", "admin", "wrong")
    a.login("d", "admin", "wrong")
    assert a.login("c", "admin", "right")
    assert [c for _, c in a.fails] == ["d"]


def test_forwarded_header_is_ignored_without_trusted_proxy(anon):
    for i in range(5):
        r = anon.post("/login", data={"username": "admin", "password": "wrong"}, headers={"X-Forwarded-For": f"10.0.0.{i}"})
        assert r.status_code == 401
    r = anon.post("/login", data={"username": "admin", "password": PW}, headers={"X-Forwarded-For": "10.0.0.99"})
    assert r.status_code == 429


def test_cleanup_runs_at_startup(settings, samples):
    settings.admin_password = PW
    a = engine.analyze(samples / "http_scenarios.pcap", settings=settings)
    old = time.time() - 8 * 86400  # nobody opened it for longer than the retention time
    os.utime(a.dir / "meta.json", (old, old))
    with TestClient(create_app(settings)):
        for _ in range(100):
            if not a.dir.exists():
                break
            time.sleep(0.02)
    assert not a.dir.exists()


def test_gzip_upload_is_analyzed(client, samples, tmp_path):
    p = tmp_path / "c.pcap.gz"
    p.write_bytes(gzip.compress((samples / "http_scenarios.pcap").read_bytes()))
    assert upload(client, p).startswith("/a/")


def test_nat_warning_is_shown(client, samples):
    page = client.get(upload(client, samples / "node_nat.pcap")).text
    assert "seen before and after NAT" in page
    client.post("/language", data={"language": "tr"})
    assert "NAT&#39;tan önce ve sonra" in client.get(upload(client, samples / "node_nat.pcap")).text


def test_zstd_upload_shows_a_clear_error(client, tmp_path):
    p = tmp_path / "c.pcap.zst"
    p.write_bytes(b"\x28\xb5\x2f\xfd" + bytes(40))
    r = client.post("/upload", files={"capture": (p.name, p.read_bytes())})
    assert r.status_code == 400 and "Decompress the file" in r.text


@pytest.mark.parametrize("field, content, expected", [
    ("capture", b"PK\x03\x04" + bytes(60), "ZIP archive"),
    ("capture", b"#NetScaler\nCLIENT_RANDOM " + b"ab" * 32 + b" " + b"cd" * 48 + b"\n", "TLS key log, not a capture"),
    ("capture", b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n", "key or certificate"),
    ("capture", b"hello\n", "text file"),
    ("keylog", bytes(range(256)) * 4, "not a TLS key log"),
    ("rsa_key", b"\x30\x82\x0b\x01" + bytes(200), "openssl pkcs12"),
    ("rsa_key", b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n", "no private key"),
])
def test_a_wrong_file_gets_a_message_that_names_it(client, samples, field, content, expected):
    files = {"capture": ("c.pcap", content if field == "capture" else (samples / "https_tls12_rsa.pcap").read_bytes())}
    if field != "capture":
        files[field] = ("x", content)
    r = client.post("/upload", files=files)
    assert r.status_code == 400 and expected in r.text and "/tmp/" not in r.text


@pytest.mark.parametrize("content, expected", [
    (b"\xd4\xc3\xb2\xa1" + bytes(10), ["cut short"]),  # tshark names the file in this message
    # tshark 4.4 and later open this file as JSON, 4.2 refuses it, and read from the pipe of an encrypted data folder it ends early
    (b"\x00\x01" * 500, ["no network packets", "format TShark understands", "cut short"]),
])
def test_an_unreadable_capture_gets_a_plain_message(client, tmp_path, content, expected):
    (tmp_path / "c.cap").write_bytes(content)
    text = upload(client, tmp_path / "c.cap")
    assert 'class="error"' in text and any(e in text for e in expected) and "/tmp/" not in text


def test_cookie_flags_and_logout(anon):
    r = anon.post("/login", data={"username": "admin", "password": PW})
    c = r.headers["set-cookie"].lower()
    assert "httponly" in c and "samesite=strict" in c
    assert anon.post("/logout", data={"csrf_token": form_token(anon)}).status_code == 303
    assert anon.get("/").status_code == 303


def test_password_hash():
    h = hash_password("x")
    assert verify_password("x", h) and not verify_password("y", h) and not verify_password("x", "junk")
    assert Auth("a", password_hash=h).login("c", "a", "x")


def test_security_headers(client):
    h = client.get("/").headers
    assert "default-src 'self'" in h["content-security-policy"] and h["x-content-type-options"] == "nosniff"


def test_cross_site_post_refused(client):
    assert client.post("/logout", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403


@pytest.mark.parametrize("path", ["/logout", "/upload", "/filters", "/filters/x/delete", "/a/x/delete", "/jobs/x/cancel"])
def test_post_needs_the_form_token(client, path):
    token = client.headers.pop("X-CSRF-Token")
    assert client.post(path).status_code == 403
    assert client.post(path, data={"csrf_token": "wrong"}).status_code == 403
    assert client.post(path, headers={"X-CSRF-Token": "wrong"}).status_code == 403
    assert client.post(path, data={"csrf_token": token}).status_code != 403
    assert path == "/logout" or client.get("/").status_code == 200


def test_form_token_belongs_to_one_session(settings):
    settings.admin_password = PW
    with TestClient(create_app(settings), follow_redirects=False, base_url="https://testserver") as c:
        def login():
            c.cookies.clear()
            assert c.post("/login", data={"username": "admin", "password": PW}).status_code == 303
            return form_token(c)
        first, second = login(), login()
        assert first != second
        assert c.post("/logout", headers={"X-CSRF-Token": first}).status_code == 403
        assert c.post("/logout", headers={"X-CSRF-Token": second}).status_code == 303


def test_refused_form_explains_itself(client):
    del client.headers["X-CSRF-Token"]
    r = client.post("/logout")
    assert "out of date" in r.text
    assert 'class="error"' in client.post("/upload", headers={"HX-Request": "true"}, files={"capture": ("a.pcap", b"x")}).text


def test_every_post_form_carries_the_token(client, samples):
    home = upload(client, samples / "http_scenarios.pcap")
    client.post("/filters", data=dict(name="Orders", url="/orders", back=f"{home}/inspect"))
    pages = [client.get(p).text for p in ("/", f"{home}/inspect", f"{home}?tab=issues", "/compare", "/capture-guide")]
    forms = [f for page in pages for f in re.findall(r"<form\b.*?</form>", page, re.S) if re.search(r'method="post"|hx-post', f)]
    assert {re.search(r'action="([^"]+)"', f)[1] for f in forms if "action=" in f} >= {"/logout", "/filters", "/language"}
    for f in forms:
        assert 'name="csrf_token"' in f or 'action="/language"' in f or "hx-post" in f, f
    assert all('"X-CSRF-Token"' in page.split("<main", 1)[0] for page in pages)


def test_https_turns_on_hsts_for_every_answer(settings):
    settings.admin_password = PW
    with TestClient(create_app(settings, https=True), follow_redirects=False, base_url="https://testserver") as c:
        for r in (c.get("/login"), c.get("/"), c.get("/static/app.css"), c.post("/upload")):
            assert r.headers["strict-transport-security"] == "max-age=31536000"
            assert r.headers["content-security-policy"]
    settings.hsts_s = 0
    with TestClient(create_app(settings, https=True), base_url="https://testserver") as c:
        assert c.get("/login").headers["strict-transport-security"] == "max-age=0"


def test_plain_http_sends_no_hsts(anon):
    assert "strict-transport-security" not in anon.get("/login").headers


def test_upload_and_all_views(client, samples):
    home = upload(client, samples / "http_scenarios.pcap")
    assert home.startswith("/a/")
    aid = home.rsplit("/", 1)[1]
    assert "http_scenarios.pcap" in client.get("/").text
    page = client.get(home).text
    assert "Where the time went" in page and "Slow service" in page
    for tab, word in (("issues", "Requests without a response"), ("urls", "data-grid"), ("connections", "data-grid"), ("hosts", "data-grid")):
        assert word in client.get(f"{home}?tab={tab}").text
        assert word in client.get(f"{home}?tab={tab}", headers={"HX-Request": "true"}).text
    assert client.get(f"{home}?tab=nope").status_code == 404
    assert "/api/users/{id}" in str(client.get(f"/api/a/{aid}/urls").json())
    assert len(client.get(f"/api/a/{aid}/connections").json()) == 12
    assert client.get(f"/api/a/{aid}/hosts").json()[0]["host"] == "app.example.test"
    assert sum(b["requests"] for b in client.get(f"/api/a/{aid}/histogram").json()) == 17
    assert client.get(f"/api/a/{aid}/statuses").status_code == 200
    assert client.get(f"/api/a/{aid}/nope").status_code == 404
    assert "HTTP 504" in client.get(f"{home}/issue/gateway").text
    assert "Connection" in client.get(f"{home}/issue/resets").text
    assert client.get(f"{home}/issue/nope").status_code == 404
    guide = client.get(f"{home}/issue/resets").text
    assert "What to check next" in guide and "9300: Idle or zombie timeout" in guide and "rfc-editor.org/rfc/rfc9293" in guide
    conn = client.get(f"{home}/conn/0").text
    assert "Slowest requests" in conn and "Window scale" in conn
    assert client.get(f"{home}/conn/999").status_code == 404
    tid = re.search(r"/txn/(\d+)", conn)[1]
    detail = client.get(f"{home}/txn/{tid}").text
    assert "Host: app.example.test" in detail and "are masked" in detail
    assert client.get(f"{home}/txn/99999").status_code == 404
    slow = re.search(r"/txn/(\d+)", client.get(f"{home}/issue/gateway").text)[1]
    page = client.get(f"{home}/txn/{slow}").text
    assert "About this result" in page and "<code>kubectl get endpointslices</code>" in page
    assert client.post(f"{home}/delete").status_code == 303
    assert client.get(home).status_code == 404


def test_inspect_and_saved_filters(client, samples):
    home = upload(client, samples / "http_scenarios.pcap")
    r = client.get(f"{home}/inspect", params=dict(src="10.10.1.50", dst="10.20.2.10", port=8080))
    assert "Slowest 10 requests" in r.text
    partial = client.get(f"{home}/inspect", params=dict(url="/files/", min_size=150000, size_of="response"), headers={"HX-Request": "true"})
    assert "large.bin" in partial.text and "<html" not in partial.text
    assert "Nothing in this capture matches" in client.get(f"{home}/inspect", params=dict(src="9.9.9.9")).text
    assert client.get(f"{home}/inspect", params=dict(port="abc")).status_code == 400
    assert client.post("/filters", data=dict(name="Orders", url="/orders", back=f"{home}/inspect")).status_code == 303
    page = client.get(f"{home}/inspect").text
    assert "Orders" in page and "url=/orders" in page.replace("%2F", "/")
    fid = re.search(r"/filters/([0-9a-f]+)/delete", page)[1]
    client.post(f"/filters/{fid}/delete", data=dict(back=f"{home}/inspect"))
    assert "Orders" not in client.get(f"{home}/inspect").text


def test_keylog_upload(client, samples):
    home = upload(client, samples / "https_tls13.pcap", {"keylog": samples / "https_tls13.keylog"})
    assert "/secure/report/{id}" in str(client.get(home.replace("/a/", "/api/a/") + "/urls").json())


def test_several_key_logs_upload(client, samples):
    files = [("capture", ("c.pcap", (samples / "https_h2.pcap").read_bytes()))] + [
        ("keylog", (p.name, p.read_bytes())) for p in (samples / "https_tls13.keylog", samples / "https_h2.keylog")]
    r = client.post("/upload", files=files)
    assert r.status_code == 200, r.text
    jid = re.search(r"/jobs/([0-9a-f]+)", r.text)[1]
    for _ in range(300):
        s = client.get(f"/jobs/{jid}")
        if "HX-Redirect" in s.headers:
            break
        time.sleep(0.05)
    home = s.headers["HX-Redirect"]
    assert len(client.get(home.replace("/a/", "/api/a/") + "/urls").json()) > 0
    assert 'name="keylog" multiple' in client.get("/").text


def test_proxy_and_gateway_facts_on_pages(client, made):
    home = upload(client, made("proxy"))
    conn = client.get(f"{home}/conn/0").text
    assert "PROXY protocol" in conn and "203.0.113.7:40000" in conn and "198.51.100.10:443" in conn
    pages = [client.get(f"{home}/txn/{i}").text for i in (1, 2, 3)]
    assert any("203.0.113.7:40000 (PROXY v2)" in p for p in pages)
    assert any("Upstream time reported by the gateway" in p and "Time in the gateway itself" in p for p in pages)


@pytest.mark.parametrize("typed", ["not a ) filter", "frame.len > 0", "tcp.port == 80"])
def test_only_a_preset_display_filter_is_accepted(client, samples, typed):
    r = client.post("/upload", files={"capture": ("a.pcap", (samples / "http_scenarios.pcap").read_bytes())}, data={"display_filter": typed})
    assert r.status_code == 400 and "Choose a display filter from the list." in r.text
    htmx = client.post("/upload", files={"capture": ("a.pcap", b"x")}, data={"display_filter": typed}, headers={"HX-Request": "true"})
    assert 'class="error"' in htmx.text


def test_a_preset_display_filter_analyzes(client, samples):
    home = upload(client, samples / "http_scenarios.pcap", display_filter="http || http2")
    assert home.startswith("/a/") and "(http || http2)" in client.get("/").text


def test_the_display_filter_is_a_list_of_presets(client, samples):
    from pcap_analyzer.display_filters import PRESETS
    page = client.get("/").text
    assert '<select name="display_filter">' in page and 'name="display_filter" spellcheck' not in page
    assert len(PRESETS) == 18 and all(f'value="{html.escape(v)}"' in page for v in PRESETS)
    assert ">TCP retransmissions<" in page and ">All packets<" in page


def test_bad_ip_rejected(client, samples):
    r = client.post("/upload", files={"capture": ("a.pcap", b"x")}, data={"host_a": "nope"})
    assert "not a valid IP" in r.text


def test_upload_size_limit(client, samples, settings):
    settings.max_size_mb = 0
    r = client.post("/upload", files={"capture": ("a.pcap", b"x" * (3 * 1024 * 1024))})
    assert r.status_code == 413


def test_garbage_file_shows_error(client, tmp_path):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(bytes(range(256)) * 4)
    assert 'class="error"' in upload(client, bad)


def test_html_is_escaped(client, samples, tmp_path):
    p = tmp_path / "<script>x.pcap"
    p.write_bytes((samples / "http_scenarios.pcap").read_bytes())
    upload(client, p)
    assert "<script>x" not in client.get("/").text


def test_compare_page(client, samples):
    a = upload(client, samples / "netscaler_front.pcap", {"keylog": samples / "netscaler_front.keylog"}).rsplit("/", 1)[1]
    b = upload(client, samples / "netscaler_back.pcap").rsplit("/", 1)[1]
    assert "Capture A" in client.get("/compare").text
    p = client.get("/compare", params=dict(a=a, b=b)).text
    assert "Summary" in p and "By URL" in p
    p = client.get("/compare", params=dict(a=a, b=b, src_a="10.10.1.50", src_b="10.30.0.5")).text
    assert "Summary" in p
    p = client.get("/compare", params=dict(a=a, b=b, mode="points")).text
    assert "2 matched by request ID" in p and "/api/b/3" in p
    p = client.get("/compare", params=dict(a=a, b=b, mode="points", offset_ms="1,5")).text
    assert "The clock difference you gave is used" in p and "1.5 ms" in p
    assert client.get("/compare", params=dict(a=a, b=b, mode="points", offset_ms="soon")).status_code == 400
    assert client.get("/compare", params=dict(a=a, b="0" * 20)).status_code == 404


def test_compare_needs_two(client):
    assert "at least two captures" in client.get("/compare").text


def test_downloads(client, samples, tmp_path):
    home = upload(client, samples / "http_scenarios.pcap")
    aid = home.rsplit("/", 1)[1]
    for name, fmt, sniff in (("urls", "csv", b"Method"), ("requests", "json", b"["), ("hosts", "xlsx", b"PK")):
        r = client.get(f"/export/{aid}/{name}.{fmt}")
        assert r.status_code == 200 and sniff in r.content[:20] and "attachment" in r.headers["content-disposition"]
    assert client.get(f"/export/{aid}/nope.csv").status_code == 404
    assert client.get(f"/export/{aid}/urls.exe").status_code == 404
    rep = client.get(f"/export/{aid}/report.html").text
    assert "Where the time went" in rep and "<style>" in rep and "<script" not in rep
    r = client.get(f"/export/{aid}/conn/2.pcapng")
    assert r.status_code == 200 and r.content[:4] == b"\x0a\x0d\x0d\x0a"
    out = tmp_path / "one.pcapng"
    out.write_bytes(r.content)
    from pcap_analyzer.tshark import packets
    assert {p["tcp.dstport"] for p in packets(out)} == {"8080", "40003"}
    assert client.get(f"/export/{aid}/conn/999.pcapng").status_code == 404


def test_download_needs_login(anon):
    assert anon.get("/export/" + "0" * 20 + "/urls.csv").status_code == 303


def test_new_pages(client, samples):
    home = upload(client, samples / "backends.pcap")
    assert "10.50.0.3:8080" in client.get(f"{home}?tab=backends").text
    assert "data-chart=\"timeline\"" in client.get(home).text
    aid = home.rsplit("/", 1)[1]
    line = client.get(f"/api/a/{aid}/timeline").json()
    assert sum(r["requests"] for r in line["rows"]) == 30
    start, end = line["rows"][0]["start"], line["rows"][5]["start"]
    assert "Show the whole capture" in client.get(f"{home}/inspect?start={start}&end={end}").text
    guide = client.get("/capture-guide?server=10.0.0.5&port=8080&seconds=30").text
    assert "timeout 30 tcpdump" in guide and "kubectl debug" in guide
    assert "valid" in client.get("/capture-guide?server=nonsense").text
    assert client.get("/capture-guide?seconds=99999").status_code == 400


def test_cancel_page(client):
    assert client.post("/jobs/unknown/cancel").status_code in (200, 404)


def test_recent_captures_are_listed_for_the_signed_in_only(client, samples):
    upload(client, samples / "http_scenarios.pcap")
    assert 'class="ticker"' in client.get("/capture-guide").text
    client.cookies.clear()
    page = client.post("/language", data={"language": "xx"})
    assert page.status_code == 400
    assert "http_scenarios.pcap" not in page.text and 'class="ticker"' not in page.text


def test_capture_pages_open_with_the_score_and_a_url_search(client, samples):
    target = upload(client, samples / "http_scenarios.pcap")
    page = client.get(target).text
    assert re.search(r'class="score".*?class="good">13<.*?class="bad">5<', page, re.S)
    assert f'action="{target}/inspect"' in page and 'name="url"' in page
    assert client.get(f"{target}/inspect", params={"url": "/api/pay"}).status_code == 200


def test_captures_are_listed_by_day(client, samples):
    upload(client, samples / "http_scenarios.pcap")
    upload(client, samples / "http_scenarios.pcap")
    assert client.get("/").text.count('class="day"') == 1


def test_static_files_carry_their_change_time(client):
    from pcap_analyzer import __version__
    page = client.get("/").text
    css, js = re.search(r'app\.css\?v=([\w.]+)"', page)[1], re.search(r'app\.js\?v=([\w.]+)"', page)[1]
    assert css == js and css.startswith(__version__ + ".") and len(css) > len(__version__) + 1
    assert 'logo-on-dark.png" alt="" width="196" height="45"' in page
