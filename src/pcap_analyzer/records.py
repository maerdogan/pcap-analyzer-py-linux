"""Small records kept beside the analyses: notes, audit trail, baseline, thresholds and API tokens. All of them are written through the vault."""
import base64
import binascii
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from pathlib import Path

from . import causes, vault

AUDIT_KEEP = 10_000
TOKEN_PREFIX = "pat_"
_audit_lock = threading.Lock()


def _read(path, default):
    return vault.read_json(path, default)


def _write(path, data):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    vault.write_json(path, data, indent=2)


def notes(settings, aid):
    return _read(settings.workdir / aid / "notes.json", dict(case="", tags="", note=""))


def save_notes(settings, aid, case, tags, note):
    _write(settings.workdir / aid / "notes.json", dict(case=case.strip()[:80], tags=tags.strip()[:200], note=note.strip()[:4000]))


def search(settings, metas, text):
    """Analyses whose file name, case, tags or note hold the text."""
    text = text.strip().casefold()
    if not text:
        return metas
    found = []
    for m in metas:
        n = notes(settings, m["id"])
        if text in " ".join((m["filename"], n["case"], n["tags"], n["note"])).casefold():
            found.append(m)
    return found


def audit_file(workdir):
    """The activity log. Its name says nothing about it, and once the data folder is encrypted every line is encrypted on its own."""
    return Path(workdir) / vault.AUDIT


def _legacy_audit(workdir):
    """An audit.log of an earlier version moves into the activity log."""
    old = Path(workdir) / "audit.log"
    if not old.exists():
        return
    v = vault.of(workdir)
    if v.is_set_up():
        v._hide_audit()
        return
    lines = old.read_text(encoding="utf-8")
    if audit_file(workdir).exists():
        lines += audit_file(workdir).read_text(encoding="utf-8")
    tmp = audit_file(workdir).with_suffix(".tmp")
    tmp.write_text(lines, encoding="utf-8")
    vault.private600(tmp)
    tmp.replace(audit_file(workdir))
    old.unlink()


def audit(settings, event, client, detail="", user=""):
    audit_to(settings.workdir, event, client, detail, user)


def audit_to(workdir, event, client, detail="", user=""):
    """Each line is encrypted with the public key alone, so lines are added while the vault is locked too."""
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    line = json.dumps(dict(time=time.time(), event=event, client=client, user=user or "", detail=str(detail)[:300]))
    v = vault.of(workdir)
    with _audit_lock:
        _legacy_audit(workdir)
        if v.is_set_up():
            line = base64.b64encode(v.seal_bytes(line.encode())).decode()
        fd = os.open(audit_file(workdir), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.write(line + "\n")


def read_audit(settings, event=None, limit=500):
    v = vault.of(settings.workdir)
    path = audit_file(settings.workdir)
    try:
        with _audit_lock:
            _legacy_audit(settings.workdir)
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    found = []
    for line in reversed(lines[-AUDIT_KEEP:]):
        if len(found) >= limit:
            break
        try:
            if line.startswith("{"):
                if v.is_set_up():
                    v.alert(path, "A plain line was added to the activity log by hand.")
                    continue
                row = json.loads(line)
            else:
                row = json.loads(v.open_bytes(base64.b64decode(line, validate=True), path))
        except vault.Locked:
            return []
        except (OSError, ValueError, binascii.Error):
            continue
        if not event or row.get("event") == event:
            row.setdefault("user", "")
            found.append(row)
    return found


def trim_audit(settings):
    path = audit_file(settings.workdir)
    with _audit_lock:
        try:
            lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        except OSError:
            return
        if len(lines) > AUDIT_KEEP:
            tmp = path.with_suffix(".tmp")
            tmp.write_text("".join(lines[-AUDIT_KEEP:]), encoding="utf-8")
            vault.private600(tmp)
            tmp.replace(path)


def baseline(settings, group=""):
    """The baseline of a group; admins without a group have their own. A baseline of an earlier version belongs to them."""
    data = _read(settings.workdir / "baseline.json", {})
    if "groups" not in data:
        return data.get("id") if not group else None
    return data["groups"].get(group or "")


def set_baseline(settings, aid, group=""):
    data = _read(settings.workdir / "baseline.json", {})
    groups = data.get("groups") or ({"": data["id"]} if data.get("id") else {})
    groups[group or ""] = aid
    _write(settings.workdir / "baseline.json", dict(groups=groups))


def thresholds(settings):
    return _read(settings.workdir / "thresholds.json", dict(slow_s=causes.SLOW_S, targets=[]))


def slow_s(settings):
    return thresholds(settings)["slow_s"]


def save_thresholds(settings, slow, targets):
    _write(settings.workdir / "thresholds.json", dict(slow_s=slow, targets=targets))


def parse_targets(text):
    """One 'URL-pattern seconds' per line. Returns the targets and the lines that could not be read."""
    targets, bad = [], []
    for line in text.splitlines():
        m = re.fullmatch(r"\s*(\S+)\s+([0-9]*\.?[0-9]+)\s*", line)
        if m:
            targets.append(dict(pattern=m[1], seconds=float(m[2])))
        elif line.strip():
            bad.append(line.strip())
    return targets, bad


def _hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def tokens(settings):
    return _read(settings.workdir / "api_tokens.json", [])


def new_token(settings, name, group=None):
    """The token itself is shown once. Only its hash is stored, and it has 256 random bits, so a plain hash is enough.
    A token with a group sees and uploads only the captures of that group; one without sees every group."""
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    rows = tokens(settings)
    rows.append(dict(id=secrets.token_hex(6), name=name.strip()[:80], hash=_hash(token), created=time.time(), group=group or None))
    _write(settings.workdir / "api_tokens.json", rows)
    return token


def revoke_token(settings, tid):
    _write(settings.workdir / "api_tokens.json", [t for t in tokens(settings) if t["id"] != tid])


def token_info(settings, token):
    """The record of a valid token, or None."""
    digest = _hash(token or "")
    return next((t for t in tokens(settings) if hmac.compare_digest(t["hash"], digest)), None)


def token_name(settings, token):
    """The name of a valid token, or None."""
    t = token_info(settings, token)
    return (t["name"] or t["id"]) if t else None
