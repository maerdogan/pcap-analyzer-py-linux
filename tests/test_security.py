"""Users, roles, groups, LDAP, the first setup, encryption seen from the web app, and retention."""
import base64
import json
import logging
import os
import re
import time

import duckdb
import pytest
from fastapi.testclient import TestClient

from conftest import MASTER, page_token, sign_in
from pcap_analyzer import engine, records, store, vault
from pcap_analyzer.config import Settings
from pcap_analyzer.web import directory
from pcap_analyzer.web.app import create_app
from pcap_analyzer.web.users import Users
from test_web import upload

ADMIN = "Admin-Password-1"
AID = "0123456789abcdef0123"
USER_PW = "User-Password-1"


def test_users_and_groups_are_encrypted(tmp_path):
    wd = tmp_path / "w"
    vault.of(wd).set_up(ADMIN, MASTER)
    people = Users(Settings(workdir=wd))
    people.add_group("neta", "Ağ ekibi")
    people.add("ali", "Ali Yılmaz", "S1", "neta", "viewer", USER_PW)
    raw = (wd / "users.json").read_bytes()
    assert b"ali" not in raw and b"neta" not in raw and b"scrypt" not in raw
    u = people.verify("ali", USER_PW)
    assert u and u.must_change, "a new local user must change the password"
    people.set_own_password("ali", "User-Password-2")
    assert not people.verify("ali", "User-Password-2").must_change
    assert people.list()[0]["full_name"] == "Ali Yılmaz" and people.delete_group("neta") == "users"


def test_password_rules_are_the_same_for_everyone():
    from pcap_analyzer.web.users import password_problem
    assert password_problem("ann", "eleven-char")
    assert password_problem("long.user.name", "Long.User.Name")
    assert password_problem("x", "ADMIN") and password_problem("admin", "admin")
    assert password_problem("ann", "twelve-chars") is None


def test_ldap_filter_is_escaped():
    assert directory.escape("a*(b)\\") == r"a\2a\28b\29\5c"
    assert directory.escape("x\0y") == r"x\00y"


class FakeConn:
    """A directory with one user, uid=ali, whose password is right-pass."""
    searched = []

    def __init__(self, dn, password):
        self.dn, self.password, self.response = dn, password, []

    def search(self, base, flt, **kw):
        FakeConn.searched.append(flt)
        self.response = [dict(type="searchResEntry", dn="uid=ali,dc=example")] if flt == "(uid=ali)" else []

    def unbind(self):
        pass


def test_ldap_users_sign_in_by_search_and_bind(tmp_path, monkeypatch):
    s = Settings(workdir=tmp_path / "w")
    s.workdir.mkdir()
    directory.save(s, dict(url="ldaps://dc.example.com:636", bind_dn="cn=svc", bind_password="svc-pass", base_dn="dc=example", user_filter="(uid={0})"))
    assert directory.load(s)["bind_password"] == "svc-pass"
    directory.save(s, dict(url="ldaps://dc.example.com:636", bind_dn="cn=svc", bind_password="", base_dn="dc=example", user_filter="(uid={0})"))
    assert directory.load(s)["bind_password"] == "svc-pass", "an empty password keeps the saved one"
    good = {("cn=svc", "svc-pass"), ("uid=ali,dc=example", "right-pass")}
    monkeypatch.setattr(directory, "_bind", lambda _s, dn, pw: FakeConn(dn, pw) if (dn, pw) in good else None)
    assert directory.authenticate(s, "ali", "right-pass")
    assert not directory.authenticate(s, "ali", "wrong")
    assert not directory.authenticate(s, "ali", ""), "an empty password is an anonymous bind on many servers"
    assert not directory.authenticate(s, "*)(uid=*", "right-pass")
    assert FakeConn.searched[-1] == r"(uid=\2a\29\28uid=\2a)"
    assert directory.test(s)[1] and directory.test(s, "ali") == ("OK: ali is uid=ali,dc=example", True)
    assert directory.problem(dict(url="http://x", user_filter="(uid={0})")) and directory.problem(dict(url="", user_filter="(uid=x)"))


# ---- the web app

def _client(app):
    return TestClient(app, follow_redirects=False, base_url="https://testserver")


@pytest.fixture
def site(settings, samples):
    """An install after its first setup, with two groups. ann and abe are analysts in red, bob an analyst in blue, val a viewer in red."""
    settings.admin_password = ADMIN
    app = create_app(settings)
    with _client(app) as admin:
        sign_in(admin, password=ADMIN)
        for g in ("red", "blue"):
            assert admin.post("/users/groups", data=dict(group_name=g, description=f"The {g} team")).status_code == 200
        for name, group, role in (("ann", "red", "analyst"), ("abe", "red", "analyst"), ("bob", "blue", "analyst"), ("val", "red", "viewer")):
            r = admin.post("/users", data=dict(name=name, full_name=name.title(), employee_id="E1", group=group, role=role, password=USER_PW))
            assert f"{name} was added" in r.text, r.text
        yield dict(app=app, admin=admin, settings=settings, samples=samples)


def _user(site, name, password=USER_PW):
    """A user's own browser, past the first sign-in, which asks for a new password."""
    c = _client(site["app"])
    r = c.post("/login", data=dict(username=name, password=password))
    assert r.status_code == 303 and r.headers["location"] == "/password"
    token = page_token(c.get("/password").text)
    assert c.get("/").headers["location"] == "/password"
    assert "at least 12" in c.post("/password", data=dict(current=password, new="short", again="short", csrf_token=token)).text
    assert "other than the current one" in c.post("/password", data=dict(current=password, new=password, again=password, csrf_token=token)).text
    done = c.post("/password", data=dict(current=password, new=f"{name}-New-Password", again=f"{name}-New-Password", csrf_token=token))
    assert done.headers["location"] == "/"
    c.headers["X-CSRF-Token"] = token
    return c


def _basic(name):
    return {"Authorization": "Basic " + base64.b64encode(f"{name}:{name}-New-Password".encode()).decode()}


def test_first_run_admin_admin_then_master_key_then_everything_is_encrypted(settings, samples):
    old = engine.analyze(samples / "http_scenarios.pcap", settings=settings)  # made before the setup, so plain and without a group
    records.audit(settings, "upload", "test")
    with _client(create_app(settings)) as c:
        r = c.post("/login", data=dict(username="admin", password="admin"))
        assert r.headers["location"] == "/password"
        token = page_token(c.get("/password").text)
        assert "at least 12" in c.post("/password", data=dict(current="admin", new="eleven-char", again="eleven-char", csrf_token=token)).text
        r = c.post("/password", data=dict(current="admin", new=ADMIN, again=ADMIN, csrf_token=token))
        assert r.headers["location"] == "/security"
        for path in ("/", "/users", "/preferences", f"/a/{old.id}"):
            assert c.get(path).headers["location"] == "/security", path
        assert "Set the master key to finish the setup" in c.get("/security").text
        assert "exactly 16 characters" in c.post("/security", data=dict(master="short", again="short", password=ADMIN, csrf_token=token)).text
        assert "only letters and digits" in c.post("/security", data=dict(master="abcdefgh12345678", again="abcdefgh12345678", password=ADMIN, csrf_token=token)).text
        assert "not the same" in c.post("/security", data=dict(master=MASTER, again=MASTER[::-1], password=ADMIN, csrf_token=token)).text
        assert "current password is wrong" in c.post("/security", data=dict(master=MASTER, again=MASTER, password="nope", csrf_token=token)).text
        assert not (settings.workdir / ".keyring").exists()
        done = c.post("/security", data=dict(master=MASTER, again=MASTER, password=ADMIN, csrf_token=token))
        assert "now encrypted" in done.text
        assert not (settings.workdir / ".admin-password.json").exists(), "the admin password now lives only in the admin key"
        for name in ("meta.json", "capture", store.KEY_FILE if store.NATIVE_ENCRYPTION else "analysis.duckdb"):
            assert vault.is_encrypted(old.dir / name), name
        with pytest.raises(duckdb.Error):
            duckdb.connect(str(old.dir / "analysis.duckdb"), read_only=True)
        assert b"upload" not in (settings.workdir / ".idx0").read_bytes()
        assert c.get(f"/a/{old.id}").status_code == 200, "the admin sees captures from before groups existed"
        page = c.get("/security").text
        assert MASTER not in page and "AES-256-GCM" in page
        assert MASTER in c.post("/security/reveal", data=dict(csrf_token=token)).text
        assert "was changed" in c.post("/security", data=dict(master="N3w&Key*2026abcd", again="N3w&Key*2026abcd", csrf_token=token)).text
        audit = c.get("/audit").text
        assert "vault_set_up" in audit and "master_key_shown" in audit and "master_key_changed" in audit


def test_the_admin_password_from_the_settings_is_taken_over_once(settings, caplog):
    settings.admin_password = ADMIN
    with caplog.at_level(logging.WARNING):
        create_app(settings)
    assert "saved as a hash" in caplog.text and "Remove it" in caplog.text
    stored = json.loads((settings.workdir / ".admin-password.json").read_text())
    assert stored["hash"].startswith("scrypt$") and ADMIN not in json.dumps(stored)
    settings.admin_password = "something-else-entirely"
    caplog.clear()
    with caplog.at_level(logging.WARNING), _client(create_app(settings)) as c:
        assert "is set but ignored" in caplog.text
        assert c.post("/login", data=dict(username="admin", password="something-else-entirely")).status_code == 401
        assert c.post("/login", data=dict(username="admin", password=ADMIN)).status_code == 303
    settings.admin_password = "short"
    (settings.workdir / ".admin-password.json").unlink()
    with _client(create_app(settings)) as c:  # a weak password from the settings must be changed at once
        assert c.post("/login", data=dict(username="admin", password="short")).headers["location"] == "/password"


def test_after_a_restart_only_the_setup_admin_opens_the_data(site):
    _user(site, "ann")
    vault.of(site["settings"].workdir).lock()  # what a restart leaves
    app = create_app(site["settings"])
    with _client(app) as c:
        r = c.post("/login", data=dict(username="ann", password="ann-New-Password"))
        assert r.status_code == 503 and "Waiting for the admin" in r.text and r.headers["retry-after"]
        assert c.get("/api/v1/analyses", headers=_basic("ann")).status_code == 503
        assert c.post("/login", data=dict(username="admin", password="wrong-password")).status_code == 401
        assert c.post("/login", data=dict(username="admin", password=ADMIN)).headers["location"] == "/"
        c.cookies.clear()
        assert c.post("/login", data=dict(username="ann", password="ann-New-Password")).headers["location"] == "/"


def test_roles(site, samples):
    ann, val, bob = _user(site, "ann"), _user(site, "val"), _user(site, "bob")
    home = upload(ann, samples / "http_scenarios.pcap")
    aid = home.rsplit("/", 1)[1]
    for c in (ann, val, bob):
        for path in ("/users", "/preferences", "/audit", "/security"):
            assert c.get(path).status_code == 403, path
        for path in ("/users/groups", "/tokens", "/users/ann/delete", "/security/alerts/clear", "/preferences"):
            assert c.post(path).status_code == 403, path
    assert val.get(home).status_code == 200 and val.get(f"/export/{aid}/requests.csv").status_code == 200
    assert "Analyze a capture" not in val.get("/").text and "Save notes" not in val.get(home).text
    for path in ("/upload", f"/a/{aid}/notes", f"/a/{aid}/baseline", f"/a/{aid}/delete", "/filters"):
        assert val.post(path, data=dict(name="x")).status_code == 403, path
    assert ann.post(f"/a/{aid}/notes", data=dict(note="seen")).status_code == 303
    assert ann.post("/filters", data=dict(name="mine", back=f"/a/{aid}/inspect")).status_code == 303
    assert "Users" not in re.sub(r"<main.*", "", ann.get("/").text, flags=re.S).split("Settings", 1)[1].split("</details>")[0]
    assert site["admin"].get("/users").status_code == 200


def test_groups_see_only_their_own_captures(site, samples):
    ann, bob = _user(site, "ann"), _user(site, "bob")
    old = engine.analyze(samples / "backends.pcap", settings=site["settings"])  # no group: admins only
    red = upload(ann, samples / "http_scenarios.pcap").rsplit("/", 1)[1]
    blue = upload(bob, samples / "http_scenarios.pcap").rsplit("/", 1)[1]
    assert red != blue, "the same capture in another group is its own analysis"
    for aid in (blue, old.id):
        for path in (f"/a/{aid}", f"/a/{aid}?tab=urls", f"/a/{aid}/inspect", f"/a/{aid}/conn/0", f"/a/{aid}/txn/1", f"/a/{aid}/flow",
                     f"/export/{aid}/report.html", f"/export/{aid}/requests.csv", f"/export/{aid}/requests.har", f"/export/{aid}/conn/0.pcapng",
                     f"/api/a/{aid}/urls", f"/api/a/{aid}/waterfall/0", f"/compare?a={red}&b={aid}", f"/compare?a={aid}&b={red}"):
            assert ann.get(path).status_code == 404, path
        for path in (f"/a/{aid}/notes", f"/a/{aid}/baseline", f"/a/{aid}/delete"):
            assert ann.post(path).status_code == 404, path
    assert ann.get(f"/compare?a={red}&b={red}").status_code == 200
    listing = ann.get("/").text
    assert red in listing and blue not in listing and old.id not in listing
    assert blue not in ann.get("/compare").text and blue not in ann.get(f"/a/{red}").text
    assert site["admin"].get(f"/a/{blue}").status_code == 200 and site["admin"].get(f"/a/{old.id}").status_code == 200
    assert {red, blue, old.id} <= set(re.findall(r"/a/([0-9a-f]{20})", site["admin"].get("/").text))
    # a baseline is one group's own
    assert bob.post(f"/a/{blue}/baseline").status_code == 303
    assert "Different from the baseline" not in ann.get(f"/a/{red}").text
    # the REST API, with a user's name and password or with a token of a group
    api = "/api/v1/analyses"
    assert [a["id"] for a in ann.get(api, headers=_basic("ann")).json()] == [red]
    for path in (f"{api}/{blue}", f"{api}/{blue}/urls", f"{api}/{blue}/overview", f"{api}/{old.id}"):
        assert ann.get(path, headers=_basic("ann")).status_code == 404, path
    assert ann.delete(f"{api}/{blue}", headers=_basic("ann")).status_code == 404
    assert ann.get(f"{api}/{red}/urls", headers=_basic("ann")).status_code == 200
    page = site["admin"].post("/tokens", data=dict(name="red-ci", group="red")).text
    red_token = re.search(r"pat_[\w-]+", page)[0]
    page = site["admin"].post("/tokens", data=dict(name="all-ci", group="")).text
    all_token = re.search(r"pat_[\w-]+", page)[0]
    assert ann.get(f"{api}/{blue}", headers={"Authorization": f"Bearer {red_token}"}).status_code == 404
    assert ann.get(f"{api}/{red}", headers={"Authorization": f"Bearer {red_token}"}).status_code == 200
    assert ann.get(f"{api}/{blue}", headers={"Authorization": f"Bearer {all_token}"}).status_code == 200
    assert ann.get(api, headers={"Authorization": "Basic " + base64.b64encode(b"ann:wrong").decode()}).status_code == 401


def test_jobs_are_seen_only_in_their_group(site, samples):
    ann, bob = _user(site, "ann"), _user(site, "bob")
    files = {"capture": ("c.pcap", (samples / "http_scenarios.pcap").read_bytes())}
    r = ann.post("/upload", files=files)
    jid = re.search(r"/jobs/([0-9a-f]+)", r.text)[1]
    assert bob.get(f"/jobs/{jid}").status_code == 404
    assert bob.post(f"/jobs/{jid}/cancel").status_code == 404
    assert bob.get(f"/api/v1/jobs/{jid}", headers=_basic("bob")).status_code == 404
    job = ann.post("/api/v1/captures", files=files, headers=_basic("ann")).json()["job"]
    assert bob.get(f"/api/v1/jobs/{job}", headers=_basic("bob")).status_code == 404
    for _ in range(300):
        state = ann.get(f"/api/v1/jobs/{job}", headers=_basic("ann")).json()
        if state["state"] == "done":
            break
        time.sleep(0.05)
    assert engine.open_analysis(state["analysis"], site["settings"]).meta["group"] == "red"
    assert engine.open_analysis(state["analysis"], site["settings"]).meta["uploader"] == "ann"


def test_only_the_uploader_or_an_admin_deletes(site, samples):
    ann, abe = _user(site, "ann"), _user(site, "abe")
    aid = upload(ann, samples / "http_scenarios.pcap").rsplit("/", 1)[1]
    assert f"/a/{aid}/delete" not in abe.get("/").text and f"/a/{aid}/delete" in ann.get("/").text
    assert abe.post(f"/a/{aid}/delete").status_code == 403
    assert abe.delete(f"/api/v1/analyses/{aid}", headers=_basic("abe")).status_code == 403
    assert ann.post(f"/a/{aid}/delete").status_code == 303 and ann.get(f"/a/{aid}").status_code == 404
    aid = upload(ann, samples / "backends.pcap").rsplit("/", 1)[1]
    assert site["admin"].post(f"/a/{aid}/delete").status_code == 303


def test_users_and_groups_are_managed_by_the_admin(site):
    admin = site["admin"]
    page = admin.get("/users").text
    assert "Setup admin" in page and "The red team" in page and "Ann" in page
    assert "still has users" in admin.post("/users/groups/red/delete").text
    assert "already exists" in admin.post("/users/groups", data=dict(group_name="red")).text
    assert "Choose one of the groups" in admin.post("/users", data=dict(name="zed", full_name="Zed", group="green", role="viewer", password=USER_PW)).text
    assert "at least 12" in admin.post("/users", data=dict(name="zed", full_name="Zed", group="red", role="viewer", password="short")).text
    assert "taken" in admin.post("/users", data=dict(name="admin", full_name="X", group="red", role="viewer", password=USER_PW)).text
    assert "full name" in admin.post("/users", data=dict(name="zed", full_name=" ", group="red", role="viewer", password=USER_PW)).text
    assert admin.post("/users/admin/delete").status_code == 403 and admin.post("/users/admin/update").status_code == 403
    assert admin.post("/users/groups", data=dict(group_name="green", description="Green")).status_code == 200
    assert admin.post("/users/groups/green/update", data=dict(description="Greens")).status_code == 303 and "Greens" in admin.get("/users").text
    assert admin.post("/users/val/update", data=dict(full_name="Val Kaya", employee_id="S-42", group="green", role="analyst")).status_code == 303
    u = Users(site["settings"]).get("val")
    assert (u["full_name"], u["employee_id"], u["group"], u["role"]) == ("Val Kaya", "S-42", "green", "analyst")
    assert admin.post("/users/groups/blue/delete").status_code == 400  # bob is still in it
    assert admin.post("/users/bob/delete").status_code == 303 and admin.post("/users/groups/blue/delete").status_code == 303
    assert "blue" not in Users(site["settings"]).groups()


def test_a_reset_password_must_be_changed(site):
    ann = _user(site, "ann")
    assert "was reset" in site["admin"].post("/users/ann/password", data=dict(password="Reset-Password-9")).text
    assert ann.get("/").headers["location"] == "/password", "the reset applies at once"
    c = _client(site["app"])
    assert c.post("/login", data=dict(username="ann", password="Reset-Password-9")).headers["location"] == "/password"
    assert c.get("/api/v1/analyses", headers={"Authorization": "Basic " + base64.b64encode(b"ann:Reset-Password-9").decode()}).status_code == 403


def test_a_role_change_and_a_deleted_user_apply_at_once(site):
    val = _user(site, "val")
    assert val.post("/filters", data=dict(name="x")).status_code == 403
    site["admin"].post("/users/val/update", data=dict(full_name="Val", group="red", role="analyst"))
    assert val.post("/filters", data=dict(name="x", back="/")).status_code == 303
    site["admin"].post("/users/val/delete")
    assert val.get("/").headers["location"] == "/login"


def test_files_changed_by_hand_raise_a_notice_for_admins(site):
    ann = _user(site, "ann")
    wd = site["settings"].workdir
    (wd / "planted.json").write_text("{}")
    vault.of(wd).scan()
    home = site["admin"].get("/").text
    assert "files were changed by hand" in home
    assert "files were changed by hand" not in ann.get("/").text
    page = site["admin"].get("/security").text
    assert "planted.json" in page and "Mark as seen" in page
    site["admin"].post("/security/alerts/clear")
    assert "files were changed by hand" not in site["admin"].get("/").text


def test_the_audit_log_is_hidden_and_names_who(site):
    _user(site, "ann")
    wd = site["settings"].workdir
    assert not (wd / "audit.log").exists()
    raw = (wd / ".idx0").read_text()
    assert "user_added" not in raw and "login" not in raw and all(not line.startswith("{") for line in raw.splitlines())
    rows = records.read_audit(site["settings"])
    assert any(r["event"] == "password_changed" and r["user"] == "ann" for r in rows)
    assert any(r["event"] == "user_added" and r["user"] == "admin" for r in rows)
    with open(wd / ".idx0", "a") as f:
        f.write('{"event":"forged","time":1}\n')
    assert not any(r["event"] == "forged" for r in records.read_audit(site["settings"]))
    assert any("plain line" in a["reason"] for a in vault.of(wd).alerts())


def test_everything_stored_is_encrypted(site, samples):
    ann = _user(site, "ann")
    aid = upload(ann, samples / "http_scenarios.pcap").rsplit("/", 1)[1]
    ann.post(f"/a/{aid}/notes", data=dict(case="CASE-77", note="a secret note"))
    ann.post("/filters", data=dict(name="my-filter", back="/"))
    ann.get(f"/a/{aid}/stats/overview")
    site["admin"].post("/preferences", data=dict(slow="2", targets="/api/* 1"))
    site["admin"].post("/tokens", data=dict(name="token-name"))
    site["admin"].post("/users/ldap", data=dict(url="ldaps://dc.example.com", bind_dn="cn=svc", bind_password="svc-secret", base_dn="dc=x", user_filter="(uid={0})"))
    wd = site["settings"].workdir
    plain = []
    for p in wd.rglob("*"):
        if p.is_file() and p.name not in (".keyring", ".idx0", ".seen") and p.suffix != ".duckdb" and not vault.is_encrypted(p):
            plain.append(str(p.relative_to(wd)))
    assert not plain
    every = b"".join(p.read_bytes() for p in wd.rglob("*") if p.is_file())
    for secret in (b"CASE-77", b"a secret note", b"my-filter", b"svc-secret", b"token-name", b"/api/*", b"http_scenarios"):
        assert secret not in every, secret
    with pytest.raises(duckdb.Error):
        duckdb.connect(str(wd / aid / "analysis.duckdb"), read_only=True).execute("SELECT 1 FROM http_transactions")


def test_retention_counts_from_the_last_view(settings, samples):
    settings.ttl_days = 7
    a = engine.analyze(samples / "http_scenarios.pcap", settings=settings)
    b = engine.analyze(samples / "backends.pcap", settings=settings)
    week = time.time() - 8 * 86400
    for d in (a.dir, b.dir):
        os.utime(d / "meta.json", (week, week))
    (b.dir / ".seen").touch()  # b was opened just now
    assert engine.purge(settings) == 1
    assert not a.dir.exists() and b.dir.exists()
    assert any(r["event"] == "expired" and r["detail"] == a.id for r in records.read_audit(settings))


def test_opening_an_analysis_marks_it_seen(site, samples):
    ann = _user(site, "ann")
    aid = upload(ann, samples / "http_scenarios.pcap").rsplit("/", 1)[1]
    seen = site["settings"].workdir / aid / ".seen"
    engine._seen.pop(aid, None)
    assert ann.get(f"/a/{aid}").status_code == 200 and seen.exists()
    week = time.time() - 8 * 86400
    os.utime(seen, (week, week))
    os.utime(seen.parent / "meta.json", (week, week))
    assert engine.purge(site["settings"]) == 1, "the retention job runs while the vault is locked too, from file times alone"


def test_empty_password_line_does_not_win_over_the_hash(tmp_path):
    """An env file with PCAP_ANALYZER_ADMIN_PASSWORD= left empty and a hash set: the hash is the password."""
    from pcap_analyzer.web.auth import Auth, hash_password
    a = Auth("admin", password="", password_hash=hash_password("From-The-Hash-1"), store=tmp_path / ".admin-password.json")
    assert a.check("admin", "From-The-Hash-1")
    assert not a.check("admin", "")
    assert not a.must_change


def test_ldap_address_takes_any_port_or_none():
    from pcap_analyzer.web import directory
    ok = ("ldaps://dc.example.com", "ldaps://dc.example.com:3269", "ldap://10.0.0.5:10389/", "ldaps://[2001:db8::1]:636")
    bad = ("ldaps://dc:0", "ldaps://dc:65536", "dc.example.com", "ldaps://a b", "http://dc.example.com")
    for url in ok:
        assert directory.problem(dict(url=url, user_filter="(uid={0})")) is None, url
    for url in bad:
        assert directory.problem(dict(url=url, user_filter="(uid={0})")) is not None, url
