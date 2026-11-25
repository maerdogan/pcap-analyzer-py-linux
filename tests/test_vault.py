"""The vault on its own, in one data folder. The tests run in order, like the life of an install, as the Java edition's VaultTest does."""
import json
import random

import duckdb
import pytest

from conftest import MASTER
from pcap_analyzer import engine, records, store, vault
from pcap_analyzer.config import Settings

ADMIN = "Admin-Password-1"
AID = "0123456789abcdef0123"


@pytest.fixture(scope="module")
def life(tmp_path_factory):
    """One data folder for the ordered vault tests: an analysis, an old audit.log and a capture of a few segments, all plain."""
    wd = tmp_path_factory.mktemp("vault-test") / "work"
    (wd / AID).mkdir(parents=True)
    (wd / AID / "meta.json").write_text('{"id":"0123456789abcdef0123"}')
    (wd / "audit.log").write_text('{"event":"upload","time":1}\n')
    big = random.Random(1).randbytes(3 * vault.SEGMENT + 12345)
    (wd / AID / "capture").write_bytes(big)
    with duckdb.connect(str(wd / AID / "analysis.duckdb")) as db:
        db.execute("CREATE TABLE t AS SELECT 'secret-word' AS s")
    return dict(wd=wd, big=big, v=vault.of(wd))


def test_master_key_rules():
    assert vault.master_problem("short#")
    assert vault.master_problem("abcdefgh12345678")  # letters and digits only
    assert vault.master_problem("abcdefgh 234567#")  # a space
    assert vault.master_problem(MASTER) is None


def test_set_up_encrypts_what_is_there(life):
    wd, v = life["wd"], life["v"]
    v.set_up(ADMIN, MASTER)
    assert vault.is_encrypted(wd / AID / "meta.json") and vault.is_encrypted(wd / AID / "capture")
    assert not (wd / "audit.log").exists() and (wd / ".idx0").exists()
    assert b"upload" not in (wd / ".idx0").read_bytes(), "the activity log must not be readable"
    assert vault.read_text(wd / AID / "meta.json") == '{"id":"0123456789abcdef0123"}'
    assert vault.read_bytes(wd / AID / "capture") == life["big"]
    with vault.open_read(wd / AID / "capture") as f:  # seeks to any byte, as splitting a capture into parts does
        f.seek(2 * vault.SEGMENT + 7)
        assert f.read(100) == life["big"][2 * vault.SEGMENT + 7:2 * vault.SEGMENT + 107]
    assert vault.size(wd / AID / "capture") == len(life["big"])
    assert b"secret-word" not in (wd / AID / "analysis.duckdb").read_bytes()
    assert vault.is_encrypted(wd / AID / store.KEY_FILE)
    with store.connect(wd / AID / "analysis.duckdb") as db:
        assert db.execute("SELECT s FROM t").fetchone()[0] == "secret-word"
    assert [r["event"] for r in records.read_audit(Settings(workdir=wd))] == ["upload"]


def test_restart_needs_the_admin_password(life):
    wd, v = life["wd"], life["v"]
    v.lock()
    with pytest.raises(vault.Locked):
        vault.read_text(wd / AID / "meta.json")
    with pytest.raises(vault.Locked):
        store.connect(wd / AID / "analysis.duckdb")
    vault.write_text(wd / AID / "notes.json", '{"note":"x"}')  # writing needs only the public key, so it works while locked
    records.audit(Settings(workdir=wd), "while_locked", "server")
    assert not v.unlock("wrong password")
    assert v.unlock(ADMIN) and v.master_key() == MASTER
    assert vault.read_text(wd / AID / "notes.json") == '{"note":"x"}'
    assert records.read_audit(Settings(workdir=wd))[0]["event"] == "while_locked"


def test_changed_cut_and_plain_files_are_found(life):
    wd, v = life["wd"], life["v"]
    v.clear_alerts()
    f = wd / AID / "capture"
    raw = bytearray(f.read_bytes())
    raw[len(raw) // 2] ^= 1
    f.write_bytes(raw)
    assert not v.verify(f)
    cut = wd / AID / "meta.json"
    cut.write_bytes(cut.read_bytes()[:-20])
    assert not v.verify(cut)
    (wd / AID / "result.json").write_text("{}")
    with pytest.raises(vault.Tampered):
        vault.read_text(wd / AID / "result.json")
    reasons = [a["reason"] for a in v.alerts()]
    assert len(reasons) == 3 and "does not verify" in reasons[0] and "ends early" in reasons[1] and "not encrypted" in reasons[2]
    # a file cut at a segment boundary, so every segment left verifies, is found too
    whole = wd / AID / "whole.bin"
    vault.write_bytes(whole, bytes(2 * vault.SEGMENT + 10))
    whole.write_bytes(whole.read_bytes()[:-(vault.FRAME + 10 + vault.TAG)])
    assert not v.verify(whole)
    # an encrypted file from another install, and a plain file the hourly check finds without anyone reading it
    other = vault.Vault(wd.parent / "other")
    other.set_up(ADMIN, MASTER)
    other.write_bytes(other.workdir / "x.json", b"{}")
    (wd / "foreign.json").write_bytes((other.workdir / "x.json").read_bytes())
    (wd / "dropped.txt").write_text("hello")
    v.clear_alerts()
    v.scan()
    found = {a["file"]: a["reason"] for a in v.alerts()}
    assert "comes from another install" in found["foreign.json"] and "not encrypted" in found["dropped.txt"]
    assert "not encrypted" in found[f"{AID}/result.json"] and "ends early" in found[f"{AID}/meta.json"]
    assert any(r["event"] == "file_tampered" for r in records.read_audit(Settings(workdir=wd)))
    for name in ("foreign.json", "dropped.txt", f"{AID}/result.json", f"{AID}/whole.bin"):
        (wd / name).unlink()
    vault.write_text(cut, '{"id":"0123456789abcdef0123"}')


def test_new_admin_password_and_master_key(life):
    wd, v = life["wd"], life["v"]
    ring = (wd / ".keyring").read_text()
    v.change_admin_password(ADMIN, "Second-Password-2")
    assert json.loads((wd / ".keyring").read_text())["data_private"] == json.loads(ring)["data_private"], "only the admin key is wrapped again"
    v.change_master("N3w&Key*2026abcd")
    assert json.loads((wd / ".keyring").read_text())["admin_private"] != json.loads(ring)["admin_private"]
    v.lock()
    assert not v.unlock(ADMIN)
    assert v.unlock("Second-Password-2") and v.master_key() == "N3w&Key*2026abcd"
    assert vault.read_text(wd / AID / "notes.json") == '{"note":"x"}'
    with pytest.raises(ValueError):
        v.change_master("onlyletters12345")


def test_an_old_duckdb_gets_the_database_encrypted_as_a_file(settings, samples, monkeypatch):
    """DuckDB before 1.4, as for glibc 2.17, cannot encrypt: the vault encrypts the whole file, and it is read from a private plain copy."""
    monkeypatch.setattr(store, "NATIVE_ENCRYPTION", False)
    vault.of(settings.workdir).set_up(ADMIN, MASTER)
    a = engine.analyze(samples / "http_scenarios.pcap", settings=settings)
    assert vault.is_encrypted(a.db_path) and not (a.dir / store.KEY_FILE).exists()
    with a.connect() as db:
        assert db.execute("SELECT count(*) FROM http_transactions").fetchone()[0] == a.meta["transactions"]
        folder = db.folder
    assert not (settings.workdir / folder).exists()
    vault.of(settings.workdir).scan()
    assert not vault.of(settings.workdir).alerts()


def test_an_analysis_made_after_the_setup_is_encrypted_from_the_start(settings, samples):
    vault.of(settings.workdir).set_up(ADMIN, MASTER)
    a = engine.analyze(samples / "http_scenarios.pcap", settings=settings)
    for name in ("meta.json", "capture", store.KEY_FILE):
        assert vault.is_encrypted(a.dir / name), name
    with pytest.raises(duckdb.Error):
        duckdb.connect(str(a.db_path), read_only=True)
    with a.connect() as db:
        assert db.execute("SELECT count(*) FROM http_transactions").fetchone()[0] == a.meta["transactions"]
    assert engine.analyze(samples / "http_scenarios.pcap", settings=settings).cached
    vault.of(settings.workdir).lock()
    with pytest.raises(vault.Locked):
        engine.open_analysis(a.id, settings)
