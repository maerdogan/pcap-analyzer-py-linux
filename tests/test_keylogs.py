"""Several key logs joined into one, as for the two TLS legs on both sides of a NetScaler."""
import pytest

from pcap_analyzer import engine
from pcap_analyzer.cli import main


def test_join_keeps_every_key_once(tmp_path):
    a, b, out = tmp_path / "a.log", tmp_path / "b.log", tmp_path / "out.log"
    a.write_text("# leg one\nCLIENT_RANDOM 01 aa\nCLIENT_RANDOM 02 bb\n")
    b.write_text("CLIENT_RANDOM 02 bb\n\nCLIENT_TRAFFIC_SECRET_0 03 cc\n")
    assert engine.join_keylogs([a, b], out) == 3
    assert out.read_text().splitlines() == ["# leg one", "CLIENT_RANDOM 01 aa", "CLIENT_RANDOM 02 bb", "CLIENT_TRAFFIC_SECRET_0 03 cc"]


def test_other_files_are_not_key_logs(samples, tmp_path):
    text = tmp_path / "notes.txt"
    text.write_text("hello\n")
    with pytest.raises(engine.WrongFile):
        engine.check_keylog(text)
    engine.check_keylog(samples / "https_tls13.keylog")


def test_joined_key_log_still_decrypts(samples, settings):
    keylogs = [samples / "https_h2.keylog", samples / "https_tls13.keylog"]
    for capture in ("https_tls13.pcap", "https_h2.pcap"):
        a = engine.analyze(samples / capture, keylog=keylogs, settings=settings)
        assert a.meta["transactions"] > 0 and a.meta["decryption"] == "keylog", capture


def test_cli_takes_keylog_more_than_once(samples, settings, monkeypatch, capsys):
    monkeypatch.setenv("PCAP_ANALYZER_WORKDIR", str(settings.workdir))
    assert main(["analyze", str(samples / "https_h2.pcap"), "--keylog", str(samples / "https_tls13.keylog"), "--keylog", str(samples / "https_h2.keylog"), "--json"]) == 0
    assert '"transactions": 3' in capsys.readouterr().out

