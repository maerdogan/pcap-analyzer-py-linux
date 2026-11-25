"""Two TLS 1.2 connections where the server asks for a client certificate: one client sends it, one does not.
The server sends a leaf and an intermediate. The capture comes from tools/gen_mtls.py."""
import pytest

from pcap_analyzer import engine, reports


@pytest.fixture(scope="module")
def result(made, tmp_path_factory):
    from pcap_analyzer.config import Settings
    return engine.analyze(made("mtls"), settings=Settings(workdir=tmp_path_factory.mktemp("work")))


def test_chain_and_client_certificate_are_per_connection(result):
    with result.connect() as db:
        sent, missing = reports.rows(db, "SELECT * FROM tcp_connections ORDER BY stream")
    assert sent["tls_chain"] == 2 and sent["tls_client_cert_requested"] is True
    assert sent["tls_client_name"] == "netscaler.example.test"
    assert missing["tls_client_certs"] == 0 and missing["tls_client_cert_requested"] is True


def test_missing_client_certificate_is_an_issue(result):
    with result.connect() as db:
        assert {i["key"]: i["count"] for i in reports.issues(db, result.meta)}["tls_no_client_cert"] == 1
        assert [p["detail"] for p in reports.issue_detail(db, "tls_no_client_cert")["packets"]] == ["gw.example.test"]


def test_summary_counts_mutual_tls(result):
    with result.connect() as db:
        tls = reports.tls_health(db)
    assert (tls["client_cert_requested"], tls["client_cert_sent"]) == (2, 1)
    assert [c["chain"] for c in tls["certificates"]] == [2]
