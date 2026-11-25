"""PROXY protocol v2 and v1 headers in front of HTTP on a gateway port, a request with X-Forwarded-For,
and an Envoy gateway that reports its upstream time. The capture comes from tools/gen_proxy.py."""
import pytest

from pcap_analyzer import engine, parser, reports


@pytest.fixture(scope="module")
def result(made, tmp_path_factory):
    from pcap_analyzer.config import Settings
    return engine.analyze(made("proxy"), settings=Settings(workdir=tmp_path_factory.mktemp("work")))


def rows(a, table):
    with a.connect() as db:
        return reports.rows(db, f"SELECT * FROM {table} ORDER BY {'stream' if table == 'tcp_connections' else 'id'}")


def test_connections_name_the_client_before_the_proxy(result):
    v2, v1, _ = rows(result, "tcp_connections")
    assert (v2["proxy_version"], v2["proxy_client"], v2["proxy_server"]) == ("v2", "203.0.113.7:40000", "198.51.100.10:443")
    assert (v1["proxy_version"], v1["proxy_client"]) == ("v1", "[2001:db8::7]:40001")


def test_requests_behind_the_header_are_still_read(result):
    txns = rows(result, "http_transactions")
    assert len(txns) == 3
    assert txns[0]["proxy_client"] == "203.0.113.7:40000" and txns[0]["status"] == 200


def test_original_client_comes_from_the_header_or_the_proxy_header(result):
    txns = rows(result, "http_transactions")
    assert (txns[0]["original_client"], txns[0]["original_client_from"]) == ("203.0.113.7:40000", "PROXY v2")
    assert (txns[2]["original_client"], txns[2]["original_client_from"]) == ("198.51.100.5", "x-forwarded-for")


def test_the_header_list_can_be_set(made, settings, monkeypatch):
    monkeypatch.setenv("PCAP_ANALYZER_CLIENT_IP_HEADER", "x-real-ip")
    a = engine.analyze(made("proxy"), settings=settings, use_cached=False)
    third = rows(a, "http_transactions")[2]
    assert third["original_client"] is None


def test_gateway_time_is_service_minus_envoy_upstream_time(result):
    t = rows(result, "http_transactions")[2]
    assert t["upstream_time"] == pytest.approx(0.005)
    assert 0.01 < t["gateway_time"] < 0.016


def test_client_address_reads_lists_and_forwarded():
    assert parser.client_address("x-forwarded-for", "198.51.100.5, 10.0.0.1") == "198.51.100.5"
    assert parser.client_address("forwarded", 'for="[2001:db8::1]:4711";proto=https, for=10.0.0.1') == "[2001:db8::1]:4711"
    assert parser.client_address("forwarded", "proto=http;for=192.0.2.60;by=203.0.113.43") == "192.0.2.60"
    assert parser.client_address("forwarded", "for=unknown") is None
