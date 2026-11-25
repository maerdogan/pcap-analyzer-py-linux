"""Requests a gateway or client sent again after a failed attempt, and health checks by path and user agent."""
import sys
from pathlib import Path

from pcap_analyzer import engine, parser, reports

TOOLS = Path(__file__).resolve().parent.parent / "tools"


def t(tid, rid, start, end, status):
    return dict(id=tid, request_id=rid, req_start=start, req_end=start, resp_end=end, status=status)


def test_a_failed_attempt_followed_by_the_same_id_is_a_retry():
    first, second = t(1, "abc", 0, 1, 503), t(2, "abc", 1.1, 1.2, 200)
    leg_a, leg_b = t(3, "xyz", 0, 1, 502), t(4, "xyz", 0.1, 0.9, 502)  # two legs of one proxy, overlapping
    ok1, ok2 = t(5, "ok", 0, 1, 200), t(6, "ok", 2, 3, 200)
    unanswered, again = dict(t(7, "na", 0, None, None), req_end=0.5), t(8, "na", 0.6, 0.7, 200)
    engine.mark_retries([first, second, leg_a, leg_b, ok1, ok2, unanswered, again])
    assert (second["retry_of"], second["attempt"]) == (1, 2)
    assert "retry_of" not in leg_b and "retry_of" not in ok2
    assert again["retry_of"] == 7


def test_health_checks_by_path_and_agent(monkeypatch):
    assert parser.health_check("/healthz", None)
    assert parser.health_check("/orders/actuator/health?x=1", None)
    assert parser.health_check("/", "NetScaler-Monitor/1.0")
    assert parser.health_check("/ready", "kube-probe/1.30")
    assert not parser.health_check("/api/order/status", None)
    assert not parser.health_check("/api/orders", "Mozilla/5.0")
    monkeypatch.setenv("PCAP_ANALYZER_HEALTH_PATHS", "/lb-check, /alive")
    assert parser.health_check("/lb-check", None) and parser.health_check("/alive/", None)


def test_retries_and_health_checks_are_saved(settings, tmp_path):
    """A 503 and the same request ID again on a new connection, then a health check, written with the helpers of tools/gen_samples.py."""
    sys.path.insert(0, str(TOOLS))
    import gen_samples as g
    path = tmp_path / "retry.pcap"
    w = g.PcapWriter(path)
    t = g.T0
    for port, status in ((53000, 503), (53001, 200)):
        c = g.Conn(w, "10.1.0.10", port, "10.2.0.20", 8080)
        t = g.txn(c, c.handshake(t), g.req("GET", "/api/orders", extra=["X-Request-Id: abc-1"]), g.resp(status, b"{}"), 0.01)
        t = c.close(t) + 0.05
    c = g.Conn(w, "10.1.0.11", 53002, "10.2.0.20", 8080)
    c.close(g.txn(c, c.handshake(t), g.req("GET", "/healthz", extra=["User-Agent: kube-probe/1.30"]), g.resp(200, b"ok"), 0.001))
    w.close()
    a = engine.analyze(path, settings=settings)
    with a.connect() as db:
        got = reports.rows(db, "SELECT id, attempt, retry_of, health_check FROM http_transactions ORDER BY id")
        issues = {i["key"]: i["count"] for i in reports.issues(db, a.meta)}
        overview = reports.overview(db, a.meta)["http"]
    assert [(x["attempt"], x["retry_of"], x["health_check"]) for x in got] == [(None, None, False), (2, got[0]["id"], False), (None, None, True)]
    assert issues["retried"] == 1 and (overview["retries"], overview["health_checks"]) == (1, 1)
