"""Inspect page: the filter of the slowest requests, every match for a duration range in pages, each URL over time, and all traffic."""
import html
import json
import re

import pytest

from pcap_analyzer import causes, engine, reports
from test_web import anon, client, upload  # noqa: F401 - fixtures


@pytest.fixture(scope="module")
def scenarios(samples, tmp_path_factory):
    from pcap_analyzer.config import Settings
    settings = Settings(workdir=tmp_path_factory.mktemp("work"), max_size_mb=100, ttl_days=7)
    return engine.analyze(samples / "http_scenarios.pcap", settings=settings)


def _inspect(a, slow=None, page=1, **f):
    with a.connect() as db:
        return reports.inspect(db, reports.Inspect(**f), slow, page)


def test_slow_filter_by_text_status_and_duration(scenarios):
    whole = _inspect(scenarios)
    assert whole["slow_matched"] == 18 and len(whole["slowest"]) == reports.SLOWEST == whole["slow_listed"]
    pay = _inspect(scenarios, reports.Slow(text="API/PAY"))
    assert pay["slow_matched"] == 3 and all("/api/pay" in t["uri"] for t in pay["slowest"])
    assert _inspect(scenarios, reports.Slow(text="no such thing"))["slowest"] == []
    for status, codes in (("2xx", {200, 201}), ("4xx", {404}), ("5xx", {502, 503, 504}), ("none", {None})):
        got = _inspect(scenarios, reports.Slow(status=status))
        assert {t["status"] for t in got["slowest"]} == codes, status
    assert _inspect(scenarios, reports.Slow(text="503"))["slow_matched"] == 1
    ranged = _inspect(scenarios, reports.Slow(min_ms=100, max_ms=30000))
    assert ranged["slowest"] and all(0.1 <= t["total"] <= 30 for t in ranged["slowest"])
    # the main filter still applies under the slow filter
    assert _inspect(scenarios, reports.Slow(text="/api/pay"), src="9.9.9.9")["slow_matched"] == 0


def test_a_duration_range_lists_every_match_in_pages(scenarios, monkeypatch):
    every = _inspect(scenarios, reports.Slow(min_ms=0))
    assert every["slow_matched"] == every["slow_listed"] == len(every["slowest"]) == 17  # the request without an answer has no duration
    monkeypatch.setattr(reports, "PAGE", 5)
    pages = [_inspect(scenarios, reports.Slow(min_ms=0), n) for n in (1, 2, 3, 4)]
    assert [p["slow_pages"] for p in pages] == [4] * 4 and [len(p["slowest"]) for p in pages] == [5, 5, 5, 2]
    assert [t["id"] for p in pages for t in p["slowest"]] == [t["id"] for t in every["slowest"]]
    assert _inspect(scenarios, reports.Slow(min_ms=0), 99)["slow_page"] == 4
    assert _inspect(scenarios, reports.Slow(min_ms=0), 0)["slow_page"] == 1


def test_each_url_over_time_and_where_its_time_went(scenarios):
    r = _inspect(scenarios)
    assert r["bucket"] in reports.SERIES_BUCKETS_S
    with scenarios.connect() as db:
        span = reports.one(db, "SELECT max(req_start) - min(req_start) AS s FROM http_transactions")["s"]
    assert span / r["bucket"] <= reports.SERIES_POINTS
    for u in r["urls"]:
        assert sum(p["n"] for p in u["series"]) == u["requests"]
        assert sum(p["failed"] for p in u["series"]) <= u["requests"]
        assert [p["t"] for p in u["series"]] == sorted(p["t"] for p in u["series"])
        assert all(set(p["phases"]) <= set(causes.PHASES) and all(v > 0 for v in p["phases"].values()) for p in u["series"])
    pay = next(u for u in r["urls"] if u["url"] == "/api/pay")
    assert pay["failed"] == 3 and sum(p["failed"] for p in pay["series"]) == 3
    bd = pay["breakdown"]
    assert bd["service"] > 19 and bd["rtt_client"] > 0 and bd["rtt_server"] > 0
    # the phases are averaged over all requests of the URL
    with scenarios.connect() as db:
        service = reports.one(db, "SELECT avg(coalesce(service, 0)) AS s FROM http_transactions WHERE url_template = '/api/pay'")["s"]
    assert bd["service"] == pytest.approx(service)


def test_many_points_get_wider_buckets(scenarios):
    import duckdb
    db = duckdb.connect()
    db.execute(f"ATTACH '{scenarios.db_path}' AS saved (READ_ONLY)")
    db.execute("CREATE TABLE tcp_connections AS SELECT * FROM saved.tcp_connections")
    db.execute("CREATE TABLE http_transactions AS SELECT * REPLACE (req_start + id * 3600 AS req_start) FROM saved.http_transactions")
    r = reports.inspect(db, reports.Inspect())
    span = reports.one(db, "SELECT max(req_start) - min(req_start) AS s FROM http_transactions")["s"]
    assert r["bucket"] > 60 and span / r["bucket"] <= reports.SERIES_POINTS
    assert sum(len(u["series"]) for u in r["urls"]) > len(r["urls"])


def test_all_traffic_in_pages(scenarios, monkeypatch):
    with scenarios.connect() as db:
        every = reports.all_traffic(db, reports.Inspect())
        assert every["total"] == 12 and every["pages"] == 1 and len(every["rows"]) == 12
        assert [r["requests"] for r in every["rows"]] == sorted((r["requests"] for r in every["rows"]), reverse=True)
        assert sum(r["requests"] for r in every["rows"]) == 18
        one = reports.all_traffic(db, reports.Inspect(src_port=40001))
        assert one["total"] == 1 and one["rows"][0]["client_port"] == 40001
        monkeypatch.setattr(reports, "PAGE", 5)
        pages = [reports.all_traffic(db, reports.Inspect(), n) for n in (1, 2, 3, 7)]
    assert [len(p["rows"]) for p in pages] == [5, 5, 2, 2] and pages[3]["page"] == 3
    assert [r["stream"] for p in pages[:3] for r in p["rows"]] == [r["stream"] for r in every["rows"]]


def test_inspect_page_slow_filter_url_view_and_all_traffic(client, samples, monkeypatch):
    home = upload(client, samples / "http_scenarios.pcap")
    page = client.get(f"{home}/inspect", params=dict(dst="10.20.2.10", slow_q="/api/pay", slow_status="5xx")).text
    assert "3 requests match." in page and "Slowest 3 requests" in page
    form = page.split('id="slowest"')[1].split("</form>")[0]
    assert 'name="dst" value="10.20.2.10"' in form and 'name="slow_q"' in form and '<option value="5xx" selected>' in form
    assert 'class="wf-tip"' in page and "Where the time went" in page.split('id="slowest"')[1]
    # a value that does not fit is left out
    assert "18 requests match." in client.get(f"{home}/inspect", params=dict(slow_status="6xx", slow_min_ms="abc", slow_max_ms="-5")).text
    assert "No request matches this filter." in client.get(f"{home}/inspect", params=dict(slow_q="nothing like this")).text
    every = client.get(f"{home}/inspect", params=dict(slow_min_ms="0")).text
    assert "Slowest 17 requests" in every and every.split('id="slowest"')[1].count('class="wf-main"') == 17
    monkeypatch.setattr(reports, "PAGE", 5)
    paged = client.get(f"{home}/inspect", params=dict(url="/api", slow_min_ms="0", slow_page="2")).text
    nav = re.findall(r'<nav class="pager pad"[^>]*>(.*?)</nav>', paged, re.S)
    slow_nav = [n for n in nav if "#slowest" in n]
    assert slow_nav and "Page 2 of" in slow_nav[0]
    links = [html.unescape(h) for h in re.findall(r'href="([^"]+)"', slow_nav[0])]
    assert any("slow_page=1#slowest" in h and "url=/api" in h and "slow_min_ms=0" in h for h in links)
    assert any("slow_page=3#slowest" in h for h in links)
    traffic = client.get(f"{home}/inspect", params=dict(conn_page="3")).text
    assert "12 connections" in traffic and "Page 3 of 3" in traffic and "conn_page=2#all-traffic" in html.unescape(traffic)
    data = json.loads(html.unescape(re.search(r"data-url-data='([^']*)'", page)[1]))
    assert data["bucket"] and data["labels"]["service"] and data["urls"][0]["title"].startswith(("GET ", "POST "))
    assert 'data-url-pick="0"' in page and 'data-url-table="1" hidden' in page
    assert "Client ↔ capture point, round trip" in page and "Average request" in page
    partial = client.get(f"{home}/inspect", params=dict(url="/api"), headers={"HX-Request": "true"}).text
    assert "<html" not in partial and 'id="url-view"' in partial and 'id="all-traffic"' in partial
