"""Views that match Wireshark's expert information, statistics, Decode As, Follow Stream and Export Objects."""
import re
import struct
import subprocess

import pytest

from pcap_analyzer import engine, reports, split, stats, tshark
from pcap_analyzer.config import Settings

from test_web import client, anon, upload  # noqa: F401 - fixtures


@pytest.fixture(scope="module")
def wire(samples, tmp_path_factory):
    s = Settings(workdir=tmp_path_factory.mktemp("wire") / "work", max_size_mb=100)
    return engine.analyze(samples / "wire.pcap", settings=s), s


def test_packet_issues(wire):
    a, _ = wire
    with a.connect() as db:
        kinds = dict(db.execute("SELECT kind, count(*) FROM packet_issues GROUP BY kind").fetchall())
        found = {i["key"]: i["count"] for i in reports.issues(db, a.meta)}
        dns = reports.issue_detail(db, "dns_errors")
        icmp = reports.issue_detail(db, "icmp_unreachable")
    assert kinds == dict(dns_error=1, icmp_unreachable=1, tcp_flags_invalid=2, port_reused=1, ecn_congestion=2, sack_blocks=1, malformed=1)
    for key in ("dns_errors", "icmp_unreachable", "tcp_flags_invalid", "port_reused", "ecn_congestion", "sack_blocks", "malformed"):
        assert key in found
    assert dns["details"][0]["label"] == "No such name (NXDOMAIN)" and dns["packets"][0]["src"] == "10.10.0.2"
    assert icmp["details"][0]["label"] == "Port unreachable" and icmp["guide"]["checks"]


def test_syn_answered_with_an_ack(wire):
    a, _ = wire
    with a.connect() as db:
        found = {i["key"]: i["count"] for i in reports.issues(db, a.meta)}
        row = db.execute("SELECT syn_seen, challenge_ack, handshake_seen FROM tcp_connections WHERE client_port = 45000").fetchone()
        normal = db.execute("SELECT count(*) FROM tcp_connections WHERE challenge_ack").fetchone()[0]
    assert row == (True, True, False) and found["syn_challenge_ack"] == 1 and normal == 1
    assert a.meta["quality"]["started_before"] == 0  # its SYN was seen, so it did not start before the capture


def test_tls_time_without_a_key(samples, settings):
    a = engine.analyze(samples / "https_tls12_ecdhe.pcap", settings=settings)
    keyed = engine.analyze(samples / "https_tls12_ecdhe.pcap", samples / "https_tls12_ecdhe.keylog", settings=settings)
    with a.connect() as db, keyed.connect() as dk:
        plain = db.execute("SELECT tls_time FROM tcp_connections ORDER BY stream").fetchall()
        known = dk.execute("SELECT tls_time FROM tcp_connections ORDER BY stream").fetchall()
    assert all(t is not None for (t,) in plain)
    assert [round(t, 3) for (t,) in plain] == [round(t, 3) for (t,) in known]  # the ChangeCipherSpec goes with the Finished


def test_quic_connection(wire):
    a, _ = wire
    with a.connect() as db:
        q = stats.quic(db)
    assert len(q) == 1
    assert q[0]["client"] == "10.10.1.50:50000" and q[0]["server"] == "10.20.2.30:443" and q[0]["version"] == "1"
    assert q[0]["packets"] == 5 and 0 < q[0]["handshake"] < 0.04


def test_decode_as(samples, settings):
    rule = ("tcp.port==9999,data",)
    plain = engine.analyze(samples / "wire.pcap", settings=settings)
    decoded = engine.analyze(samples / "wire.pcap", settings=settings, flt=tshark.Filter(decode_as=rule))
    uris = lambda a: {r[0] for r in a.connect().execute("SELECT uri FROM http_transactions").fetchall()}  # noqa: E731
    assert "/decoded" in uris(plain) and "/decoded" not in uris(decoded)
    assert decoded.meta["decode_as"] == list(rule) and decoded.id != plain.id


@pytest.mark.parametrize("rule", ["tcp.port==0,http", "tcp.port==80;rm -rf /", "ip.addr==1.2.3.4,http", "tcp.port==80,HTTP"])
def test_decode_as_refuses_bad_rules(rule):
    with pytest.raises(tshark.TsharkError, match="Decode As"):
        tshark.Filter(decode_as=(rule,)).decode_args()
    assert tshark.decode_rules("tcp.port==1,http; udp.port==2,quic\n") == ("tcp.port==1,http", "udp.port==2,quic")


def _isb(iface, ifdrop, osdrop):
    opts = struct.pack("<HHQ", 5, 8, ifdrop) + struct.pack("<HHQ", 7, 8, osdrop) + struct.pack("<HH", 0, 0)
    body = struct.pack("<III", iface, 0, 0) + opts
    size = 12 + len(body)
    return struct.pack("<II", 5, size) + body + struct.pack("<I", size)


def test_capture_drops(samples, settings, tmp_path):
    ng = tmp_path / "drops.pcapng"
    subprocess.run(["tshark", "-r", samples / "wire.pcap", "-F", "pcapng", "-w", ng], check=True, capture_output=True)
    assert split.drops(ng) is None and split.drops(samples / "wire.pcap") is None
    with open(ng, "ab") as f:
        f.write(_isb(0, 3, 1) + _isb(0, 7, 2))  # counters grow, so the last block holds the total
    assert split.drops(ng) == dict(interface=7, system=2)
    a = engine.analyze(ng, settings=settings)
    with a.connect() as db:
        found = {i["key"]: i["count"] for i in reports.issues(db, a.meta)}
    assert found["capture_drops"] == 9


def test_statistics(samples, settings):
    a = engine.analyze(samples / "wire.pcap", settings=settings)
    o = stats.overview(a, settings)
    top = {p["protocol"]: p for p in o["hierarchy"] if p["depth"] == 0}
    assert top["eth"]["packets"] == o["packets"] == a.meta["packets"]
    assert {p["protocol"] for p in o["hierarchy"]} >= {"ip", "tcp", "udp", "dns", "icmp", "quic", "http"}
    assert sum(s["packets"] for s in o["sizes"]) == o["packets"]
    udp = {(c["a"], c["b"]) for c in o["udp"]}
    assert ("10.10.1.50:50000", "10.20.2.30:443") in udp and ("10.10.0.2:53", "10.10.1.50:53100") in udp
    assert o["ethernet"][0]["frames"] == o["packets"] and len(o["macs"]) == 2
    assert sum(r["packets"] for r in o["io"]["rows"]) == o["packets"]
    io = stats.io_graph(a, settings, "dns")
    assert sum(r["packets"] for r in io["rows"]) == 5 and io["step"] == o["io"]["step"] and len(io["rows"]) == len(o["io"]["rows"])
    assert (a.dir / "stats" / "overview.json").exists()


def test_connection_views(samples, settings):
    a = engine.analyze(samples / "http_scenarios.pcap", settings=settings)
    g = stats.tcp_graphs(a, settings, 0)
    server = next(s for s in g["sides"] if not s["client"])
    assert server["stevens"] and server["throughput"]["rows"] and g["sides"][0]["sent"] >= g["sides"][1]["sent"]
    assert any(s["rtt"] for s in g["sides"]) and all(s["window"] for s in g["sides"])
    f = stats.flow_graph(a, settings, stream=0)
    assert f["hosts"] == ["10.10.1.50", "10.20.2.10"] and "[SYN]" in f["rows"][0]["info"]
    follow = stats.follow(a, settings, 0)
    assert follow["chunks"][0]["side"] == 0 and follow["chunks"][0]["text"].startswith("GET /api/users/123")
    assert follow["chunks"][1]["side"] == 1 and follow["chunks"][1]["text"].startswith("HTTP/1.1 200")
    assert stats.follow(a, settings, 0, "hex")["chunks"][0]["text"].startswith("00000000")
    found = stats.objects(a, settings)
    assert any(o["name"] == "large.bin" and o["kept"] for o in found)
    one = next(o for o in found if o["kept"])
    assert stats.object_path(a, one["file"]).stat().st_size == one["size"]
    assert stats.object_path(a, "../meta.json") is None


def test_follow_masks_secrets(samples, settings):
    a = engine.analyze(samples / "http_scenarios.pcap", settings=settings)
    text = "".join(c["text"] for c in stats.follow(a, settings, 0)["chunks"])
    assert "Authorization: Bearer" not in text


def test_http_statistics(samples, settings):
    a = engine.analyze(samples / "http_scenarios.pcap", settings=settings)
    with a.connect() as db:
        load = stats.http_load(db)
        seq = stats.http_sequences(db)
        total = db.execute("SELECT count(*) FROM http_transactions").fetchone()[0]
    assert sum(s["requests"] for s in load) == total and load[0]["server"] == "10.20.2.10:8080"
    assert sum(s["requests"] for s in seq) == total


def test_needs_the_kept_capture(samples, tmp_path):
    s = Settings(workdir=tmp_path / "w", keep_capture=False)
    a = engine.analyze(samples / "wire.pcap", settings=s)
    with pytest.raises(stats.Unavailable):
        stats.overview(a, s)


def test_parts_give_the_same_statistics(samples, settings, monkeypatch):
    whole = engine.analyze(samples / "http_scenarios.pcap", settings=settings)
    monkeypatch.setattr(engine, "PART_BYTES", 20_000)
    parts = engine.analyze(samples / "http_scenarios.pcap", settings=settings, use_cached=False)
    assert parts.meta["parts"] > 1
    a, b = stats.overview(whole, settings), stats.overview(parts, settings)
    assert a["hierarchy"][:4] == b["hierarchy"][:4] and a["sizes"] == b["sizes"] and a["io"] == b["io"]
    assert stats.follow(whole, settings, 3) == stats.follow(parts, settings, 3)
    assert [r["frame"] for r in stats.flow_graph(whole, settings, stream=3)["rows"]] == [r["frame"] for r in stats.flow_graph(parts, settings, stream=3)["rows"]]


def test_web_views(client, samples):  # noqa: F811
    url = upload(client, samples / "wire.pcap", decode_as="tcp.port==9999,http")
    aid = url.rsplit("/", 1)[1]
    assert "Statistics" in client.get(f"/a/{aid}?tab=stats").text
    o = client.get(f"/a/{aid}/stats/overview").text
    assert "Protocol hierarchy" in o and "10.20.2.30:443" in o
    assert "10.10.1.50:50000" in client.get(f"/a/{aid}", params={"tab": "stats"}, headers={"HX-Request": "true"}).text
    assert client.get(f"/api/a/{aid}/io", params={"filter": "dns"}).json()["filter"] == "dns"
    # only a preset reaches tshark; anything else draws all packets
    whole = client.get(f"/api/a/{aid}/io").json()
    for typed in ("udp", "not a ) filter"):
        assert client.get(f"/api/a/{aid}/io", params={"filter": typed}).json() == whole
        assert 'class="error"' not in client.get(f"/a/{aid}/stats/io", params={"filter": typed}).text
    assert "<svg" in client.get(f"/a/{aid}/flow", params={"filter": "dns"}).text
    flow = client.get(f"/a/{aid}/flow", params={"filter": "udp"}).text
    assert "All packets" in flow and '<option value="dns" >' in flow and '<option value="" selected>' in flow
    assert '<option value="dns" selected>' in client.get(f"/a/{aid}/flow", params={"filter": "dns"}).text
    assert client.get(f"/api/a/{aid}/tcpgraph/0").json()["sides"]
    assert "GET /api/ecn" in client.get(f"/a/{aid}/conn/0/follow").text
    assert "Follow TCP stream" in client.get(f"/a/{aid}/conn/0").text
    page = client.get(f"/a/{aid}/objects").text
    name = page.split(f"/export/{aid}/object/")[1].split('"')[0]
    assert client.get(f"/export/{aid}/object/{name}").status_code == 200
    assert client.get(f"/export/{aid}/object/x").status_code == 404
    issues = client.get(f"/a/{aid}?tab=issues").text
    assert "DNS errors" in issues and f"/a/{aid}/issue/dns_errors" in issues
    assert "No such name (NXDOMAIN)" in client.get(f"/a/{aid}/issue/dns_errors").text


def test_web_refuses_bad_decode_as(client, samples):  # noqa: F811
    path = samples / "wire.pcap"
    r = client.post("/upload", files={"capture": (path.name, path.read_bytes())}, data={"decode_as": "tcp.port==80;x"})
    assert r.status_code == 400 and "Decode As rule is not valid: tcp.port==80" in r.text


@pytest.fixture(scope="module")
def services_capture(samples, tmp_path_factory):
    s = Settings(workdir=tmp_path_factory.mktemp("services") / "work", max_size_mb=100)
    return engine.analyze(samples / "services.pcap", settings=s), s


def test_service_response_times(services_capture):
    from pcap_analyzer import services
    a, s = services_capture
    found = {r["protocol"]: r for r in services.response_times(a, s)}
    assert set(found) == {"LDAP", "SMB2", "Kafka", "SMTP", "DCERPC", "MQTT", "AMQP", "FTP"}
    ops = lambda name: {o["op"]: o for o in found[name]["operations"]}  # noqa: E731
    assert found["LDAP"]["requests"] == 2 and found["LDAP"]["errors"] == 1 and found["LDAP"]["avg"] == pytest.approx(0.04, abs=1e-3)
    assert found["SMB2"]["error_kinds"] == [dict(op="ECHO", error="0xc0000022", count=1)] and found["SMB2"]["avg"] == pytest.approx(0.06, abs=1e-3)
    assert ops("Kafka")["ApiVersions"]["avg"] == pytest.approx(0.05, abs=1e-3)
    assert set(ops("SMTP")) == {"EHLO", "MAIL", "RCPT", "QUIT"} and ops("SMTP")["RCPT"]["errors"] == 1
    assert ops("DCERPC")["opnum 5"]["errors"] == 1 and ops("DCERPC")["opnum 4"]["avg"] == pytest.approx(0.07, abs=1e-3)
    assert set(ops("MQTT")) == {"CONNECT", "SUBSCRIBE", "PINGREQ"} and found["MQTT"]["answered"] == 3
    assert found["AMQP"]["answered"] == 1
    assert ops("FTP")["CWD"]["errors"] == 1 and ops("FTP")["RETR"]["answered"] == 1  # answered by 226, after the 150
    assert found["SMB2"]["servers"][0]["server"] == "10.30.2.50:445"
    assert found["DCERPC"]["slowest"][0]["frame"] in (77, 81)  # the frame of the request


def test_sip_calls_and_rtp(services_capture, truth):
    from pcap_analyzer import services
    a, s = services_capture
    v = services.voip(a, s)
    one, two = v["calls"]
    assert one["state"] == "completed" and one["ringing"] == pytest.approx(0.5) and one["setup"] == pytest.approx(2.0) and one["duration"] == pytest.approx(2.0)
    assert one["from_user"] == "alice" and one["to_user"] == "bob"
    assert two["state"] == "rejected" and two["status"] == 486 and two["setup"] is None
    (rtp,) = v["streams"]
    t = truth["services.pcap"]
    assert rtp["packets"] == t["rtp_packets"] and rtp["lost"] == t["rtp_lost"] and rtp["out_of_order"] == t["rtp_out_of_order"]
    assert rtp["max_delta"] == pytest.approx(0.04, abs=1e-3) and 0.001 < rtp["max_jitter"] < 0.005


def test_unknown_fields_are_left_out(services_capture, monkeypatch):
    from pcap_analyzer import services
    a, s = services_capture
    monkeypatch.setitem(services.PROTOCOL_FIELDS, "LDAP", services.PROTOCOL_FIELDS["LDAP"] + ["ldap.no_such_field"])
    monkeypatch.setattr(stats, "VERSION", -1)  # make it again
    assert any(r["protocol"] == "LDAP" for r in services.response_times(a, s))
    assert tshark.usable(["ldap.no_such_field", "frame.number"]) == ["frame.number"]


def test_main_pass_leaves_out_unknown_fields(samples, settings, monkeypatch):
    monkeypatch.setattr(tshark, "FIELDS", tshark.FIELDS + ["quic.no_such_field"])
    monkeypatch.setattr(tshark, "_unknown", {})
    a = engine.analyze(samples / "wire.pcap", settings=settings, use_cached=False)
    assert a.meta["transactions"] == 4 and "quic.no_such_field" in tshark._unknown["tshark"]


def test_web_services_and_voip(client, samples, settings):  # noqa: F811
    from pcap_analyzer import records
    url = upload(client, samples / "services.pcap")
    aid = url.rsplit("/", 1)[1]
    page = client.get(f"/a/{aid}/stats/services").text
    assert "Service response times" in page and "ApiVersions" in page and "0xc0000022" in page
    voip = client.get(f"/a/{aid}/stats/voip").text
    assert "SIP calls" in voip and "Rejected" in voip and "0x11223344" in voip
    bearer = {"Authorization": f"Bearer {records.new_token(settings, 'ci')}"}
    assert client.get(f"/api/v1/analyses/{aid}/services", headers=bearer).json()[0]["protocol"] == "LDAP"
    assert client.get(f"/api/v1/analyses/{aid}/voip", headers=bearer).json()["calls"][0]["state"] == "completed"
    assert client.get(f"/api/v1/analyses/{aid}/statistics", headers=bearer).json()["packets"] > 0


def test_every_packet_of_a_connection(samples, settings):
    a = engine.analyze(samples / "http_scenarios.pcap", settings=settings)
    p = stats.packets(a, settings, 0)
    with a.connect() as db:
        count = db.execute("SELECT packets FROM tcp_connections WHERE stream = 0").fetchone()[0]
    rows = p["rows"]
    assert len(rows) == count and not p["cut"]
    assert [r["frame"] for r in rows] == sorted(r["frame"] for r in rows)
    assert rows[0]["t"] == 0 and rows[0]["from_client"] and rows[0]["flags"] == ["SYN"] and rows[1]["flags"] == ["SYN", "ACK"] and not rows[1]["from_client"]
    assert [x["flag"] for x in p["legend"]][:2] == ["SYN", "ACK"] and all(x["meaning"] for x in p["legend"])
    assert any("GET /api/users/123" in r["info"] for r in rows)


def test_packets_of_a_capture_read_in_parts(samples, settings, monkeypatch):
    whole = engine.analyze(samples / "http_scenarios.pcap", settings=settings)
    monkeypatch.setattr(engine, "PART_BYTES", 20_000)
    parts = engine.analyze(samples / "http_scenarios.pcap", settings=settings, use_cached=False)
    assert parts.meta["parts"] > 1
    assert [r["frame"] for r in stats.packets(whole, settings, 3)["rows"]] == [r["frame"] for r in stats.packets(parts, settings, 3)["rows"]]


def test_packet_marks(samples, settings):
    a = engine.analyze(samples / "http_scenarios.pcap", settings=settings)
    with a.connect() as db:
        stream = db.execute("SELECT stream FROM tcp_connections WHERE retransmissions > 0 ORDER BY stream LIMIT 1").fetchone()[0]
    assert any("retransmission" in r["marks"] for r in stats.packets(a, settings, stream)["rows"])


def test_follow_http(samples, settings):
    a = engine.analyze(samples / "http_scenarios.pcap", settings=settings)
    h2 = engine.analyze(samples / "https_h2.pcap", samples / "https_h2.keylog", settings=settings)
    with a.connect() as db:
        x = stats.follow_http(db, 0)
        total = db.execute("SELECT count(*) FROM http_transactions WHERE stream = 0").fetchone()[0]
    assert len(x) == total and x[0]["request"].startswith("GET /api/users/123 HTTP/1.1") and x[0]["response"].startswith("HTTP/1.1 200 OK")
    with h2.connect() as db:
        y = stats.follow_http(db, 0)
    assert y and ":method: GET" in y[0]["request"] and ":status: 200" in y[0]["response"] and y[0]["h2_stream"]


def test_web_connection_views(client, samples):  # noqa: F811
    url = upload(client, samples / "http_scenarios.pcap")
    aid = url.rsplit("/", 1)[1]
    conns = client.get(f"/api/a/{aid}/connections").json()
    assert all({"stream", "packets", "bytes", "start_time", "sni"} <= set(c) for c in conns)
    page = client.get(f"/a/{aid}/conn/0").text
    assert f"/a/{aid}/conn/0/packets" in page and "Follow HTTP stream" in page and "Follow TCP stream" in page
    packets = client.get(f"/a/{aid}/conn/0/packets").text
    assert "Client → server" in packets and "Server → client" in packets and 'class="error"' not in packets
    http = client.get(f"/a/{aid}/conn/0/follow?mode=http").text
    assert "GET /api/users/123 HTTP/1.1" in http and "HTTP/1.1 200 OK" in http and f"/a/{aid}/txn/" in http
    assert client.get(f"/a/{aid}/conn/0/follow?mode=nope").status_code == 404
    assert client.get(f"/a/{aid}/conn/99999/follow?mode=http").status_code == 404


def test_most_called_flows(samples, settings):
    a = engine.analyze(samples / "http_scenarios.pcap", settings=settings)
    with a.connect() as db:
        flows = reports.top_flows(db)
        most = db.execute("""SELECT c.client_port, count(*) FROM http_transactions t JOIN tcp_connections c USING (stream)
            GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 1""").fetchone()
        one = reports.inspect(db, reports.Inspect(src=flows[0]["client_ip"], src_port=flows[0]["client_port"], dst=flows[0]["server_ip"], port=flows[0]["server_port"]))
    assert 0 < len(flows) <= 10 and [f["requests"] for f in flows] == sorted((f["requests"] for f in flows), reverse=True)
    assert flows[0]["requests"] == most[1]
    assert one["connections"]["connections"] == 1 and one["requests"]["requests"] == flows[0]["requests"]


def test_web_most_called_flows(client, samples):  # noqa: F811
    url = upload(client, samples / "http_scenarios.pcap")
    aid = url.rsplit("/", 1)[1]
    page = client.get(f"/a/{aid}/inspect").text
    assert "Most called flows" in page and page.count('class="flow-pick"') == min(10, page.count('class="flow-pick"')) > 0
    first = re.search(r'data-src="([\d.]+)" data-src-port="(\d+)" data-dst="([\d.]+)" data-port="(\d+)"', page).groups()
    assert f"{first[0]}:{first[1]} → {first[2]}:{first[3]}" in page
    r = client.get(f"/a/{aid}/inspect", params=dict(src=first[0], src_port=first[1], dst=first[2], port=first[3]), headers={"HX-Request": "true"})
    assert r.status_code == 200 and 'class="error"' not in r.text
    assert client.get(f"/a/{aid}/inspect", params=dict(src_port="x")).status_code == 400


def test_url_total_time_and_sorting(client, samples, settings):  # noqa: F811
    url = upload(client, samples / "http_scenarios.pcap")
    aid = url.rsplit("/", 1)[1]
    page = client.get(f"/a/{aid}/inspect").text
    assert "Total time" in page and "<table data-sortable>" in page and page.count('data-sort="num"') == 6
    with engine.open_analysis(aid, settings).connect() as db:
        groups = reports.url_groups(db)
        total = db.execute("SELECT sum(total) FROM http_transactions").fetchone()[0]
    assert sum(g["sum_total"] or 0 for g in groups) == pytest.approx(total)
    assert all(f'data-value="{g["sum_total"]}"' in page for g in groups if g["sum_total"] is not None)


def test_packets_of_one_request(samples, settings):
    a = engine.analyze(samples / "http_scenarios.pcap", settings=settings)
    with a.connect() as db:
        txns = [dict(zip(("id", "stream", "req_frame", "req_start", "req_end", "resp_end", "new_conn", "uri"), r)) for r in db.execute(
            "SELECT id, stream, req_frame, req_start, req_end, resp_end, new_conn, uri FROM http_transactions WHERE stream = 0 ORDER BY req_start").fetchall()]
    first, second = txns[0], txns[1]
    one = stats.request_packets(a, settings, first)["rows"]
    two = stats.request_packets(a, settings, second)["rows"]
    assert first["new_conn"] and one[0]["flags"] == ["SYN"] and one[0]["t"] == 0
    assert any(first["uri"] in r["info"] for r in one) and not any(second["uri"] in r["info"] for r in one)
    assert not second["new_conn"] and two[0]["frame"] == second["req_frame"] and any(second["uri"] in r["info"] for r in two)
    assert one[-1]["frame"] < two[0]["frame"]


def test_web_request_packets(client, samples):  # noqa: F811
    url = upload(client, samples / "http_scenarios.pcap")
    aid = url.rsplit("/", 1)[1]
    assert f"/a/{aid}/txn/1/packets" in client.get(f"/a/{aid}/txn/1").text
    body = client.get(f"/a/{aid}/txn/1/packets").text
    assert "Client → server" in body and 'class="error"' not in body
    assert client.get(f"/a/{aid}/txn/999999/packets").status_code == 404
