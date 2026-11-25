"""HTTP/2 control frames between a gateway and its backend: flow control waits, refused streams and GOAWAY.
The capture comes from tools/gen_h2_control.py."""
import pytest

from pcap_analyzer import engine, parser, reports


@pytest.fixture(scope="module")
def result(made, tmp_path_factory):
    from pcap_analyzer.config import Settings
    return engine.analyze(made("h2_control"), settings=Settings(workdir=tmp_path_factory.mktemp("work")))


def counts(a):
    with a.connect() as db:
        return {i["key"]: i["count"] for i in reports.issues(db, a.meta)}


def details(a, key):
    with a.connect() as db:
        return [p["detail"] for p in reports.issue_detail(db, key)["packets"]]


def test_flow_control_wait_is_found(result):
    assert "h2_flow_stall" in counts(result)
    conn = next(d for d in details(result, "h2_flow_stall") if d.startswith("connection: "))
    assert 195 <= int(conn.removeprefix("connection: ").removesuffix(" ms")) <= 215


def test_flow_control_wait_is_its_own_phase(result):
    with result.connect() as db:
        big = reports.one(db, "SELECT * FROM http_transactions WHERE uri = '/big'")
        about = reports.describe(db, dict(big))
    assert 0.195 <= big["h2_flow_time"] <= 0.215
    assert big["cause"] == "h2_flow_stall"
    assert any(p["name"] == "h2_flow_time" for p in about["phases"])


def test_refused_stream_is_reported(result):
    assert counts(result)["h2_reset"] == 1
    assert details(result, "h2_reset") == ["stream 3: REFUSED_STREAM"]


def test_goaway_is_reported(result):
    assert counts(result)["h2_goaway"] == 1
    assert details(result, "h2_goaway") == ["NO_ERROR"]


def test_error_codes_have_names():
    assert parser.h2_error(11) == "ENHANCE_YOUR_CALM"
    assert parser.h2_error(31) == "0x1f"
