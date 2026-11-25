"""The same requests at a NetScaler (A) and at a gateway (B) whose clock is 2 s ahead and drifts 100 ppm. Each way takes 5 ms."""
import pytest

from pcap_analyzer import compare


def row(rid, req_start, resp_start, total):
    return dict(id=rid, request_id="r" + rid[1:], method="GET", uri="/x", url_template="/x", status=200,
                req_start=req_start, resp_start=resp_start, total=total, service=0.01)


def points(given):
    a, b = [], []
    for i in range(40):
        t = 1000 + i * 3.0
        off = 2.0 + 100e-6 * (t - 1000)
        b_req = t + 0.005 + off
        b_resp = b_req + 0.010
        a_resp = b_resp - off + 0.005
        a.append(row(f"a{i}", t, a_resp, a_resp - t))
        b.append(row(f"b{i}", b_req, b_resp, 0.010))
    return compare.match_points(a, b, given)


def test_offset_and_drift_are_estimated():
    p = points(None)
    assert p["clock_drift_ppm"] == pytest.approx(100, abs=1) and p["drift_warning"]
    for r in p["rows"]:
        assert r["forward"] == pytest.approx(0.005, abs=0.0005)
        assert r["back"] == pytest.approx(0.005, abs=0.0005)


def test_given_offset_replaces_the_estimate():
    p = points(1.5)
    assert p["clock_skew"] == pytest.approx(1.5) and p["clock_given"] is True and not p["drift_warning"]


def test_few_pairs_give_no_drift():
    pairs = [(dict(req_start=100.0 + i, resp_start=100.2 + i), dict(req_start=100.1 + i, resp_start=100.1 + i)) for i in range(4)]
    assert compare._clock_model(pairs)[1] == 0.0
