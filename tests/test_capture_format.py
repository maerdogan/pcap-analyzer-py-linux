"""Captures are recognised by their first bytes: pcap, pcapng and NetScaler traces."""
import pytest

from pcap_analyzer import engine


def test_pcap_and_pcapng_are_captures(made):
    assert engine.looks_like_capture(made("h2_control"))


@pytest.mark.parametrize("version", ["V10", "V20", "V30", "V35"])
def test_netscaler_traces_are_captures(tmp_path, version):
    head = bytearray(300)
    sig = f"NetScaler {version} Performance Data".encode()
    head[24:24 + len(sig)] = sig  # the text sits inside the first record
    trace = tmp_path / f"trace-{version}.cap"
    trace.write_bytes(bytes(head))
    assert engine.looks_like_capture(trace)
    engine._refuse_compressed(trace)


def test_a_netscaler_trace_with_a_text_head_is_not_refused(tmp_path):
    trace = tmp_path / "nstrace1.cap"
    trace.write_bytes(b"NetScaler V35 Performance Data" + b" " * 100)
    engine._refuse_compressed(trace)


def test_other_files_are_not(tmp_path):
    notes = tmp_path / "notes.txt"
    notes.write_text("NetScaler notes, not a trace\n")
    assert not engine.looks_like_capture(notes)
    with pytest.raises(engine.WrongFile):
        engine._refuse_compressed(notes)
