"""The two legs of a NetScaler proxy, linked by the PCB numbers of an nstrace. tshark cannot write an nstrace, so the rows are made here."""
from pcap_analyzer import engine


def conn(stream, pcb, linked):
    return dict(stream=stream, ns_pcb=pcb, ns_linked_pcb=linked)


def test_legs_are_paired_from_either_side():
    peers = engine.link_netscaler_legs([conn(0, 0x100, 0x200), conn(1, 0x200, None), conn(2, 0x300, 0x999), conn(3, None, None)])
    assert peers == {0: 1, 1: 0}


def test_a_connection_naming_itself_has_no_peer():
    assert engine.link_netscaler_legs([conn(0, 0x100, 0x100)]) == {}
