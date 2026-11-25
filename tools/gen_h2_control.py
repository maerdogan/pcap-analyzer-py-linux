#!/usr/bin/env python3
"""Write a capture for the tests, like the Java edition's h2c-control.pcap: cleartext HTTP/2 with a flow control wait, a refused stream and a GOAWAY.
It uses the frame helpers of tools/gen_samples.py. All addresses are private and all data is fake.
Usage: gen_h2_control.py OUT.pcap"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gen_samples as g  # noqa: E402

T0, ACK, PSH = g.T0, g.ACK, g.PSH
w = g.PcapWriter(Path(sys.argv[1]))
c = g.Conn(w, "10.1.0.10", 50000, "10.2.0.20", 80)
t = c.handshake(T0)
settings = g.h2_frame(4, 0, 0, b"")
t = c.send(t, True, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + settings) + 0.001
t = c.send(t, False, settings + g.h2_frame(4, 1, 0, b"")) + 0.001
t = c.send(t, True, g.h2_frame(4, 1, 0, b"")) + 0.001
get = lambda sid, path: g.h2_frame(1, 0x5, sid, g.hpack([(":method", "GET"), (":scheme", "http"), (":authority", "app.example.test"), (":path", path)]))  # noqa: E731
t = c.send(t, True, get(1, "/big")) + 0.01
t = c.send(t, False, g.h2_frame(1, 0x4, 1, g.hpack([(":status", "200")]))) + 0.001
# 65,535 bytes fill the default window, so the server must wait for WINDOW_UPDATE
for size in (16384, 16384, 16384, 16383):
    t = c.send(t, False, g.h2_frame(0, 0, 1, bytes(size)), gap=0.0001) + 0.0005
t += 0.2
update = g.h2_frame(8, 0, 0, struct.pack(">I", 1 << 20)) + g.h2_frame(8, 0, 1, struct.pack(">I", 1 << 20))
t = c.send(t, True, update) + 0.001
t = c.send(t, False, g.h2_frame(0, 1, 1, bytes(1000))) + 0.01
t = c.send(t, True, get(3, "/refused")) + 0.005
t = c.send(t, False, g.h2_frame(3, 0, 3, struct.pack(">I", 7))) + 0.01  # RST_STREAM REFUSED_STREAM
t = c.send(t, False, g.h2_frame(7, 0, 0, struct.pack(">II", 3, 0))) + 0.01  # GOAWAY NO_ERROR
c.close(t)
w.close()
print(sys.argv[1])
