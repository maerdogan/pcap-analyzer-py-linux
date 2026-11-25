#!/usr/bin/env python3
"""Write a capture for the tests, like the Java edition's proxy.pcap: a NetScaler to gateway connection that starts with a PROXY protocol v2 header
for client 203.0.113.7:40000, then one HTTP/1.1 request. A second connection uses PROXY v1 for an IPv6 client.
A third has no PROXY header; its request names the client in X-Forwarded-For,
and the Envoy gateway says its upstream took 5 ms of the 20.
Uses the frame helpers of tools/gen_samples.py. Usage: gen_proxy.py OUT.pcap"""
import socket
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gen_samples as g  # noqa: E402

w = g.PcapWriter(Path(sys.argv[1]))
addrs = socket.inet_aton("203.0.113.7") + socket.inet_aton("198.51.100.10") + struct.pack(">HH", 40000, 443)
v2 = b"\r\n\r\n\x00\r\nQUIT\n" + bytes([0x21, 0x11]) + struct.pack(">H", len(addrs)) + addrs
v1 = b"PROXY TCP6 2001:db8::7 2001:db8::10 40001 443\r\n"
t = g.T0
for port, header in ((52000, v2), (52001, v1)):
    c = g.Conn(w, "10.1.0.10", port, "10.2.0.20", 8080)
    t = c.handshake(t)
    t = c.send(t, True, header + g.req("GET", "/api/orders")) + 0.02
    t = c.send(t, False, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok") + 0.01
    t = c.close(t) + 0.05
c = g.Conn(w, "10.1.0.10", 52002, "10.2.0.20", 8080)
t = c.handshake(t)
t = c.send(t, True, g.req("GET", "/api/orders", extra=["X-Forwarded-For: 198.51.100.5, 10.0.0.1"])) + 0.02
t = c.send(t, False, b"HTTP/1.1 200 OK\r\nx-envoy-upstream-service-time: 5\r\nContent-Length: 2\r\n\r\nok") + 0.01
c.close(t)
w.close()
print(sys.argv[1])
