#!/usr/bin/env python3
"""Write a capture for the tests, like the Java edition's mtls.pcap: two TLS 1.2 connections where the server asks for a client certificate.
The first client sends one, the second sends none. The server sends a two certificate chain (leaf and intermediate).
Certificates are made here with openssl and thrown away. Uses the frame helpers of tools/gen_samples.py.
Usage: gen_mtls.py OUT.pcap"""
import shutil
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gen_samples as g  # noqa: E402

d = Path(tempfile.mkdtemp())


def sh(*a):
    subprocess.run(a, cwd=d, check=True, capture_output=True)


def cert(name, cn, issuer=None, ca=False):
    sh("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", f"{name}.key", "-out", f"{name}.csr", "-subj", f"/CN={cn}")
    ext = d / f"{name}.ext"
    ext.write_text("basicConstraints=critical,CA:TRUE\nkeyUsage=keyCertSign\n" if ca else f"subjectAltName=DNS:{cn}\n")
    if issuer is None:
        sh("openssl", "x509", "-req", "-in", f"{name}.csr", "-signkey", f"{name}.key", "-days", "3650", "-out", f"{name}.pem", "-extfile", ext.name)
    else:
        sh("openssl", "x509", "-req", "-in", f"{name}.csr", "-CA", f"{issuer}.pem", "-CAkey", f"{issuer}.key", "-CAcreateserial", "-days", "365", "-out", f"{name}.pem", "-extfile", ext.name)


cert("root", "Test Root CA", ca=True)
cert("inter", "Test Intermediate CA", "root", ca=True)
cert("server", "gw.example.test", "inter")
cert("client", "netscaler.example.test", "root")
(d / "chain.pem").write_text((d / "server.pem").read_text() + (d / "inter.pem").read_text())


def records(with_client_cert):
    srv = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    srv.maximum_version = ssl.TLSVersion.TLSv1_2
    srv.load_cert_chain(d / "chain.pem", d / "server.key")
    srv.verify_mode = ssl.CERT_OPTIONAL
    srv.load_verify_locations(d / "root.pem")
    cli = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cli.maximum_version = ssl.TLSVersion.TLSv1_2
    cli.load_verify_locations(d / "root.pem")
    if with_client_cert:
        cli.load_cert_chain(d / "client.pem", d / "client.key")
    bios = [ssl.MemoryBIO() for _ in range(4)]
    s = srv.wrap_bio(bios[0], bios[1], server_side=True)
    c = cli.wrap_bio(bios[2], bios[3], server_hostname="gw.example.test")
    flights, done = [], [False, False]
    for _ in range(10):
        for i, (o, inb, outb) in enumerate(((c, bios[2], bios[3]), (s, bios[0], bios[1]))):
            if not done[i]:
                try:
                    o.do_handshake(); done[i] = True
                except ssl.SSLWantReadError:
                    pass
            data = outb.read()
            if data:
                flights.append((i == 0, data))
                (bios[0] if i == 0 else bios[2]).write(data)
        if all(done) and not bios[1].pending and not bios[3].pending:
            break
    return flights


w = g.PcapWriter(Path(sys.argv[1]))
t = g.T0
for port, with_cert in ((51000, True), (51001, False)):
    conn = g.Conn(w, "10.1.0.10", port, "10.2.0.20", 443)
    t = conn.handshake(t)
    for from_c, data in records(with_cert):
        t = conn.send(t, from_c, data) + 0.002
    t = conn.close(t) + 0.05
w.close()
shutil.rmtree(d)
print(sys.argv[1])
