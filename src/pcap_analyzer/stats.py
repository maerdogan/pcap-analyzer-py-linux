"""Wireshark's statistics, made on demand from the kept capture and saved next to the analysis.

The analysis keeps connections and requests. Packet-level views, such as the protocol hierarchy, conversations,
packet sizes, the IO graph, the flow graph, Follow Stream and Export Objects, need the packets themselves, so they
read the kept capture again. A capture analyzed in parts is read in the same parts, so memory stays the same.
"""
import hashlib
import re
import shutil
from collections import defaultdict
from pathlib import Path

from . import knowledge, privacy, split, tshark, vault

AGG = tshark.AGG
VERSION = 3  # saved statistics of an older layout are made again
SIZE_BUCKETS = (0, 20, 40, 80, 160, 320, 640, 1280, 2560, 5120)  # the bins of Wireshark's Packet Lengths
IO_POINTS = 300
IO_STEPS = (0.001, 0.01, 0.1, 0.5, 1, 5, 10, 30, 60, 300, 600, 3600)
TOP_ROWS = 500
FLOW_ROWS = 1000
FOLLOW_BYTES = 2 << 20
OBJECT_PROTOCOLS = ("http", "imf", "smb", "tftp", "ftp-data", "dicom")
OBJECTS_BYTES = 200 << 20
OVERVIEW_FIELDS = ["frame.time_epoch", "frame.len", "frame.protocols", "eth.src", "eth.dst", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
                   "udp.srcport", "udp.dstport", "tcp.srcport", "tcp.dstport"]
GEO_FIELDS = ["ip.geoip.src_country", "ip.geoip.dst_country", "ip.geoip.src_asnum", "ip.geoip.dst_asnum"]
GRAPH_FIELDS = ["frame.time_relative", "ip.src", "ipv6.src", "tcp.srcport", "tcp.seq", "tcp.len", "tcp.ack", "tcp.window_size",
                "tcp.analysis.ack_rtt", "tcp.analysis.retransmission", "tcp.analysis.fast_retransmission", "tcp.flags.syn"]
FLOW_FIELDS = ["frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "_ws.col.protocol", "_ws.col.info"]


class Unavailable(Exception):
    """The capture was not kept, so packets cannot be read again."""


def _last(v):
    return v.rsplit(AGG, 1)[-1] if v else ""


def _first(v):
    return v.split(AGG, 1)[0] if v else ""


def _num(v, kind=float):
    try:
        return kind(v) if v else None
    except ValueError:
        return None


class Source:
    """The kept capture of one analysis, read whole or in the parts the analysis used."""

    def __init__(self, a, settings):
        self.a, self.settings = a, settings
        self.capture = a.dir / "capture"
        if not self.capture.exists():
            raise Unavailable(knowledge.t("The original capture was not kept, so this view cannot be made. Set PCAP_ANALYZER_KEEP_CAPTURE=1 and analyze again."))
        self.parts = a.meta.get("parts") or 0
        self._plan = None

    @property
    def plan(self):
        if self._plan is None and self.parts:
            self._plan = split.plan(self.capture, self.parts)
        return self._plan

    def options(self):
        args = []
        for rule in self.a.meta.get("decode_as") or ():
            args += tshark.Filter(decode_as=(rule,)).decode_args()
        if self.settings.geoip_dir:
            args += ["-o", f'uat:maxmind_db_paths:"{self.settings.geoip_dir}"']
        return args

    def run(self, args, part=None, **kw):
        feed = None
        if part is not None:
            feed = lambda: split.feed(self.capture, self.plan, part)  # noqa: E731
        return tshark.run(self.capture, self.options() + args, self.settings.tshark, self.settings.workdir, self.settings.analysis_timeout_s, feed=feed, **kw)

    def each_part(self):
        return range(len(self.plan.parts)) if self.parts else [None]

    def frame(self, part, n):
        """A frame number of a part, as a number of the whole capture."""
        return self.plan.parts[part].frames[n - 1] if part is not None else n

    def fields(self, names, display=None, part=None, extra=(), **kw):
        args = [*extra, "-T", "fields", "-E", "separator=/t", "-E", "quote=n", "-E", "occurrence=a", "-E", f"aggregator={AGG}"]
        if display:
            args += ["-Y", display]
        empty = dict.fromkeys(names, "")
        for _ in range(len(names)):
            used = tshark.usable(names, self.settings.tshark)
            try:
                for line in self.run(args + [x for n in used for x in ("-e", n)], part, **kw):
                    yield {**empty, **dict(zip(used, line.split("\t")))}
                return
            except tshark.UnknownFields:
                continue  # tshark refuses a run before its first line, so nothing was given twice

    def stream_part(self, stream):
        """Where a connection sits: (part, its number in that part), or (None, stream) for a capture read whole."""
        if not self.parts:
            return None, stream
        with self.a.connect() as db:
            row = db.execute("SELECT part, part_stream FROM stream_parts WHERE stream = ?", [stream]).fetchone()
        if row is None:
            raise Unavailable(knowledge.t("This connection does not exist."))
        return row[0], row[1]


def cached(a, name, make):
    """Statistics are made once per analysis. A name holds only letters, digits, - and _."""
    folder = a.dir / "stats"
    path = folder / f"{name}.json"
    if path.exists():
        data = vault.read_json(path, {})
        if data.get("version") == VERSION:
            return data["data"]
    data = make()
    folder.mkdir(exist_ok=True)
    vault.write_json(path, dict(version=VERSION, data=data))
    return data


def key(*parts):
    return hashlib.sha256(repr(parts).encode()).hexdigest()[:16]


# --- Protocol hierarchy, conversations, endpoints, packet sizes and traffic over time, from one pass ---

def _size_bin(n):
    for lo, hi in zip(SIZE_BUCKETS, SIZE_BUCKETS[1:]):
        if n < hi:
            return f"{lo}-{hi - 1}"
    return f"{SIZE_BUCKETS[-1]}+"


def _pair(a, b):
    return (a, b) if a <= b else (b, a)


def overview(a, settings):
    return cached(a, "overview", lambda: _overview(Source(a, settings)))


def _overview(src):
    names = OVERVIEW_FIELDS + (GEO_FIELDS if src.settings.geoip_dir else [])
    tree = {}
    sizes = defaultdict(lambda: [0, 0])
    udp, eth, macs, ips = {}, {}, {}, {}
    times = []  # (time, bytes) sampled into buckets at the end
    first = last = None
    total = total_bytes = 0
    for part in src.each_part():
        for p in src.fields(names, part=part):
            t, n = _num(p["frame.time_epoch"]), _num(p["frame.len"], int) or 0
            if t is None:
                continue
            total += 1
            total_bytes += n
            first = t if first is None else min(first, t)
            last = t if last is None else max(last, t)
            times.append((t, n))
            node = tree
            for proto in (p["frame.protocols"] or "").split(":"):
                if not proto:
                    break
                entry = node.setdefault(proto, [0, 0, {}])
                entry[0] += 1
                entry[1] += n
                node = entry[2]
            s = sizes[_size_bin(n)]
            s[0] += 1
            s[1] += n
            ms, md = _last(p["eth.src"]), _last(p["eth.dst"])
            if ms and md:
                c = eth.setdefault(_pair(ms, md), dict(frames=0, bytes=0, start=t, end=t))
                c["frames"] += 1
                c["bytes"] += n
                c["start"], c["end"] = min(c["start"], t), max(c["end"], t)
                for mac, sent in ((ms, True), (md, False)):
                    e = macs.setdefault(mac, dict(frames=0, bytes=0, sent=0, received=0))
                    e["frames"] += 1
                    e["bytes"] += n
                    e["sent" if sent else "received"] += n
            si, di = _last(p["ip.src"]) or _last(p["ipv6.src"]), _last(p["ip.dst"]) or _last(p["ipv6.dst"])
            if si and di:
                for ip, sent, side in ((si, True, "src"), (di, False, "dst")):
                    e = ips.setdefault(ip, dict(frames=0, bytes=0, sent=0, received=0, country=None, asn=None))
                    e["frames"] += 1
                    e["bytes"] += n
                    e["sent" if sent else "received"] += n
                    if src.settings.geoip_dir:
                        e["country"] = e["country"] or _last(p.get(f"ip.geoip.{side}_country")) or None
                        e["asn"] = e["asn"] or _last(p.get(f"ip.geoip.{side}_asnum")) or None
                sp, dp = _last(p["udp.srcport"]), _last(p["udp.dstport"])
                if sp and dp and not p["tcp.srcport"]:
                    k = _pair(f"{si}:{sp}", f"{di}:{dp}")
                    c = udp.setdefault(k, dict(frames=0, bytes=0, start=t, end=t, a_to_b=0, b_to_a=0))
                    c["frames"] += 1
                    c["bytes"] += n
                    c["start"], c["end"] = min(c["start"], t), max(c["end"], t)
                    c["a_to_b" if f"{si}:{sp}" == k[0] else "b_to_a"] += n
    return dict(
        packets=total, bytes=total_bytes, start=first, end=last,
        hierarchy=_flatten(tree, total, total_bytes),
        sizes=[dict(bin=b, packets=v[0], bytes=v[1]) for b, v in sorted(sizes.items(), key=lambda kv: int(kv[0].split("-")[0].rstrip("+")))],
        udp=sorted((dict(a=k[0], b=k[1], **v, duration=v["end"] - v["start"]) for k, v in udp.items()), key=lambda c: -c["bytes"])[:TOP_ROWS],
        ethernet=sorted((dict(a=k[0], b=k[1], frames=v["frames"], bytes=v["bytes"], start=v["start"], duration=v["end"] - v["start"]) for k, v in eth.items()),
                        key=lambda c: -c["bytes"])[:TOP_ROWS],
        macs=sorted((dict(address=k, **v) for k, v in macs.items()), key=lambda e: -e["bytes"])[:TOP_ROWS],
        ips=sorted((dict(address=k, **v) for k, v in ips.items()), key=lambda e: -e["bytes"])[:TOP_ROWS],
        geoip=bool(src.settings.geoip_dir),
        io=_buckets(times, first, last),
    )


def _flatten(tree, total, total_bytes, depth=0):
    out = []
    for proto, (frames, size, children) in sorted(tree.items(), key=lambda kv: -kv[1][1]):
        out.append(dict(protocol=proto, depth=depth, packets=frames, bytes=size,
                        share=frames / total if total else 0, byte_share=size / total_bytes if total_bytes else 0))
        out += _flatten(children, total, total_bytes, depth + 1)
    return out


def step_for(span):
    return next((s for s in IO_STEPS if span / s <= IO_POINTS), IO_STEPS[-1])


def _buckets(times, first, last, step=None):
    if first is None:
        return dict(step=step or 1, start=None, rows=[])
    step = step or step_for(last - first)
    n = int((last - first) // step) + 1
    packets, size = [0] * n, [0] * n
    for t, b in times:
        i = int((t - first) // step)
        packets[i] += 1
        size[i] += b
    return dict(step=step, start=first, rows=[dict(t=round(i * step, 6), packets=packets[i], bytes=size[i], bps=size[i] * 8 / step) for i in range(n)])


def io_graph(a, settings, display=None):
    """Packets and bits per interval for a display filter, on the same axis as the whole capture."""
    whole = overview(a, settings)
    if not display:
        return dict(filter=None, **whole["io"])
    display = display.strip()

    def make():
        src = Source(a, settings)
        times = []
        for part in src.each_part():
            for p in src.fields(["frame.time_epoch", "frame.len"], display, part):
                t = _num(p["frame.time_epoch"])
                if t is not None:
                    times.append((t, _num(p["frame.len"], int) or 0))
        io = whole["io"]
        if io["start"] is None:
            return dict(filter=display, **io)
        last = io["start"] + io["step"] * max(len(io["rows"]) - 1, 0)
        times = [(t, b) for t, b in times if io["start"] <= t <= last + io["step"]]
        return dict(filter=display, **_buckets(times, io["start"], last, io["step"]))
    return cached(a, "io-" + key(display), make)


# --- HTTP request sequences and load distribution, from the saved requests ---

REFERER = re.compile(r"(?im)^referer:\s*(\S+)")


def http_sequences(db):
    """Wireshark's HTTP Request Sequences: which page each request came from, by its Referer header."""
    found = defaultdict(lambda: defaultdict(int))
    for host, uri, headers in db.execute("SELECT host, uri, req_headers FROM http_transactions WHERE method IS NOT NULL").fetchall():
        m = REFERER.search(headers or "")
        target = f"{host or ''}{uri or ''}"
        found[m.group(1) if m else ""][target] += 1
    out = []
    for referer, targets in sorted(found.items(), key=lambda kv: -sum(kv[1].values())):
        out.append(dict(referer=referer or None, requests=sum(targets.values()),
                        targets=[dict(url=u, requests=n) for u, n in sorted(targets.items(), key=lambda kv: -kv[1])[:50]]))
    return out[:TOP_ROWS]


def http_load(db):
    """Wireshark's HTTP Load Distribution: requests and responses per server address and host name."""
    servers = [dict(zip(("server", "host", "requests", "responses"), r)) for r in db.execute(
        """SELECT c.server_ip || ':' || c.server_port, t.host, count(*), count(*) FILTER (t.answered)
           FROM http_transactions t JOIN tcp_connections c USING (stream) GROUP BY ALL ORDER BY 3 DESC LIMIT ?""", [TOP_ROWS]).fetchall()]
    total = sum(s["requests"] for s in servers) or 1
    for s in servers:
        s["share"] = s["requests"] / total
    return servers


# --- QUIC and HTTP/3 ---

class Quic:
    """QUIC connections, gathered during the analysis, so a TLS key log given there also shows HTTP/3 requests."""

    def __init__(self):
        self.conns = {}

    def add(self, p, t):
        number = _num(_first(p.get("quic.connection.number")), int)
        if number is None:
            return
        si, di = _last(p.get("ip.src")) or _last(p.get("ipv6.src")), _last(p.get("ip.dst")) or _last(p.get("ipv6.dst"))
        here, there = f"{si}:{_last(p.get('udp.srcport'))}", f"{di}:{_last(p.get('udp.dstport'))}"
        c = self.conns.get(_pair(here, there))
        if c is None:
            c = self.conns[_pair(here, there)] = dict(client=here, server=there, start=t, end=t, packets=0, bytes=0, version=None, sni=None,
                                                      alpn=None, handshake=None, streams=set(), h3=False)
        c["end"] = max(c["end"], t)
        c["packets"] += 1
        c["bytes"] += _num(p.get("frame.len"), int) or 0
        version = _num(_first(p.get("quic.version")), lambda v: int(v, 0))
        if version and not c["version"]:
            c["version"] = {1: "1", 0x6B3343CF: "2"}.get(version, hex(version))
        c["sni"] = c["sni"] or _first(p.get("tls.handshake.extensions_server_name")) or None
        c["alpn"] = c["alpn"] or _first(p.get("tls.handshake.extensions_alpn_str")) or None
        if here != c["client"] and c["handshake"] is None and "0" in (p.get("quic.header_form") or "").split(AGG):
            c["handshake"] = t - c["start"]  # the server's first short-header packet: the handshake is done
        for sid in (p.get("quic.stream.stream_id") or "").split(AGG):
            sid = _num(sid, lambda v: int(v, 0))
            if sid is not None and sid % 4 == 0:  # streams the client opens both ways carry HTTP/3 requests
                c["streams"].add(sid)
        c["h3"] = c["h3"] or bool(p.get("http3.frame_type"))

    def rows(self):
        out = []
        for c in sorted(self.conns.values(), key=lambda c: c["start"]):
            out.append((c["client"], c["server"], c["start"], c["end"], c["end"] - c["start"], c["packets"], c["bytes"], c["version"],
                        c["sni"], c["alpn"], c["handshake"], len(c["streams"]), c["h3"]))
        return out


def quic(db):
    try:
        return [dict(zip([d[0] for d in db.description], r)) for r in db.execute("SELECT * FROM quic_connections ORDER BY start_time LIMIT ?", [TOP_ROWS]).fetchall()]
    except Exception:  # noqa: BLE001 - saved by an older version
        return []


# --- One connection: Stevens, throughput, round trip and window graphs ---

def tcp_graphs(a, settings, stream):
    def make():
        src = Source(a, settings)
        part, number = src.stream_part(stream)
        series = defaultdict(list)
        first_side = None
        for p in src.fields(GRAPH_FIELDS, f"tcp.stream == {int(number)}", part):
            t = _num(p["frame.time_relative"])
            if t is None:
                continue
            side = f"{_last(p['ip.src']) or _last(p['ipv6.src'])}:{p['tcp.srcport']}"
            first_side = first_side or side
            series[side].append(dict(t=t, seq=_num(p["tcp.seq"], int), len=_num(p["tcp.len"], int) or 0, ack=_num(p["tcp.ack"], int),
                                     win=_num(p["tcp.window_size"], int), rtt=_num(p["tcp.analysis.ack_rtt"]),
                                     retrans=bool(p["tcp.analysis.retransmission"] or p["tcp.analysis.fast_retransmission"])))
        if not series:
            return None
        t0 = min(r["t"] for rows in series.values() for r in rows)
        sides = []
        for side, rows in series.items():
            for r in rows:
                r["t"] = round(r["t"] - t0, 6)
            sides.append(dict(side=side, client=side == first_side, sent=sum(r["len"] for r in rows), **_graphs(rows)))
        return dict(sides=sorted(sides, key=lambda s: -s["sent"]))
    return cached(a, f"tcp-{int(stream)}", make)


def _graphs(rows):
    data = [r for r in rows if r["len"]]
    span = max((r["t"] for r in rows), default=0)
    step = step_for(span) if span else 1
    throughput = defaultdict(int)
    for r in data:
        throughput[int(r["t"] // step)] += r["len"]
    return dict(
        stevens=[[r["t"], r["seq"], r["retrans"]] for r in data],
        throughput=dict(step=step, rows=[[i * step, b * 8 / step] for i, b in sorted(throughput.items())]),
        rtt=[[r["t"], r["rtt"]] for r in rows if r["rtt"] is not None],
        window=[[r["t"], r["win"]] for r in rows if r["win"] is not None],  # the window this side offers the other
    )


# --- Flow graph ---

def flow_graph(a, settings, display=None, stream=None):
    if stream is not None:
        display = None

    def make():
        src = Source(a, settings)
        if stream is not None:
            part, number = src.stream_part(stream)
            parts, expr = [part], f"tcp.stream == {int(number)}"
        else:
            parts, expr = src.each_part(), display or None
        rows = []
        for part in parts:
            for p in src.fields(FLOW_FIELDS, expr, part, max_lines=FLOW_ROWS):
                t = _num(p["frame.time_epoch"])
                if t is None:
                    continue
                rows.append(dict(frame=src.frame(part, int(p["frame.number"])), t=t, src=_last(p["ip.src"]) or _last(p["ipv6.src"]) or "?",
                                 dst=_last(p["ip.dst"]) or _last(p["ipv6.dst"]) or "?", protocol=p["_ws.col.protocol"], info=privacy.mask_uri(p["_ws.col.info"])[:200]))
        rows.sort(key=lambda r: r["frame"])
        rows = rows[:FLOW_ROWS]
        hosts = []
        for r in rows:
            for h in (r["src"], r["dst"]):
                if h not in hosts:
                    hosts.append(h)
        t0 = rows[0]["t"] if rows else 0
        for r in rows:
            r["t"] = r["t"] - t0
        return dict(hosts=hosts, rows=rows, cut=len(rows) >= FLOW_ROWS, filter=expr)
    return cached(a, "flow-" + key(display, stream), make)


# --- Follow Stream ---

SECRET_LINE = re.compile(r"(?im)^((?:%s)\s*:\s*).*$" % "|".join(map(re.escape, privacy.SENSITIVE_HEADERS)))


def follow(a, settings, stream, mode="ascii"):
    """The bytes of one TCP connection, each side in turn, as Wireshark's Follow TCP Stream shows them.
    Known secret headers and fields are masked, as in the rest of the results."""
    if mode not in ("ascii", "hex"):
        raise ValueError(mode)

    def make():
        src = Source(a, settings)
        part, number = src.stream_part(stream)
        chunks, size, node0 = [], 0, None
        lines = list(src.run(["-q", "-z", f"follow,tcp,{'hex' if mode == 'hex' else 'raw'},{int(number)}"], part))
        for line in lines:
            if line.startswith(("===", "Follow:", "Filter:", "Node 0:", "Node 1:")):
                if line.startswith("Node 0:"):
                    node0 = line.split(":", 1)[1].strip()
                continue
            if mode == "hex":
                side = 1 if line.startswith("\t") else 0
                text = line.strip()
            else:
                side = 1 if line.startswith("\t") else 0
                try:
                    text = bytes.fromhex(line.strip()).decode("utf-8", "replace")
                except ValueError:
                    continue
            if not text:
                continue
            if size + len(text) > FOLLOW_BYTES:
                chunks.append(dict(side=side, text="…", cut=True))
                break
            size += len(text)
            if chunks and chunks[-1]["side"] == side and not chunks[-1].get("cut"):
                chunks[-1]["text"] += text if mode == "ascii" else "\n" + text
            else:
                chunks.append(dict(side=side, text=text))
        if mode == "ascii":
            for c in chunks:
                c["text"] = privacy.mask_body(SECRET_LINE.sub(lambda m: m.group(1) + privacy.MASK, c["text"]))
        return dict(client=node0, chunks=chunks, mode=mode)
    return cached(a, f"follow-{int(stream)}-{mode}", make)


# --- Export Objects ---

SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def objects(a, settings):
    """Files carried in the capture, as Wireshark's Export Objects finds them. They are kept until the analysis is deleted."""
    def make():
        src = Source(a, settings)
        folder = a.dir / "objects"
        shutil.rmtree(folder, ignore_errors=True)
        folder.mkdir()
        found, total = [], 0

        def keep(proto, part):
            def collect(out):
                nonlocal total
                for f in sorted(Path(out).iterdir()):
                    if not f.is_file():
                        continue
                    size = f.stat().st_size
                    if total + size > OBJECTS_BYTES:
                        found.append(dict(protocol=proto, name=f.name, size=size, kept=False))
                        continue
                    name = f"{len(found):04d}-{SAFE_NAME.sub('_', f.name)[:120]}"
                    vault.store_copy(f, folder / name)
                    total += size
                    found.append(dict(protocol=proto, name=f.name, file=name, size=size, kept=True, part=part))
            return collect
        for proto in OBJECT_PROTOCOLS:
            for part in src.each_part():
                try:
                    for _ in src.run(["-q", "--export-objects", f"{proto},{{out}}"], part, collect=keep(proto, part)):
                        pass
                except tshark.TsharkError:
                    continue  # this tshark does not know the protocol
        return found
    return cached(a, "objects", make)


def object_path(a, name):
    if not re.fullmatch(r"\d{4}-[A-Za-z0-9._-]+", name):
        return None
    path = a.dir / "objects" / name
    return path if path.is_file() else None


# --- Every packet of one connection, in order ---

PACKET_ROWS = 5000
# TCP flags by their standard names, in the order people read them, such as SYN, ACK.
TCP_FLAGS = [(0x02, "SYN"), (0x10, "ACK"), (0x08, "PSH"), (0x01, "FIN"), (0x04, "RST"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR")]
FLAG_MEANINGS = {
    "SYN": "opens a connection", "ACK": "acknowledges data received", "PSH": "hands the data to the application at once",
    "FIN": "ends sending, a normal close", "RST": "breaks the connection off at once", "URG": "marks urgent data",
    "ECE": "reports congestion on the path", "CWR": "the sender slowed down after congestion",
}


def flag_names(value):
    bits = int(value, 0) if value else 0
    return [name for bit, name in TCP_FLAGS if bits & bit]


PACKET_FIELDS = ["frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "tcp.srcport", "tcp.flags", "tcp.seq", "tcp.ack", "tcp.len",
                 "tcp.window_size", "_ws.col.protocol", "_ws.col.info", "tcp.analysis.retransmission", "tcp.analysis.fast_retransmission",
                 "tcp.analysis.out_of_order", "tcp.analysis.duplicate_ack", "tcp.analysis.lost_segment", "tcp.analysis.ack_lost_segment",
                 "tcp.analysis.zero_window", "tcp.analysis.window_full", "tcp.analysis.keep_alive"]
PACKET_MARKS = [("tcp.analysis.retransmission", "retransmission"), ("tcp.analysis.fast_retransmission", "fast retransmission"),
                ("tcp.analysis.out_of_order", "out of order"), ("tcp.analysis.duplicate_ack", "duplicate ACK"),
                ("tcp.analysis.lost_segment", "previous segment not captured"), ("tcp.analysis.ack_lost_segment", "ACKed unseen segment"),
                ("tcp.analysis.zero_window", "zero window"), ("tcp.analysis.window_full", "window full"), ("tcp.analysis.keep_alive", "keep-alive")]


def packets(a, settings, stream):
    """Every packet of one TCP connection in capture order, as Wireshark's packet list shows it, up to PACKET_ROWS."""
    def make():
        src = Source(a, settings)
        part, number = src.stream_part(stream)
        rows, client = [], None
        for p in src.fields(PACKET_FIELDS, f"tcp.stream == {int(number)}", part, max_lines=PACKET_ROWS + 1):
            t = _num(p["frame.time_epoch"])
            if t is None:
                continue
            side = f"{_last(p['ip.src']) or _last(p['ipv6.src'])}:{p['tcp.srcport']}"
            client = client or side
            rows.append(dict(frame=src.frame(part, int(p["frame.number"])), t=t, from_client=side == client, flags=flag_names(p["tcp.flags"]),
                             seq=_num(p["tcp.seq"], int), ack=_num(p["tcp.ack"], int), len=_num(p["tcp.len"], int) or 0, win=_num(p["tcp.window_size"], int),
                             protocol=p["_ws.col.protocol"], info=privacy.mask_uri(p["_ws.col.info"] or "")[:300],
                             marks=[label for name, label in PACKET_MARKS if p.get(name)]))
        cut = len(rows) > PACKET_ROWS
        rows = rows[:PACKET_ROWS]
        start = rows[0]["t"] if rows else 0
        for r in rows:
            r["t"] = r["t"] - start
        seen = {f for r in rows for f in r["flags"]}
        legend = [dict(flag=name, meaning=FLAG_MEANINGS[name]) for _, name in TCP_FLAGS if name in seen]
        return dict(rows=rows, cut=cut, limit=PACKET_ROWS, legend=legend, start=start)
    return cached(a, f"packets-{int(stream)}", make)


def request_packets(a, settings, t):
    """The packets of one HTTP request, from the connection's handshake when the request opened it, or from its own
    first packet, to the last packet of its response and the client's acknowledgment of it."""
    whole = packets(a, settings, t["stream"])
    rows = whole["rows"]
    if not rows:
        return dict(whole, rows=[], legend=[])
    start = whole["start"]
    end = t.get("resp_end") or t.get("req_end") or t["req_start"]
    first = 0 if t.get("new_conn") else next((i for i, r in enumerate(rows) if r["frame"] >= t["req_frame"]), len(rows))
    last = first
    for i in range(first, len(rows)):
        if start + rows[i]["t"] <= end + 1e-6:
            last = i
        else:
            break
    if last + 1 < len(rows) and rows[last + 1]["from_client"] and rows[last + 1]["flags"] == ["ACK"] and not rows[last + 1]["len"]:
        last += 1  # the client's acknowledgment closes the exchange
    picked = [dict(r) for r in rows[first:last + 1]]
    t0 = picked[0]["t"] if picked else 0
    for r in picked:
        r["t"] -= t0
    seen = {f for r in picked for f in r["flags"]}
    legend = [dict(flag=name, meaning=FLAG_MEANINGS[name]) for _, name in TCP_FLAGS if name in seen]
    return dict(rows=picked, cut=whole["cut"] and last + 1 >= len(rows), limit=whole["limit"], legend=legend, start=start + t0)


# --- Follow HTTP stream, from the requests the analysis kept ---

def follow_http(db, stream):
    """The requests and responses of one connection in order, with their headers and the start of their bodies.
    They come from the analysis, so a capture decrypted with a key log shows them too, and secrets stay masked."""
    out = []
    for t in db.execute("""SELECT id, h2_stream, method, uri, host, http_version, status, phrase, req_headers, resp_headers, req_body, resp_body,
            req_start, resp_start, resp_end, total, truncated, answered FROM http_transactions WHERE stream = ? ORDER BY req_start, id""", [stream]).fetchall():
        (tid, h2, method, uri, host, version, status, phrase, req_h, resp_h, req_b, resp_b, req_start, resp_start, resp_end, total, truncated, answered) = t
        h1 = not (version or "").startswith("HTTP/2")
        request = (f"{method} {uri} {version or 'HTTP/1.1'}\n" if h1 else "") + (req_h or "") + (f"\n\n{req_b}" if req_b else "")
        response = None
        if answered:
            response = (f"{version or 'HTTP/1.1'} {status} {phrase or ''}".rstrip() + "\n" if h1 else "") + (resp_h or "") + (f"\n\n{resp_b}" if resp_b else "")
        out.append(dict(id=tid, h2_stream=h2, start=req_start, total=total, status=status, request=request.strip(), response=response.strip() if response else None,
                        truncated=bool(truncated), host=host))
    return out
