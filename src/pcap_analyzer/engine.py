"""Analyze a capture once and keep the result; the same input reopens the saved result."""
import gzip
import hashlib
import json
import os
import re
import shutil
import tempfile
import time
from dataclasses import astuple, dataclass
from pathlib import Path

from . import __version__, knowledge, records, reports, split, store, tshark, vault
from .config import Settings
from .parser import Builder, finish_stream, nat_views


DNS_WINDOW_S = 5.0
DNS_LOOKUP_S = 60.0  # one lookup can try several search domains, each with resolver timeouts
GZIP_MAGIC = b"\x1f\x8b"
COMPRESSED_MAGIC = (b"\x28\xb5\x2f\xfd", b"\x04\x22\x4d\x18")  # zstd, lz4
ARCHIVES = {b"PK\x03\x04": "ZIP", b"7z\xbc\xaf": "7-Zip", b"Rar!": "RAR", b"BZh": "bzip2", b"\xfd7zXZ": "xz"}
KEYLOG_LABELS = (b"CLIENT_RANDOM ", b"CLIENT_HANDSHAKE_TRAFFIC_SECRET ", b"SERVER_HANDSHAKE_TRAFFIC_SECRET ", b"CLIENT_TRAFFIC_SECRET_0 ", b"RSA ")
KEYLOG_MARKS = (b"CLIENT_RANDOM ", b"_TRAFFIC_SECRET", b"RSA ")  # one of these opens a key log, as the NSS format names them
# A NetScaler trace (nstrace, from "start nstrace") opens with a signature record that names its version. tshark reads versions 1.0 to 3.5.
NSTRACE_SIGNATURE = re.compile(rb"NetScaler V\d\d Performance Data")
NSTRACE_HEAD = 512
PCAP_MAGICS = (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1", b"\x0a\x0d\x0d\x0a")
HEAD_BYTES = 4096
CHUNK = 1 << 20
STALE_TMP_S = 6 * 3600
TMP_PREFIXES = ("pcap-analyzer-", "pcap-upload-", "pcap-export-")
ID = re.compile(r"[0-9a-f]{20}")
SEEN_EVERY_S = 3600
_seen = {}
PART_BYTES = 100 * CHUNK  # a larger capture is read in parts, and one part takes about as much memory as a capture this size
STREAM_FIELDS = re.compile(r"\b(frame\.number|tcp\.stream)\b")
KEYLOG_CUT_BYTES = 8 * CHUNK  # a larger key log, like NetScaler's for every session it served, is cut to the sessions in the capture
CLIENT_HELLO = re.compile(rb"\x16\x03[\x00-\x04]..\x01...\x03[\x00-\x04](.{32})", re.S)  # TLS record, ClientHello, version, random
HELLO_BYTES = 43


class CaptureTooLarge(Exception):
    pass


class NotFound(Exception):
    pass


class CompressedCapture(ValueError):
    pass


class WrongFile(ValueError):
    """A file that is not what its field asks for, such as an archive in the capture field."""


@dataclass
class Analysis:
    id: str
    dir: Path
    meta: dict
    cached: bool

    @property
    def db_path(self):
        return self.dir / "analysis.duckdb"

    def connect(self):
        return store.connect(self.db_path)


def is_nstrace(head):
    """True for the start of a NetScaler trace, such as one with "NetScaler V35 Performance Data" in its first record."""
    return bool(NSTRACE_SIGNATURE.search(head[:NSTRACE_HEAD]))


def looks_like_capture(path):
    """True for a pcap, a pcapng or a NetScaler trace, by its first bytes."""
    with vault.open_read(path) as f:
        head = f.read(NSTRACE_HEAD)
    return head.startswith(PCAP_MAGICS) or is_nstrace(head)


def _refuse_compressed(path):
    """tshark would unpack these, and the unpacked size cannot be known or limited beforehand.
    Other files people pick by mistake get a message that names them, rather than tshark's guess at an unknown format."""
    with vault.open_read(path) as f:
        head = f.read(HEAD_BYTES)
    if is_nstrace(head):  # its signature record is text, but it is a capture
        return
    if head.startswith(COMPRESSED_MAGIC):
        raise CompressedCapture(knowledge.t("Compressed captures are not accepted, because their real size cannot be checked. Decompress the file and upload it again."))
    kind = next((name for magic, name in ARCHIVES.items() if head.startswith(magic)), "tar" if head[257:262] == b"ustar" else None)
    if kind:
        raise WrongFile(knowledge.t("This is a {kind} archive, not a capture. Extract the capture from it and upload that file.", kind=kind))
    if b"\0" in head or not _is_text(head):
        return
    if any(label in head for label in KEYLOG_LABELS):
        raise WrongFile(knowledge.t("This is a TLS key log, not a capture. Choose it in the key log field and the capture in the capture field."))
    if b"-----BEGIN " in head:
        raise WrongFile(knowledge.t("This is a key or certificate file, not a capture."))
    raise WrongFile(knowledge.t("This is a text file, not a capture."))


def _is_text(head):
    try:
        head.decode("utf-8")
    except UnicodeDecodeError as e:
        return e.start >= len(head) - 4  # a character cut at the end of the sample
    return True


def check_keylog(path):
    """tshark skips lines it cannot read, so a wrong file would decrypt nothing without a word."""
    with open(path, "rb") as f:
        head = f.read(HEAD_BYTES)
    if b"\0" in head or not _is_text(head) or not any(mark in head for mark in KEYLOG_MARKS):
        raise WrongFile(knowledge.t("This is not a TLS key log. A key log is a text file with lines such as CLIENT_RANDOM."))


def join_keylogs(paths, out):
    """Write every distinct line of several key logs to out, in order, such as those of the client to NetScaler leg
    and of the NetScaler to gateway leg. Returns how many key lines out holds."""
    seen, keys = set(), 0
    with open(out, "wb") as dst:
        for path in paths:
            with open(path, "rb") as src:
                for line in src:
                    line = line.strip()
                    digest = hashlib.blake2b(line, digest_size=16).digest()  # a NetScaler key log can hold millions of lines
                    if not line or digest in seen:
                        continue
                    seen.add(digest)
                    dst.write(line + b"\n")
                    keys += not line.startswith(b"#")
    return keys


def check_rsa_key(path):
    """tshark takes a PEM private key here. A .pfx needs its password, and without a key it silently decrypts nothing."""
    with open(path, "rb") as f:
        data = f.read()
    if b"-----BEGIN" not in data:
        raise WrongFile(knowledge.t("The RSA key must be a PEM file. Convert a .pfx or .p12 file with: openssl pkcs12 -in FILE.pfx -nocerts -nodes -out key.pem"))
    if b"PRIVATE KEY-----" not in data:
        raise WrongFile(knowledge.t("This PEM file holds no private key."))


def unpack(path, folder, settings):
    """Unpack a gzip capture and stop at the size limit, because the real size is unknown until then."""
    with vault.open_read(path) as f:
        if f.read(2) != GZIP_MAGIC:
            return Path(path)
    limit, written = settings.max_size_mb * CHUNK, 0
    fd, name = tempfile.mkstemp(prefix="unpacked-", dir=folder)
    try:
        with vault.open_read(path) as raw, gzip.open(raw, "rb") as src, open(fd, "wb") as dst:
            while chunk := src.read(CHUNK):
                written += len(chunk)
                if written > limit:
                    raise CaptureTooLarge(knowledge.t("{name} is larger than the {n} MB limit", name=Path(path).name, n=settings.max_size_mb))
                dst.write(chunk)
    except (OSError, EOFError) as e:
        raise CompressedCapture(knowledge.t("This gzip file is damaged: {reason}", reason=e)) from e
    return Path(name)


def join_parts(paths, folder, settings):
    """Turn several parts into one capture, unpacking each first and holding the size limit on the result."""
    parts = [unpack(p, folder, settings) for p in paths]
    for p in parts:
        _refuse_compressed(p)
    if sum(vault.size(p) for p in parts) > settings.max_size_mb * CHUNK:
        raise CaptureTooLarge(knowledge.t("{name} is larger than the {n} MB limit", name=Path(paths[0]).name, n=settings.max_size_mb))
    if len(parts) == 1:
        return parts[0]
    out = Path(folder) / "merged.pcapng"
    tshark.merge(parts, out, settings.mergecap, settings.tshark)
    return out


def _digest(paths, flt, slow_s, group=""):
    """The same input gives the same analysis, within one group: a group never gets the result of another."""
    h = hashlib.sha256()
    h.update(__version__.encode())
    for p in paths:
        h.update(b"\0")
        if p:
            with vault.open_read(p) as f:
                while chunk := f.read(1 << 20):
                    h.update(chunk)
    h.update(repr((astuple(flt), slow_s)).encode())
    if group:
        h.update(b"\0group\0" + group.encode())
    return h.hexdigest()[:20]


def _facts(db):
    """What the warnings and the quality report need from the saved connections and requests."""
    c = db.execute("""SELECT count(*), count(*) FILTER (NOT syn_seen), count(*) FILTER (close_type IS NULL),
        count(*) FILTER ((payload_client = 0 AND payload_server = 0) OR one_way), count(*) FILTER (kind = 'TLS'),
        coalesce(bool_or(offload), false), coalesce(bool_or(kind = 'TLS' AND handshake_seen AND tls_unread), false), coalesce(bool_or(kind = 'TLS' AND NOT syn_seen), false)
        FROM tcp_connections""").fetchone()
    events = dict(db.execute("SELECT event, count(*) FROM tcp_events WHERE event IN ('ack_lost_segment', 'lost_segment') GROUP BY event").fetchall())
    shared = db.execute("""SELECT 1 FROM http_transactions WHERE request_id IS NOT NULL AND request_id <> ''
        GROUP BY request_id HAVING count(DISTINCT stream) > 1 LIMIT 1""").fetchone()
    return dict(connections=c[0], started_before=c[1], open_at_end=c[2], one_way=c[3], encrypted=c[4], offload=c[5],
                tls_handshake_seen=c[6], tls_started_before=c[7], unseen=events.get("ack_lost_segment", 0), gaps=events.get("lost_segment", 0),
                shared_request_id=bool(shared), transactions=db.execute("SELECT count(*) FROM http_transactions").fetchone()[0])


def _warnings(b, facts, keyed, warnings):
    if b.truncated:
        warnings.append("frames_truncated")
    if b.copies:
        warnings.append("copies_removed")
    if b.nat_views:
        warnings.append("nat_views_removed")
    if facts["shared_request_id"]:
        warnings.append("same_request_on_two_connections")
    if b.tunnelled:
        warnings.append("tunnel_seen")
    if facts["offload"]:
        warnings.append("offload_suspected")
    if not keyed and facts["encrypted"]:
        warnings.append("tls_not_decrypted")
    if keyed and facts["tls_handshake_seen"]:
        warnings.append("tls_key_did_not_decrypt")
    if keyed and facts["tls_started_before"]:
        warnings.append("tls_started_before_capture")  # its keys cannot be matched without the handshake
    return sorted(set(warnings))


def _attach_dns(txns, dns, asks):
    """Link a lookup to a new connection when its answer came shortly before that connection.

    The time runs from the first query of the lookup, so search domains tried before the answer and
    queries sent again after a timeout count too. A short name such as web.shop is looked up as
    web.shop.<search domain>, so those names belong to the host as well."""
    answers, sent, names_of = {}, {}, {}
    for name, duration, _, t in dns:
        if name:
            answers.setdefault(name.lower(), []).append((t, duration))
    for name, t in asks:
        if name:
            sent.setdefault(name.lower(), []).append(t)
    for x in txns:
        host = (x.get("host") or "").split(":")[0].lower().rstrip(".")
        if x.get("connect_time") is None or not host:
            continue
        if host not in names_of:
            names_of[host] = [n for n in answers.keys() | sent.keys() if n == host or n.startswith(host + ".")]
        names = names_of[host]
        near = [(t, d, n) for n in names for t, d in answers.get(n, ()) if 0 <= x["req_start"] - t <= DNS_WINDOW_S]
        if not near:
            continue
        end, duration, final = max(near)
        asked = end - duration
        since = max((t for t, _ in answers[final] if t < asked), default=asked - DNS_LOOKUP_S)  # the lookup before ended there
        start = min((t for n in names for t in sent.get(n, ()) if since < t <= asked), default=asked)
        x["dns_time"] = end - start


def _attach_packet_size(b, txns):
    for x in txns:
        s = b.streams[x["stream"]]
        hi = x["last_frame"] or x["req_frame"]
        x["max_packet"] = max((p.size for p in s.packets if x["req_frame"] <= p.frame <= hi), default=0)


def _quality(b, facts):
    """Counts that show how far this capture can be trusted. Levels and wording come later, from the reports."""
    return dict(tcp_packets=b.tcp, connections=facts["connections"], unseen=facts["unseen"], gaps=facts["gaps"], snapped=b.truncated, copies=b.copies,
                started_before=facts["started_before"], open_at_end=facts["open_at_end"], one_way=facts["one_way"], encrypted=facts["encrypted"])


def analyze(path, keylog=None, rsa_key=None, flt=None, settings=None, use_cached=True, display_name=None, limit=None, owner=None):
    """keylog is one key log, or a list of them that are joined into one. owner names who uploaded the capture and in which group: dict(user, group)."""
    settings = settings or Settings()
    own_limit = limit is None
    limit = limit or tshark.Limit(settings.analysis_timeout_s)
    try:
        return _analyze(path, keylog, rsa_key, flt, settings, use_cached, display_name, limit, owner or {})
    finally:
        if own_limit:
            limit.close()


def _analyze(path, keylog, rsa_key, flt, settings, use_cached, display_name, limit, owner):
    flt = flt or tshark.Filter()
    path = Path(path)
    if vault.size(path) > settings.max_size_mb * CHUNK:
        raise CaptureTooLarge(knowledge.t("{name} is larger than the {n} MB limit", name=path.name, n=settings.max_size_mb))
    keylogs = [keylog] if isinstance(keylog, (str, Path)) else list(keylog or ())
    for one in keylogs:
        check_keylog(one)
    if rsa_key:
        check_rsa_key(rsa_key)
    with tempfile.TemporaryDirectory(prefix="pcap-analyzer-", dir="/tmp") as folder:
        keylog = keylogs[0] if len(keylogs) == 1 else None
        if len(keylogs) > 1:
            keylog = Path(folder) / "keylog"
            join_keylogs(keylogs, keylog)
        capture = join_parts([path], folder, settings)
        display_name = display_name or path.name.removesuffix(".gz")
        return _run(capture, keylog, rsa_key, flt, settings, use_cached, display_name, limit, owner)


def _run(path, keylog, rsa_key, flt, settings, use_cached, display_name, limit, owner):
    ts_version = tshark.version(settings.tshark)
    slow_s = records.slow_s(settings)
    aid = _digest([path, keylog, rsa_key], flt, slow_s, owner.get("group") or "")
    out = settings.workdir / aid
    if use_cached and (out / "meta.json").exists():
        return Analysis(aid, out, json.loads(vault.read_bytes(out / "meta.json")), True)

    started = time.monotonic()
    warnings = []
    settings.workdir.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix=".tmp-", dir=settings.workdir))
    try:
        used_keylog = _keylog_for(path, keylog, tmp)
        run = lambda feed=None: tshark.packets(path, used_keylog, rsa_key, flt, settings.tshark, warnings, limit, settings.workdir, settings.analysis_timeout_s, feed)
        writer = store.Writer(tmp / "analysis.duckdb")
        b, views = Builder(), []
        if vault.size(path) > PART_BYTES:
            number, parts = _read_in_parts(path, flt, run, b, writer, views, limit, slow_s, warnings)
        else:
            for p in run():
                b.add(p)
            _flush(b, writer, views, limit, slow_s)
            dropped = nat_views(views, lambda sid: sid)
            number, parts = {sid: sid for sid, _, _ in views if sid not in dropped}, 0
            b.nat_views = len(dropped)
        if used_keylog != keylog:
            used_keylog.unlink()  # keys do not stay with the result
        if b.total and b.t_first is None:
            raise WrongFile(knowledge.t("This file holds no network packets."))
        limit.check()
        writer.close(number, b.dns_rows, lambda txns: _attach_dns(txns, b.dns_rows, b.dns_asks), b.packet_issues, b.quic.rows())
        _mark_capture_end(tmp / "analysis.duckdb", b.t_last, slow_s)
        _link_saved(tmp / "analysis.duckdb")
        limit.check()
        return _save(tmp, out, aid, path, keylog, rsa_key, flt, settings, display_name, ts_version, started, warnings, b, parts, slow_s, owner)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def client_randoms(path):
    """The random of every ClientHello in a capture, found in the raw bytes, so any capture format and tunnel works.
    The record header, the handshake header, the version and the random lead every ClientHello, so they sit in its first segment."""
    found, tail = set(), b""
    with vault.open_read(path) as f:
        while chunk := f.read(16 * CHUNK):
            data = tail + chunk
            found.update(r.hex() for r in CLIENT_HELLO.findall(data))
            tail = data[-(HELLO_BYTES - 1):]
    return found


def _keylog_for(path, keylog, folder):
    """A large key log cut to the sessions in the capture: tshark keeps every key it reads in memory.
    A line is keyed by the client random in its second field. Other lines, like RSA ones, stay."""
    if keylog is None or Path(keylog).stat().st_size <= KEYLOG_CUT_BYTES:
        return keylog
    randoms = client_randoms(path)
    out = Path(folder) / "keylog"
    with open(keylog, "rb") as src, open(out, "wb") as dst:
        for line in src:
            fields = line.split()
            if len(fields) >= 3 and len(fields[1]) == 64 and fields[1].decode("ascii", "replace").lower() not in randoms:
                continue
            dst.write(line)
    return out


def _mark_capture_end(db_path, capture_end, slow_s):
    """A request with no answer that the capture stopped right after is not known to be unanswered.
    The end of the capture is known only after the last part, so this runs on the saved requests."""
    if capture_end is None:
        return
    with store.connect(db_path, write=True) as db:
        db.execute("UPDATE http_transactions SET cause = 'capture_end' WHERE cause = 'no_response' AND ? - req_end < ?", [capture_end, slow_s])


def link_netscaler_legs(conns):
    """In a NetScaler trace each connection names its own PCB and the linked PCB of the other leg: client to VIP, and SNIP to server.
    Returns the stream of the other leg for each connection that has one. Either side naming the other is enough."""
    by_pcb, peer = {}, {}
    for c in conns:
        if c.get("ns_pcb") is not None:
            by_pcb.setdefault(c["ns_pcb"], c)
    for c in conns:
        other = by_pcb.get(c.get("ns_linked_pcb")) if c.get("ns_linked_pcb") is not None else None
        if other is None or other is c:
            continue
        peer.setdefault(c["stream"], other["stream"])
        peer.setdefault(other["stream"], c["stream"])
    return peer


def mark_retries(txns):
    """A request whose request ID was seen before on an attempt that failed and ended before it began: a retry by the gateway or the client.
    Sets attempt and retry_of on the retries. Two legs of one proxy carry the same ID too, but they overlap in time, so they are not counted."""
    groups = {}
    for t in txns:
        if t.get("request_id"):
            groups.setdefault(t["request_id"], []).append(t)
    for group in groups.values():
        if len(group) < 2:
            continue
        group.sort(key=lambda t: t["req_start"])
        attempt, prev = 1, group[0]
        for t in group[1:]:
            failed = not prev.get("status") or prev["status"] >= 500
            prev_end = prev["resp_end"] if prev.get("resp_end") is not None else prev["req_end"]
            if not failed or prev_end > t["req_start"]:
                continue
            attempt += 1
            t.update(attempt=attempt, retry_of=prev["id"])
            prev = t


def _link_saved(db_path):
    """What needs connections and requests of the whole capture, with their final numbers: NetScaler legs and retries."""
    with store.connect(db_path, write=True) as db:
        conns = [dict(zip(("stream", "ns_pcb", "ns_linked_pcb"), r)) for r in db.execute(
            "SELECT stream, ns_pcb, ns_linked_pcb FROM tcp_connections WHERE ns_pcb IS NOT NULL OR ns_linked_pcb IS NOT NULL ORDER BY stream").fetchall()]
        store.set_values(db, "tcp_connections", "stream", ["ns_peer"], link_netscaler_legs(conns).items(), db_path.parent)
        txns = reports.rows(db, """SELECT id, request_id, req_start, req_end, resp_end, status FROM http_transactions WHERE request_id IN
            (SELECT request_id FROM http_transactions WHERE request_id IS NOT NULL GROUP BY 1 HAVING count(*) > 1) ORDER BY req_start, id""")
        mark_retries(txns)
        store.set_values(db, "http_transactions", "id", ["attempt", "retry_of"], ((t["id"], t["attempt"], t["retry_of"]) for t in txns if "retry_of" in t), db_path.parent)


def _flush(b, writer, views, limit, slow_s, part=None, offset=0):
    """Finish the connections read so far, hand them to the writer and forget their packets."""
    conns, txns = [], []
    for s in b.streams.values():
        limit.check()
        c, t = finish_stream(s, slow_s)
        if part is not None:
            c.update(part=part, part_stream=c["stream"] - offset)
        conns.append(c)
        txns += t
        views.append((s.sid, s.syn.t if s.syn else None, s.isn))
    _attach_packet_size(b, txns)
    writer.add(conns, txns, b.events)
    b.streams.clear()
    b.events.clear()


def _read_in_parts(path, flt, run, b, writer, views, limit, slow_s, warnings):
    """Analyze a large capture in parts of whole connections, so memory stays near that of one part.
    Frame and connection numbers are turned back into those of the whole capture, the way Wireshark counts them."""
    if flt.display and STREAM_FIELDS.search(flt.display):
        raise tshark.TsharkError(knowledge.t("Captures over {n} MB are read in parts, so a display filter cannot use frame.number or tcp.stream. Filter by address, port or time instead.", n=PART_BYTES // CHUNK))
    try:
        plan = split.plan(path, -(-path.stat().st_size // PART_BYTES))
    except split.Unsupported as e:
        raise tshark.TsharkError(knowledge.t("Captures over {n} MB must be pcap or pcapng files.", n=PART_BYTES // CHUNK)) from e
    if plan.truncated:
        warnings.append("capture_truncated")
    first_frame = {}  # first frame of every connection, by its number while reading
    for k, part in enumerate(plan.parts):
        offset = max(first_frame, default=-1) + 1
        for p in run(lambda k=k: split.feed(path, plan, k)):
            _to_whole(p, part.frames, offset, first_frame)
            b.add(p)
        _flush(b, writer, views, limit, slow_s, k, offset)
    dropped = nat_views(views, first_frame.get)
    b.nat_views = len(dropped)
    order = sorted(first_frame, key=first_frame.get)
    return {sid: i for i, sid in enumerate(order) if sid not in dropped}, len(plan.parts)


def _to_whole(p, frames, offset, first_frame):
    """Frame and connection numbers of one part, as numbers of the whole capture."""
    whole = frames[int(p["frame.number"]) - 1]
    p["frame.number"] = str(whole)
    if p.get("tcp.analysis.acks_frame"):
        p["tcp.analysis.acks_frame"] = str(frames[int(p["tcp.analysis.acks_frame"]) - 1])
    for key in ("tcp.segment", "tls.segment"):
        if p.get(key):
            p[key] = tshark.AGG.join(str(frames[int(x) - 1]) for x in p[key].split(tshark.AGG))
    if p.get("tcp.stream"):
        sids = [int(x) + offset for x in p["tcp.stream"].split(tshark.AGG)]
        for sid in sids:
            first_frame.setdefault(sid, whole)
        p["tcp.stream"] = tshark.AGG.join(map(str, sids))


def _save(tmp, out, aid, path, keylog, rsa_key, flt, settings, display_name, ts_version, started, warnings, b, parts, slow_s, owner):
    with store.connect(tmp / "analysis.duckdb") as db:
        facts = _facts(db)
    meta = dict(
        id=aid, filename=display_name or path.name, size=vault.size(path), created=time.time(), tshark=ts_version, version=__version__,
        uploader=owner.get("user") or "", group=owner.get("group") or "",
        decryption="keylog" if keylog else "rsa_key" if rsa_key else None, filter=flt.expression(), decode_as=list(flt.decode_as),
        capture_drops=split.drops(path),
        packets=b.total, tcp_packets=b.tcp, bytes=b.bytes, connections=facts["connections"], transactions=facts["transactions"],
        ip_fragments=b.fragments, frag_needed=b.frag_needed, copies=b.copies, tunnelled=b.tunnelled, capture_start=b.t_first, capture_end=b.t_last, duration_s=round(time.monotonic() - started, 3), slow_s=slow_s,
        quality=_quality(b, facts), warnings=_warnings(b, facts, bool(keylog or rsa_key), warnings), parts=parts)
    if settings.keep_capture:
        vault.store_copy(path, tmp / "capture")  # encrypted once the data folder is
    meta["capture_kept"] = settings.keep_capture
    store.seal_database(tmp / "analysis.duckdb")
    vault.write_json(tmp / "meta.json", meta, indent=2)
    shutil.rmtree(out, ignore_errors=True)
    try:
        tmp.rename(out)
    except OSError:  # an identical analysis finished first
        pass
    return Analysis(aid, out, meta, False)


def open_analysis(aid, settings=None):
    settings = settings or Settings()
    if not ID.fullmatch(aid or ""):
        raise NotFound(aid)
    d = settings.workdir / aid
    if not (d / "meta.json").exists():
        raise NotFound(aid)
    try:
        meta = json.loads(vault.read_bytes(d / "meta.json"))
    except vault.Tampered as e:
        raise NotFound(aid) from e
    return Analysis(aid, d, meta, True)


def list_analyses(settings=None):
    """Every saved analysis, newest first. One whose files were changed by hand is left out, and the admin sees a notice."""
    settings = settings or Settings()
    if not settings.workdir.exists():
        return []
    metas = []
    for m in settings.workdir.glob("*/meta.json"):
        if ID.fullmatch(m.parent.name):
            try:
                metas.append(json.loads(vault.read_bytes(m)))
            except (vault.Tampered, ValueError):
                continue
    return sorted(metas, key=lambda m: -m["created"])


def seen(aid, settings):
    """Mark an analysis as opened, at most once an hour, by the time of an empty .seen file. Retention counts from it."""
    now = time.time()
    if now - _seen.get(aid, 0) < SEEN_EVERY_S:
        return
    _seen[aid] = now
    path = settings.workdir / aid / vault.SEEN
    try:
        path.touch(0o600)
        os.utime(path, (now, now))
    except OSError:
        pass


def last_use(folder):
    """When an analysis was last opened, or else when it was made. Only file times are read, so this works while the vault is locked."""
    times = []
    for name in ("meta.json", vault.SEEN):
        try:
            times.append((folder / name).stat().st_mtime)
        except OSError:
            continue
    return max(times) if times else folder.stat().st_mtime


def delete(aid, settings=None):
    settings = settings or Settings()
    try:
        target = open_analysis(aid, settings).dir
    except NotFound:
        return False
    shutil.rmtree(target)
    return True


def _remove_stale(paths, cutoff):
    for p in paths:
        try:
            if p.is_dir() and p.stat().st_mtime < cutoff:
                shutil.rmtree(p, ignore_errors=True)
        except OSError:
            continue  # another process removed it, or it belongs to another user


def purge(settings=None, now=None, tmp_root=Path("/tmp")):
    """Delete analyses nobody opened for the retention time, and what a killed process left behind. Returns how many analyses were removed.
    An analysis never opened counts from when it was made."""
    settings = settings or Settings()
    now = now or time.time()
    old = []
    if settings.workdir.exists():
        for d in settings.workdir.iterdir():
            try:
                if d.is_dir() and ID.fullmatch(d.name) and now - last_use(d) > settings.ttl_days * 86400:
                    old.append(d)
            except OSError:
                continue
    for d in old:
        shutil.rmtree(d, ignore_errors=True)
        _seen.pop(d.name, None)
        records.audit(settings, "expired", "server", d.name)
    records.trim_audit(settings)
    cutoff = now - STALE_TMP_S
    if settings.workdir.exists():
        _remove_stale(settings.workdir.glob(".tmp-*"), cutoff)
    if tmp_root.exists():  # these can hold captures and TLS keys
        _remove_stale((p for p in tmp_root.iterdir() if p.name.startswith(TMP_PREFIXES)), cutoff)
    return len(old)
