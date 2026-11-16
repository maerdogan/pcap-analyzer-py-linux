"""Service response times of protocols other than HTTP, and SIP calls with their RTP streams.

Like Wireshark's Service Response Time, SIP Flows and RTP Stream Analysis, these are made on demand from the kept
capture, in the parts the analysis used. Each protocol pairs a request with its answer by the key the protocol
gives: a message ID, a correlation ID, a call ID, or the order of commands on one connection.
"""
from collections import defaultdict, deque

from . import knowledge, reports, stats

AGG = stats.AGG
SLOWEST = 20
TOP = 200

ADDRESS = ["frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "tcp.stream", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport"]
PROTOCOL_FIELDS = {
    "LDAP": ["ldap.protocolOp", "ldap.messageID", "ldap.resultCode", "ldap.bindResponse_resultCode"],
    "Kerberos": ["kerberos.msg_type", "kerberos.error_code"],
    "SMB2": ["smb2.cmd", "smb2.time", "smb2.nt_status", "smb2.flags.response"],
    "Kafka": ["kafka.api_key", "kafka.correlation_id", "kafka.request_frame", "kafka.error"],
    "SMTP": ["smtp.req.command", "smtp.response.code"],
    "DCERPC": ["dcerpc.pkt_type", "dcerpc.opnum", "dcerpc.cn_call_id", "dcerpc.cn_status"],
    "MQTT": ["mqtt.msgtype", "mqtt.msgid", "mqtt.conack.val"],
    "AMQP": ["amqp.channel", "amqp.method.class", "amqp.method.method", "amqp.method.arguments.reply_code"],
    "FTP": ["ftp.request.command", "ftp.response.code"],
}
DISPLAY = "ldap or kerberos or smb2 or kafka or smtp or dcerpc or mqtt or amqp or ftp"

LDAP_OPS = {0: "bind", 3: "search", 6: "modify", 8: "add", 10: "delete", 12: "modify DN", 14: "compare", 23: "extended"}
LDAP_DONE = {1: 0, 5: 3, 7: 6, 9: 8, 11: 10, 13: 12, 15: 14, 24: 23}  # final answer: its request
LDAP_NOT_ERRORS = {0, 5, 6, 10, 14}  # success, compareFalse, compareTrue, referral, saslBindInProgress
KERBEROS = {10: "AS-REQ", 12: "TGS-REQ"}
KERBEROS_ANSWERS = {11, 13, 30}
SMB2_COMMANDS = {0: "NEGOTIATE", 1: "SESSION_SETUP", 2: "LOGOFF", 3: "TREE_CONNECT", 4: "TREE_DISCONNECT", 5: "CREATE", 6: "CLOSE", 7: "FLUSH",
                 8: "READ", 9: "WRITE", 10: "LOCK", 11: "IOCTL", 12: "CANCEL", 13: "ECHO", 14: "QUERY_DIRECTORY", 15: "CHANGE_NOTIFY",
                 16: "QUERY_INFO", 17: "SET_INFO", 18: "OPLOCK_BREAK"}
SMB2_NOT_ERRORS = {0, 0x103, 0xC0000016, 0x80000005, 0x80000006}  # success, pending, more processing, buffer overflow, no more files
KAFKA_APIS = {0: "Produce", 1: "Fetch", 2: "ListOffsets", 3: "Metadata", 8: "OffsetCommit", 9: "OffsetFetch", 10: "FindCoordinator",
              11: "JoinGroup", 12: "Heartbeat", 13: "LeaveGroup", 14: "SyncGroup", 15: "DescribeGroups", 16: "ListGroups",
              17: "SaslHandshake", 18: "ApiVersions", 19: "CreateTopics", 22: "InitProducerId", 36: "SaslAuthenticate"}
MQTT = {1: ("CONNECT", 2), 3: ("PUBLISH", 4), 6: ("PUBREL", 7), 8: ("SUBSCRIBE", 9), 10: ("UNSUBSCRIBE", 11), 12: ("PINGREQ", 13)}
MQTT_QOS2 = 5  # PUBREC answers a PUBLISH with QoS 2
AMQP_CLASSES = {10: "connection", 20: "channel", 40: "exchange", 50: "queue", 60: "basic", 85: "confirm", 90: "tx"}


def _int(v, base=0):
    try:
        return int(v, base) if v not in (None, "") else None
    except ValueError:
        return None


def _many(v):
    return v.split(AGG) if v else []


def _ends(p):
    src = stats._last(p["ip.src"]) or stats._last(p["ipv6.src"])
    dst = stats._last(p["ip.dst"]) or stats._last(p["ipv6.dst"])
    sp, dp = (p["tcp.srcport"], p["tcp.dstport"]) if p["tcp.srcport"] else (stats._last(p["udp.srcport"]), stats._last(p["udp.dstport"]))
    return f"{src}:{sp}", f"{dst}:{dp}"


class Exchanges:
    """Requests waiting for their answer and the answered exchanges of one protocol."""

    def __init__(self):
        self.pending = {}
        self.done = []

    def ask(self, key, frame, t, op, client, server):
        self.pending.setdefault(key, deque()).append((frame, t, op, client, server))

    def answer(self, key, t, error=None, op=None):
        waiting = self.pending.get(key)
        if not waiting:
            return
        frame, start, asked, client, server = waiting.popleft()
        self.done.append(dict(frame=frame, start=start, time=max(t - start, 0.0), op=op or asked, client=client, server=server, error=error))

    def unanswered(self):
        return [dict(frame=f, start=t, time=None, op=op, client=c, server=s, error=None) for q in self.pending.values() for f, t, op, c, s in q]


class Collector:
    def __init__(self):
        self.x = defaultdict(Exchanges)

    def add(self, p, frame):
        t = stats._num(p["frame.time_epoch"])
        if t is None:
            return
        a, b = _ends(p)
        conn = tuple(sorted((a, b)))
        for name in PROTOCOL_FIELDS:
            getattr(self, "_" + name.lower())(p, frame, t, a, b, conn, self.x[name])

    @staticmethod
    def _ldap(p, frame, t, a, b, conn, x):
        codes = _many(p["ldap.resultCode"]) or _many(p["ldap.bindResponse_resultCode"])  # a bind answer names its result code apart
        for op, mid, code in zip(_many(p["ldap.protocolOp"]), _many(p["ldap.messageID"]), codes + [""] * 8):
            op, mid = _int(op), _int(mid)
            if op in LDAP_OPS:
                x.ask((conn, mid), frame, t, LDAP_OPS[op], a, b)
            elif op in LDAP_DONE:
                code = _int(code)
                x.answer((conn, mid), t, None if code in LDAP_NOT_ERRORS or code is None else f"resultCode {code}")

    @staticmethod
    def _kerberos(p, frame, t, a, b, conn, x):
        kind = _int(stats._first(p["kerberos.msg_type"]))
        if kind in KERBEROS:
            x.ask(conn, frame, t, KERBEROS[kind], a, b)
        elif kind in KERBEROS_ANSWERS:
            code = _int(stats._first(p["kerberos.error_code"]))
            x.answer(conn, t, f"KRB-ERROR {code}" if kind == 30 else None)

    @staticmethod
    def _smb2(p, frame, t, a, b, conn, x):
        for cmd, took, status, resp in zip(_many(p["smb2.cmd"]), _many(p["smb2.time"]) + [""] * 8, _many(p["smb2.nt_status"]) + [""] * 8,
                                           _many(p["smb2.flags.response"]) + [""] * 8):
            took = stats._num(took)
            if resp not in ("1", "True") or took is None:
                continue
            status = _int(status)
            op = SMB2_COMMANDS.get(_int(cmd), cmd)
            x.done.append(dict(frame=frame, start=t - took, time=took, op=op, client=b, server=a,
                               error=None if status in SMB2_NOT_ERRORS or status is None else f"0x{status:08x}"))

    @staticmethod
    def _kafka(p, frame, t, a, b, conn, x):
        cid = _int(stats._first(p["kafka.correlation_id"]))
        if cid is None:
            return
        api = _int(stats._first(p["kafka.api_key"]))
        if p["kafka.request_frame"]:
            errors = [e for e in map(_int, _many(p["kafka.error"])) if e]
            x.answer((conn, cid), t, f"error {errors[0]}" if errors else None)
        else:
            x.ask((conn, cid), frame, t, KAFKA_APIS.get(api, f"API {api}"), a, b)

    @staticmethod
    def _smtp(p, frame, t, a, b, conn, x):
        for cmd in _many(p["smtp.req.command"]):
            x.ask(conn, frame, t, cmd.upper(), a, b)
        codes = [c for c in map(_int, _many(p["smtp.response.code"])) if c]
        if codes:
            x.answer(conn, t, str(codes[-1]) if codes[-1] >= 400 else None)

    @staticmethod
    def _dcerpc(p, frame, t, a, b, conn, x):
        """Paired by call ID, since Wireshark times a call only when it saw the bind."""
        for kind, call, op in zip(_many(p["dcerpc.pkt_type"]), _many(p["dcerpc.cn_call_id"]), _many(p["dcerpc.opnum"]) + [""] * 8):
            kind, call = _int(kind), _int(call)
            if kind == 0:
                x.ask((conn, call), frame, t, f"opnum {op}" if op else "call", a, b)
            elif kind in (2, 3):  # response or fault
                status = _int(stats._first(p["dcerpc.cn_status"]))
                x.answer((conn, call), t, (f"fault 0x{status:08x}" if status else "fault") if kind == 3 else None)

    @staticmethod
    def _mqtt(p, frame, t, a, b, conn, x):
        for kind, mid in zip(_many(p["mqtt.msgtype"]), _many(p["mqtt.msgid"]) + [""] * 8):
            kind, mid = _int(kind), _int(mid)
            if kind in MQTT and (kind != 3 or mid is not None):  # a PUBLISH with QoS 0 has no ID and no answer
                x.ask((conn, MQTT[kind][1], mid if kind not in (1, 12) else None), frame, t, MQTT[kind][0], a, b)
            elif kind == MQTT_QOS2:
                x.answer((conn, 4, mid), t, op="PUBLISH")
            elif kind in {v[1] for v in MQTT.values()}:
                code = _int(stats._first(p["mqtt.conack.val"]))
                x.answer((conn, kind, mid if kind not in (2, 13) else None), t, f"CONNACK {code}" if kind == 2 and code else None)

    @staticmethod
    def _amqp(p, frame, t, a, b, conn, x):
        for ch, cls, method in zip(_many(p["amqp.channel"]), _many(p["amqp.method.class"]), _many(p["amqp.method.method"])):
            cls, method = _int(cls), _int(method)
            if cls is None or method is None:
                continue
            name = f"{AMQP_CLASSES.get(cls, cls)}.{method}"
            if x.pending.get((conn, ch, cls, method - 1)):  # in AMQP 0-9-1 an answer is the next method of the same class
                x.answer((conn, ch, cls, method - 1), t)
            else:
                x.ask((conn, ch, cls, method), frame, t, name, a, b)
                code = _int(stats._first(p["amqp.method.arguments.reply_code"]))
                if code and code != 200:  # a close with an error code ends the channel or connection
                    x.done.append(dict(frame=frame, start=t, time=0.0, op=name, client=b, server=a, error=f"reply {code}"))

    @staticmethod
    def _ftp(p, frame, t, a, b, conn, x):
        for cmd in _many(p["ftp.request.command"]):
            x.ask(conn, frame, t, cmd.upper(), a, b)
        codes = [c for c in map(_int, _many(p["ftp.response.code"])) if c]
        if codes and codes[-1] >= 200:  # 1xx says the transfer starts, the answer comes after it
            x.answer(conn, t, str(codes[-1]) if codes[-1] >= 400 else None)


def response_times(a, settings):
    return stats.cached(a, "services", lambda: _response_times(stats.Source(a, settings)))


def _response_times(src):
    c = Collector()
    names = ADDRESS + [f for fields in PROTOCOL_FIELDS.values() for f in fields]
    for part in src.each_part():
        for p in src.fields(names, DISPLAY, part):
            c.add(p, src.frame(part, int(p["frame.number"])))
    out = []
    for name in PROTOCOL_FIELDS:
        x = c.x.get(name)
        if not x or not (x.done or x.pending):
            continue
        out.append(_summary(name, x.done, x.unanswered()))
    return out


def _stats(rows):
    times = sorted(r["time"] for r in rows if r["time"] is not None)
    return dict(requests=len(rows), answered=len(times), errors=sum(1 for r in rows if r["error"]),
                avg=sum(times) / len(times) if times else None, p95=reports.percentile(times, 0.95) if times else None,
                max=times[-1] if times else None)


def _summary(name, done, unanswered):
    rows = done + unanswered
    ops = defaultdict(list)
    servers = defaultdict(list)
    for r in rows:
        ops[r["op"]].append(r)
        servers[r["server"]].append(r)
    errors = defaultdict(int)
    for r in done:
        if r["error"]:
            errors[(r["op"], r["error"])] += 1
    return dict(
        protocol=name, **_stats(rows),
        operations=sorted((dict(op=k, **_stats(v)) for k, v in ops.items()), key=lambda o: -o["requests"])[:TOP],
        servers=sorted((dict(server=k, **_stats(v)) for k, v in servers.items()), key=lambda o: -o["requests"])[:TOP],
        error_kinds=[dict(op=k[0], error=k[1], count=n) for k, n in sorted(errors.items(), key=lambda kv: -kv[1])][:TOP],
        slowest=sorted((r for r in done if r["time"] is not None), key=lambda r: -r["time"])[:SLOWEST],
    )


# --- SIP calls and RTP streams ---

SIP_FIELDS = ADDRESS + ["sip.Call-ID", "sip.Method", "sip.Status-Code", "sip.CSeq.method", "sip.from.user", "sip.to.user"]
RTP_FIELDS = ADDRESS + ["rtp.ssrc", "rtp.seq", "rtp.timestamp", "rtp.p_type"]
RTP_CLOCK = {0: 8000, 3: 8000, 4: 8000, 8: 8000, 9: 8000, 18: 8000, 10: 44100, 11: 44100, 26: 90000, 31: 90000, 32: 90000, 33: 90000, 34: 90000}
DEFAULT_CLOCK = 8000  # dynamic payload types: most voice codecs; video and Opus streams show a skewed jitter


def voip(a, settings):
    return stats.cached(a, "voip", lambda: _voip(stats.Source(a, settings)))


def _voip(src):
    calls, streams = {}, {}
    for part in src.each_part():
        for p in src.fields(SIP_FIELDS, "sip", part):
            _sip(calls, p, src.frame(part, int(p["frame.number"])))
        for p in src.fields(RTP_FIELDS, "rtp", part, extra=["-o", "rtp.heuristic_rtp:TRUE"]):  # RTP without its SIP setup is found by its header
            _rtp(streams, p)
    return dict(calls=_calls(calls), streams=_streams(streams))


def _sip(calls, p, frame):
    t = stats._num(p["frame.time_epoch"])
    cid = stats._first(p["sip.Call-ID"])
    if t is None or not cid:
        return
    a, b = _ends(p)
    method, status, cseq = stats._first(p["sip.Method"]), _int(stats._first(p["sip.Status-Code"])), stats._first(p["sip.CSeq.method"])
    c = calls.get(cid)
    if c is None:
        c = calls[cid] = dict(call_id=cid, frame=frame, start=t, end=t, caller=None, callee=None, from_user=stats._first(p["sip.from.user"]) or None,
                              to_user=stats._first(p["sip.to.user"]) or None, method=method or cseq, invite=None, ringing=None, answered=None,
                              bye=None, status=None, messages=0)
    c["messages"] += 1
    c["end"] = max(c["end"], t)
    if method == "INVITE" and c["invite"] is None:
        c["invite"], c["caller"], c["callee"] = t, a, b
    if status and cseq == "INVITE":
        if status in (180, 183) and c["ringing"] is None:
            c["ringing"] = t
        elif status >= 200 and c["status"] is None:
            c["status"] = status
            if 200 <= status < 300:
                c["answered"] = t
    if method in ("BYE", "CANCEL") and c["bye"] is None:
        c["bye"] = t


def _calls(calls):
    out = []
    for c in sorted(calls.values(), key=lambda c: c["start"]):
        start = c["invite"] or c["start"]
        state = ("in_call" if c["bye"] is None else "completed") if c["answered"] else "rejected" if c["status"] and c["status"] >= 300 else \
            "cancelled" if c["bye"] else "unanswered" if c["invite"] else "other"
        out.append(dict(call_id=c["call_id"], frame=c["frame"], start=c["start"], caller=c["caller"], callee=c["callee"], from_user=c["from_user"],
                        to_user=c["to_user"], method=c["method"], status=c["status"], state=state, messages=c["messages"],
                        ringing=c["ringing"] - start if c["ringing"] else None, setup=c["answered"] - start if c["answered"] else None,
                        duration=(c["bye"] or c["end"]) - c["answered"] if c["answered"] else None))
    return out[:TOP * 5]


def _rtp(streams, p):
    t = stats._num(p["frame.time_epoch"])
    ssrc, seq, ts = stats._first(p["rtp.ssrc"]), _int(stats._first(p["rtp.seq"])), _int(stats._first(p["rtp.timestamp"]))
    if t is None or not ssrc or seq is None or ts is None:
        return
    a, b = _ends(p)
    key = (ssrc, a, b)
    s = streams.get(key)
    pt = _int(stats._first(p["rtp.p_type"]))
    if s is None:
        s = streams[key] = dict(ssrc=ssrc, src=a, dst=b, payload=pt, first=t, last=t, packets=0, base=seq, cycles=0, max_seq=seq,
                                out_of_order=0, duplicates=0, seen=set(), jitter=0.0, max_jitter=0.0, jitter_sum=0.0, max_delta=0.0,
                                prev=None, clock=RTP_CLOCK.get(pt, DEFAULT_CLOCK))
    s["packets"] += 1
    if s["prev"] is not None:
        s["max_delta"] = max(s["max_delta"], t - s["prev"][0])
    ext = s["cycles"] + seq
    delta = (seq - s["max_seq"]) & 0xFFFF
    if delta and delta < 0x8000:  # in order, maybe after a gap; a wrap starts a new cycle
        if seq < s["max_seq"]:
            s["cycles"] += 0x10000
        ext = s["cycles"] + seq
        s["max_seq"] = seq
    elif delta:
        s["out_of_order"] += 1
        ext = s["cycles"] + seq - (0x10000 if seq > s["max_seq"] else 0)
    if ext in s["seen"]:
        s["duplicates"] += 1
    s["seen"].add(ext)
    if s["prev"] is not None and delta and delta < 0x8000:
        # RFC 3550, 6.4.1: the change in transit time between two packets, smoothed by 1/16
        d = (t - s["prev"][0]) - ((ts - s["prev"][1]) & 0xFFFFFFFF) / s["clock"]
        s["jitter"] += (abs(d) - s["jitter"]) / 16
        s["max_jitter"] = max(s["max_jitter"], s["jitter"])
        s["jitter_sum"] += s["jitter"]
    if not delta or delta < 0x8000:
        s["prev"] = (t, ts)
    s["last"] = t


def _streams(streams):
    out = []
    for s in streams.values():
        expected = s["cycles"] + s["max_seq"] - s["base"] + 1
        unique = len(s["seen"])
        lost = max(expected - unique, 0)
        out.append(dict(ssrc=s["ssrc"], src=s["src"], dst=s["dst"], payload=s["payload"], packets=s["packets"], expected=expected, lost=lost,
                        loss=lost / expected if expected else 0, out_of_order=s["out_of_order"], duplicates=s["duplicates"],
                        max_delta=s["max_delta"], max_jitter=s["max_jitter"], mean_jitter=s["jitter_sum"] / max(s["packets"] - 1, 1),
                        start=s["first"], duration=s["last"] - s["first"]))
    return sorted(out, key=lambda s: s["start"])[:TOP * 5]


STATE_LABELS = {"completed": "Completed", "in_call": "In call when the capture ended", "rejected": "Rejected", "cancelled": "Cancelled",
                "unanswered": "Not answered", "other": "Other"}


def state_label(state):
    return knowledge.t(STATE_LABELS.get(state, state))
