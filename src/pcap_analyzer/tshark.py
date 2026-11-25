"""Run tshark and yield one dict per packet.

A capture of an encrypted data folder reaches tshark through a pipe, decrypted as it is read, so it is never on disk in plain.
A plain capture and any TLS key are copied to a private directory under /tmp first, because
Ubuntu's AppArmor profile stops tshark from reading most other paths.
"""
import ctypes
import ipaddress
import os
import re
import resource
import select
import shutil
import subprocess
import struct
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

from . import vault

MIN_VERSION = (4, 0)
FILE_LIMIT = 1 << 34  # tshark writes no files here, apart from its temporary reassembly data
# Linux Landlock works without privileges or namespaces, so it also works in a pod. Numbers are the same on x86_64 and arm64.
SYS_CREATE_RULESET, SYS_ADD_RULE, SYS_RESTRICT_SELF = 444, 445, 446
PR_SET_NO_NEW_PRIVS = 38
RULE_PATH_BENEATH = 1
FS_ALL = (1 << 13) - 1
FS_READ = 1 | 1 << 2 | 1 << 3  # run, read files, list folders
SYSTEM_PATHS = ("/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/sys", "/dev")
_libc = ctypes.CDLL(None, use_errno=True)
POLL_S = 0.2
AGG = "\x1f"

SINGLE = [
    "frame.number", "frame.time_epoch", "frame.len", "frame.cap_len", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.stream", "tcp.srcport", "tcp.dstport", "tcp.seq", "tcp.seq_raw", "tcp.ack", "tcp.len", "ip.id", "tcp.flags", "tcp.window_size", "tcp.window_size_value",
    "tcp.options.mss_val", "tcp.options.wscale.shift", "tcp.options.sack_perm", "tcp.analysis.initial_rtt",
    "tcp.analysis.ack_rtt", "tcp.analysis.acks_frame", "dns.qry.name", "dns.time", "dns.flags.response", "ip.flags.mf", "icmp.type", "icmp.code",
    "dns.flags.rcode", "icmpv6.type", "icmpv6.code", "_ws.malformed", "tcp.options.sack_le", "tcp.analysis.reused_ports",
    "udp.srcport", "udp.dstport", "quic.connection.number", "quic.version", "quic.header_form",
]
MULTI = [
    "http.request.method", "http.request.uri", "http.request.version", "http.host", "http.response.code",
    "http.response.phrase", "http.response.version", "http.content_length", "http.content_type",
    "http.content_encoding", "http.transfer_encoding", "http.x_forwarded_for", "http.request.line",
    "http.response.line", "tcp.segment", "tls.segment", "tls.record.content_type", "tls.record.opaque_type", "tls.handshake.type",
    "tls.handshake.extensions_server_name", "tls.handshake.extensions.supported_version",
    "http2.type", "http2.streamid", "http2.flags", "http2.length", "http2.header.count",
    "http2.header.name", "http2.header.value", "http.file_data", "tls.handshake.ciphersuite", "tls.handshake.extensions_alpn_str",
    "tls.alert_message.desc", "x509af.utcTime", "quic.stream.stream_id", "http3.frame_type",
    "http2.rst_stream.error", "http2.goaway.error", "http2.window_update.window_size_increment", "http2.settings.id", "http2.settings.initial_window_size",
    "tls.handshake.certificate_length", "x509ce.dNSName", "nstrace.pdevno", "nstrace.l_pdevno", "nstrace.tcpdbg.rtrtt", "nstrace.rtt",
    "proxy.version", "proxy.v1.magic", "proxy.src.ipv4", "proxy.src.ipv6", "proxy.srcport", "proxy.dst.ipv4", "proxy.dst.ipv6", "proxy.dstport",
]
DECODE_AS = re.compile(r"(tcp|udp|sctp)\.port==(\d{1,5}),([a-z0-9][a-z0-9_.-]{0,31})")  # Wireshark's Decode As: a port read as another protocol
PRIVATE_PATH = re.compile(r' ?"?/tmp/pcap-(?:analyzer|upload|export)-[^"\s]*"?')
# Flags that tshark's TCP analysis sets on a packet. Stored as events.
EVENTS = [
    "retransmission", "fast_retransmission", "spurious_retransmission", "out_of_order", "lost_segment", "ack_lost_segment",
    "duplicate_ack", "zero_window", "zero_window_probe", "window_full", "window_update", "keep_alive",
]
FIELDS = SINGLE + MULTI + [f"tcp.analysis.{e}" for e in EVENTS]


class TsharkError(Exception):
    """tshark is missing, too old, or rejected the capture or filter. Its message names our private copy, which means nothing to a reader."""

    def __init__(self, message):
        super().__init__(PRIVATE_PATH.sub("", str(message)))


class Stopped(Exception):
    """The analysis ran past its time limit or someone cancelled it."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason  # "timeout" or "cancelled"


class Limit:
    """Stop one analysis on time or on request. A hung tshark writes nothing, so it has to be killed from outside."""

    def __init__(self, seconds=0):
        self.reason = None
        self.proc = None
        self.timer = None
        self.lock = threading.Lock()
        self.start(seconds)

    def start(self, seconds):
        if seconds:
            self.timer = threading.Timer(seconds, self.stop, ["timeout"])
            self.timer.daemon = True
            self.timer.start()

    def stop(self, reason="cancelled"):
        with self.lock:
            self.reason = self.reason or reason
            self._kill()

    def attach(self, proc):
        with self.lock:
            self.proc = proc
            if self.reason:
                self._kill()

    def _kill(self):
        try:
            if self.proc:
                self.proc.kill()
        except PermissionError:  # Ubuntu's AppArmor profile refuses signals to tshark. It then ends on its next write.
            pass

    def check(self):
        if self.reason:
            raise Stopped(self.reason)

    def close(self):
        if self.timer:
            self.timer.cancel()


@dataclass(frozen=True)
class Filter:
    """Pre-analysis filter. IP and port match both directions, so a connection stays whole."""
    host_a: str | None = None
    host_b: str | None = None
    port: int | None = None
    start: float | None = None
    end: float | None = None
    display: str | None = None
    decode_as: tuple = ()

    def decode_args(self):
        """tshark -d arguments. Each rule is checked, since it goes to tshark as written."""
        args = []
        for rule in self.decode_as:
            m = DECODE_AS.fullmatch(rule.replace(" ", ""))
            if not m or not 0 < int(m.group(2)) < 65536:
                from . import knowledge
                raise TsharkError(knowledge.t("Decode As rule is not valid: {rule}. Write it as tcp.port==8080,http", rule=rule))
            args += ["-d", m.group(0)]
        return args

    def expression(self):
        parts = []
        for host in (self.host_a, self.host_b):
            if host:
                net = ipaddress.ip_network(host, strict=False)
                parts.append(f"{'ip' if net.version == 4 else 'ipv6'}.addr == {net.compressed}")
        if self.port is not None:
            parts.append(f"tcp.port == {int(self.port)}")
        if self.start is not None:
            parts.append(f"frame.time_epoch >= {float(self.start)}")
        if self.end is not None:
            parts.append(f"frame.time_epoch <= {float(self.end)}")
        if self.display:
            parts.append(f"({self.display})")
        return " and ".join(parts) or None


_unknown = {}  # fields each tshark refused: older versions lack some


class UnknownFields(TsharkError):
    """tshark refused the whole run because it does not know some fields. They are left out on the next try."""


def _refused_fields(err, binary):
    """The fields tshark names in "Some fields aren't valid", one per line after a tab."""
    if "Some fields aren't valid" not in err:
        return None
    names = {line.strip() for line in err.split("Some fields aren't valid", 1)[1].splitlines()[1:] if line.startswith("\t") and line.strip()}
    if not names:
        return None
    _unknown.setdefault(binary, set()).update(names)
    return names


def usable(names, binary="tshark"):
    """The names this tshark has not refused before."""
    gone = _unknown.get(binary, set())
    return [n for n in names if n not in gone]


def decode_rules(text):
    """Decode As rules from one line, separated by ; or new lines."""
    return tuple(r.strip() for r in re.split(r"[;\n]", text or "") if r.strip())


def version(binary="tshark"):
    try:
        out = subprocess.run([binary, "--version"], capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        raise TsharkError(f"tshark could not be started: {e}") from e
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", out)
    if not m:
        raise TsharkError("tshark version could not be read")
    found = tuple(int(x) for x in m.groups())
    if found[:2] < MIN_VERSION:
        raise TsharkError(f"tshark {found} is too old, need {MIN_VERSION[0]}.{MIN_VERSION[1]} or newer")
    return ".".join(map(str, found))


def _command(binary, capture, keylog, rsa_key, expr, decode=()):
    # Header reassembly stays off: it takes a body segment with no line end for a partial header and loses later responses.
    # A resend that was the first copy on the wire looks like a retransmission, and without this its HTTP head is not dissected.
    cmd = [binary, "-n", "-r", str(capture), "-o", "http.desegment_body:FALSE", "-o", "http.desegment_headers:FALSE",
           "-o", "tcp.desegment_tcp_streams:TRUE", "-o", "tcp.reassemble_out_of_order:TRUE", "-o", "tls.desegment_ssl_records:TRUE",
           # A PROXY protocol header comes before HTTP or TLS on the same port, so its heuristic has to run before the port's dissector
           "-o", "tcp.try_heuristic_first:TRUE",
           "-T", "fields", "-E", "separator=/t", "-E", "quote=n", "-E", "occurrence=a", "-E", f"aggregator={AGG}"]
    if keylog:
        cmd += ["-o", f"tls.keylog_file:{keylog}"]
    if rsa_key:
        cmd += ["-o", f'uat:rsa_keys:"{rsa_key}",""']
    cmd += list(decode)
    if expr:
        cmd += ["-Y", expr]
    for f in usable(FIELDS, binary):
        cmd += ["-e", f]
    return cmd


# Inside new user, mount and network namespaces, only this run's own folder stays visible.
_ISOLATE = """
mount --bind "$1" /mnt
mount -t tmpfs tmpfs /tmp
mkdir -p "$1"
mount --move /mnt "$1"
if [ -d "$2" ]; then mount -t tmpfs tmpfs "$2"; fi
shift 2
exec "$@"
"""
_can_isolate = None


def can_isolate():
    """True where this kernel lets an unprivileged process make namespaces. Pods and locked-down hosts usually do not."""
    global _can_isolate
    if _can_isolate is None:
        if os.environ.get("PCAP_ANALYZER_SANDBOX") == "0" or not shutil.which("unshare"):
            _can_isolate = False
        else:
            with tempfile.TemporaryDirectory(prefix="pcap-analyzer-", dir="/tmp") as tmp:
                _can_isolate = subprocess.run(isolated(["true"], tmp, "/nonexistent"), capture_output=True).returncode == 0
    return _can_isolate


def isolated(cmd, folder, workdir):
    return ["unshare", "-Urmn", "sh", "-ec", _ISOLATE, "sh", str(folder), str(workdir), *cmd]


def _allow(ruleset, path, access):
    try:
        fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
    except OSError:
        return  # this system has no such folder
    _libc.syscall(SYS_ADD_RULE, ruleset, RULE_PATH_BENEATH, struct.pack("<Qi", access, fd), 0)
    os.close(fd)


def lock_files(read, write):
    """Limit this process and its children to these folders. Kernels without Landlock simply skip this."""
    ruleset = _libc.syscall(SYS_CREATE_RULESET, struct.pack("<Q", FS_ALL), 8, 0)
    if ruleset < 0:
        return False
    for path in read:
        _allow(ruleset, path, FS_READ)
    for path in write:
        _allow(ruleset, path, FS_ALL)
    _libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    done = _libc.syscall(SYS_RESTRICT_SELF, ruleset, 0) == 0
    os.close(ruleset)
    return done


def _limits(seconds, read=(), write=()):
    """Set in the child before tshark starts, so one bad capture cannot take the host down."""
    def apply():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_LIMIT, FILE_LIMIT))
        if seconds:
            resource.setrlimit(resource.RLIMIT_CPU, (seconds, seconds))
        if write:
            lock_files(read, write)
    return apply


def _first_packet(path, reader):
    done = subprocess.run([reader, "-n", "-r", str(path), "-c", "1", "-T", "fields", "-e", "frame.time_epoch"], capture_output=True, text=True)
    if done.returncode != 0:
        raise TsharkError(done.stderr.strip().splitlines()[-1] if done.stderr.strip() else "tshark could not read a part")
    return float(done.stdout.strip() or 0)


def _join_sections(paths, out, reader):
    """Without mergecap: a pcapng file may hold several sections, so parts can follow each other in the order they start."""
    with open(out, "wb") as joined:
        for i, path in enumerate(sorted(paths, key=lambda p: _first_packet(p, reader))):
            section = Path(out).with_suffix(f".{i}")
            done = subprocess.run([reader, "-n", "-r", str(path), "-F", "pcapng", "-w", str(section)], capture_output=True, text=True)
            if done.returncode != 0:
                raise TsharkError(done.stderr.strip().splitlines()[-1] if done.stderr.strip() else "tshark could not read a part")
            joined.write(section.read_bytes())
            section.unlink()


def merge(paths, out, binary="mergecap", reader="tshark"):
    """Join parts of one capture into a single file, in time order."""
    if not shutil.which(binary):
        _join_sections(paths, out, reader)
        return
    try:
        done = subprocess.run([binary, "-w", str(out), *map(str, paths)], capture_output=True, text=True)
    except OSError as e:
        raise TsharkError(f"mergecap could not be started: {e}") from e
    if done.returncode != 0:
        raise TsharkError(done.stderr.strip().splitlines()[-1] if done.stderr.strip() else "mergecap could not join the files")


def _private_copy(src, directory, name):
    dst = Path(directory) / name
    shutil.copyfile(src, dst)
    os.chmod(dst, 0o600)
    return dst


def _decrypting(path, feed):
    """An encrypted capture is fed through a pipe, decrypted as tshark reads it."""
    if feed is None and vault.is_encrypted(path):
        return lambda: vault.chunks(path)
    return feed


def extract_stream(capture, stream, out, binary="tshark", feed=None):
    """Write one TCP connection to a new capture file, keeping it whole so Wireshark can reassemble it.
    With feed, tshark reads one part of the capture from a pipe, and stream is the connection's number in that part."""
    feed = _decrypting(capture, feed)
    with tempfile.TemporaryDirectory(prefix="pcap-analyzer-", dir="/tmp") as tmp:
        os.chmod(tmp, 0o700)
        src = "-" if feed else _private_copy(capture, tmp, "capture")
        dst = Path(tmp) / "out.pcapng"
        with tempfile.TemporaryFile(dir=tmp) as errfile:
            proc = subprocess.Popen([binary, "-n", "-r", str(src), "-Y", f"tcp.stream == {int(stream)}", "-w", str(dst)],
                                    stdin=subprocess.PIPE if feed else subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=errfile)
            pump = threading.Thread(target=_pump, args=(proc, feed), daemon=True) if feed else None
            if pump:
                pump.start()
            code = proc.wait()
            if pump:
                pump.join()
            errfile.seek(0)
            err = errfile.read().decode("utf-8", "replace").strip()
        if code != 0:
            raise TsharkError(err.splitlines()[-1] if err else "tshark could not write the file")
        shutil.copyfile(dst, out)


def _lines(proc, limit):
    """Read tshark's output, looking up regularly so that a stop works even when tshark hangs and cannot be killed."""
    fd, tail = proc.stdout.fileno(), b""
    while True:
        limit.check()
        if not select.select([fd], [], [], POLL_S)[0]:
            continue
        chunk = os.read(fd, 1 << 20)
        if not chunk:
            break
        *lines, tail = (tail + chunk).split(b"\n")
        for line in lines:
            yield line.decode("utf-8", "replace")
    if tail:
        yield tail.decode("utf-8", "replace")


def _pump(proc, feed):
    """Write a capture into tshark. When tshark stops early its exit code says why, so a closed pipe is no error here."""
    try:
        with proc.stdin:
            for chunk in feed():
                proc.stdin.write(chunk)
    except (OSError, ValueError):
        pass


def packets(path, keylog=None, rsa_key=None, flt=None, binary="tshark", warnings=None, limit=None, workdir=None, seconds=0, feed=None):
    """Yield packets as dicts. Non-fatal problems are appended to warnings. With feed, tshark reads the capture that feed() yields from a pipe instead of path.
    A field this tshark does not know is left out and the run starts again; tshark refuses it before it reads any packet."""
    for _ in range(len(FIELDS)):
        try:
            yield from _packets(path, keylog, rsa_key, flt, binary, warnings, limit, workdir, seconds, feed)
            return
        except UnknownFields:
            continue
    raise TsharkError("tshark knows none of the fields it was asked for")


def _packets(path, keylog, rsa_key, flt, binary, warnings, limit, workdir, seconds, feed):
    limit = limit or Limit()
    feed = _decrypting(path, feed)
    expr = flt.expression() if flt else None
    decode = flt.decode_args() if flt else []
    with tempfile.TemporaryDirectory(prefix="pcap-analyzer-", dir="/tmp") as tmp:
        os.chmod(tmp, 0o700)
        capture = "-" if feed else _private_copy(path, tmp, "capture")
        kl = _private_copy(keylog, tmp, "keylog") if keylog else None
        rk = _private_copy(rsa_key, tmp, "rsa.pem") if rsa_key else None
        env = dict(os.environ, LC_ALL="C")
        with tempfile.TemporaryFile(mode="w+", dir=tmp) as errfile:
            try:
                cmd = _command(binary, capture, kl, rk, expr, decode)
                found = os.path.realpath(shutil.which(binary) or binary)
                read, write = (), ()
                if workdir and not found.startswith(("/tmp/", str(workdir))):  # a program kept there would disappear with them
                    if can_isolate():
                        cmd = isolated(cmd, tmp, workdir)
                    else:
                        env["TMPDIR"] = tmp
                        data = os.environ.get("WIRESHARK_DATA_DIR")
                        read, write = (*SYSTEM_PATHS, os.path.dirname(os.path.dirname(found)), *([data] if data else [])), (tmp,)
                proc = subprocess.Popen(cmd, stdin=subprocess.PIPE if feed else subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=errfile, env=env,
                                        preexec_fn=_limits(seconds, read, write))
            except OSError as e:
                raise TsharkError(f"tshark could not be started: {e}") from e
            limit.attach(proc)
            pump = threading.Thread(target=_pump, args=(proc, feed), daemon=True) if feed else None
            if pump:
                pump.start()
            count = 0
            names = usable(FIELDS, binary)
            empty = dict.fromkeys(FIELDS, "")
            with proc.stdout:
                for line in _lines(proc, limit):
                    vals = line.split("\t")
                    count += 1
                    yield {**empty, **dict(zip(names, vals))}
            code = proc.wait()
            if pump:
                pump.join()
            limit.check()
            errfile.seek(0)
            err = errfile.read().strip()
        if code == 0:
            return
        if "cut short" in err and count:
            if warnings is not None:
                warnings.append("capture_truncated")
            return
        if not count and _refused_fields(err, binary):
            raise UnknownFields(err)
        raise TsharkError(err.splitlines()[-1] if err else f"tshark exited with code {code}")


def run(capture, args, binary="tshark", workdir=None, seconds=0, limit=None, feed=None, collect=None, max_lines=None):
    """Yield the output lines of tshark -n -r capture with more arguments, in the same sandbox as packets().
    The arguments may name {out}, a folder in the private directory that tshark may write to, as --export-objects does,
    and collect(folder) runs on it before the directory goes away. max_lines stops tshark after that many lines."""
    limit = limit or Limit()
    feed = _decrypting(capture, feed)
    with tempfile.TemporaryDirectory(prefix="pcap-analyzer-", dir="/tmp") as tmp:
        os.chmod(tmp, 0o700)
        out = Path(tmp) / "out"
        out.mkdir()
        src = "-" if feed else _private_copy(capture, tmp, "capture")
        cmd = [binary, "-n", "-r", str(src), *[a.replace("{out}", str(out)) for a in args]]
        env = dict(os.environ, LC_ALL="C")
        with tempfile.TemporaryFile(mode="w+", dir=tmp) as errfile:
            try:
                found = os.path.realpath(shutil.which(binary) or binary)
                read, write = (), ()
                if workdir and not found.startswith(("/tmp/", str(workdir))):
                    if can_isolate():
                        cmd = isolated(cmd, tmp, workdir)
                    else:
                        env["TMPDIR"] = tmp
                        data = os.environ.get("WIRESHARK_DATA_DIR")
                        read, write = (*SYSTEM_PATHS, os.path.dirname(os.path.dirname(found)), *([data] if data else [])), (tmp,)
                proc = subprocess.Popen(cmd, stdin=subprocess.PIPE if feed else subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=errfile, env=env,
                                        preexec_fn=_limits(seconds, read, write))
            except OSError as e:
                raise TsharkError(f"tshark could not be started: {e}") from e
            limit.attach(proc)
            pump = threading.Thread(target=_pump, args=(proc, feed), daemon=True) if feed else None
            if pump:
                pump.start()
            count, stopped = 0, False
            with proc.stdout:
                for line in _lines(proc, limit):
                    count += 1
                    if max_lines and count > max_lines:
                        stopped = True
                        limit._kill() if limit.proc is proc else proc.kill()
                        break
                    yield line
            code = proc.wait()
            if pump:
                pump.join()
            limit.check()
            errfile.seek(0)
            err = errfile.read().strip()
            if code != 0 and not stopped and not ("cut short" in err and count):
                if not count and _refused_fields(err, binary):
                    raise UnknownFields(err)
                raise TsharkError(err.splitlines()[-1] if err else f"tshark exited with code {code}")
            if collect:
                collect(out)
