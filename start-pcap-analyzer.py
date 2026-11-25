#!/usr/bin/env python3
"""Start pcap-analyzer on a Linux server, with no internet, no sudo and nothing to install.

    python3 start-pcap-analyzer.py            prepare everything and start the app in the background
    python3 start-pcap-analyzer.py stop       stop it
    python3 start-pcap-analyzer.py restart    stop it and start it again, reading the settings again
    python3 start-pcap-analyzer.py status     show whether it runs
    python3 start-pcap-analyzer.py logs       show the last 50 log lines
    python3 start-pcap-analyzer.py run        run it in this terminal until Ctrl-C
    python3 start-pcap-analyzer.py cli ...    run any pcap-analyzer command, such as: cli analyze capture.pcap

Python, its packages and tshark come from bundle/ in this folder and are unpacked to runtime/ on the first start.
Settings are in pcap-analyzer.env, written on the first start. The first sign-in is admin / admin, and the app
then asks for a new password. Results are kept in data/.

This file runs with Python 3.6 or newer, so the system Python of an older server is enough.
"""
import hashlib
import os
import platform
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tarfile
import time
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "src")
BUNDLE = os.path.join(HERE, "bundle")
RUNTIME = os.path.join(HERE, "runtime")
DATA = os.path.join(HERE, "data")
SETTINGS = os.path.join(HERE, "pcap-analyzer.env")
PIDFILE = os.path.join(HERE, "pcap-analyzer.pid")
LOG = os.path.join(HERE, "pcap-analyzer.log")
PYTHON = os.path.join(RUNTIME, "python", "bin", "python3")
PARTS = "runtime-linux-x86_64.tar.gz.part-"
MIN_GLIBC = (2, 17)
NEW_DUCKDB_GLIBC = (2, 26)  # the bundled DuckDB needs this; older systems get the wheel in bundle/
START_S = 60

SETTINGS_TEMPLATE = """# pcap-analyzer settings. Run "python3 start-pcap-analyzer.py restart" after a change.
# The first sign-in is admin / admin, and the app asks for a new password and the master key before anything else.
PCAP_ANALYZER_ADMIN_USER=admin

# 127.0.0.1 reaches only this host. Use 0.0.0.0 to reach it from other machines, with a certificate or an HTTPS proxy.
PCAP_ANALYZER_HOST=127.0.0.1
PCAP_ANALYZER_PORT=8000
# Paths of a certificate and its key, to serve HTTPS.
PCAP_ANALYZER_CERT=
PCAP_ANALYZER_KEY=

# Set to 1 when an HTTPS proxy is in front of the port.
PCAP_ANALYZER_BEHIND_PROXY=0
# Proxy addresses or networks whose forwarded headers are believed.
# PCAP_ANALYZER_TRUSTED_PROXIES=10.0.0.5

PCAP_ANALYZER_MAX_SIZE_MB=1000
PCAP_ANALYZER_TTL_DAYS=7
PCAP_ANALYZER_MAX_JOBS=2
PCAP_ANALYZER_KEEP_CAPTURE=1
PCAP_ANALYZER_ANALYSIS_TIMEOUT_S=600
# Default language: tr, en, de or es. Each user can choose another in the app.
PCAP_ANALYZER_LANGUAGE=tr
"""


class Stop(Exception):
    """A problem the user can fix. It is printed without a traceback."""


def say(text):
    print(text, flush=True)


# --- The host ---

def check_host():
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "AMD64"):
        raise Stop("pcap-analyzer runs on Linux x86_64 only, this host is {} {}".format(platform.system(), platform.machine()))
    glibc = glibc_version()
    if glibc < MIN_GLIBC:
        raise Stop("pcap-analyzer needs glibc {}.{} or newer, this host has {}.{}".format(*(MIN_GLIBC + glibc)))
    if not os.path.isfile(os.path.join(SRC, "pcap_analyzer", "cli.py")):
        raise Stop("src/ is missing. Keep start-pcap-analyzer.py in the folder it came with")
    return glibc


def glibc_version():
    try:
        text = os.confstr("CS_GNU_LIBC_VERSION")  # such as "glibc 2.17"
        return tuple(int(x) for x in text.split()[1].split(".")[:2])
    except (ValueError, OSError, IndexError, AttributeError):
        raise Stop("this host has no GNU C library (glibc). Alpine and other musl systems are not supported")


# --- The runtime: Python, its packages and tshark ---

def bundle_parts():
    names = sorted(n for n in os.listdir(BUNDLE) if n.startswith(PARTS)) if os.path.isdir(BUNDLE) else []
    if not names:
        raise Stop("bundle/ is empty. Download the whole repository, or build the bundle with tools/build-bundle.sh")
    return [os.path.join(BUNDLE, n) for n in names]


def expected_sums():
    sums = {}
    with open(os.path.join(BUNDLE, "runtime.sha256")) as f:
        for line in f:
            if line.strip():
                digest, name = line.split()
                sums[name.lstrip("*")] = digest
    return sums


class Joined:
    """The bundle parts read as one file, for tarfile."""

    def __init__(self, paths):
        self.paths, self.index, self.current = list(paths), 0, None

    def read(self, size=-1):
        out = b""
        while size < 0 or len(out) < size:
            if self.current is None:
                if self.index >= len(self.paths):
                    break
                self.current = open(self.paths[self.index], "rb")
                self.index += 1
            chunk = self.current.read(-1 if size < 0 else size - len(out))
            if not chunk:
                self.current.close()
                self.current = None
                continue
            out += chunk
        return out


def unpack():
    """Unpack bundle/ to runtime/ once. A runtime from another bundle is replaced."""
    parts = bundle_parts()
    with open(os.path.join(BUNDLE, "runtime.sha256"), "rb") as f:
        stamp = hashlib.sha256(f.read()).hexdigest()
    marker = os.path.join(RUNTIME, ".bundle")
    if os.path.isfile(marker) and open(marker).read().strip() == stamp and os.path.isfile(PYTHON):
        return
    say("Checking the bundle...")
    sums = expected_sums()
    for path in parts:
        digest = hashlib.sha256()
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(1 << 20), b""):
                digest.update(block)
        if sums.get(os.path.basename(path)) != digest.hexdigest():
            raise Stop("{} is damaged. Download the repository again".format(os.path.relpath(path, HERE)))
    say("Unpacking Python, its packages and tshark to runtime/ (once, about a minute)...")
    shutil.rmtree(RUNTIME, ignore_errors=True)
    staging = RUNTIME + ".partial"
    shutil.rmtree(staging, ignore_errors=True)
    os.makedirs(staging)
    with tarfile.open(fileobj=Joined(parts), mode="r|gz") as tar:
        for member in tar:
            target = os.path.realpath(os.path.join(staging, member.name))
            if not target.startswith(os.path.realpath(staging) + os.sep):
                raise Stop("the bundle holds an unsafe path: {}".format(member.name))
            tar.extract(member, staging)
    os.rename(os.path.join(staging, "runtime"), RUNTIME)
    os.rmdir(staging)
    with open(marker, "w") as f:
        f.write(stamp + "\n")


def use_older_duckdb(glibc):
    """The bundled DuckDB needs glibc 2.26. On an older host, such as CentOS 7, the last DuckDB that runs there replaces it."""
    if glibc >= NEW_DUCKDB_GLIBC:
        return
    marker = os.path.join(RUNTIME, ".older-duckdb")
    if os.path.isfile(marker):
        return
    wheels = [n for n in os.listdir(BUNDLE) if n.startswith("duckdb-") and n.endswith(".whl")]
    if not wheels:
        raise Stop("this host has glibc {}.{}, which needs the older DuckDB wheel in bundle/".format(*glibc))
    site = subprocess.check_output([PYTHON, "-c", "import site; print(site.getsitepackages()[0])"]).decode().strip()
    for name in os.listdir(site):
        if name == "duckdb" or name.startswith(("_duckdb", "duckdb-")):
            path = os.path.join(site, name)
            shutil.rmtree(path) if os.path.isdir(path) else os.remove(path)
    with zipfile.ZipFile(os.path.join(BUNDLE, sorted(wheels)[-1])) as z:
        z.extractall(site)
    open(marker, "w").close()


# --- Settings and environment ---

def settings():
    if not os.path.isfile(SETTINGS):
        with open(SETTINGS, "w") as f:
            f.write(SETTINGS_TEMPLATE)
        os.chmod(SETTINGS, 0o600)
        say("Wrote the settings to pcap-analyzer.env.")
    values = {}
    with open(SETTINGS) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip().strip("'\"")
    return values


def environment(values):
    env = dict(os.environ)
    env.update({k: v for k, v in values.items() if v != ""})
    env["PATH"] = os.pathsep.join([os.path.join(RUNTIME, "tshark", "bin"), os.path.join(RUNTIME, "python", "bin"), env.get("PATH", "/usr/bin:/bin")])
    env["WIRESHARK_DATA_DIR"] = os.path.join(RUNTIME, "tshark", "share", "wireshark")
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONPATH"] = SRC
    env.setdefault("PCAP_ANALYZER_WORKDIR", DATA)
    return env


def prepare():
    glibc = check_host()
    os.umask(0o077)
    unpack()
    use_older_duckdb(glibc)
    values = settings()
    env = environment(values)
    os.makedirs(env["PCAP_ANALYZER_WORKDIR"], exist_ok=True)
    return values, env


def address(values):
    host = values.get("PCAP_ANALYZER_HOST") or "127.0.0.1"
    port = int(values.get("PCAP_ANALYZER_PORT") or 8000)
    tls = bool(values.get("PCAP_ANALYZER_CERT"))
    return host, port, tls


def serve_args(values):
    host, port, tls = address(values)
    args = [PYTHON, "-m", "pcap_analyzer.cli", "serve", "--host", host, "--port", str(port)]
    if tls:
        args += ["--cert", values["PCAP_ANALYZER_CERT"], "--key", values.get("PCAP_ANALYZER_KEY", "")]
    return args


def url(values, for_check=False):
    host, port, tls = address(values)
    if for_check or host in ("0.0.0.0", "::"):
        host = "127.0.0.1" if for_check or host == "0.0.0.0" else host
    return "{}://{}:{}".format("https" if tls else "http", host, port)


# --- The process ---

def running_pid():
    try:
        pid = int(open(PIDFILE).read().strip())
        with open("/proc/{}/cmdline".format(pid), "rb") as f:
            if b"pcap_analyzer.cli" in f.read():
                return pid
    except (OSError, ValueError):
        pass
    return None


def port_busy(values):
    host, port, _ = address(values)
    with socket.socket() as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1" if host == "0.0.0.0" else host, port)) == 0


def healthy(values):
    """Asks the server this script just started, on 127.0.0.1, whether it answers. Its own certificate may be
    self-signed or made for another name, and nothing is sent, so this one local check does not verify it."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        urllib.request.urlopen(url(values, True) + "/healthz", timeout=2, context=context)
        return True
    except OSError:
        return False


def start():
    values, env = prepare()
    pid = running_pid()
    if pid:
        say("Already running with PID {}: {}".format(pid, url(values)))
        return
    if port_busy(values):
        raise Stop("port {} is already in use. Stop that program or change PCAP_ANALYZER_PORT in pcap-analyzer.env".format(address(values)[1]))
    with open(LOG, "ab") as log:
        proc = subprocess.Popen(serve_args(values), cwd=HERE, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=True)
    with open(PIDFILE, "w") as f:
        f.write(str(proc.pid))
    deadline = time.time() + START_S
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        if healthy(values):
            say("pcap-analyzer runs with PID {}.".format(proc.pid))
            say("Open {} and {}".format(url(values), sign_in_hint(values, env)))
            say("Stop it with: python3 start-pcap-analyzer.py stop")
            return
        time.sleep(1)
    stop(quiet=True)
    raise Stop("the server did not start. The last lines of pcap-analyzer.log:\n" + tail(10))


def sign_in_hint(values, env):
    """admin / admin only works until a password is set, in the app or in pcap-analyzer.env."""
    user = values.get("PCAP_ANALYZER_ADMIN_USER") or "admin"
    # the password, once chosen, lives in the data folder: as a hash, then as the key of the encrypted data
    chosen = any(os.path.isfile(os.path.join(env["PCAP_ANALYZER_WORKDIR"], f)) for f in (".admin-password.json", ".keyring"))
    configured = values.get("PCAP_ANALYZER_ADMIN_PASSWORD") not in (None, "", "admin") or values.get("PCAP_ANALYZER_ADMIN_PASSWORD_HASH")
    if chosen or configured:
        return "sign in as {} with your password.".format(user)
    return "sign in as {} / admin. The app then asks for a new password and the master key that encrypts the data.".format(user)


def stop(quiet=False):
    pid = running_pid()
    if not pid:
        if not quiet:
            say("Not running.")
    else:
        try:
            os.kill(pid, signal.SIGTERM)
        except PermissionError:
            raise Stop("this user may not stop PID {}. Stop it as the user that started it".format(pid))
        for _ in range(15):
            if running_pid() != pid:
                break
            time.sleep(1)
        else:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        if not quiet:
            say("Stopped.")
    if os.path.exists(PIDFILE):
        os.remove(PIDFILE)


def status():
    values = settings()
    pid = running_pid()
    say("Running with PID {}: {}".format(pid, url(values)) if pid else "Not running.")
    return 0 if pid else 3


def tail(n=50):
    try:
        with open(LOG, "rb") as f:
            return b"".join(f.readlines()[-n:]).decode("utf-8", "replace")
    except OSError:
        return "(no log yet)\n"


def run_here():
    values, env = prepare()
    if port_busy(values):
        raise Stop("port {} is already in use".format(address(values)[1]))
    say("Open {} and sign in as admin / admin. Ctrl-C stops it.".format(url(values)))
    try:
        return subprocess.call(serve_args(values), cwd=HERE, env=env)
    except KeyboardInterrupt:
        return 0


def cli(args):
    _, env = prepare()
    return subprocess.call([PYTHON, "-m", "pcap_analyzer.cli"] + args, cwd=os.getcwd(), env=env)


def main(argv):
    command = argv[0] if argv else "start"
    try:
        if command == "start":
            start()
        elif command == "stop":
            stop()
        elif command == "restart":
            stop(quiet=True)
            start()
        elif command == "status":
            return status()
        elif command == "logs":
            sys.stdout.write(tail())
        elif command == "run":
            return run_here()
        elif command == "cli":
            return cli(argv[1:])
        elif command in ("-h", "--help", "help"):
            say(__doc__.strip())
        else:
            say(__doc__.strip())
            return 2
    except Stop as e:
        sys.stderr.write("error: {}\n".format(e))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
