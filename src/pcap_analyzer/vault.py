"""Everything the app keeps in its data folder is encrypted here: captures, analysis results, notes, users, settings and the activity log.

Each file has its own random 256-bit key and is encrypted with AES-256-GCM in 1 MiB segments, so captures of any size stream
without being held in memory, and a changed, cut or reordered segment is found. The nonce of a segment is a random prefix of the
file and the segment number, and the associated data marks the last segment, so a file cut at a segment boundary is found too.
The file key is wrapped with the data key pair, RSA-2048 with OAEP and SHA-256. Writing needs only its public half, so files can be
written at any time.

The private half of the data key pair is encrypted with the master key, a 16-character secret the admin sets. The master key is in
turn wrapped with a second RSA-2048 key pair, whose private half is encrypted with a key derived from the setup admin's password
(PBKDF2-HMAC-SHA256, 310,000 rounds). So after a restart nothing can be read until the setup admin signs in, and a copy of the folder
cannot be opened elsewhere without that password. A new admin password re-wraps only the admin key, and a new master key re-encrypts
only the data private key, so no file has to be rewritten. The file format is the one of the Java edition's Vault.
"""
import base64
import contextlib
import hashlib
import hmac
import io
import json
import logging
import os
import secrets
import struct
import threading
import time
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ALGORITHM = ("Files: AES-256-GCM in 1 MiB segments, a random key per file. "
             "Analysis databases: DuckDB's own AES-256-GCM encryption, a random key per analysis, kept as an encrypted file. "
             "File and database keys: RSA-2048 OAEP (SHA-256). "
             "Data private key: AES-256-GCM with a key derived from the master key (PBKDF2-HMAC-SHA256, 310,000 rounds). "
             "Master key: RSA-2048 OAEP with the admin key pair, whose private key is AES-256-GCM with a key derived from the setup admin's password (PBKDF2-HMAC-SHA256, 310,000 rounds). "
             "User passwords: scrypt one-way hashes, inside the encrypted users file.")
MAGIC = b"PAV1"
SEGMENT = 1 << 20
TAG = 16
FRAME = 1 + 4  # last flag and length before each segment
RECORD = FRAME + SEGMENT + TAG  # a full segment on disk
ROUNDS = 310_000
KEYRING = ".keyring"
AUDIT = ".idx0"  # the activity log: its name says nothing about it
SEEN = ".seen"  # an empty file whose time says when an analysis was last opened
IN_PROGRESS = ".tmp-"  # folders of uploads and analyses that are still running; they are removed when done
PLAIN = {KEYRING, AUDIT, SEEN}
MAX_ALERTS = 200
CACHE_BYTES = 256 << 10  # small files such as meta.json are kept decrypted in memory, while the vault is open
CACHE_ENTRIES = 512
OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
LOG = logging.getLogger("pcap_analyzer.vault")

NOT_ENCRYPTED = "The file is not encrypted. It was put or changed by hand."


class Locked(OSError):
    def __init__(self):
        super().__init__("The data is locked until the setup admin signs in.")


class Tampered(OSError):
    """A file that was changed, cut, put there by hand, or encrypted by another install."""


def master_problem(key):
    """16 printable characters without spaces, at least one neither a letter nor a digit. The problem in plain words, or None."""
    if key is None or len(key) != 16:
        return "The master key must have exactly 16 characters."
    if any(not 33 <= ord(ch) <= 126 for ch in key):
        return "Use printable characters without spaces in the master key."
    if all(ch.isalnum() for ch in key):
        return "The master key must not be only letters and digits. Add at least one sign such as ! or #."
    return None


def _b64(data):
    return base64.b64encode(data).decode()


def _unb64(text):
    return base64.b64decode(str(text))


def _derive(secret, salt):
    return hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, ROUNDS, 32)


def _seal(plain, secret):
    """AES-256-GCM with a key derived from a secret, as {salt, iv, data} in base64."""
    salt, iv = secrets.token_bytes(16), secrets.token_bytes(12)
    return dict(salt=_b64(salt), iv=_b64(iv), data=_b64(AESGCM(_derive(secret, salt)).encrypt(iv, plain, None)))


def _open(sealed, secret):
    return AESGCM(_derive(secret, _unb64(sealed["salt"]))).decrypt(_unb64(sealed["iv"]), _unb64(sealed["data"]), None)


def _nonce(prefix, index):
    return prefix + struct.pack(">Q", index)


def _aad(index, last):
    return struct.pack(">QB", index, 1 if last else 0)


def private600(path):
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)


class _Writer(io.RawIOBase):
    """Header with the wrapped file key, then segments. The last segment is written on close, even when it is empty."""

    def __init__(self, raw, key, wrapped, prefix):
        super().__init__()
        self.raw, self.aes, self.prefix = raw, AESGCM(key), prefix
        self.buf, self.index = bytearray(), 0
        raw.write(MAGIC + struct.pack(">H", len(wrapped)) + wrapped + prefix)

    def writable(self):
        return True

    def write(self, b):
        self.buf += b
        while len(self.buf) > SEGMENT:
            self._segment(bytes(self.buf[:SEGMENT]), False)
            del self.buf[:SEGMENT]
        return len(b)

    def _segment(self, plain, last):
        ct = self.aes.encrypt(_nonce(self.prefix, self.index), plain, _aad(self.index, last))
        self.raw.write(struct.pack(">BI", 1 if last else 0, len(ct)) + ct)
        self.index += 1

    def close(self):
        if not self.closed:
            try:
                self._segment(bytes(self.buf), True)
                self.buf.clear()
            finally:
                self.raw.close()
        super().close()


class _Reader(io.RawIOBase):
    """Decrypts as it reads, and seeks: a segment is found by its number, since every segment but the last is full."""

    def __init__(self, vault, path, raw, key, start):
        super().__init__()
        self.vault, self.path, self.raw, self.start = vault, path, raw, start
        self.aes = AESGCM(key)
        self.prefix = raw.read(4)
        self.start += 4
        body = raw.seek(0, io.SEEK_END) - self.start
        self.count = max(1, -(-body // RECORD))
        self.size = max(0, body - self.count * (FRAME + TAG))
        self.pos, self.index, self.plain = 0, None, b""

    def readable(self):
        return True

    def seekable(self):
        return True

    def _fail(self, reason):
        self.vault.alert(self.path, reason)
        raise Tampered(f"{reason} ({Path(self.path).name})")

    def _load(self, i):
        if self.index == i:
            return
        self.raw.seek(self.start + i * RECORD)
        head = self.raw.read(FRAME)
        if len(head) < FRAME:
            self._fail("The file ends early. It was cut or changed by hand.")
        last, n = struct.unpack(">BI", head)
        if n < TAG or n > SEGMENT + TAG or last > 1:
            self._fail("A segment has a wrong length. The file was changed by hand.")
        ct = self.raw.read(n)
        if len(ct) < n:
            self._fail("The file ends early. It was cut or changed by hand.")
        try:
            plain = self.aes.decrypt(_nonce(self.prefix, i), ct, _aad(i, last))
        except InvalidTag:
            self._fail("A segment does not verify. The file was changed by hand.")
        if last and self.raw.read(1):
            self._fail("Data follows the end of the file. It was changed by hand.")
        if not last and (i == self.count - 1 or len(plain) != SEGMENT):
            self._fail("The file ends early. It was cut or changed by hand.")
        self.index, self.plain = i, plain

    def readinto(self, b):
        if self.pos >= self.size:
            if self.pos == self.size and self.index != self.count - 1:
                self._load(self.count - 1)  # the end is only known to be the end once the last segment verifies
            return 0
        i, off = divmod(self.pos, SEGMENT)
        self._load(i)
        n = min(len(b), len(self.plain) - off)
        if n <= 0:
            return 0
        b[:n] = self.plain[off:off + n]
        self.pos += n
        return n

    def seek(self, offset, whence=io.SEEK_SET):
        base = {io.SEEK_SET: 0, io.SEEK_CUR: self.pos, io.SEEK_END: self.size}[whence]
        self.pos = max(0, base + offset)
        return self.pos

    def tell(self):
        return self.pos

    def close(self):
        if not self.closed:
            self.raw.close()
        super().close()


class Vault:
    """The keys of one data folder. Before the setup it writes plain files, as the app did before encryption existed."""

    def __init__(self, workdir):
        self.workdir = Path(os.path.realpath(workdir))
        self.lock_ = threading.RLock()
        self._pub = self._priv = self._master = None
        self._check = None
        self._check_salt = secrets.token_bytes(16)
        self._alerts = []
        self._cache = {}

    @property
    def ring_path(self):
        return self.workdir / KEYRING

    def is_set_up(self):
        return self.ring_path.is_file()

    def is_unlocked(self):
        return self._priv is not None

    def master_key(self):
        """The master key, for the admin to see. None while locked."""
        return self._master

    # ---- key management

    def set_up(self, admin_password, master):
        """Create both key pairs, then encrypt every file already in the data folder."""
        problem = master_problem(master)
        if problem:
            raise ValueError(problem)
        with self.lock_:
            if self.is_set_up():
                raise ValueError("The data folder is already encrypted.")
            data = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            admin = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self._write_ring(dict(
                version=1,
                data_public=_b64(_public_der(data.public_key())),
                data_private=_seal(_private_der(data), master),
                admin_public=_b64(_public_der(admin.public_key())),
                admin_private=_seal(_private_der(admin), admin_password),
                master=_b64(admin.public_key().encrypt(master.encode(), OAEP)),
            ))
            self._pub, self._priv, self._master, self._check = data.public_key(), data, master, self._digest(admin_password)
            self._cache.clear()
            self._migrate()
        LOG.info("The data folder is encrypted")

    def unlock(self, admin_password):
        """Open the vault with the setup admin's password. False when the password is wrong."""
        with self.lock_:
            if self.is_unlocked():
                return self.check_admin(admin_password)
            try:
                ring = self._ring()
                admin = serialization.load_der_private_key(_open(ring["admin_private"], admin_password), None)
                master = admin.decrypt(_unb64(ring["master"]), OAEP).decode()
                data = serialization.load_der_private_key(_open(ring["data_private"], master), None)
                pub = serialization.load_der_public_key(_unb64(ring["data_public"]))
            except InvalidTag:
                return False
            except (OSError, ValueError, KeyError, TypeError) as e:
                self.alert(self.ring_path, f"The key file could not be read: {type(e).__name__}")
                return False
            self._pub, self._priv, self._master, self._check = pub, data, master, self._digest(admin_password)
            LOG.info("The data folder was opened by the setup admin")
            return True

    def check_admin(self, admin_password):
        """True when this is the setup admin's password, checked against the admin key without opening anything else."""
        check = self._check
        if check is not None:
            return hmac.compare_digest(check, self._digest(admin_password))
        try:
            _open(self._ring()["admin_private"], admin_password)
            return True
        except (InvalidTag, OSError, ValueError, KeyError, TypeError):
            return False

    def change_admin_password(self, old, new):
        """Only the admin private key is encrypted again."""
        with self.lock_:
            ring = self._ring()
            ring["admin_private"] = _seal(_open(ring["admin_private"], old), new)
            self._write_ring(ring)
            self._check = self._digest(new)

    def change_master(self, new):
        """The data private key is encrypted with the new master key, which is wrapped again for the admin."""
        problem = master_problem(new)
        if problem:
            raise ValueError(problem)
        with self.lock_:
            if not self.is_unlocked():
                raise Locked()
            ring = self._ring()
            admin_pub = serialization.load_der_public_key(_unb64(ring["admin_public"]))
            ring["data_private"] = _seal(_private_der(self._priv), new)
            ring["master"] = _b64(admin_pub.encrypt(new.encode(), OAEP))
            self._write_ring(ring)
            self._master = new

    def lock(self):
        """Forget the keys in memory, as a restart does."""
        with self.lock_:
            self._pub = self._priv = self._master = self._check = None
            self._cache.clear()

    def _digest(self, password):
        return hashlib.sha256(self._check_salt + password.encode()).digest()

    def _ring(self):
        return json.loads(self.ring_path.read_text(encoding="utf-8"))

    def _write_ring(self, ring):
        self.workdir.mkdir(parents=True, exist_ok=True)
        tmp = self.workdir / f"{KEYRING}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(ring, f)
        os.replace(tmp, self.ring_path)

    def _public(self):
        if self._pub is None:
            self._pub = serialization.load_der_public_key(_unb64(self._ring()["data_public"]))
        return self._pub

    # ---- files

    def may_be_plain(self, path):
        """Files that are plain on purpose: the key file, the activity log (each line is encrypted), markers, and the work of a running upload or analysis."""
        p = Path(os.path.realpath(path))
        try:
            parts = p.relative_to(self.workdir).parts
        except ValueError:
            return True  # not in this data folder
        return p.name in PLAIN or p.name.endswith(".tmp") or any(part.startswith(IN_PROGRESS) for part in parts[:-1])

    def writer(self, path):
        """A new file, encrypted once the vault is set up. Use create() to replace a file only when writing succeeded."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        raw = os.fdopen(fd, "wb")
        if not self.is_set_up():
            return raw
        try:
            key = AESGCM.generate_key(bit_length=256)
            return io.BufferedWriter(_Writer(raw, key, self._public().encrypt(key, OAEP), secrets.token_bytes(4)), 1 << 16)
        except BaseException:
            raw.close()
            raise

    @contextlib.contextmanager
    def create(self, path):
        """Write a file whole or not at all: to a temporary name first, which replaces the file at the end."""
        path = Path(path)
        tmp = path.with_name(f"{path.name}.{secrets.token_hex(4)}.tmp")
        try:
            with self.writer(tmp) as out:
                yield out
            os.replace(tmp, path)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        self._cache.pop(str(path), None)

    def reader(self, path):
        """A file, decrypted as it is read. A plain file is read as it is before the setup; afterwards it is a changed file."""
        raw = open(path, "rb")
        try:
            head = raw.read(6)
            if head[:4] != MAGIC:
                raw.seek(0)
                if self.is_set_up() and not self.may_be_plain(path):
                    raise self._tampered(path, NOT_ENCRYPTED)
                return raw
            if not self.is_unlocked():
                raise Locked()
            wrapped = raw.read(struct.unpack(">H", head[4:6])[0])
            key = self._unwrap(path, wrapped)
            return io.BufferedReader(_Reader(self, path, raw, key, raw.tell()), 1 << 16)
        except BaseException:
            raw.close()
            raise

    def _unwrap(self, path, wrapped):
        try:
            return self._priv.decrypt(wrapped, OAEP)
        except ValueError:
            raise self._tampered(path, "The file key does not open. The file was changed by hand or comes from another install.") from None

    def _tampered(self, path, reason):
        self.alert(path, reason)
        return Tampered(f"{reason} ({Path(path).name})")

    def read_bytes(self, path):
        path = Path(path)
        st = path.stat()
        small = st.st_size <= CACHE_BYTES
        if small:
            hit = self._cache.get(str(path))
            if hit and hit[0] == (st.st_mtime_ns, st.st_size):
                return hit[1]
        with self.reader(path) as f:
            data = f.read()
        if small and self.is_unlocked():
            if len(self._cache) >= CACHE_ENTRIES:
                self._cache.clear()
            self._cache[str(path)] = ((st.st_mtime_ns, st.st_size), data)
        return data

    def write_bytes(self, path, data):
        with self.create(path) as out:
            out.write(data)

    def encrypt_in_place(self, path):
        """Encrypt a plain file where it is. Nothing to do before the setup, or when it is encrypted already."""
        path = Path(path)
        if not self.is_set_up() or is_encrypted(path):
            return
        with open(path, "rb") as src, self.create(path) as out:
            while chunk := src.read(SEGMENT):
                out.write(chunk)

    def verify(self, path):
        """Read a whole file, so every segment is checked. False, with a notice for the admin, when it does not verify."""
        try:
            with self.reader(path) as f:
                while f.read(SEGMENT):
                    pass
            return True
        except Locked:
            return True
        except (Tampered, OSError):
            return False

    def key_opens(self, path):
        """True when the file key of an encrypted file opens: the file comes from this install. Reads only the header."""
        try:
            with open(path, "rb") as raw:
                head = raw.read(6)
                self._unwrap(path, raw.read(struct.unpack(">H", head[4:6])[0]))
            return True
        except Tampered:
            return False
        except (OSError, struct.error):
            return False

    # ---- small records, such as one line of the activity log

    def seal_bytes(self, plain):
        buf = io.BytesIO()
        buf.close = lambda: None  # the writer closes what it writes to
        key = AESGCM.generate_key(bit_length=256)
        w = _Writer(buf, key, self._public().encrypt(key, OAEP), secrets.token_bytes(4))
        w.write(plain)
        w.close()
        return buf.getvalue()

    def open_bytes(self, blob, path):
        if not self.is_unlocked():
            raise Locked()
        if blob[:4] != MAGIC:
            raise self._tampered(path, "A record is not encrypted. The file was changed by hand.")
        n = struct.unpack(">H", blob[4:6])[0]
        key = self._unwrap(path, blob[6:6 + n])
        with _Reader(self, path, io.BytesIO(blob[6 + n:]), key, 0) as r:
            return r.read()

    # ---- notices for the admin

    def alert(self, path, reason):
        try:
            name = str(Path(os.path.realpath(path)).relative_to(self.workdir))
        except ValueError:
            name = Path(path).name
        with self.lock_:
            if any(a["file"] == name and a["reason"] == reason for a in self._alerts):
                return
            self._alerts.append(dict(time=time.time(), file=name, reason=reason))
            del self._alerts[:-MAX_ALERTS]
        LOG.warning("File integrity: %s: %s", name, reason)
        from . import records  # records writes through the vault
        records.audit_to(self.workdir, "file_tampered", "server", f"{name}: {reason}")

    def alerts(self):
        with self.lock_:
            return list(self._alerts)

    def clear_alerts(self):
        with self.lock_:
            self._alerts.clear()

    # ---- the first setup

    def _migrate(self):
        """Encrypt the lines of the activity log and every plain file in the data folder, and forget the plain admin password file."""
        from . import store  # analysis databases use DuckDB's own encryption
        self._hide_audit()
        for path in sorted(self.workdir.rglob("*")):
            if not path.is_file() or self.may_be_plain(path) or path.name == ".admin-password.json":
                continue
            if path.suffix == ".duckdb":
                store.seal_database(path)
            elif path.name != store.KEY_FILE or not is_encrypted(path):
                self.encrypt_in_place(path)
        (self.workdir / ".admin-password.json").unlink(missing_ok=True)

    def _hide_audit(self):
        lines = []
        for name in ("audit.log", AUDIT):
            with contextlib.suppress(OSError):
                lines += (self.workdir / name).read_text(encoding="utf-8").splitlines()
        out = [_b64(self.seal_bytes(line.encode())) if line.startswith("{") else line for line in lines if line.strip()]
        tmp = self.workdir / f"{AUDIT}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("".join(line + "\n" for line in out))
        os.replace(tmp, self.workdir / AUDIT)
        (self.workdir / "audit.log").unlink(missing_ok=True)

    # ---- the hourly check

    def scan(self, verify=True):
        """Look for files put or changed by hand: anything plain in the data folder, files whose key does not open, and records that do not verify."""
        if not self.is_set_up():
            return
        from . import store
        for path in self.workdir.rglob("*"):
            try:
                if not path.is_file() or self.may_be_plain(path):
                    continue
                if path.suffix == ".duckdb":
                    store.check_database(self, path)
                elif path.stat().st_size == 0 or not is_encrypted(path):
                    self.alert(path, NOT_ENCRYPTED)
                elif self.is_unlocked() and not self.key_opens(path):
                    continue  # key_opens raised the notice
                elif verify and self.is_unlocked() and path.suffix in (".json", ".key"):
                    self.verify(path)
            except OSError:
                continue  # removed while looking


def _public_der(key):
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _private_der(key):
    return key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


# ---- one vault per data folder, found from any path inside it

_vaults = {}
_registry_lock = threading.Lock()


def of(workdir):
    key = os.path.realpath(workdir)
    with _registry_lock:
        v = _vaults.get(key)
        if v is None:
            v = _vaults[key] = Vault(key)
        return v


def find(path):
    """The vault of the data folder that holds path, or None for a file outside every data folder, such as a capture given on the command line."""
    p = Path(os.path.realpath(path))
    for d in p.parents:
        v = _vaults.get(str(d))
        if v is not None:
            return v
    for d in p.parents:
        if (d / KEYRING).is_file():
            return of(d)
    return None


def is_encrypted(path):
    try:
        with open(path, "rb") as f:
            return f.read(4) == MAGIC
    except OSError:
        return False


def open_read(path):
    """A file of any data folder, decrypted as it is read, or a plain file from outside."""
    v = find(path)
    return v.reader(path) if v else open(path, "rb")


def size(path):
    """The plain size of a file."""
    if not is_encrypted(path):
        return Path(path).stat().st_size
    with open_read(path) as f:
        return f.seek(0, io.SEEK_END)


def chunks(path, n=SEGMENT):
    with open_read(path) as f:
        while chunk := f.read(n):
            yield chunk


def read_bytes(path):
    v = find(path)
    return v.read_bytes(path) if v else Path(path).read_bytes()


def read_text(path):
    return read_bytes(path).decode("utf-8")


def read_json(path, default=None):
    """A JSON file through the vault; default when it is missing or cannot be read."""
    try:
        return json.loads(read_bytes(path))
    except (OSError, ValueError):
        return default


def write_bytes(path, data):
    v = find(path)
    if v is None:
        v = Vault(Path(path).parent)  # outside every data folder: plain, written whole
    v.write_bytes(path, data)


def write_text(path, text):
    write_bytes(path, text.encode("utf-8"))


def write_json(path, data, indent=None):
    write_text(path, json.dumps(data, indent=indent))


def store_copy(src, dst):
    """Copy a file into a data folder, decrypting what is encrypted and encrypting it for the place it goes to."""
    v = find(dst) or Vault(Path(dst).parent)
    with open_read(src) as f, v.create(dst) as out:
        while chunk := f.read(SEGMENT):
            out.write(chunk)
