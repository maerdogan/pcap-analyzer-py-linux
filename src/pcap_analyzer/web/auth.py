"""One admin account, with sessions held in memory."""
import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from collections import deque

SESSION_S = 12 * 3600
MAX_FAILS = 5
MAX_TOTAL_FAILS = 30  # across all clients, because a client address can be faked
FAIL_WINDOW_S = 300
SCRYPT = dict(n=2 ** 14, r=8, p=1)
DEFAULT_PASSWORD = "admin"  # the first sign-in only: it must be changed before anything else
MIN_PASSWORD = 10


def hash_password(password):
    salt = secrets.token_bytes(16)
    key = hashlib.scrypt(password.encode(), salt=salt, **SCRYPT)
    return f"scrypt${base64.b64encode(salt).decode()}${base64.b64encode(key).decode()}"


def verify_password(password, stored):
    try:
        _, salt, key = stored.split("$")
        got = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), **SCRYPT)
        return hmac.compare_digest(got, base64.b64decode(key))
    except ValueError:
        return False


def valid_hash(stored):
    parts = stored.split("$")
    if len(parts) != 3 or parts[0] != "scrypt":
        return False
    try:
        base64.b64decode(parts[1], validate=True)
        base64.b64decode(parts[2], validate=True)
    except ValueError:
        return False
    return True


class Auth:
    """With no password set, or with the password admin, the first sign-in uses admin and must choose a new password.
    A password chosen in the app is kept in store, a file in the data folder, and wins over the settings from then on."""

    def __init__(self, user, password=None, password_hash=None, store=None):
        if password_hash and not valid_hash(password_hash):
            raise ValueError("PCAP_ANALYZER_ADMIN_PASSWORD_HASH is not a valid hash. Create one with: pcap-analyzer hash-password")
        self.user = user
        self.store = store
        saved = self._saved()
        self.hash = saved or password_hash or hash_password(password or DEFAULT_PASSWORD)
        self.must_change = not saved and verify_password(DEFAULT_PASSWORD, self.hash)
        self.sessions = {}
        self.form_key = secrets.token_bytes(32)  # sessions live in memory, so this can too
        self.fails = deque()  # (time, client). Blocking stops new entries, so this stays small.
        self.lock = threading.Lock()

    def blocked(self, client):
        cutoff = time.time() - FAIL_WINDOW_S
        with self.lock:
            while self.fails and self.fails[0][0] < cutoff:
                self.fails.popleft()
            return len(self.fails) >= MAX_TOTAL_FAILS or sum(c == client for _, c in self.fails) >= MAX_FAILS

    def login(self, client, user, password):
        ok_pw = verify_password(password, self.hash)  # always hash, so timing does not reveal the user name
        if hmac.compare_digest(user.encode(), self.user.encode()) and ok_pw:
            with self.lock:
                self.fails = deque(f for f in self.fails if f[1] != client)
            token = secrets.token_urlsafe(32)
            self.sessions[token] = time.time() + SESSION_S
            return token
        with self.lock:
            self.fails.append((time.time(), client))
        return None

    def valid(self, token):
        expiry = self.sessions.get(token or "")
        if expiry is None:
            return False
        if expiry < time.time():
            del self.sessions[token]
            return False
        return True

    def form_token(self, token):
        """Forms prove with this that they came from a page of this session."""
        return hmac.new(self.form_key, (token or "").encode(), hashlib.sha256).hexdigest()

    def form_token_ok(self, token, sent):
        return hmac.compare_digest(self.form_token(token).encode(), str(sent or "").encode())

    def _saved(self):
        try:
            stored = json.loads(self.store.read_text())["hash"] if self.store else None
        except (OSError, ValueError, KeyError, TypeError):
            return None
        return stored if stored and valid_hash(stored) else None

    def change_password(self, current, new, again):
        """Return a problem in plain words, or None when the new password is saved."""
        if not verify_password(current, self.hash):
            return "The current password is wrong."
        if new != again:
            return "The new passwords do not match."
        if len(new) < MIN_PASSWORD:
            return "The new password must have at least 10 characters."
        if new == current or new.lower() in (DEFAULT_PASSWORD, self.user.lower()):
            return "Choose a password other than the current one, admin or the user name."
        stored = hash_password(new)
        if self.store:
            self.store.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.store.with_suffix(".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(dict(hash=stored, changed=time.time()), f)
            tmp.replace(self.store)
        with self.lock:
            self.hash = stored
            self.must_change = False
        return None

    def logout(self, token):
        self.sessions.pop(token or "", None)
