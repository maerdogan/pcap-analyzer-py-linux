"""Sign-in: the setup admin and the users an admin made, with sessions held in memory.

The setup admin (PCAP_ANALYZER_ADMIN_USER) signs in first with admin / admin and must choose a new password. Until the data folder is
encrypted that password is kept as a scrypt hash in .admin-password.json. Once it is, the password is what opens the vault, and no
other copy of it is kept. A password given in PCAP_ANALYZER_ADMIN_PASSWORD or PCAP_ANALYZER_ADMIN_PASSWORD_HASH is taken over once
into that file, and is ignored from then on, so it does not have to stay in the server settings.
"""
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
from collections import deque

from .. import vault as vaults

SESSION_S = 12 * 3600
MAX_FAILS = 5
MAX_TOTAL_FAILS = 30  # across all clients, because a client address can be faked
FAIL_WINDOW_S = 300
SCRYPT = dict(n=2 ** 14, r=8, p=1)
DEFAULT_PASSWORD = "admin"  # the first sign-in only: it must be changed before anything else
MIN_PASSWORD = 12
LOG = logging.getLogger("pcap_analyzer.auth")


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


def _weak(user, password):
    return len(password) < MIN_PASSWORD or password.casefold() in (DEFAULT_PASSWORD, user.casefold())


class Auth:
    """users is the store of the other users, and vault the one of the data folder. Without them only the setup admin signs in."""

    def __init__(self, user, password=None, password_hash=None, store=None, vault=None, users=None):
        if password_hash and not valid_hash(password_hash):
            raise ValueError("PCAP_ANALYZER_ADMIN_PASSWORD_HASH is not a valid hash. Create one with: pcap-analyzer hash-password")
        self.user = user
        self.store = store
        self.vault = vault
        self.users = users
        self.sessions = {}  # token: (user name, expiry, setup admin)
        self.form_key = secrets.token_bytes(32)  # sessions live in memory, so this can too
        self.fails = deque()  # (time, client). Blocking stops new entries, so this stays small.
        self.lock = threading.Lock()
        self._adopt(password, password_hash)

    def _encrypted(self):
        return self.vault is not None and self.vault.is_set_up()

    def _adopt(self, password, password_hash):
        """Take over a password from the settings once, or start with admin / admin."""
        saved = self._saved()
        given = password is not None or bool(password_hash)
        if self._encrypted() or saved:
            if given:
                LOG.warning("PCAP_ANALYZER_ADMIN_PASSWORD%s is set but ignored, since the password is kept in the data folder. Remove it from the server settings.",
                            "" if password is not None else "_HASH")
            self.hash = None if self._encrypted() else saved["hash"]
            self.must_change = not self._encrypted() and bool(saved.get("must_change"))
            if self._encrypted() and self.store:
                self.store.unlink(missing_ok=True)
            return
        if password is not None:
            self.hash, self.must_change = hash_password(password), _weak(self.user, password)
        elif password_hash:
            self.hash, self.must_change = password_hash, verify_password(DEFAULT_PASSWORD, password_hash)
        else:
            self.hash, self.must_change = hash_password(DEFAULT_PASSWORD), True
            return
        if self.store:
            self._save(self.hash, self.must_change)
            LOG.warning("PCAP_ANALYZER_ADMIN_PASSWORD%s was saved as a hash in the data folder and is ignored from now on. Remove it from the server settings.",
                        "" if password is not None else "_HASH")

    def blocked(self, client):
        cutoff = time.time() - FAIL_WINDOW_S
        with self.lock:
            while self.fails and self.fails[0][0] < cutoff:
                self.fails.popleft()
            return len(self.fails) >= MAX_TOTAL_FAILS or sum(c == client for _, c in self.fails) >= MAX_FAILS

    def _admin_password_ok(self, password):
        if self._encrypted():
            return self.vault.unlock(password)  # opens the vault after a restart
        return verify_password(password, self.hash)

    def is_admin_name(self, user):
        return hmac.compare_digest(user.encode(), self.user.encode())

    def check(self, user, password):
        """Who signs in with this name and password, or None. Raises vault.Locked when another user tries while the data is locked."""
        from .users import Current
        if self.is_admin_name(user):
            ok = self._admin_password_ok(password)
            return Current(self.user, "admin", True, None, self.must_change) if ok else None
        if self.users is None:
            verify_password(password, hash_password(DEFAULT_PASSWORD))
            return None
        if self.vault is not None and not self.vault.is_unlocked():
            raise vaults.Locked()  # before the setup and after a restart only the setup admin can open the user list
        return self.users.verify(user, password)

    def failed(self, client):
        with self.lock:
            self.fails.append((time.time(), client))

    def login(self, client, user, password):
        """A new session, or None. Raises vault.Locked as check() does."""
        try:
            who = self.check(user, password)
        except vaults.Locked:
            raise
        if who is None:
            self.failed(client)
            return None
        with self.lock:
            self.fails = deque(f for f in self.fails if f[1] != client)
        token = secrets.token_urlsafe(32)
        self.sessions[token] = (who.name, time.time() + SESSION_S, who.setup_admin)
        return token

    def current(self, token):
        """The user of a session, read again on every request so a changed role or a deleted user applies at once."""
        from .users import Current, current
        s = self.sessions.get(token or "")
        if s is None:
            return None
        name, expiry, setup = s
        if expiry < time.time():
            self.sessions.pop(token, None)
            return None
        if setup:
            return Current(self.user, "admin", True, None, self.must_change)
        try:
            u = self.users.get(name) if self.users else None
        except OSError:
            u = None
        if u is None:
            self.sessions.pop(token, None)
            return None
        return current(u)

    def valid(self, token):
        return self.current(token) is not None

    def form_token(self, token):
        """Forms prove with this that they came from a page of this session."""
        return hmac.new(self.form_key, (token or "").encode(), hashlib.sha256).hexdigest()

    def form_token_ok(self, token, sent):
        return hmac.compare_digest(self.form_token(token).encode(), str(sent or "").encode())

    def _saved(self):
        try:
            stored = json.loads(self.store.read_text()) if self.store else None
        except (OSError, ValueError):
            return None
        return stored if isinstance(stored, dict) and valid_hash(str(stored.get("hash", ""))) else None

    def _save(self, stored, must_change=False):
        self.store.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.store.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(dict(hash=stored, changed=time.time(), must_change=must_change), f)
        tmp.replace(self.store)

    def change_password(self, current, new, again):
        """The setup admin's new password. A problem in plain words, or None when it is saved.
        Once the data folder is encrypted, only the admin key is encrypted again with it."""
        if not self._admin_password_ok(current):
            return "The current password is wrong."
        if new != again:
            return "The new passwords do not match."
        if len(new) < MIN_PASSWORD:
            return "The new password must have at least {n} characters."
        if new == current or new.casefold() in (DEFAULT_PASSWORD, self.user.casefold()):
            return "Choose a password other than the current one, admin or the user name."
        if self._encrypted():
            self.vault.change_admin_password(current, new)
            stored = None
        else:
            stored = hash_password(new)
            if self.store:
                self._save(stored)
        with self.lock:
            self.hash = stored
            self.must_change = False
        return None

    def encrypted_now(self):
        """The vault was just set up: the admin password now lives in the admin key only."""
        with self.lock:
            self.hash = None
        if self.store:
            self.store.unlink(missing_ok=True)

    def logout(self, token):
        self.sessions.pop(token or "", None)
