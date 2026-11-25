"""Users, groups and roles besides the setup admin, kept in users.json in the data folder, which the vault encrypts.

viewer: opens and exports captures. analyst: also uploads, deletes own captures, writes notes and saves filters.
admin: also manages users, settings, tokens, the activity log and encryption.
Each user is in one group and sees only the captures uploaded in that group; admins see every group.
A local user's password is a salted scrypt hash. An LDAP user has no password here: the directory checks it.
The setup admin (PCAP_ANALYZER_ADMIN_USER) is not in the file and cannot be changed or deleted here.
"""
import re
import threading
import time
from dataclasses import dataclass

from .. import vault
from . import directory
from .auth import DEFAULT_PASSWORD, hash_password, verify_password

ROLES = ("viewer", "analyst", "admin")
NAME = re.compile(r"[a-z0-9][a-z0-9._-]{1,39}")
MIN_PASSWORD = 12
_DUMMY = hash_password(DEFAULT_PASSWORD)  # an unknown name takes as long as a known one
CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def rank(role):
    return ROLES.index(role) if role in ROLES else -1


@dataclass(frozen=True)
class Current:
    """Who sends a request. group is None for those who see every group: the setup admin and tokens made for every group."""
    name: str
    role: str
    setup_admin: bool = False
    group: str | None = None
    must_change: bool = False
    full_name: str = ""
    source: str = "local"
    token: bool = False

    def can(self, role):
        return rank(self.role) >= rank(role)

    def sees(self, group):
        """Admins see every capture; everyone else only those uploaded in their own group. A capture from before groups has none."""
        return self.role == "admin" or self.group is None or (bool(group) and group == self.group)

    def may_delete(self, meta):
        return self.role == "admin" or (bool(meta.get("uploader")) and meta.get("uploader") == self.name)

    @property
    def upload_group(self):
        return self.group or ""


def clean(text, limit):
    """Free text such as a full name or an employee number: trimmed, without control characters, cut to a safe length."""
    return CONTROL.sub("", (text or "").strip())[:limit]


def password_problem(name, password):
    """The same rules for everyone, the setup admin too. The problem in plain words, or None."""
    if len(password or "") < MIN_PASSWORD:
        return "The new password must have at least {n} characters."
    if password.casefold() in (DEFAULT_PASSWORD, (name or "").casefold()):
        return "Choose a password other than admin or the user name."
    return None


class Users:
    def __init__(self, settings, setup_admin="admin"):
        self.settings = settings
        self.setup_admin = setup_admin
        self.lock = threading.Lock()

    @property
    def path(self):
        return self.settings.workdir / "users.json"

    def _content(self):
        data = vault.read_json(self.path, {})
        return dict(users=list(data.get("users") or []), groups=list(data.get("groups") or []))

    def _write(self, content):
        self.settings.workdir.mkdir(parents=True, exist_ok=True)
        vault.write_json(self.path, content, indent=2)

    # ---- groups

    def group_list(self):
        """The groups an admin made, with how many users each has, by name."""
        c = self._content()
        members = {}
        for u in c["users"]:
            members[u.get("group", "")] = members.get(u.get("group", ""), 0) + 1
        return sorted(({**g, "users": members.get(g["name"], 0)} for g in c["groups"]), key=lambda g: g["name"])

    def groups(self):
        return [g["name"] for g in self.group_list()]

    def group_problem(self, name):
        if not NAME.fullmatch(name):
            return "The group name needs 2 to 40 characters: lowercase letters, digits, dot, dash or underscore."
        if name in self.groups():
            return "This group already exists."
        return None

    def add_group(self, name, description):
        with self.lock:
            c = self._content()
            c["groups"].append(dict(name=name, description=clean(description, 120), created=time.time()))
            self._write(c)

    def update_group(self, name, description):
        with self.lock:
            c = self._content()
            for g in c["groups"]:
                if g["name"] == name:
                    g["description"] = clean(description, 120)
                    self._write(c)
                    return True
            return False

    def delete_group(self, name):
        """'users' while users are still in it, 'missing' for no such group, None once it is deleted."""
        with self.lock:
            c = self._content()
            if any(u.get("group") == name for u in c["users"]):
                return "users"
            kept = [g for g in c["groups"] if g["name"] != name]
            if len(kept) == len(c["groups"]):
                return "missing"
            c["groups"] = kept
            self._write(c)
            return None

    # ---- users

    def list(self):
        """Every user without the password hashes, by name."""
        out = [{k: u.get(k, d) for k, d in (("name", ""), ("full_name", ""), ("employee_id", ""), ("group", ""), ("role", "viewer"),
                                            ("source", "local"), ("must_change", False), ("created", None))} for u in self._content()["users"]]
        return sorted(out, key=lambda u: u["name"])

    def get(self, name):
        return next((u for u in self._content()["users"] if u["name"] == name), None)

    def problem(self, name, group, role, password, new):
        """Checks a new or changed user. The problem in plain words, or None. A password of None is not checked."""
        if role not in ROLES:
            return "Choose a role."
        if group not in self.groups():
            return "Choose one of the groups. An admin adds groups above."
        if new and not NAME.fullmatch(name):
            return "The user name needs 2 to 40 characters: lowercase letters, digits, dot, dash or underscore."
        if new and (name == self.setup_admin.lower() or self.get(name)):
            return "This user name is taken."
        if password is not None:
            return password_problem(name, password)
        return None

    def add(self, name, full_name, employee_id, group, role, password=None, ldap=False):
        """A local user gets the password the admin chose and must change it at the first sign-in."""
        with self.lock:
            c = self._content()
            u = dict(name=name, full_name=clean(full_name, 80), employee_id=clean(employee_id, 30), group=group, role=role,
                     source="ldap" if ldap else "local", created=time.time())
            if not ldap:
                u.update(hash=hash_password(password), must_change=True)
            c["users"].append(u)
            self._write(c)

    def update(self, name, full_name=None, employee_id=None, group=None, role=None, password=None):
        """Change a user; False when there is none. A password an admin sets must be changed at the next sign-in."""
        with self.lock:
            c = self._content()
            for u in c["users"]:
                if u["name"] != name:
                    continue
                if full_name is not None:
                    u["full_name"] = clean(full_name, 80)
                if employee_id is not None:
                    u["employee_id"] = clean(employee_id, 30)
                if group is not None:
                    u["group"] = group
                if role is not None:
                    u["role"] = role
                if password is not None:
                    u.update(hash=hash_password(password), must_change=True)
                self._write(c)
                return True
            return False

    def set_own_password(self, name, password):
        with self.lock:
            c = self._content()
            for u in c["users"]:
                if u["name"] == name:
                    u["hash"] = hash_password(password)
                    u.pop("must_change", None)
            self._write(c)

    def delete(self, name):
        with self.lock:
            c = self._content()
            kept = [u for u in c["users"] if u["name"] != name]
            if len(kept) == len(c["users"]):
                return False
            c["users"] = kept
            self._write(c)
            return True

    def verify(self, name, password):
        """The user whose password matches, or None. Local users are checked against their hash, LDAP users against the directory."""
        u = self.get(name)
        if u is None or u.get("role") not in ROLES:
            verify_password(password, _DUMMY)
            return None
        if u.get("source") == "ldap":
            ok = directory.authenticate(self.settings, name, password)
        else:
            ok = verify_password(password, u.get("hash", ""))
        return current(u) if ok else None


def current(u):
    return Current(u["name"], u["role"], False, u.get("group") or "", bool(u.get("must_change")), u.get("full_name", ""), u.get("source", "local"))
