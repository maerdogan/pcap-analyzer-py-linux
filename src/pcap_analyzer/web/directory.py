"""Sign-in against an LDAP directory, such as Active Directory.

The admin sets the server, a service account that may search, the base DN and the filter that finds a user by name. A user marked
as LDAP in the app keeps no password here: the app finds the user's DN with the service account, then binds as that DN with the
password given. The group and role still come from the app. The settings, the service account's password too, are kept encrypted.
"""
import os
import re
import ssl

from .. import vault

FIELDS = ("url", "bind_dn", "bind_password", "base_dn", "user_filter")
DEFAULTS = dict(url="", bind_dn="", bind_password="", base_dn="", user_filter="(uid={0})")
URL = re.compile(r"ldaps?://[A-Za-z0-9.\-\[\]:]+(:\d{1,5})?/?")
TIMEOUT_S = 5
CA_FILE_ENV = "PCAP_ANALYZER_LDAP_CA_FILE"  # a private CA for ldaps; without it the system's trusted certificates are used


def _path(settings):
    return settings.workdir / "ldap.json"


def load(settings):
    return {**DEFAULTS, **vault.read_json(_path(settings), {})}


def configured(settings):
    s = load(settings)
    return bool(s["url"].strip() and s["base_dn"].strip())


def problem(values):
    """The problem with new settings in plain words, or None."""
    url = values.get("url", "")
    if url and not URL.fullmatch(url):
        return "The LDAP address must look like ldaps://dc.example.com:636 or ldap://dc.example.com:389."
    if "{0}" not in values.get("user_filter", ""):
        return "The user filter must contain {0}, where the user name goes, such as (sAMAccountName={0})."
    return None


def save(settings, values):
    """An empty service account password keeps the saved one."""
    old = load(settings)
    out = {f: str(values.get(f) or "").strip()[:400] for f in FIELDS}
    if not out["bind_password"]:
        out["bind_password"] = old.get("bind_password", "")
    settings.workdir.mkdir(parents=True, exist_ok=True)
    vault.write_json(_path(settings), out)


def escape(value):
    """RFC 4515: characters that would change a filter are escaped, so a user name cannot widen the search."""
    return "".join({"\\": r"\5c", "*": r"\2a", "(": r"\28", ")": r"\29", "\0": r"\00"}.get(ch, ch) for ch in value)


def _server(url):
    import ldap3  # loaded only where LDAP is used
    tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLS_CLIENT, ca_certs_file=os.environ.get(CA_FILE_ENV) or None)
    return ldap3.Server(url, connect_timeout=TIMEOUT_S, get_info=ldap3.NONE, tls=tls)


def _bind(s, dn, password):
    """A bound connection, or None when the directory refuses the name and password."""
    import ldap3
    conn = ldap3.Connection(_server(s["url"]), user=dn, password=password, authentication=ldap3.SIMPLE, receive_timeout=TIMEOUT_S,
                            raise_exceptions=False, read_only=True, auto_referrals=False)
    if not conn.bind():
        conn.unbind()
        return None
    return conn


def find(s, name):
    """The DN of a user, found with the service account; None when no single user matches. Raises when the service account cannot sign in."""
    conn = _bind(s, s["bind_dn"], s["bind_password"])
    if conn is None:
        raise ConnectionError("the service account could not sign in")
    try:
        conn.search(s["base_dn"], s["user_filter"].replace("{0}", escape(name)), attributes=[], size_limit=2)
        entries = [e for e in conn.response or () if e.get("type") == "searchResEntry"]
        return entries[0]["dn"] if len(entries) == 1 else None
    finally:
        conn.unbind()


def authenticate(settings, name, password):
    """True when the directory accepts this name and password. An empty password is refused, since many servers take it as an anonymous bind."""
    if not password or not configured(settings):
        return False
    s = load(settings)
    try:
        dn = find(s, name)
        if dn is None:
            return False
        conn = _bind(s, dn, password)
        if conn is None:
            return False
        conn.unbind()
        return True
    except Exception:  # noqa: BLE001 - a directory that cannot be reached refuses the sign-in
        return False


def test(settings, name=""):
    """Check the settings with the service account, and find a user when a name is given. A line for the admin, and whether it worked."""
    if not configured(settings):
        return "LDAP is not set up.", False
    s = load(settings)
    try:
        if not name.strip():
            conn = _bind(s, s["bind_dn"], s["bind_password"])
            if conn is None:
                return "Failed: the service account could not sign in.", False
            conn.unbind()
            return "OK: the service account signed in.", True
        dn = find(s, name.strip())
        if dn is None:
            return f"The service account signed in, but no single user matches {name.strip()}.", False
        return f"OK: {name.strip()} is {dn}", True
    except Exception as e:  # noqa: BLE001 - the admin sees why
        return f"Failed: {e}", False
