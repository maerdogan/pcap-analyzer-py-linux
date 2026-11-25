"""Saved inspection filters, kept as one JSON file because there is no shared database. Each filter belongs to the group it was saved in."""
import secrets
import threading

from .. import vault

FIELDS = ("src", "src_port", "dst", "port", "kind", "url", "min_size", "size_of")
_lock = threading.Lock()


def _path(settings):
    return settings.workdir / "saved_filters.json"


def _all(settings):
    return vault.read_json(_path(settings), [])


def load(settings, group=None):
    """The filters of a group. None gives every filter, for admins."""
    return [i for i in _all(settings) if group is None or (i.get("group") or "") == group]


def _write(settings, items):
    settings.workdir.mkdir(parents=True, exist_ok=True)
    vault.write_json(_path(settings), items, indent=2)


def add(settings, name, values, group=""):
    with _lock:
        items = _all(settings)
        items.append(dict(id=secrets.token_hex(6), name=name, group=group or "", **{k: values.get(k) or None for k in FIELDS}))
        _write(settings, items)


def remove(settings, fid, group=None):
    """Remove a filter of the group; None may remove any."""
    with _lock:
        _write(settings, [i for i in _all(settings) if i["id"] != fid or (group is not None and (i.get("group") or "") != group)])
