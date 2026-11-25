import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from pcap_analyzer import knowledge, vault
from pcap_analyzer.config import Settings

ROOT = Path(__file__).resolve().parent.parent
MASTER = "Q7#mZ2!pL9x$Rt4w"
_KEYS = []
_make_key = rsa.generate_private_key


@pytest.fixture(autouse=True)
def quick_keys(monkeypatch):
    """Making RSA keys takes a while; the tests share a few, which changes nothing they check."""
    def key(public_exponent, key_size):
        if len(_KEYS) < 4:
            _KEYS.append(_make_key(public_exponent=public_exponent, key_size=key_size))
            return _KEYS[-1]
        _KEYS.append(_KEYS.pop(0))
        return _KEYS[-1]
    monkeypatch.setattr(vault.rsa, "generate_private_key", key)


def page_token(text):
    return re.search(r'name="csrf_token" value="(\w+)"', text)[1]


def sign_in(c, user="admin", password=None, master=MASTER):
    """Sign in as the web pages do. The first sign-in of the setup admin also sets the master key, which encrypts the data folder."""
    r = c.post("/login", data={"username": user, "password": password})
    assert r.status_code == 303, r.text
    if r.headers["location"] == "/security":
        page = c.get("/security").text
        done = c.post("/security", data=dict(master=master, again=master, password=password, csrf_token=page_token(page)))
        assert done.status_code == 200 and "now encrypted" in done.text, done.text
    c.headers["X-CSRF-Token"] = re.search(r'"X-CSRF-Token": "(\w+)"', c.get("/").text)[1]
    return c


@pytest.fixture(autouse=True)
def english(monkeypatch):
    """Most tests read English text. Tests of other languages set their own."""
    monkeypatch.setenv("PCAP_ANALYZER_LANGUAGE", "en")
    knowledge.set_language(None)


@pytest.fixture(scope="session")
def samples(tmp_path_factory):
    out = tmp_path_factory.mktemp("samples")
    subprocess.run([sys.executable, ROOT / "tools/gen_samples.py", out], check=True, capture_output=True)
    return out


@pytest.fixture(scope="session")
def truth(samples):
    return json.loads((samples / "truth.json").read_text())


@pytest.fixture
def settings(tmp_path):
    return Settings(workdir=tmp_path / "work", max_size_mb=100, ttl_days=7)


@pytest.fixture(scope="session")
def made(tmp_path_factory):
    """Captures written by one of the tools/gen_*.py generators, by name, as the Java edition's tests use them."""
    out = tmp_path_factory.mktemp("made")

    def make(name):
        path = out / f"{name}.pcap"
        if not path.exists():
            subprocess.run([sys.executable, ROOT / f"tools/gen_{name}.py", path], check=True, capture_output=True)
        return path
    return make
