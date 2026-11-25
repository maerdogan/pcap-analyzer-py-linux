"""Write analysis results to one DuckDB file per analysis.

Once the data folder is encrypted, each database uses DuckDB's own encryption (AES-256-GCM, from DuckDB 1.4) with a random key of its
own. The key is kept next to it in db.key, a file encrypted by the vault, so it opens only while the vault is open. A DuckDB too old to
encrypt, such as the one for glibc 2.17, gets the whole file encrypted by the vault instead, and a plain copy in a private temporary
folder while it is read.
"""
import contextlib
import json
import os
import secrets
import shutil
import tempfile
from pathlib import Path

import duckdb

from . import vault

SCHEMA = {
    "tcp_connections": """
        stream INT PRIMARY KEY, client_ip VARCHAR, client_port INT, server_ip VARCHAR, server_port INT, kind VARCHAR,
        first_frame BIGINT, start_time DOUBLE, end_time DOUBLE, duration DOUBLE, packets BIGINT, bytes BIGINT,
        payload_client BIGINT, payload_server BIGINT, handshake_seen BOOLEAN, connect_time DOUBLE, rtt_server DOUBLE,
        rtt_client DOUBLE, capture_point VARCHAR, mss INT, tls_version VARCHAR, sni VARCHAR, tls_time DOUBLE,
        close_type VARCHAR, closed_by VARCHAR, transactions INT, sack BOOLEAN, wscale INT, min_window BIGINT,
        retransmissions INT, zero_windows INT, byte_ratio_db DOUBLE, offload BOOLEAN, rst_code INT, one_way BOOLEAN,
        tls_cipher VARCHAR, tls_alpn VARCHAR, tls_alert VARCHAR, tls_resumed BOOLEAN, tls_no_answer BOOLEAN, tls_cert_expires VARCHAR, tls_unread BOOLEAN,
        syn_seen BOOLEAN, challenge_ack BOOLEAN, tls_chain INT, tls_client_cert_requested BOOLEAN, tls_client_certs INT, tls_client_name VARCHAR,
        proxy_version VARCHAR, proxy_client VARCHAR, proxy_server VARCHAR, ns_pcb BIGINT, ns_linked_pcb BIGINT, ns_rtt_ms INT, ns_peer INT""",
    "http_transactions": """
        id BIGINT PRIMARY KEY, stream INT, h2_stream INT, seq_on_conn INT, new_conn BOOLEAN, method VARCHAR, uri VARCHAR,
        url_template VARCHAR, host VARCHAR, http_version VARCHAR, status INT, phrase VARCHAR, answered BOOLEAN, req_frame BIGINT, resp_frame BIGINT,
        req_start DOUBLE, req_end DOUBLE, resp_start DOUBLE, resp_end DOUBLE, connect_time DOUBLE, tls_time DOUBLE,
        request_send DOUBLE, wait DOUBLE, service DOUBLE, ttfb DOUBLE, transfer DOUBLE, total DOUBLE, req_bytes BIGINT,
        resp_bytes BIGINT, req_content_length BIGINT, resp_content_length BIGINT, content_type VARCHAR,
        content_encoding VARCHAR, transfer_encoding VARCHAR, server_timing VARCHAR, x_forwarded_for VARCHAR, request_id VARCHAR, req_headers VARCHAR, resp_headers VARCHAR,
        req_body VARCHAR, resp_body VARCHAR, retrans_count INT, retrans_time DOUBLE, zero_window_time DOUBLE,
        delayed_ack_time DOUBLE, queue_time DOUBLE, network DOUBLE, transfer_clean DOUBLE, request_clean DOUBLE,
        body_bytes BIGINT, truncated BOOLEAN, server_reported DOUBLE, cause VARCHAR, cause_share DOUBLE, flags VARCHAR,
        max_packet INT, dns_time DOUBLE, grpc_status INT, grpc_message VARCHAR, h2_flow_time DOUBLE, proxy_client VARCHAR,
        original_client VARCHAR, original_client_from VARCHAR, user_agent VARCHAR, health_check BOOLEAN, upstream_time DOUBLE, gateway_time DOUBLE,
        attempt INT, retry_of BIGINT""",
    "tcp_events": "stream INT, frame BIGINT, time DOUBLE, sender VARCHAR, event VARCHAR",
    "dns_queries": "name VARCHAR, duration DOUBLE, frame BIGINT, time DOUBLE",
    "stream_parts": "stream INT, part INT, part_stream INT",
    "packet_issues": "frame BIGINT, time DOUBLE, kind VARCHAR, detail VARCHAR, src VARCHAR, dst VARCHAR",
    "quic_connections": """client VARCHAR, server VARCHAR, start_time DOUBLE, end_time DOUBLE, duration DOUBLE, packets BIGINT, bytes BIGINT,
        version VARCHAR, sni VARCHAR, alpn VARCHAR, handshake DOUBLE, requests INT, http3 BOOLEAN""",  # where a capture read in parts keeps each connection
}


def columns(table):
    return [c.split()[0] for c in SCHEMA[table].split(",") if c.split() and c.split()[0].isidentifier()]


def _load(db, table, rows, folder):
    """Bulk load through JSON lines: fast, and safe for multi-line text. The file sits next to the database, since /tmp may be small."""
    if not rows:
        return
    cols = columns(table)
    with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8", dir=folder) as f:
        for r in rows:
            f.write(json.dumps(dict(zip(cols, r))) + "\n")
        f.flush()
        db.execute(f"COPY {table} ({', '.join(cols)}) FROM '{f.name}' (FORMAT json)")


def _types(table, extra=()):
    """Column types for read_json, from the table's definition."""
    found = {}
    for c in SCHEMA[table].split(","):
        words = c.split()
        if words and words[0].isidentifier():
            found[words[0]] = words[1]
    found.update(extra)
    return "{" + ", ".join(f"'{k}': '{v}'" for k, v in found.items()) + "}"


STAGED = {"tcp_connections": {"part": "INT", "part_stream": "INT"}, "http_transactions": {"n": "BIGINT"}, "tcp_events": {"n": "BIGINT"}}
MEMORY_LIMIT = "768MB"  # tshark has ended by then, so this and the app stay well inside a 2 GiB pod
THREADS = 2  # each reading thread holds its own buffers


class Writer:
    """Results arrive one part of a capture at a time and wait in files next to the database, so memory does not grow with the capture.
    Connection numbers are final only at the end, when connections seen twice through NAT are known."""

    def __init__(self, path):
        self.path = Path(path)
        self.files = {t: self.path.parent / f"stage-{t}.json" for t in STAGED}
        self.out = {t: open(f, "w", encoding="utf-8") for t, f in self.files.items()}
        self.n = 0

    def add(self, conns, txns, events):
        cols = columns("tcp_connections") + list(STAGED["tcp_connections"])
        for c in conns:
            self.out["tcp_connections"].write(json.dumps({k: c.get(k) for k in cols}) + "\n")
        cols = columns("http_transactions")
        for t in txns:
            self.n += 1
            self.out["http_transactions"].write(json.dumps({**{k: t.get(k) for k in cols}, "n": self.n}) + "\n")
        cols = columns("tcp_events")
        for e in events:
            self.n += 1
            self.out["tcp_events"].write(json.dumps({**dict(zip(cols, e)), "n": self.n}) + "\n")

    def _read(self, table):
        return f"read_json('{self.files[table]}', format='newline_delimited', columns={_types(table, STAGED[table])})"

    def close(self, number, dns, attach_dns, packet_issues=(), quic=()):
        """number: each connection that stays, from its number while reading to its final number.
        attach_dns gets the requests that opened a connection and fills in their dns_time."""
        for f in self.out.values():
            f.close()
        folder = self.path.parent
        with duckdb.connect(str(self.path)) as db:
            db.execute(f"SET memory_limit = '{MEMORY_LIMIT}'")
            db.execute(f"SET threads = {THREADS}")
            db.execute(f"SET temp_directory = '{folder / 'duckdb.tmp'}'")
            for table, ddl in SCHEMA.items():
                db.execute(f"CREATE TABLE {table} ({ddl})")
            db.execute("CREATE TEMP TABLE renumber (reading INT, final INT)")
            _load_into(db, "renumber", ["reading", "final"], number.items(), folder)
            opened = [dict(zip(("n", "host", "connect_time", "req_start"), r)) for r in db.execute(
                f"SELECT n, host, connect_time, req_start FROM {self._read('http_transactions')} WHERE connect_time IS NOT NULL").fetchall()]
            attach_dns(opened)
            db.execute("CREATE TEMP TABLE dns_fix (n BIGINT, dns_time DOUBLE)")
            _load_into(db, "dns_fix", ["n", "dns_time"], ((o["n"], o["dns_time"]) for o in opened if o.get("dns_time") is not None), folder)

            cols = columns("tcp_connections")
            pick = ", ".join("m.final" if c == "stream" else f"c.{c}" for c in cols)
            db.execute(f"INSERT INTO tcp_connections SELECT {pick} FROM {self._read('tcp_connections')} c JOIN renumber m ON c.stream = m.reading ORDER BY m.final")
            db.execute(f"""INSERT INTO stream_parts SELECT m.final, c.part, c.part_stream FROM {self._read('tcp_connections')} c
                JOIN renumber m ON c.stream = m.reading WHERE c.part IS NOT NULL ORDER BY m.final""")
            cols = columns("http_transactions")
            pick = ", ".join({"id": "row_number() OVER (ORDER BY t.req_start, m.final, t.n)", "stream": "m.final", "dns_time": "coalesce(f.dns_time, t.dns_time)"}.get(c, f"t.{c}") for c in cols)
            db.execute(f"""INSERT INTO http_transactions SELECT {pick} FROM {self._read('http_transactions')} t JOIN renumber m ON t.stream = m.reading
                LEFT JOIN dns_fix f ON f.n = t.n ORDER BY t.req_start, m.final, t.n""")
            cols = columns("tcp_events")
            pick = ", ".join("m.final" if c == "stream" else f"e.{c}" for c in cols)
            db.execute(f"INSERT INTO tcp_events SELECT {pick} FROM {self._read('tcp_events')} e JOIN renumber m ON e.stream = m.reading ORDER BY e.n")
            _load(db, "dns_queries", dns, folder)
            _load(db, "packet_issues", sorted(packet_issues, key=lambda r: r[0] or 0), folder)
            _load(db, "quic_connections", quic, folder)
        for f in self.files.values():
            f.unlink()
        shutil.rmtree(folder / "duckdb.tmp", ignore_errors=True)


def _load_into(db, table, cols, rows, folder):
    with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8", dir=folder) as f:
        for r in rows:
            f.write(json.dumps(dict(zip(cols, r))) + "\n")
        f.flush()
        if f.tell():
            db.execute(f"COPY {table} FROM '{f.name}' (FORMAT json)")


def set_values(db, table, key, cols, rows, folder):
    """Set some columns of saved rows, found by their key. rows hold the key first, then the values in the order of cols."""
    rows = list(rows)
    if not rows:
        return
    types = dict(c.split()[:2] for c in SCHEMA[table].split(",") if c.split() and c.split()[0].isidentifier())
    names = [key, *cols]
    db.execute(f"CREATE TEMP TABLE fix ({', '.join(f'{n} {types[n]}' for n in names)})")
    _load_into(db, "fix", names, rows, folder)
    db.execute(f"UPDATE {table} SET {', '.join(f'{c} = fix.{c}' for c in cols)} FROM fix WHERE {table}.{key} = fix.{key}")
    db.execute("DROP TABLE fix")


KEY_FILE = "db.key"
NATIVE_ENCRYPTION = tuple(int(x) for x in duckdb.__version__.split(".")[:2]) >= (1, 4)
RAM_FOLDER = Path("/dev/shm")


def _quote(path):
    return "'" + str(path).replace("'", "''") + "'"


def _key(path):
    key_file = Path(path).with_name(KEY_FILE)
    return vault.read_text(key_file).strip() if key_file.exists() else None


def connect(path, write=False):
    """A connection to an analysis database, plain or encrypted, with its tables in the default schema."""
    path = Path(path)
    key = _key(path)
    if key:
        db = duckdb.connect()
        try:
            db.execute(f"ATTACH {_quote(path)} AS analysis (ENCRYPTION_KEY '{key}'{'' if write else ', READ_ONLY'})")
        except duckdb.Error as e:
            db.close()
            v = vault.find(path)
            if v is not None and not isinstance(e, duckdb.IOException):
                v.alert(path, "The database does not open with its key. It was changed by hand.")
            raise vault.Tampered(f"The database does not open ({path.name})") from e
        db.execute("USE analysis")
        return db
    if vault.is_encrypted(path):
        return _Decrypted(path)
    v = vault.find(path)
    if v is not None and v.is_set_up() and not v.may_be_plain(path):
        v.alert(path, vault.NOT_ENCRYPTED)
        raise vault.Tampered(f"{vault.NOT_ENCRYPTED} ({path.name})")
    return duckdb.connect(str(path), read_only=not write)


class _Decrypted:
    """A database the vault encrypted whole, for a DuckDB without encryption: read from a plain copy in a private folder, in memory where the system has one."""

    def __init__(self, path):
        base = RAM_FOLDER if RAM_FOLDER.is_dir() and os.access(RAM_FOLDER, os.W_OK) else None
        self.folder = tempfile.mkdtemp(prefix="pcap-analyzer-db-", dir=base)
        copy = Path(self.folder) / "analysis.duckdb"
        try:
            vault.store_copy(path, copy)
            self.db = duckdb.connect(str(copy), read_only=True)
        except BaseException:
            shutil.rmtree(self.folder, ignore_errors=True)
            raise

    def __getattr__(self, name):
        return getattr(self.db, name)

    def close(self):
        with contextlib.suppress(duckdb.Error):
            self.db.close()
        shutil.rmtree(self.folder, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def __del__(self):
        shutil.rmtree(self.folder, ignore_errors=True)


def seal_database(path):
    """Encrypt a finished plain database where it is: with DuckDB's own encryption and a new random key, or by the vault for an old DuckDB."""
    path = Path(path)
    v = vault.find(path)
    if v is None or not v.is_set_up() or _key(path) or vault.is_encrypted(path):
        return
    if not NATIVE_ENCRYPTION:
        v.encrypt_in_place(path)
        return
    key = secrets.token_hex(32)
    tmp = path.with_name(f"{path.name}.{secrets.token_hex(4)}.tmp")
    try:
        with duckdb.connect() as db:
            db.execute(f"ATTACH {_quote(path)} AS plain (READ_ONLY)")
            db.execute(f"ATTACH {_quote(tmp)} AS sealed (ENCRYPTION_KEY '{key}')")
            db.execute("COPY FROM DATABASE plain TO sealed")
        vault.private600(tmp)
        v.write_bytes(path.with_name(KEY_FILE), key.encode())  # before the swap, so the database never stays without its key
        os.replace(tmp, path)
    finally:
        Path(tmp).unlink(missing_ok=True)
        Path(f"{tmp}.wal").unlink(missing_ok=True)


def check_database(v, path):
    """For the hourly check: a database must be encrypted, and open with its key while the vault is open."""
    path = Path(path)
    if vault.is_encrypted(path):
        if v.is_unlocked():
            v.key_opens(path)  # a key that does not open raises the notice
        return
    key_file = path.with_name(KEY_FILE)
    if not key_file.exists():
        v.alert(path, vault.NOT_ENCRYPTED)
        return
    if not v.is_unlocked():
        return
    try:
        with connect(path):
            pass
    except (duckdb.Error, OSError):
        v.alert(path, "The database does not open with its key. It was changed by hand.")
