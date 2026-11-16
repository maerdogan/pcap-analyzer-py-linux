# Install

Read the [security section](../README.md#security) first. HTTPS, network isolation and encrypted storage are yours to add.

Everything below works without internet on the server.

## Linux server

Copy the repository to the server, by `git clone` or as a ZIP from another machine, and start it from its folder:

```bash
cd pcap-analyzer-py-linux
python3 start-pcap-analyzer.py
```

It needs Linux x86_64 with glibc 2.17 or newer and any `python3` from 3.6 on. It needs no internet, sudo, Docker, systemd or `tar`. The first start:

1. checks `bundle/` against `bundle/runtime.sha256` and unpacks Python, its packages and tshark to `runtime/`, once,
2. puts in the older DuckDB from `bundle/` on glibc older than 2.26, such as CentOS 7,
3. writes `pcap-analyzer.env` with the settings below,
4. starts the app in the background, writes its log to `pcap-analyzer.log` and results to `data/`.

The first sign-in is `admin` / `admin`, and the app asks for a new password. It keeps that password in `data/`.

| Command | Does |
|---|---|
| `python3 start-pcap-analyzer.py` | Prepares everything and starts the app in the background |
| `python3 start-pcap-analyzer.py stop` | Stops it |
| `python3 start-pcap-analyzer.py restart` | Restarts it and reads `pcap-analyzer.env` again |
| `python3 start-pcap-analyzer.py status` | Shows whether it runs |
| `python3 start-pcap-analyzer.py logs` | Shows the last 50 log lines |
| `python3 start-pcap-analyzer.py run` | Runs it in this terminal until Ctrl-C |
| `python3 start-pcap-analyzer.py cli ARGS` | Runs any `pcap-analyzer` command, such as `cli analyze capture.pcap` |

### Reach it from other machines

Set `PCAP_ANALYZER_HOST=0.0.0.0` in `pcap-analyzer.env`, and give it a certificate with `PCAP_ANALYZER_CERT` and `PCAP_ANALYZER_KEY`, or put an HTTPS proxy in front and set `PCAP_ANALYZER_BEHIND_PROXY=1`. Then run `python3 start-pcap-analyzer.py restart`. Limit the port to your team's network with a firewall.

The app does not start again after a reboot by itself. Run `python3 start-pcap-analyzer.py` again, or add it to your user's crontab with `@reboot`.

### Update

Replace the folder with the new version and keep `pcap-analyzer.env` and `data/`. The bundle is unpacked again only when it changed.

## Check an install

`tools/smoke.py` signs in, uploads a capture, opens every page, downloads each export, deletes the analysis and signs out. It stops at the first failure. Run it with the bundled Python after the password was changed in the app:

```bash
read -rs PCAP_ANALYZER_SMOKE_PASSWORD && export PCAP_ANALYZER_SMOKE_PASSWORD
runtime/python/bin/python3 tools/smoke.py http://127.0.0.1:8000 capture.pcap
```

`tools/check_install.sh` starts the app with `start-pcap-analyzer.py` and runs that walk, on this host or in a container without network. CI runs it on Ubuntu 18.04, Rocky Linux 8, openSUSE Leap 15.0, CentOS 7 and with Python 3.6.

## Settings

`pcap-analyzer.env` holds these. Run `python3 start-pcap-analyzer.py restart` after a change.

| Variable | Default | Meaning |
|---|---|---|
| `PCAP_ANALYZER_HOST` | `127.0.0.1` | Address to listen on, `0.0.0.0` for every address |
| `PCAP_ANALYZER_PORT` | `8000` | Port |
| `PCAP_ANALYZER_CERT`, `PCAP_ANALYZER_KEY` | | Certificate and key files, to serve HTTPS |
| `PCAP_ANALYZER_ADMIN_USER` | `admin` | Login name |
| `PCAP_ANALYZER_ADMIN_PASSWORD_HASH` | | Password hash, preferred |
| `PCAP_ANALYZER_ADMIN_PASSWORD` | | Plain password, as the alternative. With neither set, or with the password `admin`, the first sign-in is `admin` / `admin` and every page asks for a new password first. The new password is kept in `.admin-password.json` in the data folder and wins over these settings; delete that file to go back to them |
| `PCAP_ANALYZER_BEHIND_PROXY` | `0` | `1` when an HTTPS proxy is in front |
| `PCAP_ANALYZER_HSTS_S` | `31536000` | How long browsers must use HTTPS, sent whenever HTTPS is on. `0` tells them to stop. Applies to the host name on every port |
| `PCAP_ANALYZER_REQUEST_ID_HEADER` | `x-request-id` | Header that follows a request through proxies. `traceparent` is read when it is absent |
| `PCAP_ANALYZER_MERGECAP` | `mergecap` | Program that joins parts of a capture |
| `PCAP_ANALYZER_SANDBOX` | on where possible | `0` stops running tshark in its own namespaces |
| `PCAP_ANALYZER_TRUSTED_PROXIES` | | Proxy addresses or networks whose forwarded headers are believed, such as `10.0.0.5,10.1.0.0/16`. When empty, all users behind the proxy share one login lockout |
| `PCAP_ANALYZER_WORKDIR` | `data/` in this folder | Where results are saved |
| `PCAP_ANALYZER_MAX_SIZE_MB` | `1000` | Largest accepted capture. Captures over 100 MB are read in parts of whole connections |
| `PCAP_ANALYZER_TTL_DAYS` | `7` | Days results are kept. The server removes older ones every hour |
| `PCAP_ANALYZER_MAX_JOBS` | `2` | Analyses running at once |
| `PCAP_ANALYZER_KEEP_CAPTURE` | `1` | Keep the capture for PCAP export, `0` to delete it after analysis. The Statistics tab, TCP graphs, Flow Graph, Follow Stream and Export Objects read the kept capture, so they need `1` |
| `PCAP_ANALYZER_GEOIP_DIR` | none | A folder of MaxMind GeoLite2 `.mmdb` files. IP endpoints then show their country and AS number |
| `PCAP_ANALYZER_LANGUAGE` | `tr` | Default language: `tr`, `en`, `de` or `es`. Each user can choose another in the app |
| `PCAP_ANALYZER_ANALYSIS_TIMEOUT_S` | `600` | Longest analysis in seconds, `0` for no limit |
| `PCAP_ANALYZER_KNOWLEDGE` | | Path of another knowledge file, built with `tools/build_knowledge.py` |
