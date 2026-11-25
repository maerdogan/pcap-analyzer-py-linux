# Release notes

All changes made on the same day are one minor version.

## Unreleased

### Added

- HTTP/2 between a gateway and its backend: flow control waits are a phase of their own and an issue, and stream resets (RST_STREAM) and GOAWAY are issues with their error names.
- Several TLS key logs per analysis, such as the client to NetScaler leg and the NetScaler to gateway leg; the CLI takes `--keylog` more than once.
- NetScaler traces (nstrace) are accepted as captures; the two legs of the NetScaler are linked by their PCB numbers, with the NetScaler's own round trip.
- Certificate chain length and the first certificate to expire; mutual TLS: whether the server asked for a client certificate, and the issue "client certificate asked for but not sent".
- PROXY protocol v1 and v2: the client before the proxy, per connection and request.
- The original client from a list of headers, `PCAP_ANALYZER_CLIENT_IP_HEADER`, then from PROXY protocol.
- Envoy's `x-envoy-upstream-service-time`: the upstream time and the gateway's own time per request.
- Health checks by path and user agent (`PCAP_ANALYZER_HEALTH_PATHS` adds paths), and requests sent again after a failed attempt, as an issue.
- Compare at two points: the drift of the two clocks is estimated and taken out, and a known clock difference can be given.
- Users, groups and roles. An admin adds groups and users under Settings → Users: user name, full name, employee ID, group, and the role viewer (opens and exports), analyst (also uploads, deletes own captures, notes, saved filters) or admin (also users, preferences, tokens, the activity log and encryption). Users sign in with a local password or through LDAP, with the group and role from the app. A role that may not do something gets 403.
- Groups keep their captures apart: each capture records its uploader and group, and a user sees only the captures of their own group on every page, export, comparison, trend, baseline and REST call, including jobs; others answer 404. Admins see every group. Only the uploader or an admin may delete a capture.
- Encryption at rest, the design of the Java edition: every file in the data folder is encrypted with its own AES-256-GCM key in 1 MiB segments, keys are wrapped with RSA-2048, the data key is sealed with a 16-character master key and the master key with the setup admin's password. Analysis databases use DuckDB's own encryption. After a restart nothing opens until the setup admin signs in; others see a waiting page. The setup admin sets the master key on Settings → Encryption at the first sign-in, which encrypts what is already there, and can show and change it later.
- Files changed, cut, left plain or brought from another install are found when read and by an hourly check, and admins see a notice on every page.
- The REST API takes a user's name and password as well as tokens, and a token can be made for one group.

### Changed

- The first sign-in still is admin / admin, then the master key. A password in PCAP_ANALYZER_ADMIN_PASSWORD or PCAP_ANALYZER_ADMIN_PASSWORD_HASH is taken over once into the data folder and can be removed from the settings.
- Passwords need at least 12 characters, for everyone.
- The activity log is kept encrypted, line by line, in a file whose name says nothing about it, and records who did what.
- An analysis is deleted when nobody opened it for PCAP_ANALYZER_TTL_DAYS days, counting from its last view rather than from its upload.
- Uploads wait in a private folder inside the data folder rather than in /tmp, and tshark reads encrypted captures through a pipe.
- The web interface has a new look with the PCAP Analyzer logo. The sections, the views of the open capture and the recent captures sit in a dark side menu; the URL search, language and sign out sit in a bar at the top. On narrow screens the side menu opens with a menu button.
- Pages use softer, less bright backgrounds, and tables have clearer column titles. Text keeps at least 4.5:1 contrast.
- The explanation on a request and an issue page spreads over the page in columns: the first sentence of what it means, what this capture shows and three checks. The rest, the common misreading and the sources open on demand.
- Wireshark display filters on the upload form, the IO graph and the flow graph are picked from a list of presets, such as TLS handshakes, DNS errors or TCP retransmissions, and are no longer typed. The server takes only these: an upload with another filter is refused, and the graphs then show all packets. The command line still takes any filter.
- Inspect traffic lists all traffic the filter selects, most requests first, in pages of 30.
- The slowest requests on Inspect traffic can be filtered by text in the request, the status class (2xx to 5xx, or no response) and a duration range in milliseconds, keeping the page's other filters. A duration range lists every match, in pages of 30.
- Inspect traffic shows each URL over time: its phases stacked per time bucket, the 95th percentile as a dashed line and the requests and failed requests as bars below, beside where its average time went, including the round trips on both sides of the capture point and the gateway's upstream time. Selecting a row in the URL table switches to that URL.
- Holding the pointer over a slow request shows where its time went.

## 0.8.0 (2026-11-17)

### Added

- This repository is the Linux server edition of pcap-analyzer. `python3 start-pcap-analyzer.py` prepares and starts everything from this folder, with no internet, sudo, Docker or installation. The Kubernetes and Docker editions are in their own repositories, and [pcap-analyzer-py](https://github.com/maerdogan/pcap-analyzer-py) keeps every environment in one place.
- `start-pcap-analyzer.py` replaces the `linux-glibc2.26-server` and `linux-glibc2.17-server` folders and their `run.sh`. It runs with the system Python 3.6 or newer, checks and unpacks the bundle itself without `tar`, picks the older DuckDB on glibc 2.17, and has `stop`, `restart`, `status`, `logs`, `run` and `cli`.
- Settings are in `pcap-analyzer.env`, written on the first start. The first sign-in is `admin` / `admin`, and the app asks for a new password.
- A connection page lists every packet in order with the TCP flags by name, such as SYN and ACK, and explains each flag and the Seq and Ack numbers under the list.
- A request page lists the packets of that request alone: the connection setup when the request opened it, the request, the response and its acknowledgment.
- `ROADMAP.md` lists every roadmap item with its stage, area and state.

### Added

- Users, groups and roles. An admin adds groups and users under Settings → Users: user name, full name, employee ID, group, and the role viewer (opens and exports), analyst (also uploads, deletes own captures, notes, saved filters) or admin (also users, preferences, tokens, the activity log and encryption). Users sign in with a local password or through LDAP, with the group and role from the app. A role that may not do something gets 403.
- Groups keep their captures apart: each capture records its uploader and group, and a user sees only the captures of their own group on every page, export, comparison, trend, baseline and REST call, including jobs; others answer 404. Admins see every group. Only the uploader or an admin may delete a capture.
- Encryption at rest, the design of the Java edition: every file in the data folder is encrypted with its own AES-256-GCM key in 1 MiB segments, keys are wrapped with RSA-2048, the data key is sealed with a 16-character master key and the master key with the setup admin's password. Analysis databases use DuckDB's own encryption. After a restart nothing opens until the setup admin signs in; others see a waiting page. The setup admin sets the master key on Settings → Encryption at the first sign-in, which encrypts what is already there, and can show and change it later.
- Files changed, cut, left plain or brought from another install are found when read and by an hourly check, and admins see a notice on every page.
- The REST API takes a user's name and password as well as tokens, and a token can be made for one group.

### Changed

- The first sign-in still is admin / admin, then the master key. A password in PCAP_ANALYZER_ADMIN_PASSWORD or PCAP_ANALYZER_ADMIN_PASSWORD_HASH is taken over once into the data folder and can be removed from the settings.
- Passwords need at least 12 characters, for everyone.
- The activity log is kept encrypted, line by line, in a file whose name says nothing about it, and records who did what.
- An analysis is deleted when nobody opened it for PCAP_ANALYZER_TTL_DAYS days, counting from its last view rather than from its upload.
- Uploads wait in a private folder inside the data folder rather than in /tmp, and tshark reads encrypted captures through a pipe.
- The web interface has a new look with the PCAP Analyzer logo. The sections, the views of the open capture and the recent captures sit in a dark side menu; the URL search, language and sign out sit in a bar at the top. On narrow screens the side menu opens with a menu button.
- Pages use softer, less bright backgrounds, and tables have clearer column titles. Text keeps at least 4.5:1 contrast.
- The explanation on a request and an issue page spreads over the page in columns: the first sentence of what it means, what this capture shows and three checks. The rest, the common misreading and the sources open on demand.
- Wireshark display filters on the upload form, the IO graph and the flow graph are picked from a list of presets, such as TLS handshakes, DNS errors or TCP retransmissions, and are no longer typed. The server takes only these: an upload with another filter is refused, and the graphs then show all packets. The command line still takes any filter.
- Inspect traffic lists all traffic the filter selects, most requests first, in pages of 30.
- The slowest requests on Inspect traffic can be filtered by text in the request, the status class (2xx to 5xx, or no response) and a duration range in milliseconds, keeping the page's other filters. A duration range lists every match, in pages of 30.
- Inspect traffic shows each URL over time: its phases stacked per time bucket, the 95th percentile as a dashed line and the requests and failed requests as bars below, beside where its average time went, including the round trips on both sides of the capture point and the gateway's upstream time. Selecting a row in the URL table switches to that URL.
- Holding the pointer over a slow request shows where its time went.

## 0.7.6 (2026-11-16)

### Added

- Inspect traffic lists the 10 most called flows under the filter, as source ip:port → destination ip:port, ranked by HTTP requests, or by packets where no request was read. Selecting one fills the filter with its two ends and inspects it.
- A source port field in the inspect filter and in saved filters.
- By URL on the inspect page shows the total time spent on each URL shape, and every column sorts when its title is selected.

## 0.7.5 (2026-11-15)

### Added

- A connection page lists every packet of the connection in order, as Wireshark's packet list does: time, direction, flags, sequence and acknowledgment numbers, length, window, protocol and information, with retransmissions, lost segments and other TCP marks. It shows up to 5,000 packets.
- Follow HTTP stream: each request and its response on a connection in order, with headers and the start of each body. It comes from the analysis, so HTTP/2 and HTTPS decrypted with a key log work too, and secrets stay masked. Follow TCP stream has Text, Hex and HTTP views.
- The Connections table shows the connection number, start time, server name, packets and bytes of every TCP connection.

### Changed

- `kubernetes/vks` serves the app at `pcap-analyzer.internal`, a name not tied to the platform's own zone. `secrets.sh` makes the certificate again for a new name, and its first login is `admin` / `admin`, which the app asks to change.

## 0.7.4 (2026-11-15)

### Added

- With no password set, or with the password `admin`, the first sign-in is `admin` / `admin`, and every page asks for a new password before anything else. The new password needs at least 10 characters and cannot be `admin` or the user name. It is kept in `.admin-password.json` in the data folder, so it stays after a restart and wins over the settings.
- Preferences has a link to change the password at any time.

### Changed

- The app starts without `PCAP_ANALYZER_ADMIN_PASSWORD` or `PCAP_ANALYZER_ADMIN_PASSWORD_HASH`. Before, it refused to start.

## 0.7.3 (2026-11-15)

### Added

- An issue for a SYN that the server answers with a plain ACK instead of a SYN-ACK. The server still held an older connection on the same ports, so the client reset it and tried again. Found in a capture of 1,360 short HTTPS connections, 39 of which opened this way.

### Fixed

- Connections whose SYN was seen but not answered by a SYN-ACK were counted as started before the capture. Only those without a SYN are now.
- Without a TLS key, the handshake time of every TLS connection was empty, because the client's Finished is encrypted. It now ends at the client's ChangeCipherSpec, which goes with the Finished.

## 0.7.2 (2026-11-15)

### Fixed

- A release tag pushed again started a second release run beside the first. Both pushed the image and raced to create the release. Runs for one tag now wait in turn.

## 0.7.1 (2026-11-15)

### Added

- Service response times on the Statistics tab, as Wireshark's Service Response Time shows them, for LDAP, Kerberos, SMB2, Kafka, SMTP, DCERPC, MQTT, AMQP and FTP: requests, answers, errors, average, 95th percentile and slowest per operation and per server, the error answers and the slowest exchanges.
- SIP calls with caller, callee, state, final answer, time to ringing, time to answer and talk time.
- RTP streams with lost, out of order and duplicate packets, the largest gap and RFC 3550 jitter. RTP is found by its header also without the SIP that set it up.
- The REST API gives these and the packet statistics under `/api/v1/analyses/{id}/services`, `/voip` and `/statistics`.

### Changed

- tshark is asked only for fields it knows, so a tshark that lacks a newer field still analyzes the capture and leaves that value empty.
- `kubernetes/vks` targets the platform's `analyzers` cluster and its `dump-analyzers` namespace.
- `tools/smoke.py` also opens the Statistics tab, the flow graph, Follow TCP stream and the TCP graphs.

### Fixed

- The release workflow made its SBOM with cyclonedx-bom 5.0.0, which cannot be installed on Python 3.14 of the newer GitHub runners. It uses 7.6.0 now.

## 0.7.0 (2026-11-15)

### Added

- Issues found on single packets, as Wireshark's expert information shows them: malformed packets, ICMP and ICMPv6 destination unreachable with their reason, DNS errors such as NXDOMAIN and SERVFAIL, invalid TCP flags such as SYN with FIN, reused port numbers, ECN congestion marks and SACK blocks. Each issue lists its packets, kinds and addresses.
- Packets the capture itself dropped, read from the interface statistics at the end of a pcapng file.
- Decode As on the upload page, the API and the CLI, such as `tcp.port==9000,http`.
- A Statistics tab: protocol hierarchy, packet lengths, UDP and Ethernet conversations, MAC and IP endpoints with GeoIP when `PCAP_ANALYZER_GEOIP_DIR` is set, an IO graph for any display filter, HTTP load distribution and request sequences, and QUIC connections with their handshake time and, with a key log, HTTP/3 requests.
- On a connection page: Stevens, throughput, round trip and window graphs, the flow graph and Follow TCP Stream. A flow graph also works for any display filter.
- Export Objects for HTTP, SMB, TFTP, FTP, e-mail and DICOM, kept with the analysis up to 200 MB.
- These views read the kept capture again, in the same parts as the analysis for captures over 100 MB, and keep their result next to the analysis.

## 0.6.1 (2026-11-05)

### Added

- A TLS key log can be up to 512 MB, such as one from NetScaler with the keys of every session it served. Before, the limit was 8 MB. A key log over 8 MB is cut to the sessions in the capture, so tshark does not hold keys it will not use, and the cut copy is deleted after analysis.
- A request that the capture stopped right after, sooner than the slow request limit, is shown as "Capture ended first". It no longer counts as a request without a response or as a failed request.
- A ZIP, 7-Zip, RAR, bzip2, xz or tar archive, a key log, a certificate or a text file chosen as the capture gets a message that names it. A `.pfx` or a certificate without a private key in the RSA key field is refused with the `openssl` command that converts it, and a file that is not a key log in the key log field is refused. Before, these decrypted nothing without saying why.

### Fixed

These were found by testing every step with real captures from a Linux server, a `tcpdump -i any` host and both sides of a NetScaler.

- With `Expect: 100-continue`, a response ran on to the `100 Continue` of the next request on the same connection. Its transfer time and size grew, and most such requests were wrongly called slow transfers.
- On `tcpdump -i any`, GSO frames cut differently on two interfaces were taken for retransmissions when the connection started before the capture, because no MSS was known. Parts are now matched by IP ID and sequence number alone.
- "The key did not decrypt some TLS traffic" no longer appears for connections that sent no encrypted data, such as a handshake cut by the end of the capture or one followed by no request.
- Matching two captures of 12,000 and 7,000 requests took 75 seconds, because every request was checked against every other one. Each request now looks only at those with its method, URL and status near its start, which takes about 2 seconds.
- tshark messages no longer show the app's temporary file paths.
- A file that tshark opens but that holds no network packets stops with a plain message instead of an internal error.
- The DNS time of a request now runs from the first query of its lookup. In a Kubernetes pod with `ndots:5`, a name is first tried with each search domain, and a query that times out is sent again; a 6-second lookup was shown as 0.4 ms. A short service name such as `web.shop`, found under a search domain, now gets a DNS time too. Found in a capture of two pods in different namespaces.
- A test expected tshark 4.4 or later, so the checks failed on Ubuntu 24.04 with tshark 4.2.

## 0.6.0 (2026-11-03)

### Added

- Captures up to 1000 MB. One over 100 MB is split into parts of whole connections, found by their innermost addresses also inside VXLAN, Geneve, GRE and IP-in-IP, and each part goes to its own tshark through a pipe. Results, frame numbers and connection numbers are the same as in one pass. A 1 GB capture with 1.6 million packets took under 3 minutes and peaked near 700 MiB.
- A warning that names TLS connections which started before the capture, since a key log cannot be matched to them.
- Screenshots of the overview and the upload page in the README.

### Changed

- `PCAP_ANALYZER_MAX_SIZE_MB` defaults to 1000. Ingress upload limits are 1100 MB, `/tmp` holds 3 GiB in Compose and Kubernetes, and Compose allows 4 GiB of memory, because its `/tmp` is memory.
- Results are written to disk as each part finishes, and CSV, JSON, Excel and HAR downloads are written while they are sent, so memory no longer grows with the number of requests.
- On captures over 100 MB, a display filter cannot use `frame.number` or `tcp.stream`.
- `tools/pcap-collect.sh` and the capture guide stop a capture near the new limit.

### Fixed

- On a Kubernetes node with `tcpdump -i any`, a connection seen with the Service address and again with the pod address after NAT is counted once. Before, its requests were counted twice.
- A key log that decrypted most traffic no longer says the key did not work because of connections that started before the capture.
- `tools/pcap-collect.sh`: Ctrl-C stops the captures and keeps what they took, and `pod:` and `node:` start tcpdump after kubectl attaches, so the file header is not lost.
- A SYN-ACK that answers a SYN sent again is no longer taken for a copy from `tcpdump -i any`, so it counts as a retransmission, as in Wireshark.
- A request without a response shows a dash instead of "None" in its status badge.
- The Turkish text about removed packet copies no longer shows code quotes.

## 0.4.1 (2026-11-03)

### Added

- A warning when the same requests appear on two connections, as on both sides of a NAT or proxy.

### Fixed

- A request or response whose first copy on the wire was a resend was not read, so on lossy traffic it went missing and later responses could be paired with the wrong request.
- `tcpdump -i any` captures no longer show false retransmissions from a packet seen on several interfaces, including frames split differently on each.
- Complete responses are no longer marked as truncated when a loss repair was the only copy captured. Bytes are attributed by TCP sequence number.
- Body text that looks like HTTP no longer creates a fake request or response.
- Round trip time skips segments that were sent twice, which also corrects the capture point.
- Pipelined requests keep their own request IDs.
- `tools/pcap-collect.sh` shows why a capture failed and exits with an error, reports packets the kernel dropped, keeps a capture when its upload fails, handles filters safely and removes the pod `node:` leaves behind.

## 0.4.0 (2026-11-03)

### Added

- REST API under `/api/v1` with tokens you create and revoke in Preferences. See `docs/api.md`.
- Limits in Preferences: the slow request limit, and targets per URL pattern with a report of what went over.
- Baseline analysis: later analyses list the URLs that got slower, started failing or are new. A Trend page follows one URL across analyses.
- Case number, tags and notes on an analysis, a search over them, and the notes in the HTML report.
- Activity log of sign-ins, uploads, downloads and deletions, with address and time. The login is shared, so it does not name people.
- HAR download of all or filtered requests, with the same masking as the rest of the app.
- Requests of a connection on one time axis, saved as PNG or SVG.
- `pcap-analyzer check` exits with code 2 when an analysis breaks a limit, for CI.
- W3C `traceparent` gives an exact match between two capture points. `PCAP_ANALYZER_REQUEST_ID_HEADER` sets another header name.
- TLS tab: versions, ciphers, ALPN, resumed sessions, unanswered ClientHello, alerts and certificate end dates, without a key.
- WebSocket upgrades are measured on their own, so a long-lived connection no longer counts as slow. gRPC status from HTTP/2 trailers, with a gRPC errors issue.
- gzip captures open, and unpacking stops at the size limit. Several parts of one capture can be joined, with `mergecap` or, where it is missing, with tshark alone.
- tshark runs with CPU and file limits. Where the host allows user namespaces, it also runs without network and sees only its own files, and elsewhere, such as in a pod, Linux Landlock keeps it away from other analyses. `PCAP_ANALYZER_SANDBOX=0` turns the namespaces off.
- `kubernetes/helm/pcap-analyzer` chart, `tools/pcap-collect.sh` to capture from servers, pods and worker nodes at the same time and upload, `docs/usage.md` and `docs/api.md`.
- `requirements.lock`, a pinned base image, a dependency audit in CI, an SBOM in each Release and a signed record of how each image was built.
- `linux-glibc2.17-server` for CentOS 7 and similar hosts.
- `SECURITY.md`, `CONTRIBUTING.md`, issue templates, and exact source locations for GPL components in `THIRD_PARTY.md`.

### Changed

- zstd and lz4 captures stay refused, because their size cannot be limited the same way.
- Analyses saved by 0.2.0 still open. Their TLS tab asks you to analyze the capture again.

## 0.2.0 (2026-11-02)

### Added

- Interface in Turkish, English, German and Spanish. Turkish is the default, and each user can choose another language. Reports and exported column titles follow the choice.
- Bundled knowledge base for explanations. Each cause and issue says what it means, what this capture shows, what to check next and which sources back it. No AI model or outside service is used.
- Capture trust summary: high, medium or low, with the reasons, such as packets the capture missed, one-way traffic or connections cut at either end.
- Load balancer effect from its two sides: median and 95th percentile of added time per URL, kept apart from service time, with match rate and confidence.
- Servers tab with each backend's requests, times, errors and resets. A server out of line with its peers is marked and raises an issue.
- Traffic over time: requests, errors, 95th percentile, retransmissions and open connections. A period chosen on the chart narrows the Inspect tables.
- Capture guide with ready commands for Linux servers, pods and worker nodes.
- Time limit for each analysis and a cancel button. A stopped analysis leaves no files behind and frees its slot for the next one.
- NetScaler reset reason read from the window field of an RST packet, shown when the value is a documented code.
- VXLAN, Geneve and IP-in-IP traffic shows the addresses inside the tunnel.
- `tools/lab.py`: real Linux traffic with known delays, captured without root in network namespaces. The tests compare the results with those delays and with tshark.
- Form tokens tied to the session on everything that changes data. A page from a sibling subdomain can no longer sign you out or delete an analysis.
- HSTS whenever HTTPS is on, with `PCAP_ANALYZER_HSTS_S` to change or end it.
- `NetworkPolicy` in `kubernetes/generic`: only the ingress controller reaches the app, and the pod has no way out.
- CPU, memory and process limits in the Compose file and the systemd unit, and a tighter sandbox in the unit.
- `tools/smoke.py` walks through a running install from sign-in to deletion. `tools/check_install.sh` follows the install guide and runs that walk, and CI does this for Compose, systemd and the Linux folder on three old distributions.
- Release workflow: a `v*` tag runs all tests and install checks, then publishes the image to GitHub Container Registry and a GitHub Release with the image file, the wheel and checksums.
- `PCAP_ANALYZER_LANGUAGE`, `PCAP_ANALYZER_KNOWLEDGE` and `PCAP_ANALYZER_ANALYSIS_TIMEOUT_S`.

### Changed

- New interface: a blue top bar with the views of a capture, a strip of recent captures, a URL search and two-column pages. Each capture, connection and request opens with a scoreboard, and Compare shows the two captures side by side. Errors in Traffic over time now hang below the axis.
- `linux-glibc2.26-server` runs the application from `src/`, so a code update needs no new bundle. Keep the folder next to `src/`.
- All cause, issue, phase, warning and interface text moved to `knowledge/`. `tools/build_knowledge.py` checks it and builds `knowledge.bin`.
- A slow service explanation no longer rules out the network when the capture is not next to the server.
- Requests without a shared ID are matched in two passes, which holds up better when the capture clocks differ.
- Security headers are now on every answer, also on redirects and refusals.
- Compose takes its port from `PCAP_ANALYZER_PORT`.
- GitHub Actions in the workflows are pinned to exact commits.

### Fixed

- On kept-open HTTP/1.1 connections, responses were lost when the body came in its own TCP segment without a line end, so later requests looked unanswered and the first one looked very long. Header reassembly is now off. With headers longer than one segment, the part in later segments is not read.
- Extra copies of packets from `tcpdump -i any` looked like retransmissions and could show false packet loss. They are now removed and counted.
- With shared request IDs, the delay toward B was shown as zero and the whole delay as the way back. Both directions are now estimated, and the total added time is unchanged.
- ICMP errors that quote a TCP header no longer count as packets of that connection.
- The systemd steps in the install guide were missing `sudo`, the rights on the certificate files and `daemon-reload`. The guide also had no way to create a password hash on a host with only the image.

## 0.1.0 (2026-11-01)

### Added

- Analysis engine on tshark, with results saved to one DuckDB file per analysis. The same input reopens the saved result.
- HTTP/1.1 and HTTP/2 timing per request: send, wait, service, first byte, transfer and total.
- HTTPS decryption with a TLS key log file or an RSA private key, with a warning when traffic stays encrypted.
- Round-trip time per side of a connection, capture point detection and service time without network delay.
- Pre-analysis filter by IP or CIDR, port, time range and Wireshark display filter.
- Capture overview, URL groups such as `/users/{id}`, host names, TCP connection list and TCP details per connection.
- Inspection of one traffic pair by source, destination, port, type, URL and size.
- Slowest requests with a time breakdown and a plain explanation of the cause: slow service, network delay, packet loss, slow receiver, delayed ACK, queueing, gateway error, incomplete response and more.
- Masking of secrets in URLs, headers and body previews before anything is saved.
- Web interface with a single admin login, capture upload, history, issues list, response time chart, sortable tables, request content view and saved filters.
- Comparison of two captures with changes per URL and phase, separate filters for each side, and matching of the same requests seen at two points.
- Export of tables to CSV, Excel and JSON, charts to PNG and SVG, a single-file HTML report, and one connection as PCAP.
- Container image, Compose file, Kubernetes manifests, an example overlay with a Gateway API route, systemd unit and install guide.
- Command line: `analyze`, `report`, `connection`, `inspect`, `compare`, `list`, `delete`, `purge`, `serve` and `hash-password`.
- Professional interface layout: side navigation, metrics band, sorted time breakdown and aligned slowest-request tables.
- Synthetic sample generator with known timings, used by the tests.
- Run without sudo, Docker, systemd or internet from `linux-glibc2.26-server`, with Python, its packages and tshark included.
- One folder for each environment: `kubernetes`, `docker` and `linux-glibc2.26-server`.
- Security guidance in the README: what is not included, what operators must add, and a deployment diagram.

### Fixed

- Captures with no TCP events or DNS queries no longer fail while saving results.
- `X-Request-ID` and `Server-Timing` values no longer keep a literal `\r\n` from tshark output.
- Multi-line headers no longer break saving results.
- Two identical analyses running together no longer collide.
- Table icons no longer break under the content security policy.
- The server now refuses to start with an invalid password hash, instead of starting with a login that can never succeed.
- A fake `X-Forwarded-For` header can no longer avoid the login lockout. Forwarded headers are believed only from `PCAP_ANALYZER_TRUSTED_PROXIES`, and all addresses share a limit of 30 failed logins in 5 minutes.
- Compressed captures are refused, because they could unpack past the size limit.
- Expired results are now removed every hour, even when nobody uses the app. Leftover temporary files that can hold captures or TLS keys are removed too.
- Sample generator: the TLS client now verifies the test certificate.
- Sample generator: the high-latency scenario now acknowledges data at the real round-trip time.
