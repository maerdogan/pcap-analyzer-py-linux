# REST API

Create a token under **Preferences**. It is shown once. Send it with each call:

```bash
curl -H "Authorization: Bearer $TOKEN" https://pcap.example.internal/api/v1/analyses
```

A token uploads and reads like an analyst. A token made for one group sees and uploads only the captures of that group; one made for every group sees all of them. A user can also call the API with their own name and password, `curl -u name:password`, with their role and group. Captures of another group, and jobs of uploads in another group, answer `404`, as if they did not exist. While the data is locked after a restart, until the setup admin signs in, every call gets `503`.

| Call | Result |
|---|---|
| `POST /api/v1/captures` | Upload with the form field `capture`. Optional: `keylog` (may be sent more than once), `rsa_key`, `host_a`, `host_b`, `port`, `display_filter` (one of the presets the upload form lists, such as `tls` or `http || http2`; any other value gets `400`), `decode_as` (rules such as `tcp.port==9000,http`, separated by `;`). Returns `202` and a `job`. |
| `GET /api/v1/jobs/{job}` | `state` is `waiting`, `running`, `done`, `failed` or `cancelled`. `analysis` holds the id when done. |
| `GET /api/v1/analyses` | Saved analyses. |
| `GET /api/v1/analyses/{id}` | Details of one analysis. |
| `GET /api/v1/analyses/{id}/{section}` | `overview`, `urls`, `connections`, `hosts`, `issues` or `slowest`. Also `statistics`, `services` and `voip`, which read the kept capture again and can take minutes the first time. |
| `DELETE /api/v1/analyses/{id}` | Deletes an analysis. Only the one who uploaded it, or an admin, may: others get `403`. |

Upload and wait:

```bash
job=$(curl -s -H "Authorization: Bearer $TOKEN" -F capture=@web.pcap "$URL/api/v1/captures" | python3 -c 'import json,sys; print(json.load(sys.stdin)["job"])')
curl -s -H "Authorization: Bearer $TOKEN" "$URL/api/v1/jobs/$job"
```

Errors come back as `{"error": "..."}`. A wrong or revoked token, or a wrong password, gives `401`, and a role that may not do the call gives `403`. Keep a token like a password.
