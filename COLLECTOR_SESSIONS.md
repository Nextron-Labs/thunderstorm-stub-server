# Collector Sessions — `/api/collection` Endpoint

## Motivation

Thunderstorm collectors run periodically (cron, scheduled tasks) or ad-hoc during incident response. Currently the server has no way to know:

- When a collection run started or ended on a given host
- Which uploaded files belong to the same run
- Whether a run completed successfully or was interrupted
- How many files were scanned vs. submitted vs. skipped

The `/api/collection` endpoint gives collectors a way to **bracket their runs** with begin/end markers, enabling the server to track collection sessions over time.

## Design Principles

1. **Forward-compatible.** Collectors must handle 404 gracefully — the endpoint may not exist on older servers. A failed marker call must never abort the collection.
2. **Server-assigned IDs.** The server generates the `scan_id` on `begin` and returns it. Collectors don't invent their own IDs.
3. **Lightweight.** Two HTTP calls per run (begin + end). No heartbeats, no keepalives.
4. **Optional enrichment.** The `scan_id` can be appended to upload URLs so the server can correlate individual file submissions with a session, but this is not required.

---

## Endpoint: `POST /api/collection`

Single endpoint, behavior determined by the `type` field in the JSON body.

### Begin a Collection

**Request:**

```http
POST /api/collection HTTP/1.1
Content-Type: application/json

{
  "type": "begin",
  "source": "webserver-prod-01",
  "collector": "bash/0.4.0",
  "timestamp": "2026-02-24T09:00:00Z"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | ✅ | Must be `"begin"` |
| `source` | string | ✅ | Hostname or identifier of the scanned system (same value used in `?source=` on uploads) |
| `collector` | string | ✅ | Collector name and version (e.g. `"bash/0.4.0"`, `"python3/0.1"`, `"powershell3/1.0"`) |
| `timestamp` | string | ✅ | ISO 8601 UTC timestamp of when the collection started |

**Response (200 OK):**

```json
{
  "scan_id": "b7c680b0-b720-4b64-aba2-f871efc08b0b"
}
```

| Field | Type | Description |
|---|---|---|
| `scan_id` | string | Server-generated unique identifier for this collection session. UUID v4 recommended. |

### End a Collection

**Request:**

```http
POST /api/collection HTTP/1.1
Content-Type: application/json

{
  "type": "end",
  "source": "webserver-prod-01",
  "collector": "bash/0.4.0",
  "scan_id": "b7c680b0-b720-4b64-aba2-f871efc08b0b",
  "timestamp": "2026-02-24T09:05:23Z",
  "stats": {
    "scanned": 1500,
    "submitted": 273,
    "skipped": 1227,
    "failed": 0,
    "elapsed_seconds": 323
  }
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | ✅ | Must be `"end"` |
| `source` | string | ✅ | Same source as the begin marker |
| `collector` | string | ✅ | Same collector as the begin marker |
| `scan_id` | string | ✅ | The `scan_id` returned by the begin call |
| `timestamp` | string | ✅ | ISO 8601 UTC timestamp of when the collection ended |
| `stats` | object | ✅ | Run statistics (see below) |

**`stats` object:**

| Field | Type | Description |
|---|---|---|
| `scanned` | integer | Total files discovered and considered |
| `submitted` | integer | Files successfully uploaded to the server |
| `skipped` | integer | Files skipped (size/age/extension filters, unreadable, etc.) |
| `failed` | integer | Files where upload was attempted but failed |
| `elapsed_seconds` | integer | Wall-clock duration of the collection run |

**Response (200 OK):**

```json
{
  "ok": true
}
```

---

## Upload URL Enrichment

After receiving a `scan_id` from the begin call, collectors append it to every subsequent upload URL:

```
# Before (no session tracking)
POST /api/checkAsync?source=webserver-prod-01

# After (with session tracking)
POST /api/checkAsync?source=webserver-prod-01&scan_id=b7c680b0-b720-4b64-aba2-f871efc08b0b
```

The `scan_id` value must be URL-encoded (though UUID v4 strings are already URL-safe).

This allows the server to:
- Group all uploads from a single collection run
- Detect incomplete runs (begin received, no end)
- Build per-run reports with scan statistics

---

## Error Handling

### Collector-side

Collectors **must not** fail if the endpoint is unavailable:

```
begin() → 404/timeout/error → proceed without scan_id
end()   → 404/timeout/error → ignore, exit normally
```

If `begin` fails, the collector runs without a `scan_id` (uploads work exactly as before). If `end` fails, the server will see the begin marker and uploads but no end marker — it can infer the run was interrupted or the endpoint is not supported.

### Server-side

| Condition | Response |
|---|---|
| Invalid JSON body | `400 Bad Request` |
| Unknown `type` value | `400 Bad Request` |
| Wrong HTTP method | `405 Method Not Allowed` |
| `end` with unknown `scan_id` | `200 OK` (log a warning, don't reject — the begin may have been lost) |

---

## Sequence Diagram

```
Collector                          Thunderstorm Server
    |                                      |
    |  POST /api/collection                |
    |  {"type":"begin", ...}               |
    |------------------------------------->|
    |                                      |  Generate scan_id
    |  {"scan_id":"b7c6..."}               |
    |<-------------------------------------|
    |                                      |
    |  POST /api/checkAsync?source=...     |
    |       &scan_id=b7c6...               |
    |  [file 1]                            |
    |------------------------------------->|
    |                                      |
    |  POST /api/checkAsync?source=...     |
    |       &scan_id=b7c6...               |
    |  [file 2]                            |
    |------------------------------------->|
    |                                      |
    |  ... (N files)                       |
    |                                      |
    |  POST /api/collection                |
    |  {"type":"end", scan_id, stats}      |
    |------------------------------------->|
    |                                      |  Log session complete
    |  {"ok":true}                         |
    |<-------------------------------------|
```

---

## Currently Implemented In

All 7 script collectors send begin/end markers as of the `script-robustness` branch:

| Collector | Collector String | Notes |
|---|---|---|
| `thunderstorm-collector.sh` | `bash/0.4.0` | curl or wget for the POST |
| `thunderstorm-collector-ash.sh` | `ash/0.4.0` | curl, wget, or raw POST if available |
| `thunderstorm-collector.py` | `python3/0.1` | stdlib `http.client` |
| `thunderstorm-collector-py2.py` | `python2/0.1` | stdlib `httplib` |
| `thunderstorm-collector.pl` | `perl/0.2` | `LWP::UserAgent` |
| `thunderstorm-collector.ps1` | `powershell3/1.0` | `Invoke-WebRequest` |
| `thunderstorm-collector-ps2.ps1` | `powershell2/1.0` | `System.Net.HttpWebRequest` |

The Go collector does not yet implement this feature.

---

## Future Considerations

- **Server-side session store:** Track active sessions, detect incomplete runs, build dashboards.
- **Scan ID in JSONL log:** Include `scan_id` from the upload query parameter in the per-file JSONL log entries for correlation.
- **Session metadata:** The begin request could carry additional fields like `scan_dirs`, `max_age`, `max_size` to record the collector configuration.
- **Abort marker:** A `{"type":"abort"}` for collectors that catch SIGINT/SIGTERM mid-run.
