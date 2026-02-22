# thunderstorm-stub-server

Minimal open-source THOR Thunderstorm-compatible HTTP server for integration-testing
[thunderstorm-collector](https://github.com/nextron-systems/thunderstorm-collector) and
[thunderstormAPI](https://github.com/nextron-systems/thunderstormAPI) clients.

**Goal**: exercise the full client↔server HTTP contract in CI without a THOR licence.
**Not a goal**: replicate proprietary scanning, Sigma, IOC checks, or any THOR-internal logic.

---

## Protocol summary

Derived from reading `thunderstorm-collector/go/collector.go` and
`thunderstormAPI/thunderstormAPI/thunderstorm.py` — no speculation.

### Endpoints

| Method | Path                   | Query params | Purpose                                              |
|--------|------------------------|--------------|------------------------------------------------------|
| POST   | `/api/check`           | `source=`    | Synchronous scan — result in response                |
| POST   | `/api/checkAsync`      | `source=`    | Async submission — returns `{"id":"…"}` immediately  |
| GET    | `/api/getAsyncResults` | `id=`        | Poll async result                                    |
| GET    | `/api/status`          | —            | Server metrics                                       |
| GET    | `/api/info`            | —            | Version / mode info                                  |

### File upload

Both POST endpoints accept `multipart/form-data`:

- **Field name**: `file`
- **Filename** (Content-Disposition): absolute path as reported by the client
  (`filepath.Abs` / `path.abspath`)
- **Content-Type**: `application/octet-stream`
- **`source` query param**: optional; identifies the sending host; defaults to
  sender's hostname in both clients

### Response shapes

**`POST /api/check`** — JSON array (empty `[]` when no rules match):

```json
[{
  "level":   "Alert",
  "module":  "Filescan",
  "message": "Malicious file found",
  "score":   90,
  "context": {
    "ext": ".bin", "file": "/abs/path/on/client",
    "firstBytes": "5448554e44455253544f524d / THUNDERS",
    "md5": "…", "sha1": "…", "sha256": "…",
    "size": 62, "type": ""
  },
  "matches": [{
    "matched":  ["$marker: 5448554e44455253544f524d"],
    "reason":   "YARA rule TestRule",
    "ref":      "", "ruledate": "",
    "rulename": "TestRule",
    "subscore": 90,
    "tags":     []
  }]
}]
```

**`POST /api/checkAsync`** — `{"id": "<uuid4>"}` (client stores the ID and polls later)

**`GET /api/getAsyncResults?id=<id>`** — `status` key always present (required by client):

```json
{"status": "queued|running|done|error", "results": []}
```

**`GET /api/status`** — `uptime_seconds` always present (required by client):

```json
{
  "uptime_seconds": 42,
  "scanned_samples": 3,
  "avg_scan_time_milliseconds": 1,
  "queued_async_requests": 0
}
```

**`GET /api/info`**:

```json
{"thor_version": "10.6.0", "yara_version": "4.5.0", "stub_mode": false, "rules_dir": "./rules"}
```

### Overload / retry

- If too many simultaneous sync scans (`MAX_CONCURRENT`) or the async queue is
  full (`QUEUE_MAX_SIZE`): **HTTP 503** with `Retry-After: <seconds>` header.
- Both clients retry indefinitely on 503, sleeping `Retry-After` seconds between
  attempts.
- The Go collector also retries up to 3× on network errors with exponential
  backoff (4 s × 2^n).

---

## Scoring (from THOR manual)

| Condition                                      | Level   |
|------------------------------------------------|---------|
| score > 80 **and** at least one subscore > 75  | Alert   |
| score ≥ 60                                     | Warning |
| score ≥ 40                                     | Notice  |
| score < 40                                     | Info    |

Default YARA rule score when no `score` meta field is set: **75** (Warning).

Multiple rule matches are combined with the THOR accumulation formula:

```text
total = 100 × (1 − ∏ (1 − sᵢ / 100 / 2ⁱ))   scores sorted descending, capped at 100
```

---

## Build & run

The `rules/` directory is the default rules path. Drop any `*.yar` / `*.yara` files there
(e.g. the [YARA-Forge](https://github.com/YARAHQ/yara-forge) bundle) and they are
picked up at startup without extra flags.

### Stub mode (no YARA — always returns no matches, API stays compatible)

```bash
go build -o thunderstorm-stub .
./thunderstorm-stub --log-file ./audit.jsonl
# rules/ is ignored in stub mode; use -tags yara to enable scanning
```

### YARA mode

```bash
# macOS
brew install yara

# Debian / Ubuntu
apt install libyara-dev

go get github.com/hillu/go-yara/v4
go build -tags yara -o thunderstorm-stub .
./thunderstorm-stub --log-file ./audit.jsonl
# loads rules/*.yar and rules/*.yara (recursive) automatically
```

### Configuration

All options are available as CLI flags **and** environment variables (flags take precedence):

| Flag               | Env var          | Default | Description                                         |
|--------------------|------------------|---------|-----------------------------------------------------|
| `--port`           | `PORT`           | `8080`  | Listening port                                      |
| `--rules-dir`      | `RULES_DIR`      | `rules` | Directory with `*.yar` / `*.yara` files (recursive) |
| `--log-file`       | `LOG_FILE`       | `""`    | JSONL audit log path (empty = no file)              |
| `--uploads-dir`    | `UPLOADS_DIR`    | `""`    | Persist uploaded samples here (empty = discard)     |
| `--max-concurrent` | `MAX_CONCURRENT` | `4`     | Max simultaneous sync scans before 503              |
| `--queue-max-size` | `QUEUE_MAX_SIZE` | `100`   | Max queued async jobs before 503                    |
| `--retry-after`    | `RETRY_AFTER`    | `30`    | `Retry-After` value in seconds on 503               |

---

## Pointing collectors at it

### thunderstormAPI (Python)

```python
from thunderstormAPI.thunderstorm import ThunderstormAPI

t = ThunderstormAPI(host="127.0.0.1", port=8080, source="my-host")

# Synchronous
results = t.scan("/path/to/sample.exe")
print(results)

# Asynchronous
receipt = t.scan("/path/to/sample.exe", asyn=True)
result  = t.get_async_result(id=receipt["id"])
print(result["status"])  # queued | running | done | error
```

### thunderstorm-collector (Go) — synchronous mode

```bash
./thunderstorm-collector \
  --server http://127.0.0.1:8080 \
  --upload-synchronous \
  --directory /path/to/scan
```

### thunderstorm-collector — asynchronous mode (default)

```bash
./thunderstorm-collector \
  --server http://127.0.0.1:8080 \
  --directory /path/to/scan
```

### curl

```bash
# Sync
curl -s -F "file=@/tmp/sample.bin" \
  "http://127.0.0.1:8080/api/check?source=my-host" | jq .

# Async submit
ID=$(curl -s -F "file=@/tmp/sample.bin" \
  "http://127.0.0.1:8080/api/checkAsync?source=my-host" | jq -r .id)

# Poll
curl -s "http://127.0.0.1:8080/api/getAsyncResults?id=$ID" | jq .
```

---

## Tests

```bash
# Stub mode (no YARA required — runs in CI without libyara)
go test ./...

# Full YARA mode (requires libyara + go-yara)
go test -tags yara ./...
```

The `*_FullRoundtrip` and `*_Deterministic` tests are automatically skipped in
stub mode and run only with `-tags yara`.

---

## Sample JSONL log line

One line is appended per uploaded file (matches or not):

```json
{
  "type": "THOR finding",
  "meta": {
    "time": "2026-02-22T00:00:00Z",
    "level": "Alert",
    "module": "YARA",
    "scan_id": "a1b2c3d4-e5f6-4789-ab01-cd23ef456789",
    "hostname": "my-server"
  },
  "message": "Malicious file found",
  "subject": {
    "type": "file",
    "path": "/tmp/uploads/a1b2c3d4.bin",
    "exists": "yes",
    "extension": ".bin",
    "hashes": {
      "sha256": "e3b0c44298fc1c149afbf4c8996fb924…",
      "sha1": "da39a3ee5e6b4b0d3255bfef95601890…",
      "md5": "d41d8cd98f00b204e9800998ecf8427e"
    },
    "first_bytes": {"hex": "5448554e44455253544f524d", "ascii": "THUNDERSTORM"},
    "size": 62,
    "source": "my-host"
  },
  "score": 90,
  "reasons": [{
    "type": "reason",
    "summary": "YARA rule TestRule / Test rule matching the stub server test sample",
    "signature": {
      "score": 90, "origin": "custom", "kind": "YARA Rule",
      "tags": [], "rule_name": "TestRule",
      "description": "Test rule matching the stub server test sample",
      "author": "thunderstorm-stub-server"
    },
    "matched": [{
      "data":    {"data": "5448554e44455253544f524d54455354", "encoding": "plain"},
      "context": {"data": "", "encoding": "plain"},
      "offset": 0,
      "field": "/content"
    }]
  }],
  "reason_count": 1,
  "log_version": "v3.0.0"
}
```
