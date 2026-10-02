# SIEMLite

A lightweight, embedded SIEM in a single Go binary. It collects logs over HTTPS, normalizes them to the
[OCSF](https://schema.ocsf.io/) event model, stores them in one SQLite file, and gives you full-text search through
a built-in web UI and a small JSON API.

- **Send any log**: syslog, JSON lines or plain text. The original line is kept verbatim.
- **OCSF-normalized**: category, class and severity mean the same thing across sources.
- **Full-text search**: SQLite FTS5 combined with time, severity, category, IP and user filters.
- **HTTPS only**: no plain-HTTP listener. Self-signed certificate generated on first start, or bring your own.
- **Scoped API keys**: write-only keys for apps, read keys for analysts, admin keys for you.
- **Automatic retention**: old events are deleted in batches and disk space is reclaimed.
- **Pure Go, no CGO**: uses [`modernc.org/sqlite`](https://pkg.go.dev/modernc.org/sqlite).

> Early-stage project. Client-certificate (mTLS) verification and per-key rate limiting are not implemented yet.

## Quick start

Requires Go.

```sh
git clone https://github.com/justwaters/SIEMLite.git
cd SIEMLite
go build -o siemlite .
./siemlite -sample=false
```

On first start SIEMLite creates `siemlite.db`, generates `siemlite.crt` / `siemlite.key`, and prints an admin API key
**once**. Copy it. The UI is at <https://localhost:8443>; your browser will warn about the self-signed certificate
unless you trust `siemlite.crt` or supply your own with `-tls-cert` / `-tls-key`.

By default the server inserts a few demo events and runs a sample search at startup. Use `-sample=false` for real use.

### Send logs from an app

Create a write-only key for the app:

```sh
./siemlite keys create -name myapp -role write
```

Then post logs, one per line:

```sh
curl --cacert siemlite.crt -X POST 'https://localhost:8443/api/v1/logs?source=myapp' \
  -H "Authorization: Bearer $SIEMLITE_KEY" \
  --data-binary @app.log
```

Or post structured OCSF events:

```sh
curl --cacert siemlite.crt -X POST https://localhost:8443/api/v1/events \
  -H "Authorization: Bearer $SIEMLITE_KEY" \
  -d '[{"category_uid":3,"class_uid":3002,"severity_id":4,
        "message":"Failed password for root","src_endpoint":{"ip":"203.0.113.7"}}]'
```

If the app connects with a hostname or IP other than `localhost`, start SIEMLite with `-tls-hosts` listing it before the
certificate is first generated, so the certificate matches.

### Search

Sign in to the UI with a read or admin key, or use the API:

```sh
curl --cacert siemlite.crt -H "Authorization: Bearer $SIEMLITE_READ_KEY" \
  'https://localhost:8443/api/v1/search?q=failed+AND+ssh&severity=3&limit=20'
```

`q` uses [FTS5 query syntax](https://www.sqlite.org/fts5.html#full_text_query_syntax): `failed AND ssh`,
`"invalid user"`, `admin*`.

## API

| Endpoint | Role | Purpose |
|---|---|---|
| `POST /api/v1/logs` | write | Raw log text, one entry per line. Optional `source` and `severity` query params. |
| `POST /api/v1/events` | write | JSON array of OCSF events (up to 10,000 per request). |
| `GET /api/v1/search` | read | `q`, `start`, `end` (RFC3339 or epoch ms), `severity`, `category`, `class`, `src_ip`, `dst_ip`, `user`, `limit` (max 1000), `offset`. Newest first. |
| `GET /health` | public | Up/down only. With a read key it also returns event count, database size and ingest queue state. |

Authenticate with `Authorization: Bearer <key>`. A missing or revoked key returns `401`; a key without the needed role
returns `403`. An `admin` key can do everything.

### Log parsing

`/api/v1/logs` converts each line into an OCSF event: syslog (RFC 3164 and 5424) headers give the time and hostname,
the first two IPv4 addresses become source and destination, a user is picked up from patterns like `for user alice`,
and severity comes from the syslog priority or keywords (`error`, `failed`, `warning`, ...). JSON objects that already
contain `category_uid` are stored as OCSF; other JSON uses its `message`, `level` and timestamp fields. The detection
is heuristic; use `?severity=` to override it.

## API keys

```sh
./siemlite keys create -name <name> -role read|write|admin
./siemlite keys list
./siemlite keys revoke -id <id>
```

Keys look like `slk_...`. Only a SHA-256 hash is stored, so the secret is shown once at creation. The key commands work
while the server is running. Pass `-db` if your database is not `./siemlite.db`.

## Options

| Flag | Default | Meaning |
|---|---|---|
| `-addr` | `localhost:8443` | HTTPS listen address |
| `-db` | `siemlite.db` | SQLite database path |
| `-retention-days` | `30` | Delete events older than this many days (checked daily) |
| `-tls-cert`, `-tls-key` | `<db dir>/siemlite.crt`, `.key` | Certificate and key; a self-signed pair is generated if both are missing |
| `-tls-hosts` | | Extra DNS names or IPs for a generated certificate |
| `-sample` | `true` | Insert demo events and run a sample search at startup |

## How it works

```
clients ──HTTPS + API key──▶ api ──▶ ingest worker pool ──▶ batched SQLite transactions
                              │            (500 events or 500 ms)            │
                              └──▶ search engine ──▶ events ⋈ events_fts ◀───┘
                                                     retention worker (daily delete + incremental vacuum)
```

- **`pkg/ocsf`**: event model and validation.
- **`pkg/parser`**: raw log lines to OCSF events.
- **`pkg/storage`**: SQLite setup (WAL, `synchronous=NORMAL`, `busy_timeout=5000`), schema, queries. `events_fts` is an
  external-content FTS5 table kept in sync by triggers, so log text is not stored twice.
- **`pkg/ingest`**: buffered channel and worker pool that flushes in batches.
- **`pkg/search`**: combines time window, OCSF filters and FTS5.
- **`pkg/retention`**: deletes expired events in batches, then runs `PRAGMA incremental_vacuum`.
- **`pkg/auth`**: API keys and role enforcement.
- **`api`**: HTTPS server and endpoints. **`web`**: the embedded UI.

## Development

```sh
go test -race ./...
```

## License

[MIT](LICENSE)
