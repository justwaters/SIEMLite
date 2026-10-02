# SIEMLite

[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE) [![Open Source](https://img.shields.io/badge/open%20source-OSI%20approved-brightgreen.svg)](https://opensource.org/license/agpl-v3)

A lightweight, embedded SIEM in a single Go binary. It collects logs over HTTPS, normalizes them to the
[OCSF](https://schema.ocsf.io/) event model, stores them in one SQLite file, and gives you full-text search through
a built-in web UI and a small JSON API.

- **Send any log**: syslog, JSON lines or plain text. The original line is kept verbatim.
- **OCSF-normalized**: category, class and severity mean the same thing across sources.
- **Full-text search**: SQLite FTS5 combined with time, severity, category, IP and user filters.
- **HTTPS only**: no plain-HTTP listener. Self-signed certificate generated on first start, or bring your own.
- **Two kinds of access**: API keys let applications send logs (and nothing else); people sign in to the UI with a username and password.
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

On first start SIEMLite creates `siemlite.db`, generates `siemlite.crt` / `siemlite.key`, and creates an `admin` user
with a random password that is printed **once**. Copy it. Open <https://localhost:8443> and sign in; your browser will
warn about the self-signed certificate unless you trust `siemlite.crt` or supply your own with `-tls-cert` / `-tls-key`.

By default the server inserts a few demo events and runs a sample search at startup. Use `-sample=false` for real use.

### Send logs from an app

Create an API key for the app. Keys can only send logs; they cannot search or sign in.

```sh
./siemlite keys create -name myapp
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

Sign in to the UI with your username and password. Searching is for signed-in users only; API keys are refused.
The search API uses the same browser session (an `HttpOnly` cookie), so it is meant for the UI rather than scripts.

`q` uses [FTS5 query syntax](https://www.sqlite.org/fts5.html#full_text_query_syntax): `failed AND ssh`,
`"invalid user"`, `admin*`.

## API

| Endpoint | Who | Purpose |
|---|---|---|
| `POST /api/v1/logs` | API key, or admin user | Raw log text, one entry per line. Optional `source` and `severity` query params. |
| `POST /api/v1/events` | API key, or admin user | JSON array of OCSF events (up to 10,000 per request). |
| `GET /api/v1/search` | any signed-in user | `q`, `start`, `end` (RFC3339 or epoch ms), `severity`, `category`, `class`, `src_ip`, `dst_ip`, `user`, `limit` (max 1000), `offset`. Newest first. |
| `POST /api/v1/login`, `POST /api/v1/logout`, `GET /api/v1/me` | | Browser sign-in, sign-out and current session. |
| `GET /health` | public | Up/down only. When signed in it also returns event count, database size and ingest queue state. |

Applications authenticate with `Authorization: Bearer <key>`. A missing or revoked key returns `401`; an API key used on
a search returns `403`.

### Log parsing

`/api/v1/logs` converts each line into an OCSF event: syslog (RFC 3164 and 5424) headers give the time and hostname,
the first two IPv4 addresses become source and destination, a user is picked up from patterns like `for user alice`,
and severity comes from the syslog priority or keywords (`error`, `failed`, `warning`, ...). JSON objects that already
contain `category_uid` are stored as OCSF; other JSON uses its `message`, `level` and timestamp fields. The detection
is heuristic; use `?severity=` to override it.

## Users

People sign in with a username and password. There are two roles:

- **admin**: search, and add logs from the UI.
- **analyst**: search only.

```sh
./siemlite users create -username alice -role analyst   # prompts for a password (min 12 characters)
./siemlite users list
./siemlite users passwd -username alice                 # also signs alice out everywhere
./siemlite users delete -username alice
```

Passwords are stored as bcrypt hashes. Sessions last 12 hours, use an `HttpOnly`, `Secure`, `SameSite=Strict` cookie,
and end on sign-out. After 10 failed sign-ins in 15 minutes a client address is locked out for the rest of the window.

## API keys

For applications that send logs. A key can only post to `/api/v1/logs` and `/api/v1/events`.

```sh
./siemlite keys create -name <name>
./siemlite keys list
./siemlite keys revoke -id <id>
```

Keys look like `slk_...`. Only a SHA-256 hash is stored, so the secret is shown once at creation. The `keys` and `users`
commands work while the server is running. Pass `-db` if your database is not `./siemlite.db`.

**Upgrading from v0.1:** read and admin API keys no longer exist and are revoked on first start. Sign in with the
`admin` account created for you (or create users with `siemlite users create`). Write keys keep working.

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
- **`pkg/auth`**: API keys, users, sessions and permission checks.
- **`api`**: HTTPS server and endpoints. **`web`**: the embedded UI.

## Development

```sh
go test -race ./...
```

## License

SIEMLite is free and open-source software, released under the
[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0), which is approved by the
[Open Source Initiative](https://opensource.org/license/agpl-v3).

You may use, modify and redistribute it, including commercially. If you modify SIEMLite and let others interact with
it over a network (for example, by running it as a service), you must offer those users the complete source code of
your modified version under the same license. The web UI links to this repository to make that easy; if you fork it,
point that link (the footer in `web/static/index.html`) at your own source.
