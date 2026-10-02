# SIEMLite

[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE) [![Open Source](https://img.shields.io/badge/open%20source-OSI%20approved-brightgreen.svg)](https://opensource.org/license/agpl-v3)

A lightweight, embedded SIEM in a single Go binary. It collects logs over HTTPS, normalizes them to the
[OCSF](https://schema.ocsf.io/) event model, stores them in one SQLite file, and gives you full-text search through
a built-in web UI and a small JSON API.

- **Send any log**: over HTTPS, or native syslog on UDP, TCP or TLS. Syslog, JSON lines or plain text; the original line is kept verbatim.
- **OCSF-normalized**: category, class and severity mean the same thing across sources.
- **Enrichment**: GeoIP country/city and ASN for public IPs, and threat intel matching against IP, CIDR, domain and hash blocklists.
- **Full-text search**: SQLite FTS5 combined with time, severity, category, IP, user, source, country, ASN and threat filters.
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
./siemlite
```

On first start SIEMLite creates `siemlite.db`, generates `siemlite.crt` / `siemlite.key`, and creates an `admin` user
with a random password that is printed **once**. Copy it. Open <https://localhost:8443> and sign in; your browser will
warn about the self-signed certificate unless you trust `siemlite.crt` or supply your own with `-tls-cert` / `-tls-key`.

Nothing to look at yet? Turn on **Sample data** at the top right of the UI (admins only) to load a day of demo
events. See [Sample data](#sample-data).

### Run with Docker

The web UI is built into the binary, so this is a single container. Deploy and upgrade with one command:

```sh
git clone https://github.com/justwaters/SIEMLite.git && cd SIEMLite
cp .env.example .env        # optional: ports, certificate names, GeoIP, feeds, retention
git pull && docker compose up -d --build
docker compose logs siemlite | grep -A1 'username: admin'   # first start only: the admin password
```

- The database and certificate live in the `siemlite-data` volume, so rebuilds and upgrades keep every event,
  account and key. `docker compose down` keeps the volume; `docker compose down -v` deletes it.
- Ports: HTTPS on 8443, syslog on 514 (UDP and TCP) and syslog over TLS on 6514. Change the host ports in `.env`.
- Settings: every server flag can be set in `.env` as `SIEMLITE_<FLAG>`, e.g. `SIEMLITE_RETENTION_DAYS=90`
  for `-retention-days`. `.env.example` lists the useful ones.
- Set `SIEMLITE_TLS_HOSTS` to the names or IPs people use to reach the server **before the first start**: the
  certificate is generated once. To regenerate it later, delete it from the volume and restart (the image has no
  shell, so use a throwaway container; the volume is named after the checkout folder):
  `docker run --rm -v siemlite_siemlite-data:/data alpine rm /data/siemlite.crt /data/siemlite.key && docker compose restart`.
  To trust the certificate on a client, copy it out with `docker compose cp siemlite:/data/siemlite.crt .`.
- GeoIP: put the `.mmdb` files in `./geoip/` and set `SIEMLITE_GEOIP_CITY=/geoip/GeoLite2-City.mmdb` (and `_ASN`).
- Management commands run inside the container:
  `docker compose exec siemlite siemlite users create -username alice -role analyst`, and the same for `keys`
  and `intel`. To import a feed file, pipe it in: `docker compose exec -T siemlite siemlite intel import -source x -file - < iocs.txt`.
- Syslog senders keep their real IP through Docker's port mapping, so `-syslog-allow` works. The exception is a
  sender on the Docker host itself, which appears as the Docker network's gateway address.
- The image is about 25 MB, has no shell, and runs as an unprivileged user. Docker restarts it if `/health` stops
  answering.

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

### Send syslog

Point rsyslog, syslog-ng, firewalls, switches or anything else that speaks syslog at SIEMLite:

```sh
./siemlite -syslog-udp :514 -syslog-tcp :514 -syslog-tls :6514
```

- **UDP** (RFC 5426), **TCP** (RFC 6587; octet-counted or newline-delimited frames) and **TLS** (RFC 5425, using the same
  certificate as the web UI). Each listener is off unless its flag is set.
- Syslog has no authentication, so only senders on loopback and private networks (10/8, 172.16/12, 192.168/16,
  100.64/10, fc00::/7, link-local) are accepted by default. Set `-syslog-allow 192.0.2.0/24,198.51.100.4` to choose
  exactly who may send; refused senders are counted and logged once a minute.
- The syslog hostname becomes the event's **host** and the app name or tag (`sshd[311]:`) its **source**. The
  sender's address is kept as `device.ip`.
- Messages over 64 KiB are dropped. With UDP, messages are dropped when the ingest queue is full; TCP waits briefly.
- Ports below 1024 need root or `sudo setcap cap_net_bind_service=+ep ./siemlite`.

rsyslog example (`/etc/rsyslog.d/siemlite.conf`): `*.* @@siemlite.internal:514` (TCP; one `@` for UDP).

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
| `GET /api/v1/search` | any signed-in user | `q`, `start`, `end` (RFC3339 or epoch ms), `severity`, `category`, `class`, `src_ip`, `dst_ip`, `user`, `source`, `host`, `country`, `asn`, `threat=true`, `limit` (max 1000), `offset`. Newest first. Each event includes its `enrichment` (location, autonomous system, threat intel matches). |
| `POST /api/v1/login`, `POST /api/v1/logout`, `GET /api/v1/me` | | Browser sign-in, sign-out and current session. |
| `GET /health` | public | Up/down only. When signed in it also returns event count, database size, ingest queue state, indicator count and syslog counters. |

Applications authenticate with `Authorization: Bearer <key>`. A missing or revoked key returns `401`; an API key used on
a search returns `403`.

### Log parsing

`/api/v1/logs` converts each line into an OCSF event: syslog (RFC 3164 and 5424) headers give the time and hostname,
the first two IPv4 addresses become source and destination, a user is picked up from patterns like `for user alice`,
and severity comes from the syslog priority or keywords (`error`, `failed`, `warning`, ...). JSON objects that already
contain `category_uid` are stored as OCSF; other JSON uses its `message`, `level` and timestamp fields. The detection
is heuristic; use `?severity=` to override it.

## GeoIP and ASN

Give SIEMLite a MaxMind-format database and every public source and destination IP gets a country, city,
coordinates and autonomous system as it is stored:

```sh
./siemlite -geoip-city GeoLite2-City.mmdb -geoip-asn GeoLite2-ASN.mmdb
```

- Works with MaxMind [GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) (free with an account;
  keep it fresh with `geoipupdate`) or GeoIP2, and the [DB-IP lite](https://db-ip.com/db/lite.php) databases (free, no
  account, CC BY 4.0). A Country database works in place of City. Either flag can be used alone.
- Files are checked hourly and reloaded when they change, so `geoipupdate` needs no restart.
- Private, loopback and other non-public addresses are skipped.
- Search with `country=CN` or `asn=AS4134` (either endpoint). The country code shows next to each IP in the UI; the
  full location and AS name are in the event detail.

Only events stored after GeoIP is enabled are enriched.

## Threat intel

SIEMLite checks every event against a list of indicators: IP addresses, CIDR ranges, domains (which also match
subdomains) and MD5/SHA-1/SHA-256 hashes. It looks at the source and destination IPs and at IPv4 addresses, domain
names and hashes anywhere in the raw log. A hit marks the event as a threat (red bar and **INTEL** badge in the UI,
`threat=true` in search) and records which indicator, source and field matched.

Download feeds automatically (refreshed every `-intel-refresh`, default 6h):

```sh
./siemlite \
  -intel-feed feodo=https://feodotracker.abuse.ch/downloads/ipblocklist.txt \
  -intel-feed drop=https://www.spamhaus.org/drop/drop.txt \
  -intel-feed urlhaus=https://urlhaus.abuse.ch/downloads/hostfile/
```

Or manage indicators from the command line (works while the server is running; changes are picked up within 30s):

```sh
./siemlite intel import -source mylist -file iocs.txt     # replaces everything in "mylist"; -file - reads stdin
./siemlite intel import -source feodo -url https://feodotracker.abuse.ch/downloads/ipblocklist.txt
./siemlite intel add -source manual -value 203.0.113.7 -description "seen in phishing"
./siemlite intel list
./siemlite intel delete -source mylist
```

Feed files have one indicator per line. Plain lists, CSV (first column), Spamhaus DROP (`1.2.3.0/24 ; SBL123`), hosts
files (`0.0.0.0 evil.example`) and URL lists (the host is used) are understood; comments and invalid lines are
skipped. The type is detected, or forced with `-type ip|cidr|domain|hash`. Importing or refreshing a source replaces
all of its indicators, so entries removed from a feed stop matching. A download that fails or comes back empty keeps
the previous indicators.

Matching happens when an event is stored; adding an indicator does not flag older events (search for it instead).

## Sample data

The **Sample data** switch at the top right of the UI (admins only) loads about 380 demo events covering the last
24 hours, so you can try searching before real logs arrive. Analysts see a "Sample data on" label instead.

- Background traffic: web requests, firewall blocks, DNS lookups, VPN logins, database housekeeping and backups.
- An incident to investigate: a web scanner, an SSH brute force against `web1` that ends in a successful login,
  a malware download and antivirus detection, blocked C2 callouts, and password guessing against the database
  and domain controller. Also, `bob` logs in to the VPN from two continents 15 minutes apart.
- Every sample event has a **SAMPLE** badge. GeoIP, ASN and threat intel context are filled in for the sample's
  addresses, so the INTEL badge and country filters have something to show without real databases or feeds.
- Only documentation IP ranges, documentation AS numbers and `.example` domains are used.
- Turning it on again reloads the data with fresh timestamps. Turning it off deletes the sample events and nothing
  else: they carry a marker that real logs can't set.
- `POST /api/v1/sample` with `{"enabled": true}` or `false` does the same (signed-in admins only);
  `GET /api/v1/sample` reports the state.

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

**Upgrading from v0.2:** the database is upgraded automatically on first start and keeps every event. Events stored
before the upgrade have no source, host or enrichment.

**Upgrading from v0.1:** read and admin API keys no longer exist and are revoked on first start. Sign in with the
`admin` account created for you (or create users with `siemlite users create`). Write keys keep working.

## Options

Each flag can also be set with an environment variable named `SIEMLITE_` plus the flag name in capitals with `_` for
`-` (e.g. `SIEMLITE_GEOIP_CITY`). A flag on the command line wins. `SIEMLITE_INTEL_FEED` takes several feeds separated
by spaces.

| Flag | Default | Meaning |
|---|---|---|
| `-addr` | `localhost:8443` | HTTPS listen address |
| `-db` | `siemlite.db` | SQLite database path |
| `-retention-days` | `30` | Delete events older than this many days (checked daily) |
| `-tls-cert`, `-tls-key` | `<db dir>/siemlite.crt`, `.key` | Certificate and key; a self-signed pair is generated if both are missing |
| `-tls-hosts` | | Extra DNS names or IPs for a generated certificate |
| `-sample` | `false` | Load sample data at startup if it is not already loaded (same as the UI switch) |
| `-syslog-udp`, `-syslog-tcp`, `-syslog-tls` | | Syslog listen addresses, e.g. `:514`, `:514`, `:6514` (each off when empty) |
| `-syslog-allow` | loopback and private networks | Comma-separated IPs/CIDRs allowed to send syslog |
| `-geoip-city` | | MaxMind or DB-IP City/Country `.mmdb` |
| `-geoip-asn` | | MaxMind or DB-IP ASN `.mmdb` |
| `-intel-feed` | | Threat intel feed as `name=https://url`; repeat for several |
| `-intel-refresh` | `6h` | How often to re-download feeds |

## How it works

```
clients ──HTTPS + API key──▶ api ─────┐
devices ──syslog UDP/TCP/TLS──▶ syslogd ┴─▶ enrich (GeoIP, threat intel) ─▶ ingest worker pool ─▶ batched SQLite transactions
                                                                          (500 events or 500 ms)            │
                               api ──▶ search engine ──▶ events ⋈ events_fts ◀──────────────────────────────┘
                                       retention worker (daily delete + incremental vacuum)
                                       intel service (feed refresh, reload on change)
```

- **`pkg/ocsf`**: event model and validation.
- **`pkg/parser`**: raw log lines to OCSF events.
- **`pkg/storage`**: SQLite setup (WAL, `synchronous=NORMAL`, `busy_timeout=5000`), schema, queries. `events_fts` is an
  external-content FTS5 table kept in sync by triggers, so log text is not stored twice.
- **`pkg/ingest`**: enriches each event, then a buffered channel and worker pool that flushes in batches.
- **`pkg/syslogd`**: UDP, TCP and TLS syslog listeners with a sender allowlist.
- **`pkg/enrich`**: enrichment document and GeoIP/ASN lookups (`.mmdb`, reloaded on change).
- **`pkg/intel`**: feed parsing, the in-memory indicator matcher and feed refresh.
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
