# SIEMLite

[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE) [![Open Source](https://img.shields.io/badge/open%20source-OSI%20approved-brightgreen.svg)](https://opensource.org/license/agpl-v3)

A lightweight, embedded SIEM in a single Go binary. It collects logs over HTTPS, normalizes them to the
[OCSF](https://schema.ocsf.io/) event model, stores them in SQLite, one file per day, and gives you full-text search through
a built-in web UI and a small JSON API.

- **Send any log**: over HTTPS, or native syslog on UDP, TCP or TLS. Syslog, JSON lines or plain text; the parsed event is stored, and the original line is kept for 24 hours after it arrives.
- **OCSF-normalized**: category, class and severity mean the same thing across sources.
- **Enrichment**: GeoIP country/city and ASN for public IPs, and threat intel matching against IP, CIDR, domain and hash blocklists.
- **A quiet web UI**: one search field to start, light and dark themes (or follow the system), and fonts bundled
  in the binary, so the UI never contacts a font service.
- **Full-text search**: SQLite FTS5 over the message, program, host, user, addresses and parsed fields, combined with time, severity, category, IP, user, source, country, ASN and threat filters.
- **HTTPS only**: no plain-HTTP listener. Self-signed certificate generated on first start, or bring your own.
- **Sources and parsers**: each application gets an access token that can only send logs, with a "last used" time and
  a parser of your choice. Build parsers in the UI from sample lines, upload them, or let a local AI model suggest one.
- **Alerts**: rules that watch for patterns, like 10 failed SSH passwords from one address in 5 minutes, with four
  built in. Acknowledge and close alerts on the Alerts page.
- **Audit log**: sign-ins, changes to users, sources, parsers and rules, backups and restores are recorded as events
  from the **INTERNAL** source, searchable like any other log.
- **Test logs built in**: `loggen` sends realistic logs from a fictional company, attacks included, at 1 to 1,000,000
  events a second, to SIEMLite (set up for it out of the box) or any SIEM over syslog.
- **People and permissions**: Admins manage everything; Standard users search, optionally limited to chosen sources.
- **One file per day**: each day's events are their own SQLite file, so storing stays fast as history grows, searches
  with dates only open the days they need, and retention just deletes old days.
- **Pure Go, no CGO**: uses [`modernc.org/sqlite`](https://pkg.go.dev/modernc.org/sqlite).

> Early-stage project. Client-certificate (mTLS) verification and per-key rate limiting are not implemented yet.

## Quick start

Download a prebuilt binary for Linux, macOS or Windows (x86-64 or ARM64) from the
[latest release](https://github.com/justwaters/SIEMLite/releases/latest), check it against `SHA256SUMS`, unpack it and run
`./siemlite`. Or build it yourself (requires Go):

```sh
git clone https://github.com/justwaters/SIEMLite.git
cd SIEMLite
go build -o siemlite .
./siemlite
```

On first start SIEMLite creates `siemlite.db` (users, sources, rules, alerts and settings) and a `siemlite-events`
folder for the events, generates `siemlite.crt` / `siemlite.key`, and creates an `admin` user
with a random password that is printed **once**. Copy it. Open <https://localhost:8443> and sign in; your browser will
warn about the self-signed certificate unless you trust `siemlite.crt` or supply your own with `-tls-cert` / `-tls-key`.

Nothing to look at yet? Run the log generator next to it, which SIEMLite sets up on first start: `loggen -eps 10`
sends ten realistic test events a second, attacks included. See [Test logs](#test-logs).

### Run with Docker

The web UI is built into the binary, so this is a single container. Every release is published as an image for x86-64
and ARM64: set `SIEMLITE_IMAGE=ghcr.io/justwaters/siemlite:v0.9` in `.env` and run `docker compose pull && docker compose up -d`.
Or build from the checkout, and deploy and upgrade with one command:

```sh
git clone https://github.com/justwaters/SIEMLite.git && cd SIEMLite
cp .env.example .env        # optional: ports, certificate names, GeoIP, feeds, retention
git pull && docker compose up -d --build
docker compose logs siemlite | grep -A1 'username: admin'   # the admin password, printed on first start
```

The password is printed only by the first container. Rebuilding replaces the container and its logs, so if you
missed it, set a new one: `docker compose exec siemlite siemlite users passwd -username admin`.

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
  `docker compose exec siemlite siemlite users create -username alice -role standard`, and the same for `keys`
  and `intel`. To import a feed file, pipe it in: `docker compose exec -T siemlite siemlite intel import -source x -file - < iocs.txt`.
- Syslog senders keep their real IP through Docker's port mapping, so `-syslog-allow` works. The exception is a
  sender on the Docker host itself, which appears as the Docker network's gateway address.
- The image is about 25 MB, has no shell, and runs as an unprivileged user. Docker restarts it if `/health` stops
  answering.

### The pages

- **Dashboard**: a search field and the last 24 hours, 7 days or 30 days at a glance: events, threat intel matches,
  high-severity events, events over time, severity, busiest sources and the IPs on threat lists. Type a search and press
  Enter to open the results in the Database.
- **Database**: every event, newest first, with full-text search, a **From mm/dd/yy to mm/dd/yy** date range and filters
  for source, severity, category, IPs, user, program, country and threat matches. Open an event for its details.
  The address bar keeps the search, so it can be bookmarked or shared.
- **Alerts**: alerts raised by the rules, by severity, with how many events and when. Open the events behind an alert,
  acknowledge it while you look into it, then close it. The **Rules** tab lists the rules; admins add, edit and switch them off.
  Users limited to some sources don't see alerts, since a rule looks at every source.
- **Users** (admins): add people, set their role, limit what they can see, change passwords.
- **Sources** (admins): create access tokens, see when each source last sent logs, choose its parser, add logs by hand.
- **Parsers** (admins): build, upload, export and edit parsers.
- **System** (admins): the version, database size and uptime, and backups: create, schedule, download, upload, restore and delete.

### Send logs from an app

On the **Sources** page, choose **New access token**, name it after the app and optionally pick a parser. The token is
shown once. Tokens can only send logs; they can't search or sign in. From the command line:

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

Sign in to the UI and search from the Dashboard or the Database. Searching is for signed-in users only; access tokens
are refused. Standard users limited to some sources only ever see events from those sources.
The search API uses the same browser session (an `HttpOnly` cookie), so it is meant for the UI rather than scripts.

`q` uses [FTS5 query syntax](https://www.sqlite.org/fts5.html#full_text_query_syntax): `failed AND ssh`,
`"invalid user"`, `admin*`.

Full-text search covers the parsed event: its message, program, host, user, source and destination addresses and the
extra fields a parser picked out. The original line is kept for 24 hours after it arrives (shown in an event's details),
then removed; the parsed event stays for the whole retention period and is what the Database page shows. Searching works
the same before and after the original goes, so search for what the parser understood rather than for a stray piece of
the raw text.

## API

| Endpoint | Who | Purpose |
|---|---|---|
| `POST /api/v1/logs` | access token, or admin | Raw log text, one entry per line, read with the source's parser. Optional `source` (program name) and `severity` query params. |
| `POST /api/v1/events` | access token, or admin | JSON array of OCSF events (up to 10,000 per request). |
| `GET /api/v1/search` | any signed-in user | `q`, `start`, `end` (RFC3339 or epoch ms), `severity`, `category`, `class`, `src_ip`, `dst_ip`, `user`, `source` (program), `source_id`, `host`, `country`, `asn`, `threat=true`, `limit` (max 1000), `offset`. Newest first. Each event includes its parsed `message`, its `source_name`, extra parsed `fields` and `enrichment`, and `raw_data`, the original line (empty once it has been removed, 24 hours after the event arrived). |
| `GET /api/v1/stats?hours=24` | any signed-in user | Dashboard figures for the last 1-2160 hours. |
| `GET /api/v1/sources` | any signed-in user | Admins get every source; others get the names of the sources they can see. |
| `POST /api/v1/sources`, `PATCH`/`DELETE /api/v1/sources/{id}` | admin | Create an access token (`{"name", "parser_id"}`), rename or set the parser (`"parser_id": null` for automatic), revoke. |
| `GET`/`POST /api/v1/users`, `PATCH`/`DELETE /api/v1/users/{id}`, `POST /api/v1/users/{id}/password` | admin | Manage users: `{"username", "password", "role", "limited", "sources"}`. A limited standard user sees only `sources`. Updates change only the fields sent. |
| `GET`/`POST /api/v1/parsers`, `GET`/`PUT`/`DELETE /api/v1/parsers/{id}`, `GET /api/v1/parsers/templates` | admin | Manage parsers. |
| `GET /api/v1/alerts?status=open` | any signed-in user not limited to some sources | Alerts (`open`, `acknowledged`, `closed` or `all`) and the count in each state. |
| `PATCH /api/v1/alerts/{id}` | same | Acknowledge, close or reopen: `{"status": "acknowledged"}`. |
| `GET /api/v1/rules`, `POST /api/v1/rules`, `PUT`/`DELETE /api/v1/rules/{id}` | any signed-in user (list), admin | Alert rules: `{"name", "description", "enabled", "severity", "query", "min_severity", "threat_only", "source_id", "group_by", "threshold", "window_minutes"}`. |
| `GET /api/v1/system` | admin | Database size and version, uptime, backups folder and free space. |
| `GET`/`POST /api/v1/backups`, `PUT /api/v1/backups/settings`, `POST /api/v1/backups/upload` | admin | List backups and the job status, start a backup, set the schedule (`{"interval_hours": 0/6/24/168, "keep"}`), upload a backup file. |
| `GET`/`DELETE /api/v1/backups/{name}`, `POST /api/v1/backups/{name}/restore` | admin | Download or delete a backup; restore it (SIEMLite restarts). |
| `POST /api/v1/parsers/test`, `POST /api/v1/parsers/suggest` | admin | Run a parser over `{"definition", "lines"}`; ask the AI model for a parser for `{"lines"}`. |
| `POST /api/v1/login`, `POST /api/v1/logout`, `GET /api/v1/me` | | Browser sign-in, sign-out and current session. |
| `GET /health` | public | Up/down only. When signed in it also returns event count, database size, ingest queue state, indicator count and syslog counters. |

Applications authenticate with `Authorization: Bearer <token>`. A missing or revoked token returns `401`; a token used
for anything but sending logs returns `403`.

Events must be dated within the retention period and no more than a day ahead (a sender's clock can run a little fast).
Others are refused and counted as rejected, with the reason, since each day's events are kept in their own file.

### Log parsing

`/api/v1/logs` converts each line into an OCSF event: syslog (RFC 3164 and 5424) headers give the time and hostname,
the first two IPv4 addresses become source and destination, a user is picked up from patterns like `for user alice`,
and severity comes from the syslog priority or keywords (`error`, `failed`, `warning`, ...). JSON objects that already
contain `category_uid` are stored as OCSF; other JSON uses its `message`, `level` and timestamp fields. The detection
is heuristic; use `?severity=` to override it, or give the source a parser.

## Parsers

A parser tells SIEMLite how to read one source's lines: where the time, IPs, user and severity are, and which other
values to keep. Choose a parser for a source on the Sources page; sources without one are parsed automatically.
Build one on the Parsers page: paste a few sample lines, describe them, and the preview shows how each line is read.

- **Text with a fixed layout**: write one line out with `{name}` where values change, e.g.
  `{src_ip} - {user} [{time}] "{method} {path} {protocol}" {status}`. Spaces match any run of spaces, `{}` skips text,
  and `{name:regex}` sets exactly what to match (`{status:\d+}`).
- **JSON objects** and **key=value pairs**: every field is picked up; nested JSON keys read as `client.ip`.
- **Fields**: values named like `time`, `src_ip`, `dst_port`, `user`, `host`, `message` or `level` fill the event
  automatically; map any other name in the Fields table. Everything else is kept as an extra field, shown in the
  event's details.
- **Syslog**: tick "Lines start with a syslog header" and the pattern only needs to describe the message.
- **Severity**: detected from the line, always the same, or decided by rules on a field (e.g. status `^5` -> High).
- **Templates** for web server access logs, JSON application logs and key=value firewall logs.
- **Upload and export** parsers as small JSON files to share them or keep them in version control.
- A line that doesn't match its source's parser is still stored, parsed automatically, with a `parse_error` field.

### AI help

With a local model running in [Ollama](https://ollama.com), the editor gets a **Suggest a parser** button. SIEMLite
removes syslog headers and recognises JSON and key=value lines itself, drafts a pattern that matches every sample
line, and asks the model to name the fields and pick severity and category. It keeps the model's answer only when it
still reads every sample line. Nothing leaves your network.

With Docker, add to `.env` and run `docker compose up -d` (the model, about 2 GB, downloads once on first start):

```sh
COMPOSE_PROFILES=ai
SIEMLITE_AI_URL=http://ollama:11434
```

Without Docker, run Ollama yourself and start SIEMLite with `-ai-url http://localhost:11434`. The default model is
`qwen2.5-coder:3b`, which runs on a CPU; a suggestion takes about 10-40 seconds there. Choose another with `-ai-model`.

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

## Test logs

`loggen` (in [`cmd/loggen`](cmd/loggen/main.go)) sends random, realistic test logs at a steady rate, for trying SIEMLite
out or load-testing it. It describes a small company: a firewall, two web servers, an SSH bastion, VPN, DNS, a database,
mail, backups and workstation antivirus, with attacks mixed in (SSH brute force, port scans, malware calling home and
password spraying against the VPN), so the alert rules have something to find.

```sh
loggen -eps 10                       # to SIEMLite on this machine
loggen -eps 1k -for 10m              # a load test
loggen -eps 100 -to udp://siem:514   # to any SIEM over syslog
loggen -eps 1 -to stdout             # just look at the lines
```

- **Rate**: `-eps` takes 1, 10, 100, 1k, 10k, 100k or 1m events a second (any number works). It keeps that rate for as
  long as it runs (until you stop it, or `-for` ends it): a slow moment or a restart of the receiver is made up for, but
  only up to a second's worth, so a long outage doesn't end in a flood. It can make well over a million lines a second;
  how many arrive depends on the receiver. When SIEMLite is busy it answers `503`, and loggen waits as asked and sends the
  rest again, so nothing is lost, and the progress line says when the rate it achieved is below the one you asked for.
- **Keep it running in the background**: `docker compose exec` stops when your terminal does. To send continuously, turn
  on the `loggen` service: add `testlogs` to `COMPOSE_PROFILES` in `.env` (`COMPOSE_PROFILES=testlogs`, or
  `ai,testlogs`), set the rate with `LOGGEN_EPS=100` (default 10), and run `docker compose up -d`. It restarts with Docker,
  carries on through restarts and upgrades of SIEMLite, and logs a progress line a minute. Remove `testlogs` and run
  `docker compose up -d --remove-orphans` to stop it. Without Docker, run `nohup loggen -eps 10 > /dev/null 2>&1 &`, or
  from systemd or any process manager.
- **Set up for you**: on first start SIEMLite creates a **Log generator** parser and an access token source that uses
  it, and saves the token as `siemlite-loggen.token` next to the database. loggen reads that file and trusts
  `siemlite.crt`, looking in the current folder and in `/data`, so it needs no options on the same machine. With Docker
  it's in the image: `docker compose exec siemlite loggen -eps 10`. The token can only send logs; revoke the source on
  the Sources page to turn it off. It isn't created again.
- **Its own format**, not syslog, JSON or key=value, so it shows a parser at work:
  `time|host|app|level|action|src_ip|src_port|dst_ip|dst_port|user|message`, for example
  `2026-10-04T13:42:07.123Z|bastion-01|sshd|warning|auth.failure|203.0.113.7|51234|10.0.4.12|22|root|Failed password for root from 203.0.113.7`.
  Empty fields are `-`. Addresses outside the company are from documentation ranges only.
- **For other SIEMs**: point `-to` at a syslog port (UDP or TCP, RFC 3164), or at any URL that takes lines like
  SIEMLite's `/api/v1/logs` (`-servername` checks its certificate against another name, `-insecure` skips the check). It uses only Go's standard library, and `-seed` repeats the same logs.

Binaries for loggen come with every release, next to `siemlite`. To build it: `go build -o loggen ./cmd/loggen`.

## Alerts

A rule counts matching events and raises an alert when there are enough of them within a time window. Matching events
can be narrowed by a search (the same syntax as the Database), a minimum severity, threat intel matches and a source,
and counted separately for each source address, destination address, user or host. The alert engine checks new events
every 10 seconds.

| Built-in rule | Raises an alert for |
|---|---|
| SSH brute force | 10 `"failed password"` events from one address within 5 minutes |
| Threat intel match | any event involving an address, domain or hash on a threat list |
| Critical event | any event rated Critical or Fatal, per host |
| Failed sign-ins to SIEMLite | 5 failed sign-ins to SIEMLite itself from one address within 15 minutes |

While an alert is open or acknowledged, more matching events add to it instead of raising a new one. Once it's closed,
the next match raises a new alert. Built-in rules can be edited or switched off but not deleted. The [log
generator](#test-logs)'s attacks raise alerts too.

## Audit log

SIEMLite records what people do in it as events from the built-in **INTERNAL** source: sign-ins, failed and blocked
sign-ins, sign-outs, changes to users, sources, parsers and rules, alerts acknowledged or closed, and backups created, downloaded, uploaded, restored or deleted. Command-line changes are recorded too, as "command line
(user)". Each event names who did it and from which address, and has an `action` field such as `signin.failed` or
`user.delete`. Search for them in the Database by choosing the INTERNAL source, or with a search like `"sign-in failed"`.
They are kept, and removed by retention, like any other events.

A failed sign-in names the account only if it exists; otherwise it says "an unknown username", so a password typed
into the username field is never stored. Every failed sign-in is recorded until the address is locked out; the lockout is
recorded once, not each retry. Beyond 600 failed sign-ins a minute (a flood from many addresses) the rest are counted
in one Critical event, which raises an alert. Every analyst who isn't limited to some sources can
read the audit log and acknowledge or close alerts.

## Backups

On the **System** page, choose **Create backup now**, or set automatic backups to run every 6 hours, every day or every
week, keeping the newest 1-365. A backup is a compressed copy of everything (every day's events, users, sources,
parsers, rules, alerts and settings), made while SIEMLite keeps running and logging.

- **Restore**: SIEMLite checks the backup, saves the current database as a "Before a restore" backup, restarts, and
  comes back with the backup in place, usually within seconds. To undo, restore the "Before a restore" backup.
  Backups from older versions are upgraded as they open; backups from newer versions are refused. Version 0.7 and
  earlier can't restore backups made by 0.8 or later.
- **Download** a backup to keep a copy off the server, and **Upload** one (a `.tar.gz`, a `.db.gz` from before version
  0.8, or a `.db` file) to move SIEMLite to
  a new server or recover after losing the old one. Uploads are checked before they're accepted.
- Old automatic backups are removed as new ones are made. Manual, uploaded and "Before a restore" backups are only
  removed when you delete them.
- Backups are kept in `<db folder>/backups` (`/data/backups` with Docker, inside the same volume as the database), or
  wherever `-backup-dir` points. Keep copies somewhere else too: download them, or point `-backup-dir` at other storage.

From the command line (works while the server runs; a restore is applied at the next start):

```sh
./siemlite backups create
./siemlite backups list
./siemlite backups restore -name siemlite-20261003-211924-manual.tar.gz
```

## Users

People sign in with a username and password. Manage them on the Users page or from the command line. There are two roles:

- **Admin**: everything, including the Users, Sources, Parsers and System pages.
- **Standard**: the Dashboard and Database. A standard user can be limited to the events from chosen sources; they then
  see only those sources' events, in search and on the dashboard.

There must always be at least one admin, and admins can't delete themselves.

```sh
./siemlite users create -username alice -role standard  # prompts for a password (min 12 characters)
./siemlite users list
./siemlite users passwd -username alice                 # also signs alice out everywhere
./siemlite users delete -username alice
```

Passwords are stored as bcrypt hashes. Sessions last 12 hours, use an `HttpOnly`, `Secure`, `SameSite=Strict` cookie,
and end on sign-out. After 10 failed sign-ins in 15 minutes a client address is locked out for the rest of the window.

## Sources

Every event belongs to a source: an **access token** an application sends with, the **Syslog** listener, **Added in
the UI** (logs pasted or uploaded on the Sources page) or **INTERNAL** (SIEMLite's own audit log). Each shows when it
was last used, so you can see which are active, and each (except INTERNAL) can have a parser. A new install also has a
**Log generator** token source for [test logs](#test-logs).

Access tokens can only post to `/api/v1/logs` and `/api/v1/events`. Revoking one stops it immediately; its events are
kept. From the command line:

```sh
./siemlite keys create -name <name>
./siemlite keys list      # with last used times
./siemlite keys revoke -id <id>
```

Tokens look like `slk_...`. Only a SHA-256 hash is stored, so a token is shown once at creation. The `keys` and `users`
commands work while the server is running. Pass `-db` if your database is not `./siemlite.db`.

**Upgrading from v0.8:** each day file is upgraded once, when the server (or a command) first opens it: the stored line
becomes the event's message and the search index is rebuilt over the parsed event, which can take a little while on a
large history. Original lines from before the upgrade are removed about 24 hours later, like any other. Backups made
before the upgrade can still be restored; backups made after it can't be restored by 0.8.

**Upgrading from v0.7 or earlier:** Sample data is gone: its events, alerts and source are deleted, and the [log
generator](#test-logs) takes its place. Events move from `siemlite.db` into one file per day in the background after the
first start (the log shows progress, and a restart resumes where it stopped). Search, the dashboard and alerts work
throughout. When it finishes, `siemlite.db` shrinks to just users, sources, rules, alerts and settings. Make a backup
first if you like; backups made by 0.8 can't be restored by 0.7.

**Upgrading from v0.4:** the database is upgraded automatically and keeps every event. API keys become access token
sources and keep working; analysts become Standard users who can see every source. Everyone is signed out once
during the upgrade. Events stored before it have no source except sample data.

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
| `-db` | `siemlite.db` | SQLite database path; events go in a folder beside it named after it (`siemlite-events`) |
| `-retention-days` | `30` | Delete events older than this many days (checked daily; whole days are deleted as files) |
| `-tls-cert`, `-tls-key` | `<db dir>/siemlite.crt`, `.key` | Certificate and key; a self-signed pair is generated if both are missing |
| `-tls-hosts` | | Extra DNS names or IPs for a generated certificate |
| `-syslog-udp`, `-syslog-tcp`, `-syslog-tls` | | Syslog listen addresses, e.g. `:514`, `:514`, `:6514` (each off when empty) |
| `-syslog-allow` | loopback and private networks | Comma-separated IPs/CIDRs allowed to send syslog |
| `-geoip-city` | | MaxMind or DB-IP City/Country `.mmdb` |
| `-geoip-asn` | | MaxMind or DB-IP ASN `.mmdb` |
| `-intel-feed` | | Threat intel feed as `name=https://url`; repeat for several |
| `-intel-refresh` | `6h` | How often to re-download feeds |
| `-ai-url` | | Ollama server for AI parser help, e.g. `http://ollama:11434` (off when empty) |
| `-ai-model` | `qwen2.5-coder:3b` | Model for AI parser help; downloaded on first start if missing |
| `-backup-dir` | `<db dir>/backups` | Folder for database backups |

`siemlite version` prints the version.

## How it works

```
clients ──HTTPS + token──▶ api ───────┐
devices ──syslog UDP/TCP/TLS──▶ syslogd ┴─▶ enrich (GeoIP, threat intel) ─▶ ingest worker pool ─▶ batched transactions,
                                                                          (500 events or 500 ms)  one per day file
                                                                                                           │
                               api ──▶ search engine ──▶ day files, newest first ◀──────────────────────────┘
                                       (events ⋈ events_fts in each)
                                       retention worker (deletes old day files)
                                       intel service (feed refresh, reload on change)
```

- **`pkg/ocsf`**: event model and validation.
- **`pkg/parser`**: automatic parsing, custom parsers (pattern, JSON, key=value), templates and pattern drafting.
- **`pkg/sources`**: applies each source's parser to its lines.
- **`pkg/ai`**: parser suggestions from a local model via Ollama.
- **`pkg/backup`**: backups (`VACUUM INTO` of every file, in a `.tar.gz`), the schedule, uploads, and restores applied at
  startup.
- **`pkg/storage`**: SQLite setup (WAL, `synchronous=NORMAL`, `busy_timeout=5000`), schema, queries. Events are stored
  one file per UTC day by when they happened (`siemlite-events/2026-10-04.db`); everything else is in `siemlite.db`.
  A search reads the days newest first and stops as soon as the page is full; within a day, a search with many matches
  reads them newest first instead of sorting them all. Each day's `events_fts` is an external-content FTS5 table kept
  in sync by a trigger and one bulk update per batch, so log text is not stored twice. It indexes the parsed message, program, host, user, addresses and fields, not the original line, which an hourly job clears 24 hours after the event arrived (by arrival, tracked with arrival-number watermarks, so late events keep theirs for a day too). Event ids carry their day, and an arrival number lets the alert
  engine find late events filed in older days.
- **`pkg/ingest`**: enriches each event, then a buffered channel and worker pool that flushes in batches.
- **`pkg/syslogd`**: UDP, TCP and TLS syslog listeners with a sender allowlist.
- **`pkg/enrich`**: enrichment document and GeoIP/ASN lookups (`.mmdb`, reloaded on change).
- **`pkg/intel`**: feed parsing, the in-memory indicator matcher and feed refresh.
- **`pkg/search`**: combines time window, OCSF filters and FTS5.
- **`pkg/retention`**: deletes expired days' files, and older events from the day the cutoff falls in.
- **`pkg/alerts`**: the alert engine: runs each rule over the events since its last check.
- **`pkg/audit`**: writes the audit log as INTERNAL events.
- **`pkg/auth`**: access tokens, users, roles, source limits, sessions and permission checks.
- **`api`**: HTTPS server and endpoints. **`web`**: the embedded UI.

## Performance

Measured with the load tests in [`loadtest`](loadtest/doc.go) (`SIEMLITE_LOAD=hard`) on one small machine: an AMD Ryzen
Embedded R2544 (4 cores, 8 threads), 14 GB of memory and an SSD, with the database on that SSD. Each figure is the 95th
percentile with many clients working at once.

The table below is version 0.7, which kept every event in one file, at 5 million events. Version 0.8 stores one file per
day, and stores batches with multi-row inserts and one text-index update per batch, which made storing about four
times faster. Measured on the `small` tier (500,000 events across 30 days, 8 senders): logs over HTTPS 19,500 events/s
stored and searchable, TCP syslog 21,000 lines/s, filling storage directly 31,000 events/s, searches 6-170 ms, results
5,001-5,100 about 450 ms, the dashboard 65 ms, the first alert check under 1 s, and backup and restore 4 s and 2 s.

| Workload | Result |
|---|---|
| Logs over HTTPS, 32 apps sending 500-line batches at once | 4,600 events/s accepted, 3,700/s stored and searchable (about 320 million a day) |
| Syslog over UDP at 4,000 messages/s for 75 s | 300,000 of 300,000 stored |
| Syslog over TCP, 4 senders as fast as they can | 4,100 lines/s stored, none lost |
| Search 5 million events (2.4 GB), 16 people at once: newest page, a common word, an address, a user | 4-27 ms |
| ... a phrase, three words with AND, a host and severity | 28-80 ms |
| ... a word within one day, results 5,001-5,100 | 190-200 ms (a user limited to some sources: up to 530 ms) |
| Dashboard over 5 million events | 1.4 s |
| Alert rules, first check of all 5 million events | 7 s |
| Backup of 5 million events (684 MB compressed) / restore | 33 s / 21 s |

When senders outpace storage, SIEMLite answers `503` with `Retry-After` and how many lines it kept, so nothing is
lost silently; UDP syslog has no way to push back, so keep its rate under what storage sustains.

Version 0.7 made search much faster on large databases. On 500,000 events with 8 people searching at once:

| Search | v0.6 | v0.7 |
|---|---|---|
| A common word | 2,330 ms | 20 ms |
| Results 5,001-5,100 for a common word | 3,131 ms | 78 ms |
| An address | 299 ms | 1 ms |
| A host and severity, by a user limited to some sources | 960 ms | 41 ms |

## Development

```sh
go test -race ./...                                   # everything below except load and fuzzing
SIEMLITE_LOAD=small go test ./loadtest -run Load -v   # load tests: ci (~1 min), small (~6 min), or hard with SIEMLITE_LOAD_FOR=5m, 30m or 2h
go test ./pkg/parser -run '^$' -fuzz FuzzDraftPattern # one fuzzer; see .github/workflows/ci.yml for all of them
python3 e2e/ui_test.py ./siemlite                     # browser test (needs Playwright for Python)
```

The tests go beyond examples:

- **Every route, every caller**: the API's route table is read from the source, and each route is called with no
  credentials, a forged cookie, a bad token, a valid access token, a standard user and an admin, and cross-site. A new
  route can't ship without a permission.
- **Limited users never see other sources**: random users get random sets of sources and run random searches, filters
  and pages; their results must equal an admin's results less the sources they weren't given.
- **Upgrades from every version**: a populated database from every schema version SIEMLite has shipped is upgraded and
  must end up identical to a new one, with every row, reference and search index intact.
- **Day files against one table**: every search, filter and page across day files (with late events, clocks ahead and
  ties at midnight) must equal the same events searched in one table; the dashboard must add up the same; and moving
  events out of an old database while searches run must never show one twice or miss one.
- **Fuzzing**: log lines, parser patterns, the pattern builder, syslog framing, backup names and threat intel feeds get
  millions of generated inputs. This found and fixed four ways the pattern builder could draft a pattern that didn't
  match its own sample lines.
- **Everything at once**: ingest over HTTPS and syslog, searches by admins and limited users, retention, backups, the alert
  engine, the log generator and user changes run together, under the race detector too. Nothing may be lost, leaked or
  corrupted, and every backup must open. This found backups failing with "database is locked" on a busy server; fixed.
- **Load**: ingest over HTTPS, syslog floods and searches on millions of events, each with a floor it must reach;
  see [Performance](#performance). Running these found and fixed slow searches for common words and deep pages, and an
  alert engine that would have needed minutes for a large database.
- **In a browser**: a real SIEMLite fed by the log generator is clicked through page by page, at desktop and phone
  sizes, until the generator's brute force shows up as an alert.

Every pull request and every commit on `main` runs these on GitHub (`.github/workflows/ci.yml`): formatting, `go vet`,
the tests with the race detector, the `ci` load tests, 20 seconds of each fuzzer, the browser test, a build, a syntax
check of the web UI's script, `govulncheck` for known vulnerabilities in code SIEMLite actually calls, and a build of the
Docker image for x86-64 and ARM64.

## License

SIEMLite is free and open-source software, released under the
[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0), which is approved by the
[Open Source Initiative](https://opensource.org/license/agpl-v3).

You may use, modify and redistribute it, including commercially. If you modify SIEMLite and let others interact with
it over a network (for example, by running it as a service), you must offer those users the complete source code of
your modified version under the same license. The web UI links to this repository to make that easy; if you fork it,
point that link (the footer in `web/static/index.html`) at your own source.
