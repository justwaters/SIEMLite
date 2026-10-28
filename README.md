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
- **HTTPS only**: a self-signed certificate is generated on first start, or SIEMLite gets one from Let's Encrypt for your domain and
  renews it (see [Run on the internet](#run-on-the-internet)), or bring your own.
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
and ARM64: set `SIEMLITE_IMAGE=ghcr.io/justwaters/siemlite:v0.26` in `.env` to use it, or leave it out to build from the
checkout. Either way, start and update with `./update.sh`:

```sh
git clone https://github.com/justwaters/SIEMLite.git && cd SIEMLite
cp .env.example .env        # optional: ports, certificate names, GeoIP, feeds, retention
./update.sh                 # starts SIEMLite; run it again to update
docker compose logs siemlite | grep -A1 'username: admin'   # the admin password, printed on first start
```

`./update.sh` gets the newest release (moving `SIEMLITE_IMAGE` in `.env` to it) or, when built from the checkout, runs
`git pull` and rebuilds; then it restarts SIEMLite, says which version it went from and to, and waits until it is healthy:

```
Downloading SIEMLite v0.19.1...
Updating SIEMLite v0.19 -> v0.19.1
SIEMLite v0.19.1 is up.
```

`./update.sh v0.19` picks a particular release. Going back to an older one warns that the database may have been changed
by the newer version, and asks first. `docker compose pull && docker compose up -d` (or `docker compose up -d --build`)
still works too; it just doesn't say what changed.

The password is printed only by the first container. Rebuilding replaces the container and its logs, so if you
missed it, set a new one: `docker compose exec siemlite siemlite users passwd -username admin`.

- The database and certificate live in the `siemlite-data` volume, so rebuilds and upgrades keep every event,
  account and key. `docker compose down` keeps the volume; `docker compose down -v` deletes it.
- Ports: HTTPS on 8443, syslog on 514 (UDP and TCP) and syslog over TLS on 6514. Change the host ports in `.env`.
  The local port, 8444, is published on `127.0.0.1` only, so only the server itself reaches it (see [Sign-in restrictions](#sign-in-restrictions)).
- Settings: every server flag can be set in `.env` as `SIEMLITE_<FLAG>`, e.g. `SIEMLITE_SYSLOG_ALLOW=10.0.0.0/8`
  for `-syslog-allow`. `.env.example` lists the useful ones.
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

### Run on the internet

SIEMLite can get a certificate from [Let's Encrypt](https://letsencrypt.org) for your domain and renew it by itself, so browsers
and apps trust it with no warning and nothing else to install. Before you start:

- A DNS name (an A or AAAA record) that points at this server's public address, such as `siem.example.com`.
- Port **443** reachable from the internet and forwarded to SIEMLite: Let's Encrypt connects to it to check you control the name.
  With Docker, publish it with `SIEMLITE_HTTPS_PORT=443` in `.env` (and leave `SIEMLITE_BIND` empty, or set it to the public address),
  then `docker compose up -d`. Without Docker, use `-addr :443` (as root, or after `sudo setcap cap_net_bind_service=+ep ./siemlite`).

Then on the **System** page, under **HTTPS certificate**, choose **Let's Encrypt**, enter the domain, choose **Check this address** (it
confirms that the name and port 443 really lead to this SIEMLite), and **Save**. The status shows the certificate being obtained,
usually within seconds, then who issued it and until when. Or set it from the start in `.env` with `SIEMLITE_TLS_MODE=letsencrypt` and
`SIEMLITE_DOMAIN=siem.example.com`; what you save on the System page takes precedence.

- **Nothing is lost if it fails.** Only visitors who ask for that domain get its certificate. Anyone using another address (an IP or a
  LAN name), and the domain itself until its certificate arrives, still gets the self-signed one, so you can always get back in and
  switch back. The status says what went wrong (DNS, port 443, Let's Encrypt's rate limit).
- **Renewal is automatic**, well before the certificate expires. The certificate and the Let's Encrypt account are kept in an `acme`
  folder next to the database (`/data/acme` with Docker, so in the volume); keep it, or a rebuild asks Let's Encrypt again and can
  hit its rate limits.
- **Syslog over TLS** uses the same certificate for senders that ask for the domain.
- **Apps sending logs** use `https://siem.example.com/api/v1/logs`. The certificate is trusted everywhere, so the snippets on the
  Connect screen work without `siemlite.crt`; remove those lines.
- **Microsoft sign-in**: set the SIEMLite address on the Entra card to `https://siem.example.com`.
- Only port 443 is needed; there is no plain-HTTP port to redirect from. **Syslog** keeps its own ports, and senders outside loopback
  and private networks are refused unless you list them in `SIEMLITE_SYSLOG_ALLOW`. Don't open syslog to the internet: it has no
  authentication.
- To test without using up Let's Encrypt's limits, point `-acme-directory` at its staging server
  (`https://acme-staging-v02.api.letsencrypt.org/directory`; its certificates aren't trusted by browsers). `-acme-directory` also
  works with other ACME CAs, and `-acme-ca-root` adds a private CA for talking to one.
- **Behind your own reverse proxy** (nginx, Traefik, a load balancer) that does the HTTPS instead: give SIEMLite a private plain-HTTP
  port with `-http-addr` and name the proxy in `-trusted-proxies`, so visitors' real addresses reach the sign-in lockout and the audit
  log. SIEMLite believes `X-Forwarded-For` only from those proxies, reading it from the right so a visitor can't forge it, and the
  plain port refuses everyone else.

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
- **Users** (admins): add people, set their role, limit what they can see, change passwords, and keep the built-in admin account to the server itself.
- **Sources** (admins): add sources (each gets an access token and ready-to-paste code), see when each source last sent logs, choose how each source's lines are read (Automatic, None or a parser), add logs by hand, and enable, disable or delete a token (Manage).
- **Parsers** (admins): build, upload, export and edit parsers.
- **Integrations** (admins): connect SIEMLite to other services. Each integration is a card you set up and then turn on or off: email, sign-in with Microsoft Entra ID, and AI Parsers.
- **System** (admins): the version and whether a newer release is out (with an update button), the HTTPS certificate (self-signed or Let's Encrypt), how long events are kept, database size and uptime, and backups: create, schedule, download, upload, restore and delete.
- **Account** (everyone; select your name at the bottom of the sidebar): your role and what it lets you see, the theme (System, Light
  or Dark), signing out, and how you sign in: a local password, which you can change here, or Microsoft Entra ID.

### Send logs from an app

On the **Sources** page, choose **Add source**, name it after the app and optionally pick a parser. The next screen,
**Connect**, shows the address to send logs to (`<address>/api/v1/logs`), the access token, which is shown once, and a
snippet that sends a log in curl, Python, Go, JavaScript or React, with the address and token already filled in. The
address starts as the one in your browser; change it to the address your apps use to reach SIEMLite if that differs.
Tokens can only send logs; they can't search or sign in.

The snippets trust `siemlite.crt`, since the certificate is self-signed unless you supplied your own. Copy it next to
the code (`docker compose cp siemlite:/data/siemlite.crt .` with Docker) and remove those lines if your certificate is
already trusted. A log sent returns `202` when accepted, `401` if the token is wrong or the source is disabled, and
`503` with `Retry-After` when SIEMLite is busy: wait that many seconds, then send again.

The React example goes through your own backend. A token in front-end code is public, and SIEMLite doesn't allow
cross-origin browser calls (it answers a browser's preflight request with `405`, so the browser blocks the call). The
page sends the log to a route on your server, such as `/api/log`, and the server adds the token and forwards it.

From the command line:

```sh
./siemlite keys create -name myapp
```

Then post logs, one per line. A body that is all JSON (pretty-printed objects, or arrays of them) is read one object at a
time instead, so an app can send its JSON logs as it prints them:

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
| `POST /api/v1/sources`, `PATCH`/`DELETE /api/v1/sources/{id}` | admin | Create an access token (`{"name", "parser_id", "parser_none"}`), rename, set how its lines are read (`"parser_id": 3` for a parser, `"parser_id": null` for Automatic, `"parser_none": true` for None; not both together), and switch a token on or off (`"enabled": true` or `false`; to disable a token use `PATCH`, not `DELETE`). `DELETE` removes the source and its token for good (it used to revoke the token); it returns `409` naming the alert rules that are scoped to the source, and `400` for built-in sources. Only access tokens can be enabled, disabled or deleted. A source shows `parser_none` and `enabled` in its JSON (`revoked_at` is set while it's disabled). |
| `GET`/`POST /api/v1/users`, `PATCH`/`DELETE /api/v1/users/{id}`, `POST /api/v1/users/{id}/password` | admin | Manage users: `{"username", "password", "role", "limited", "sources"}`. A limited standard user sees only `sources`. Updates change only the fields sent. |
| `GET`/`POST /api/v1/parsers`, `GET`/`PUT`/`DELETE /api/v1/parsers/{id}`, `GET /api/v1/parsers/templates` | admin | Manage parsers. |
| `GET /api/v1/alerts?status=open` | any signed-in user not limited to some sources | Alerts (`open`, `acknowledged`, `closed` or `all`) and the count in each state. |
| `PATCH /api/v1/alerts/{id}` | same | Acknowledge, close or reopen: `{"status": "acknowledged"}`. |
| `GET /api/v1/rules`, `POST /api/v1/rules`, `PUT`/`DELETE /api/v1/rules/{id}` | any signed-in user (list), admin | Alert rules: `{"name", "description", "enabled", "severity", "query", "min_severity", "threat_only", "source_id", "group_by", "threshold", "window_minutes", "kind"}`. `kind` is `match` (the default), or `volume_over` / `volume_under` to alert when the source in `source_id` (required) sends more than / fewer than `threshold` events in `window_minutes`; those ignore `query`, `min_severity`, `threat_only` and `group_by`. |
| `GET /api/v1/system` | admin | Database size and version, uptime, backups folder and free space. |
| `GET`/`PUT /api/v1/system/tls`, `POST /api/v1/system/tls/check` | admin | The HTTPS certificate: `{"mode": "self-signed"/"letsencrypt", "domain"}`; the reply describes the certificates, whether one is being obtained, the last error and what the domain resolves to. The check (`{"domain"}`) says whether that name on port 443 reaches this SIEMLite. |
| `GET /.well-known/siemlite-check/{token}` | public | Answers the check above with its one-time token. |
| `GET /api/v1/integrations` | admin | The built-in integrations and their state: `{"integrations": [{"id", "name", "description", "state": "needs_setup"/"off"/"on"/"error", "summary", "configured", "enabled"}]}`. |
| `POST /api/v1/integrations/{id}/enabled` | admin | Turn an integration on or off, keeping its settings: `{"enabled": true}`. Refused until it is set up. |
| `GET`/`PUT /api/v1/integrations/email`, `POST /api/v1/integrations/email/test` | admin | The email settings (`{"host", "port", "security": "starttls"/"tls"/"none", "username", "password", "from_address", "from_name", "skip_verify"}`; the password is write-only, and leaving it out keeps the saved one) and a test send (the same fields plus `"to"`). These were `/api/v1/system/email` in v0.10, which still works. |
| `GET`/`PUT /api/v1/integrations/entra`, `POST /api/v1/integrations/entra/test`, `POST /api/v1/integrations/entra/sync` | admin | The Microsoft Entra ID settings (`{"tenant_id", "client_id", "client_secret", "public_url", "access_group_id", "admin_group_id"}`; the client secret is write-only, and leaving it out keeps the saved one, but only for the same tenant and app), a connection test (the same fields; reports the groups it can read), and an immediate membership check. |
| `GET /api/v1/auth/providers`, `GET /api/v1/auth/entra/start`, `GET /api/v1/auth/entra/callback` | public | The sign-in page's "Continue with Microsoft": which buttons to show, where the browser is sent to sign in, and where Microsoft sends it back. Not for scripts. |
| `GET`/`POST /api/v1/backups`, `PUT /api/v1/backups/settings`, `POST /api/v1/backups/upload` | admin | List backups and the job status, start a backup, set the schedule (`{"interval_hours": 0/6/24/168, "keep"}`), upload a backup file. |
| `GET`/`DELETE /api/v1/backups/{name}`, `POST /api/v1/backups/{name}/restore` | admin | Download or delete a backup; restore it (SIEMLite restarts). |
| `GET`/`PUT /api/v1/integrations/ai`, `POST /api/v1/integrations/ai/test`, `GET /api/v1/integrations/ai/cloud-models` | admin | The [AI Parsers](#ai-parsers) settings (`{"provider": "local"/"openrouter"/"anthropic"/"google"/"openai"/"nvidia", "ollama_url", "local_model", "cloud_model", "send_addresses", "api_key", "key_for"}`; `api_key` is write-only and is for the service `key_for` (or `provider`): leaving it out keeps the saved one and `""` removes it; `openrouter_key` from v0.19 still works), with this server's hardware, the recommended model and the download's progress; a connection test (the same fields); and a service's models with the ones recommended (`GET ?provider=` uses the saved key, `POST {"provider", "api_key"}` the one given). |
| `POST /api/v1/parsers/test`, `POST /api/v1/parsers/draft`, `POST /api/v1/parsers/suggest` | admin | Run a parser over `{"definition", "lines"}`; draft a parser with no AI model from `{"text"}` (pasted text; pretty-printed JSON is split into objects) or `{"lines"}`, answering the definition, how many samples it reads, and the samples as lines; ask the AI model for a parser for `{"lines"}`. |
| `POST /api/v1/login`, `POST /api/v1/logout`, `GET /api/v1/me` | | Browser sign-in, sign-out and current session (`/me` includes `auth_provider`: `local` or `entra`, and `display_name` for a Microsoft account). A password sign-in refused by a [sign-in restriction](#sign-in-restrictions) gets `403`. |
| `GET`/`PUT /api/v1/system/retention` | admin | How long events are kept: `{"days"}` (1 to 3650). The answer also gives the default, whether the page has set it, and the late-ingestion thresholds; shortening it deletes the events now too old, at once. |
| `GET`/`PUT /api/v1/system/signin` | admin | The [sign-in restrictions](#sign-in-restrictions): `{"admin_local_only", "entra_only"}` (send either). The answer also says what is enforced now, the local port, and whether the request came in on it. Turning either on is refused without a local port; Microsoft-only also needs sign-in with Microsoft on and a local Admin account named `admin`. |
| `POST /api/v1/me/password` | any signed-in user | Change your own password: `{"current_password", "new_password"}`. After 10 wrong current passwords in 15 minutes the account can't try again for the rest of the window (a limit of its own, separate from signing in); your other sessions end, this one continues. Refused for Microsoft accounts. |
| `GET /health` | public | Up/down only. When signed in it also returns event count, database size, ingest queue state, indicator count and syslog counters. |

Applications authenticate with `Authorization: Bearer <token>`. A missing or disabled token, or one whose source was deleted, returns `401`; a token used
for anything but sending logs returns `403`.

Events are stored under their own date, however late they arrive, as long as it is within the retention period (two years
by default; see [Keeping events](#keeping-events)) and no more than a day ahead (a sender's clock can run a little fast).
Others are refused and counted as rejected, with the reason, since each day's events are kept in their own file.

### Log parsing

`/api/v1/logs` converts each line into an OCSF event: syslog (RFC 3164 and 5424) headers give the time and hostname,
the first two IPv4 addresses become source and destination, a user is picked up from patterns like `for user alice`,
and severity comes from the syslog priority or keywords (`error`, `failed`, `warning`, ...). JSON objects that already
contain `category_uid` are stored as OCSF; other JSON uses its `message`, `level` and timestamp fields. The detection
is heuristic; use `?severity=` to override it, or give the source a parser. The message stored with an event is the
text after the syslog header (the whole line when there isn't one). A line that only starts with a timestamp, such as
`2026-10-04T13:42:07Z ERROR payment failed`, gets its time from it but no hostname.

This is the **Automatic** setting of a source. **None** skips detection: each line is stored as it is, with the line as
its message, the time it arrived, Informational severity and no addresses, user or host. `?source=` and `?severity=`
still apply, and [threat intel](#threat-intel) still checks the line.

## Parsers

A parser tells SIEMLite how to read one source's lines: where the time, IPs, user and severity are, and which other
values to keep. Choose how a source's lines are read on the Sources page:

- **Automatic** (the default): SIEMLite detects syslog and JSON, addresses, users and severity, as described under
  [Log parsing](#log-parsing).
- **None**: no detection. Each line is stored as it is, with the arrival time and Informational severity (`parser_none`
  in the API).
- **A parser** you built, as below.

Build one on the Parsers page: paste a few sample lines, describe them, and the preview shows how each line is read.

Or let SIEMLite build it: paste the samples and choose **Draft a parser**. It needs no AI model. SIEMLite works out the
format (JSON, key=value, syslog or free text) and, for JSON and key=value lines, which keys hold what, from both their names
and their values: timestamps become the time, IP addresses the source or destination (by names like `dest_`), `detail` or
`description` the message, `username` or `actor` the user, a level field the severity. Without a level field, an action,
outcome or status field decides it (failures and refusals medium, deletions and permission changes low, the rest
informational; for HTTP status codes, 5xx medium and 4xx low). Free text gets a pattern that matches every sample. Check the
preview and the field mapping, adjust anything, and save. With [AI Parsers](#ai-parsers) on, **Suggest with AI** starts from
the same draft and asks the model to improve it.

JSON can be pasted as it comes: pretty-printed objects, or an array of them, become one object per line.

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
- A line that doesn't match its source's parser is still stored, parsed as Automatic would, with a `parse_error` field.

### AI Parsers

With the **AI Parsers** integration on, the parser editor gets a **Suggest a parser** button. SIEMLite removes syslog
headers and recognises JSON and key=value lines itself, drafts a pattern that matches every sample line, and asks the
model to name the fields and pick severity and category. It keeps the model's answer only when it still reads every
sample line.

Set it up on the **Integrations** page, choosing where the model runs:

- **On this server**, with [Ollama](https://ollama.com). Nothing leaves your network. Choose a model size: the card shows
  this server's CPU cores and memory, recommends the largest model that will answer in reasonable time on them, and marks
  models that are too big. The chosen model downloads in the background (1 to 9 GB, once), with its progress on the card.
  With Docker, start Ollama by adding `ai` to `COMPOSE_PROFILES` in `.env` and running `docker compose up -d`; its address is
  `http://ollama:11434`. Without Docker, run Ollama yourself (`http://localhost:11434`). On a CPU, the medium model
  (`qwen2.5-coder:3b`) takes about 10-40 seconds per suggestion. Any Ollama model that can answer in a JSON shape can be used.
- **In the cloud**, with your API key for one of these services:
  - [OpenRouter](https://openrouter.ai) (keys at [openrouter.ai/keys](https://openrouter.ai/keys)): hundreds of models from many
    companies, with prices shown. SIEMLite asks OpenRouter to use only companies that don't keep or train on what they're sent.
  - [Anthropic](https://www.anthropic.com) (keys at [console.anthropic.com](https://console.anthropic.com/settings/keys)): Claude.
  - [Google Gemini](https://ai.google.dev) (keys at [aistudio.google.com](https://aistudio.google.com/apikey)). With a free key,
    Google may use what is sent to improve its products; a key on a paid (billing) project doesn't.
  - [OpenAI](https://platform.openai.com) (keys at [platform.openai.com](https://platform.openai.com/api-keys)).
  - [NVIDIA](https://build.nvidia.com) (keys at [build.nvidia.com](https://build.nvidia.com/settings/api-keys)): NVIDIA's hosted
    open models, such as Llama and Nemotron.

  Choose the service and a model: the card reads the service's own model list with your key and recommends small, fast and
  inexpensive ones. Each service keeps its own key and model, so you can switch between them without entering them again.
  The sample lines you ask about are sent to the service, so:
  - IP, email and MAC addresses and host names are replaced before sending (on unless you turn it off). Every dotted name
    counts as a host name, including file and field names such as `index.html` or `actor.ip`, so nothing slips through on an
    unusual domain; this can make field mapping for JSON with dotted field names less precise. The stand-ins keep the lines'
    shape, and the answer is changed back, so the parser fits the real lines. Other text, such as user names, is sent as written.
  - Before anything is sent, SIEMLite checks the exact text: if an address, or part of one, is still there, nothing is sent
    and you are asked to remove it from the samples or use a model on this server.
  - The keys are encrypted like the [email](#email) password and never shown again.

Turning the integration off hides the button; its settings are kept. Asking for a suggestion is recorded in the
[audit log](#audit-log) (`parser.suggest`), and so are changes to the settings (`system.ai.save`). Before v0.19 this was
set with `SIEMLITE_AI_URL`; that still works, as the starting settings, until the page saves its own.

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
  it's in the image: `docker compose exec siemlite loggen -eps 10`. The token can only send logs. To turn it off,
  choose **Manage** on its row on the Sources page, then **Disable**. While it's disabled loggen keeps retrying and
  carries on by itself once you choose **Enable**. **Delete** removes its token for good; then create a new access
  token with the Log generator parser and give it to loggen with `-token` or `LOGGEN_TOKEN`. The source isn't created
  again.
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
| Mass ingestion of late logs | 50 or more events more than 30 days old arriving from one source at once (High; see [Keeping events](#keeping-events)) |

A rule can instead watch **how much one source sends**: choose "A source sends more than a number of events" or "fewer than a
number of events" when you make a rule, then the source, the number and the time window ("fewer than 1 event in 15 minutes" is
a source that went quiet; "more than 5,000 in 10 minutes" is one flooding you). It counts the source's events in the last
window, by when the events happened, every 10 seconds, so a batch of old logs doesn't count as a burst. A "fewer than" rule
waits a whole window after it is saved or edited, or after SIEMLite starts, before it can say a source went quiet, since
SIEMLite being off looks the same. The alert's count is the highest number seen for "more than" and the lowest for "fewer than".
A source can't be deleted while a rule watches it.

While an alert is open or acknowledged, more matching events add to it instead of raising a new one. Once it's closed,
the next match raises a new alert. Built-in rules can be edited or switched off but not deleted. The [log
generator](#test-logs)'s attacks raise alerts too.

## AI agents (MCP)

AI agents can connect to SIEMLite through the [Model Context Protocol](https://modelcontextprotocol.io): the endpoint is
`POST https://<your SIEMLite>/mcp` (streamable HTTP, JSON answers), and any MCP client can use it. Turn it on and make tokens on
the **Integrations** page under **AI agents (MCP)**. Each token has a name and a level, is shown once, and can be removed at any
time (the agent using it is refused straight away). The switch on the card keeps all agents out while leaving the tokens in place.

| Level | Tools |
|---|---|
| **Read-only** | `search_events` (the Database search with its filters, newest first, 200 at most; the original line only with `include_raw`), `get_stats` (the dashboard's numbers for the last N hours), `list_alerts`, `list_rules`, `list_sources` |
| **Analyst** | the above, and `set_alert_status` (acknowledge, close or reopen an alert) |
| **Admin** | the above, and `list_parsers`, `get_parser`, `draft_parser`, `test_parser`, `save_parser`, `delete_parser`, `create_source`, `update_source`, `delete_source` |

Agents can't reach users, passwords, sign-in settings, Microsoft sign-in, certificates, email, backups, retention or alert rules
(they can read rules). A tool the token's level doesn't allow isn't listed, and calling it by name is refused. The tools run the
same checks as the web pages, so a bad search, a missing name or a parser that doesn't compile comes back as a message the agent
can act on. To connect Claude Code:

```
claude mcp add --transport http siemlite https://siemlite.example.com/mcp --header "Authorization: Bearer slmcp_..."
```

For the Gemini CLI: `gemini mcp add --transport http --header "Authorization: Bearer slmcp_..." siemlite https://siemlite.example.com/mcp`
(or `"httpUrl"` and `"headers"` in its `settings.json`). For OpenCode, add the server to `opencode.json`:

```json
{ "mcp": { "siemlite": { "type": "remote", "url": "https://siemlite.example.com/mcp", "enabled": true,
                          "headers": { "Authorization": "Bearer slmcp_..." } } } }
```

Other clients take the same URL and an `Authorization: Bearer slmcp_...` header. The dialog shown with a new token has ready-to-copy
snippets for all of these, with the token filled in. With a self-signed certificate the agent's computer must trust `siemlite.crt`.

Things to know:

- Tokens are stored only as hashes. They start with `slmcp_` so secret scanners can find them, and they work only on `/mcp`: not on
  the REST API, and an ingest token or a signed-in session doesn't work on `/mcp`.
- Everything an agent changes is in the [audit log](#audit-log) as `agent:<token name> ...` with the field `via=mcp`, and making
  or removing a token is recorded too. Bad tokens are recorded and lock the address out like wrong passwords do; a request that
  names another site in `Origin` is refused.
- Log text comes from outside systems, so an agent reading it can be misled by what it says. SIEMLite tells agents to treat it as
  data, but give each agent the lowest level it needs. A read-only token can't change anything.

The same settings are in the API (admin only): `GET /api/v1/integrations/mcp`, `POST /api/v1/integrations/mcp/tokens`
(`{"name", "level"}`; the answer holds the token once), `DELETE /api/v1/integrations/mcp/tokens/{id}`, and
`POST /api/v1/integrations/{id}/enabled` with `mcp` as the id (`{"enabled": false}`).

## Keeping events

SIEMLite keeps events for two years by default. Change it on the **System** page (**Keep events**: 30 days, 90 days, 1 year,
2 years or any number of days up to ten years); it takes effect at once. Once a day, events older than that are deleted,
whole days at a time, and making the period shorter deletes them straight away (after asking). Before the page sets it,
`-retention-days` (`SIEMLITE_RETENTION_DAYS`) does.

Each event is stored under its own date, even when it arrives late, such as a batch of old logs sent at once. An event dated
before the retention period is refused, since it would be deleted straight away. When 50 or more events more than 30 days
old arrive from one source in one go (a burst ends after a quiet minute, or after ten minutes), SIEMLite records it in the
[audit log](#audit-log) and the built-in rule **Mass ingestion of late logs** raises a High alert naming the source, how many
events, and the dates they cover. The events themselves keep their own severity. Old logs loaded in bulk on purpose raise it
too: close the alert once you know why.

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

## Updates

The **System** page shows the version you're running and checks GitHub for a newer release (at most every six hours,
or when you choose **Check now**). When one is out, **Update and restart** downloads the build for your platform,
checks it against the release's `SHA256SUMS`, swaps it in for the running program and restarts, usually within
seconds. Nothing changes if the download or check fails. Updates are recorded in the audit log. Make a backup
first if you might want to go back: a newer version can upgrade the database in ways older versions can't read.
Pass `-update-check=false` (or `SIEMLITE_UPDATE_CHECK=false`) to stop SIEMLite contacting GitHub at all.

**Everyone is signed out when SIEMLite changes version**, however it was updated (the button, `docker compose pull`, a new
binary, or going back to an older one), so people sign in again on the new version. Restarting the same version keeps
sessions. The audit log records it ("SIEMLite changed from v0.25 to v0.26: everyone was signed out"), and the person who
used **Update and restart** is told why when the sign-in page comes back.

- **A plain program** is replaced in place. The button appears when SIEMLite can write to its own folder.
- **Docker** can't replace the program inside the image, so the update is saved in the data volume
  (`/data/bin`) and the image's program hands over to it each time it starts. It survives restarts and
  `docker compose up -d`. When you later rebuild or pull an image that is as new, the saved copy is removed
  automatically. If a saved update doesn't come up after two starts, it is removed and the image's own version runs,
  so a bad update can't stop the container from starting. This needs no access to the Docker socket.
  `docker compose exec siemlite siemlite ...` commands (and `siemlite version`) still run the image's own version
  until the image is rebuilt or pulled.
- If SIEMLite can't write where it needs to, the card says so and suggests `./update.sh` (see [Run with Docker](#run-with-docker)).

## Integrations

The **Integrations** page lists the services SIEMLite can connect to. Each is built in, and appears as a card with a state
(**Not set up**, **Off**, **On**, or **Problem**), an **On** switch, and a **Settings** button that opens its settings. Set an
integration up first; the switch then turns it on or off without losing its settings. Only admins see the page, and
turning one on or off is recorded in the [audit log](#audit-log).

## Sign in with Microsoft (Entra ID)

The **Integrations** page has a **Microsoft Entra ID** card. When it is on, the sign-in page leads with **Continue with Microsoft**
(the password form is under **Other sign-in methods**), and the people in one Entra group can sign in with their work account. Everyone else is refused, even if they are in your organization.

**Set it up.** The card has the steps; in short, in the Entra admin center:

1. Register an app (**App registrations**, **New registration**, this directory only). Add a **Web** redirect URI, which the card shows
   (your SIEMLite address plus `/api/v1/auth/entra/callback`). SIEMLite is https only, so the address must be https.
2. Copy the **Directory (tenant) ID** and **Application (client) ID**, and create a **client secret** (copy its *Value*).
3. Under **API permissions**, add the Microsoft Graph **application** permission `GroupMember.Read.All` and **grant admin consent**.
4. Copy the **Object ID** of the group whose members may sign in. Optionally copy a second group's for Admins.

Enter them on the card, choose **Test connection** (it shows the group names and how many people are in them), then **Save**.

**How it behaves**

- **Who may sign in** is decided by Microsoft Graph at the moment of sign-in, by asking whether the person is in the access group
  (members of nested groups count). Nothing in the sign-in token is trusted for that.
- **First sign-in** creates the account (named after their Microsoft user name, lower-cased) as a **Standard** user who sees every
  source, like a new Standard user made by hand; limit them on the Users page. With an **admin group**, its members are **Admins**
  and everyone else is Standard; the role follows the group at each sign-in and check. Without one, roles are yours to set.
- **Leaving the group** switches the account off and ends its sessions within five minutes (SIEMLite checks every five minutes, and
  you can choose **Check the group now**). It is also refused at the next sign-in. Someone who is added back is switched on again.
  If Microsoft can't be reached, nothing is changed. An account is never switched off or demoted if it is the last enabled admin: it is
  kept, the check says so, and it can't sign in again while it is outside the group, so create another admin.
- **Accounts are matched by Microsoft's object ID**, not by name. A Microsoft user name that matches an existing local account is
  refused, never linked to it, so nobody can take over a local account by having the same name.
- **The display name is shown** (Justin Waters) in the sidebar, on the Account and Users pages and in audit messages, with
  the account's email (its username, which stays unique) beside it where it identifies the account. It is taken from
  Microsoft at each sign-in and at every membership check, so a rename in Entra shows up within five minutes.
- **Password sign-in stays** for local accounts unless you choose **Only allow sign-in with Microsoft** (see
  [Sign-in restrictions](#sign-in-restrictions)), so keep a local admin in case Microsoft is unreachable. Accounts that sign in with
  Microsoft have no password. Turning the integration off, or removing it, stops new Microsoft sign-ins and signs out everyone who signed in
  with Microsoft right away; the accounts stay, and local sessions are not touched. It is refused if the only enabled admins sign
  in with Microsoft, since they would be locked out: create a local admin first.
- The **client secret** is encrypted like the [email](#email) password (with `siemlite-secret.key`), is never shown again, and is only
  ever used with the tenant and app it was saved for.
- Sign-ins, refusals, and changes to these settings are in the [audit log](#audit-log) (`signin.sso`, `signin.sso.failed`,
  `system.entra.save`, `system.entra.test`, `system.entra.sync`).
- This is for the Microsoft public cloud. Government and other sovereign clouds use different addresses and aren't supported yet.

## Email

The **Integrations** page has an **Email** card for the mail server SIEMLite sends email through. (It was on the System page in v0.10; the settings carried over.) Fill in the server,
choose the connection security, add a login if the server needs one, and say what address mail is sent from.
**Send test** sends a message with the settings as they are in the form, before you save them, and shows the
server's own error if it fails (a wrong password, a port that isn't listening, a certificate that doesn't verify).

| Security | Usual port | Use it for |
|---|---|---|
| **STARTTLS** | 587 | Most mail providers and relays: starts plain, then upgrades to an encrypted connection. |
| **TLS** | 465 | Servers that expect an encrypted connection from the first byte. |
| **None** | 25 | A relay on a network you trust. The login and every message cross the network in plain text. |

- Logins use PLAIN or LOGIN, whichever the server offers.
- **Accept any certificate** is for a server with a self-signed certificate. The connection is still encrypted, but SIEMLite
  can't tell whether it is talking to the right server.
- The password is **encrypted** with a key in `siemlite-secret.key`, next to the database (`/data` with Docker). It is
  never shown again, and the page only says whether one is saved. A backup contains the encrypted password but not the
  key, so after a backup is restored onto a different server the page says the password can't be read there; enter
  it again. Keep `siemlite-secret.key` private, like `siemlite.key`.
- The saved password is only ever used with the server and login it was saved for. If you change the server, port,
  security or username, and for **Send test** against a different server, type the password again, so nothing can
  make SIEMLite log in somewhere else with the saved one.
- Saving and testing are recorded in the [audit log](#audit-log) (without the password).
- This sets up the connection only; nothing sends email by itself yet.

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

Accounts that sign in with Microsoft (see [Sign in with Microsoft](#sign-in-with-microsoft-entra-id)) are marked **Microsoft** on the
Users page. They have no password, so **Change password** isn't offered for them. An admin can still change their role and which sources
they see.

Anyone with a local account can change their own password on the **Account** page (it asks for the current one, and signs them out
on every other browser). Wrong guesses there are limited separately from signing in, so someone using an unlocked session
can't lock the owner out of signing in. Admins can set anyone's password on the Users page.

Passwords are stored as bcrypt hashes. Sessions last 12 hours, use an `HttpOnly`, `Secure`, `SameSite=Strict` cookie,
and end on sign-out. After 10 failed sign-ins in 15 minutes a client address is locked out for the rest of the window.

### Sign-in restrictions

Two switches tighten who can sign in with a password. Both take effect at once, for new sign-ins and for sessions already open.

- **Keep the admin account to this server** (Users page): the built-in local account named `admin` (the one made on first start) can
  then sign in, and work, only on SIEMLite's **local port**: `https://localhost:8444` on the server itself. Elsewhere its sign-in is
  refused, whatever the password, and its sessions stop working. From another computer, reach the local port through an SSH tunnel
  (`ssh -L 8444:localhost:8444 you@server`, then open `https://localhost:8444`). Other admins aren't affected.
- **Only allow sign-in with Microsoft** (the Microsoft Entra ID card on the Integrations page): every account that signs in with a password
  is signed out and refused, so only Microsoft accounts can sign in. The built-in `admin` account is the exception, but only on the local
  port, so you can still get in if Microsoft sign-in breaks. It needs sign-in with Microsoft turned on and a local Admin account named
  `admin`. It applies only while sign-in with Microsoft is on: turning that off brings passwords back.

"On the server itself" means the request came in on the local port, not that it came from a particular address: behind Docker or a
proxy on the same machine, visitors from anywhere can arrive from a local-looking address. The local port is set with `-local-addr`
(default `localhost:8444`; outside a container, keep it on localhost). The Docker setup publishes it on the server's `127.0.0.1` only
(`SIEMLITE_LOCAL_PORT` in `.env`). The port also checks who is connecting: it answers loopback and, in a container, only the
container's gateway, which is where the server's own connections come from. Other containers on the network, and other machines that
route to the container's address, are refused.

If no one can sign in to lift the restrictions, run this on the server (a running SIEMLite applies it within a minute):

```sh
./siemlite signin show
./siemlite signin reset            # Docker: docker compose exec siemlite siemlite signin reset
```

Changes are in the [audit log](#audit-log) (`system.signin`), and so are refused sign-ins (`signin.refused`).

## Sources

Every event belongs to a source: an **access token** an application sends with, the **Syslog** listener, **Added in
the UI** (logs pasted or uploaded on the Sources page) or **INTERNAL** (SIEMLite's own audit log). Each shows when it
was last used, so you can see which are active, and each (except INTERNAL) can have a parser, or be set to Automatic or None. A new install also has a
**Log generator** token source for [test logs](#test-logs).

Access tokens can only post to `/api/v1/logs` and `/api/v1/events`. Choose **Manage** on a token's row to open a popup
with three options:

- **Enable**: the token is accepted. This is how a new token starts.
- **Disable**: the token is rejected straight away. The source, its token and its logs are kept, and choosing Enable
  makes the same token work again.
- **Delete**: removes the source and its token for good; the token can't be restored. Its logs stay in the Database,
  shown as "Deleted source". SIEMLite asks again before it deletes, and refuses while an alert rule is scoped to the
  source (it names the rules; change them first).

The built-in sources can't be disabled or deleted. Each change is recorded in the audit log. From the command line:

```sh
./siemlite keys create -name <name>
./siemlite keys list      # with last used times; a disabled token shows "disabled"
./siemlite keys disable -id <id>   # revoke is the same thing
./siemlite keys enable -id <id>
./siemlite keys delete -id <id>
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
| `-tls-mode` | `self-signed` | `self-signed` (or the `-tls-cert` files), or `letsencrypt` for `-domain`; the System page takes precedence |
| `-domain` | | The domain to get a Let's Encrypt certificate for; port 443 must reach SIEMLite |
| `-acme-directory` | Let's Encrypt | Another ACME server, such as Let's Encrypt's staging server for testing |
| `-acme-ca-root` | | A CA certificate (PEM file) to trust when talking to the ACME server, for a private ACME CA |
| `-local-addr` | `localhost:8444` | HTTPS listen address that counts as the server itself, for the [sign-in restrictions](#sign-in-restrictions) (off when empty). Only the server must be able to reach it |
| `-http-addr` | | Plain-HTTP listen address for your own reverse proxy that does the HTTPS (off when empty). Never publish it |
| `-trusted-proxies` | | Reverse proxies whose `X-Forwarded-For` is believed: addresses, networks or host names, e.g. `proxy`. With it set, the `-http-addr` port refuses everyone else |
| `-db` | `siemlite.db` | SQLite database path; events go in a folder beside it named after it (`siemlite-events`) |
| `-retention-days` | `730` | Keep events this many days, two years by default (checked daily; whole days are deleted as files). The System page takes precedence once it is saved there |
| `-tls-cert`, `-tls-key` | `<db dir>/siemlite.crt`, `.key` | Certificate and key; a self-signed pair is generated if both are missing |
| `-tls-hosts` | | Extra DNS names or IPs for a generated certificate |
| `-syslog-udp`, `-syslog-tcp`, `-syslog-tls` | | Syslog listen addresses, e.g. `:514`, `:514`, `:6514` (each off when empty) |
| `-syslog-allow` | loopback and private networks | Comma-separated IPs/CIDRs allowed to send syslog |
| `-geoip-city` | | MaxMind or DB-IP City/Country `.mmdb` |
| `-geoip-asn` | | MaxMind or DB-IP ASN `.mmdb` |
| `-intel-feed` | | Threat intel feed as `name=https://url`; repeat for several |
| `-intel-refresh` | `6h` | How often to re-download feeds |
| `-ai-url` | | Ollama server for [AI Parsers](#ai-parsers), e.g. `http://ollama:11434`: turns it on with this server until the Integrations page saves its own settings |
| `-ai-model` | `qwen2.5-coder:3b` | Ollama model for AI Parsers, with `-ai-url` |
| `-backup-dir` | `<db dir>/backups` | Folder for database backups |
| `-update-check` | `true` | Check GitHub for new releases and offer updates on the System page |

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
- **`pkg/mcp`**: a small Model Context Protocol server (JSON-RPC over HTTP, tools filtered by access level); **`pkg/agents`**: AI agent tokens and the "AI agents (MCP)" integration; the tools themselves are in `api/mcp.go` and run the REST handlers as the token.
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
