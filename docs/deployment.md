# yk-portal deployment guide

How to install yk-portal on Ubuntu 26.04 LTS, put it behind a reverse proxy,
run it under systemd, check it, upgrade it and go back (spec §49; addendum
§20). The [README](../README.md) has the commands, the audit log and backups
in detail.

| What | Where |
|---|---|
| The code, one directory per installation | `/opt/yk-portal/releases/VERSION-TIME`, root's |
| The release in use | `/opt/yk-portal/current` → `releases/VERSION-TIME` |
| The `yk-portal` command | `/usr/local/bin/yk-portal` → `/opt/yk-portal/current/bin/yk-portal` |
| Configuration and master key | `/etc/yk-portal/` |
| The SQLite database | `/var/lib/yk-portal/` |
| The service | `yk-portal.service`, running `yk-portal serve` (gunicorn) as `yk-portal` |
| Logs | the system journal: `journalctl -u yk-portal`, `journalctl -t yk-portal-audit` |

The application listens on `127.0.0.1:8000` for the reverse proxy, which
terminates TLS (spec §3, §32). Files in the repository: `deploy/install`,
`deploy/yk-portal.service`, `deploy/nginx/`, `config.example.toml`.

## Prerequisites

Ubuntu 26.04's Python (3.14.4 or newer), `libpq5` for PostgreSQL, and
[uv](https://docs.astral.sh/uv/) 0.13.1 or newer, installed for root:

```bash
sudo apt install python3 libpq5 curl
curl -LsSf https://astral.sh/uv/0.13.1/install.sh | sudo env UV_INSTALL_DIR=/usr/local/bin UV_NO_MODIFY_PATH=1 sh
```

uv installs the locked dependencies only; the system's Python, so Ubuntu's
security updates apply to it. With PostgreSQL, psycopg's C implementation
makes backups and restores about 1.5 times as fast (addendum §20.6); it is
built at install time and needs:

```bash
sudo apt install build-essential python3-dev libpq-dev
```

## Install

From the release's source tree (a checkout or an unpacked archive), as root:

```bash
sudo deploy/install                  # SQLite
sudo deploy/install --postgresql-c   # PostgreSQL, with psycopg's C implementation
```

`deploy/install` creates the `yk-portal` service account (no login shell),
`/etc/yk-portal` (`root:yk-portal`, 0750), `/var/lib/yk-portal` and
`/var/backups/yk-portal` (`yk-portal`, 0700), installs the release into a new
directory, `/opt/yk-portal/releases/VERSION-TIME` (such as
`0.1.0-20261019T053000Z`), points `current` and `/usr/local/bin/yk-portal` at
it, and installs `yk-portal.service`. A first install also copies
`config.example.toml` to `/etc/yk-portal/config.toml` (`root:yk-portal`,
0640). It never changes the configuration, the master key or the database,
and never starts or stops the service: a running service keeps the release it
started with, until it is restarted. Run it again at any time to repair an
installation: it installs a fresh copy and switches to it.

## Configure

```bash
sudoedit /etc/yk-portal/config.toml   # public_base_url, and [database] for PostgreSQL
```

Only settings needed before the database is reachable are in the file
(addendum §3.5); timeouts, the portal name and the sign-in limits are on the
admin settings page. `public_base_url` is the address users browse to, such as
`https://yk-portal.example.com`, or a path of a site
(`https://www.example.com/yk`, see [Under a path](#under-a-path)).
`trusted_proxy_addresses` lists the reverse proxy's addresses; the default,
`127.0.0.1` and `::1`, is right for a proxy on the same server.

The master key encrypts the stored YubiKey secrets and the backups (spec
§22.4). Create it once and keep a copy somewhere safe, apart from the backups:

```bash
sudo yk-portal master-key-create                    # /etc/yk-portal/master.key, mode 0600
sudo chown yk-portal:yk-portal /etc/yk-portal/master.key
```

### SQLite

Nothing more to do: the database is `/var/lib/yk-portal/yk-portal.sqlite3`.

### PostgreSQL

Give yk-portal a role of its own that owns its database and has no other
privileges, and a UTF-8 database with the `C.UTF-8` locale (addendum §18.2):

```bash
sudo -u postgres psql <<'SQL'
CREATE ROLE yk_portal LOGIN;
CREATE DATABASE yk_portal OWNER yk_portal
    ENCODING 'UTF8' LOCALE 'C.UTF-8' TEMPLATE template0;
REVOKE ALL ON DATABASE yk_portal FROM PUBLIC;
SQL
sudo -u postgres psql -c '\password yk_portal'   # prompts, so it stays out of shell history
```

Put the password in a passfile only the service account can read, and name it
in the connection string, with TLS across the network:

```bash
sudo install -m 0600 -o yk-portal -g yk-portal /dev/null /etc/yk-portal/pgpass
sudoedit /etc/yk-portal/pgpass   # one line: db.example.com:5432:yk_portal:yk_portal:PASSWORD
```

```toml
[database]
backend = "postgresql"
postgres_dsn = "host=db.example.com dbname=yk_portal user=yk_portal sslmode=verify-full sslrootcert=/etc/yk-portal/db-ca.crt passfile=/etc/yk-portal/pgpass"
```

On the same server, peer authentication over the Unix socket needs no
password: name the role after the service account (`CREATE ROLE "yk-portal"
LOGIN`, owning the database) and use `postgres_dsn = "dbname=yk_portal
user=yk-portal"`.

### The database and the first admin

```bash
sudo -u yk-portal yk-portal migrate
sudo -u yk-portal yk-portal database-status
sudo -u yk-portal yk-portal bootstrap-admin root   # prints a temporary password
```

Give the temporary password to the admin privately; they sign in with it,
then add their YubiKey and choose its PIN.

## Start the service

```bash
sudo systemctl enable --now yk-portal
systemctl status yk-portal
curl -s http://127.0.0.1:8000/health/ready        # {"status": "ready"}
```

`yk-portal serve` runs gunicorn with the configured number of workers
(`[application] workers`, 4 by default) and tells systemd once it listens. It
loads the application before starting the workers, so a missing master key
or a wrong setting stops it at once, with the reason in
`journalctl -u yk-portal`; systemd tries again 5 times in 2 minutes, then
leaves it failed. Once fixed: `sudo systemctl reset-failed yk-portal`, then
start it.

The unit runs the service as `yk-portal` in a sandbox: no privileges, a
read-only system, no home directories, its own `/tmp` and `/dev`, only the
network families it needs, and writes only to `/var/lib/yk-portal`.
`systemd-analyze security yk-portal` rates it 1.1, "OK". The commands
(`sudo -u yk-portal yk-portal ...`) run outside it, as the same account.

## Reverse proxy

The proxy terminates TLS with the enterprise's certificate, redirects HTTP to
HTTPS, sends the client's address in `X-Forwarded-For` and the scheme in
`X-Forwarded-Proto`, limits request sizes and the rate of sign-ins, and
proxies to `listen_address:listen_port` only (spec §32). yk-portal sets the
security headers and the caching of every response itself: the proxy
shouldn't add them as well.

yk-portal believes `X-Forwarded-For` and `X-Forwarded-Proto` only from the
addresses in `trusted_proxy_addresses`. A request from anywhere else can't
say it came over HTTPS: it is redirected to `public_base_url`.

### nginx, on a host name of its own

[`deploy/nginx/yk-portal.conf`](../deploy/nginx/yk-portal.conf) is a whole
configuration for `https://yk-portal.example.com`:

```bash
sudo install -m 0644 deploy/nginx/yk-portal.conf /etc/nginx/conf.d/yk-portal.conf
sudoedit /etc/nginx/conf.d/yk-portal.conf   # server_name, ssl_certificate, ssl_certificate_key
sudo nginx -t && sudo systemctl reload nginx
```

It limits sign-in attempts to 10 a minute per client address (bursts of 10),
before yk-portal's own limit on failed sign-ins (addendum §20.4), refuses
bodies over 256 KiB, and answers 404 for `/health/`, which is for local
monitoring.

### Under a path

yk-portal can be published under a path of an existing site, such as
`https://www.example.com/yk/` (addendum §20.2): set `public_base_url =
"https://www.example.com/yk"`. The proxy strips the path before passing the
request on, and yk-portal puts it back in its links, redirects and cookies.
[`deploy/nginx/yk-portal-path.conf`](../deploy/nginx/yk-portal-path.conf) has
the two parts: one for the `http { }` context, one to include in the site's
`server { }` block.

yk-portal then shares the site's origin, so script on any page of the site
can read yk-portal's pages with the user's session. Publish it under a path
only on a site whose other pages are trusted as much; a host name of its own
keeps it apart. Under a path, yk-portal sends no HSTS header, since its policy
would be the whole site's: the site's own applies.

### Other proxies

Caddy and Apache work the same way: proxy to `127.0.0.1:8000`, set
`X-Forwarded-For` to the client's address (replacing what the client sent)
and `X-Forwarded-Proto` to `https`, keep the `Host` header, and for a path,
strip it. Caddy's `reverse_proxy` sets the forwarded headers itself.

## Check it

```bash
curl -s http://127.0.0.1:8000/health/live         # the process answers
curl -s http://127.0.0.1:8000/health/ready        # it can serve: database, migrations, master key
sudo -u yk-portal yk-portal database-status
sudo -u yk-portal yk-portal check --deploy        # Django's own checks of the settings
curl -sI https://yk-portal.example.com/login/     # Content-Security-Policy, Strict-Transport-Security, ...
```

`/health/ready` answers 503 with the failed checks' names (`database`,
`migrations`, `master key`), never a value from the configuration;
`journalctl -u yk-portal` has the reasons. The health checks answer any host
name, so monitoring can ask `127.0.0.1:8000` directly.

## Backups

`backup-create` runs while yk-portal runs; see the README, "Backup and
restore", for a nightly cron job, verifying and restoring. Keep a copy of
`/etc/yk-portal/master.key` apart from the backups: a backup can't be read
without it.

## Upgrade

1. Back up, with the version still installed (a backup is made from a
   database with all of its version's migrations):
   ```bash
   sudo -u yk-portal yk-portal backup-create /var/backups/yk-portal
   ```
2. Install the new release from its source tree. The service keeps running
   the release it started with:
   ```bash
   sudo deploy/install                # with --postgresql-c if installed with it
   ```
3. Stop, migrate, start:
   ```bash
   sudo systemctl stop yk-portal
   sudo -u yk-portal yk-portal migrate
   sudo systemctl start yk-portal
   curl -s http://127.0.0.1:8000/health/ready
   ```

Do steps 2 and 3 together. In between, the `yk-portal` command is already the
new release's while the database isn't migrated yet: a backup from cron is
refused ("isn't fully migrated"), and a restart of the service would start
the new release, which `/health/ready` reports as `migrations` until step 3.

`ls /opt/yk-portal/releases` lists the releases installed; remove old ones
with `sudo rm -r /opt/yk-portal/releases/VERSION-TIME` once they're no longer
needed for going back, never the one `current` points at.

## Go back to the previous release

A database migrated by the new release can't be used by the old one, and a
backup restores only with the release that made it (addendum §19.5). So go
back with the backup made before the upgrade:

```bash
sudo systemctl stop yk-portal
ls /opt/yk-portal/releases                                    # the previous one, VERSION-TIME
sudo ln -sfn releases/VERSION-TIME /opt/yk-portal/current
```

Then give the old release an empty database and restore. SQLite:

```bash
sudo mv /var/lib/yk-portal/yk-portal.sqlite3 /var/lib/yk-portal/yk-portal.sqlite3.new-release
sudo rm -f /var/lib/yk-portal/yk-portal.sqlite3-wal /var/lib/yk-portal/yk-portal.sqlite3-shm
```

PostgreSQL: `DROP DATABASE yk_portal` and create it again as in
[PostgreSQL](#postgresql). Then, for either:

```bash
sudo -u yk-portal yk-portal migrate
sudo -u yk-portal yk-portal backup-restore /var/backups/yk-portal/yk-portal-YYYYMMDDTHHMMSSZ.backup
sudo systemctl start yk-portal
```

Changes made since the backup are lost, and the counters of YubiKeys used
since are behind: move them forward from radiator-yubikey (README, "Backup
and restore").

## Files and permissions

| Path | Owner | Mode | Holds |
|---|---|---|---|
| `/etc/yk-portal/` | `root:yk-portal` | 0750 | |
| `/etc/yk-portal/config.toml` | `root:yk-portal` | 0640 | the configuration: no secrets |
| `/etc/yk-portal/master.key` | `yk-portal:yk-portal` | 0600 | the master key; yk-portal refuses a key others can read |
| `/etc/yk-portal/pgpass` | `yk-portal:yk-portal` | 0600 | the PostgreSQL password |
| `/var/lib/yk-portal/` | `yk-portal:yk-portal` | 0700 | the SQLite database (0600) |
| `/opt/yk-portal/` | `root:root` | 0755 | the code: the service can't change it |
| `/var/backups/yk-portal/` | `yk-portal:yk-portal` | 0700 | backups (0600), by `backup-create` |

Every `yk-portal` command and the service create their files for the service
account alone (umask 077), whatever the umask of the shell or sudo. There is
no `/var/log/yk-portal`: the logs go to the journal.

## Logs

| Log | Holds | Read it with |
|---|---|---|
| The service's | startup, readiness problems, request errors, warnings | `journalctl -u yk-portal` |
| The audit log's copy | every audit event, from the service and the commands | `journalctl -t yk-portal-audit` |

Requests are logged by the reverse proxy, which knows the clients' addresses;
gunicorn's own access log is off. Neither log ever holds a secret (spec §40).
`[logging] level` sets the service's level; the audit copy is written at any
level.

## Troubleshooting

| Symptom | Cause |
|---|---|
| The service stops at once, then is failed; `journalctl -u yk-portal` names the master key | `/etc/yk-portal/master.key` missing, unreadable by `yk-portal`, or readable by others; once fixed, `sudo systemctl reset-failed yk-portal` and start it |
| `/health/ready` says `migrations` | run `sudo -u yk-portal yk-portal migrate` |
| `/health/ready` says `master key` after the key file changed | the service still uses the key it read: restart it |
| 400 Bad Request for every page | the browser's host name isn't `public_base_url`'s |
| The browser loops between redirects | the proxy doesn't send `X-Forwarded-Proto: https`, or its address isn't in `trusted_proxy_addresses` |
| "Form not accepted" on every form | the page wasn't served over HTTPS, or `public_base_url` differs from the address in the browser |
| The journal says a sign-in came "from a trusted proxy, without the client's address" | the proxy doesn't send `X-Forwarded-For`: failed sign-ins can't be limited per address |
| Everyone must wait after a few failed sign-ins anywhere | the proxy's address isn't in `trusted_proxy_addresses`, so every client looks like the proxy |
| An address must wait | 10 failed sign-ins from it within 15 minutes (the settings page); it waits until the oldest is 15 minutes old |
| 502 from the proxy | the service isn't running, or listens elsewhere than the proxy's upstream |
