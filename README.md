# yk-portal

[Documents](#documents) ([web version](https://robert-patrick-texas.github.io/yk-portal/)) · [Deployment guide](docs/deployment.md) · [Releases](https://github.com/robert-patrick-texas/yk-portal/releases) · [Changelog](CHANGELOG.md) · [MIT license](LICENSE)

A self-hosted web portal where network operations staff sign in with a
YubiKey's PIN and its OTP, and where admins manage user accounts, groups and
YubiKey OTP credentials. Accounts and keys are stored in SQLite (the default)
or PostgreSQL.

yk-portal runs alongside
[radiator-yubikey](https://github.com/robert-patrick-texas/radiator-yubikey),
which provides offline YubiKey OTP logins for Radiator RADIUS. yk-portal
exports its accounts in radiator-yubikey's CSV format, and imports and
syncs counters from it. It never changes radiator-yubikey itself.

**Status:** spec Phases 1 to 10 done: configuration file, master key,
AES-256-GCM encryption, Argon2id and SHA-512 crypt hashing; accounts and
their states, temporary passwords, roles with last-admin protection, groups,
the database-backed settings and audit events, and the `bootstrap-admin`,
`create-admin` and `reset-admin` commands; YubiKey credentials with
encrypted secrets, a PIN each, and Yubico OTP checking; the sign-in page,
lockout counted per YubiKey, sessions and themes; onboarding (email, then
adding a YubiKey and its PIN, or testing one an admin set up and choosing
its PIN), and each user's YubiKey pages (add, test, edit, set the PIN,
disable, remove); the export to radiator-yubikey and the import and counter
sync from it; the admin pages (users: list and search, create, edit with a
display name and comment for admins, disable, enable, unlock, reset to
provisioning, temporary passwords, the admin role, hard delete; any account's YubiKeys: pre-provision, edit, set
the PIN, disable, remove, reveal the secrets after a step-up; groups;
settings); the audit log, whose events can't be changed or deleted, with
its admin page and its copy in the system journal; PostgreSQL alongside
SQLite, alike in behavior and schema, with `database-status`; encrypted
backups, made while yk-portal runs, and their verification and restore, on
either backend; production hardening: the application server under systemd,
behind a reverse proxy, on a host name of its own or under a path, a limit on
failed sign-ins per address, security headers, health checks, the
installation and its deployment guide, and a lab in Docker.

## Documents

| Document | What it is |
|---|---|
| [docs/network_ops_yubikey_otp_tool_planning.md](docs/network_ops_yubikey_otp_tool_planning.md) | The planning and build specification: the functional baseline |
| [docs/requirements-addendum.md](docs/requirements-addendum.md) | Decisions made since; where it differs from the spec, the addendum wins |
| [docs/deployment.md](docs/deployment.md) | Installing, configuring, running, checking, upgrading and going back; building the package and releasing |
| [CHANGELOG.md](CHANGELOG.md) | What changed in each release |
| [lab/README.md](lab/README.md) | The lab: yk-portal in Docker behind the host's nginx, for trying changes |

GitHub Pages publishes these documents as a website, the
[web version](https://robert-patrick-texas.github.io/yk-portal/), built from
the Markdown by `scripts/build_pages.py` on each push to `main`
(`.github/workflows/pages.yml`). To see the site before pushing:

```bash
uv run --only-group pages scripts/build_pages.py   # into _site/; a broken link stops it
uv run --only-group pages python -m http.server -d _site   # http://localhost:8000/
```

## Requirements

- Ubuntu 26.04 LTS; the package is for amd64
- Python 3.14.4 or newer
- [uv](https://docs.astral.sh/uv/) 0.13.1 or newer, except to install the package
- for PostgreSQL: PostgreSQL 14 or newer (tested with 18), and `libpq5`
  (used by `psycopg`)

## Development

```bash
uv sync                                          # create .venv with every dependency
scripts/check                                    # every check below, before a commit
uv run pytest                                    # tests, on SQLite
YK_PORTAL_TEST_DATABASE=postgresql uv run pytest # the same tests, on PostgreSQL
uv run ruff check .                              # lint
uv run ruff format .                             # format
uv run ty check                                  # type check
```

Both test runs use the production database settings (addendum §18.7). The
SQLite run keeps its database in a file in the temporary directory. The
PostgreSQL run connects with the usual libpq defaults and environment
(`PGHOST`, `PGUSER`, ...) as a role that may create databases; it creates and
drops `test_yk_portal` (and `test_yk_portal_from_models`, for the schema
check).

`tests/yubikeys/test_radiator_crosscheck.py` checks OTP verdicts and stored
counters against radiator-yubikey's `tests/make-otp.sh` and `yubikey-db.sh
verify` (addendum §8.2), and `tests/radiator/test_radiator_crosscheck.py`
loads yk-portal's export into `yubikey-db.sh` and imports its export, without
changing radiator-yubikey. They use the checkout at `../radiator-yubikey` (or
`$YK_PORTAL_RADIATOR_YUBIKEY`) and need `sqlite3`, `openssl` and
`libcrypt-rijndael-perl`; without them they are skipped.

`manage.py` uses the development settings (`yk_portal.settings.dev`), with
files in the current directory: `dev.sqlite3` and `dev-master.key`.

```bash
uv run yk-portal master-key-create dev-master.key   # once
uv run python manage.py migrate
uv run python manage.py bootstrap-admin             # prints a temporary password
uv run python manage.py runserver                   # http://localhost:8000/login/
```

The session and CSRF cookies are marked Secure; browsers still send them to
`localhost` over plain HTTP.

To try a change as it will run in production, installed, behind a real
reverse proxy and over HTTPS, use the lab ([lab/README.md](lab/README.md)):
`lab/lab up`, then `lab/lab down`.

## Installation

[docs/deployment.md](docs/deployment.md) is the deployment guide. In short,
with the package from the
[releases](https://github.com/robert-patrick-texas/yk-portal/releases) (or
`sudo deploy/install` from the release's source tree):

```bash
sudo apt install ./yk-portal_1.0.0-1_amd64.deb      # into /opt/yk-portal, with the yk-portal account and the unit
sudoedit /etc/yk-portal/config.toml                 # public_base_url, database
sudo yk-portal master-key-create                    # mode 0600; back it up safely
sudo chown yk-portal:yk-portal /etc/yk-portal/master.key
sudo -u yk-portal yk-portal migrate
sudo -u yk-portal yk-portal bootstrap-admin root    # the first admin; prints a temporary password
sudo systemctl enable --now yk-portal               # yk-portal serve, on 127.0.0.1:8000
```

then the reverse proxy (`deploy/nginx/`). The installed `yk-portal` command
and the service use the production settings, built from
`/etc/yk-portal/config.toml` (or the file named by `$YK_PORTAL_CONFIG`) and
the master key it names. Django's secret key is derived from the master key,
so nothing starts without it. `yk-portal database-status` shows which
database is in use and whether it is ready; it exits with status 1 if not
(addendum §18.6).

## Audit log

Every security-sensitive action records an audit event (spec §27; addendum
§17): sign-ins and sign-outs, account and YubiKey changes, secret reveals,
settings, groups, the commands, and refused admin pages. Events are never
changed or deleted, by the application or by SQL (database triggers), except
by restoring a backup, which needs no extra privilege; no secret is ever
recorded. Admins read them on the Audit log page. Each
event is also written to the system journal, apart from the application's
log and whatever its level, from the web application and the commands alike:

```bash
journalctl -t yk-portal-audit --since today
```

## Administrative commands

Run as the yk-portal service account (`sudo -u yk-portal yk-portal ...`), or
with `uv run python manage.py ...` in development. Each command records an
audit event naming the operating-system user (and the `sudo` caller).

| Command | What it does |
|---|---|
| `serve` | Runs the application server (gunicorn) as configured, until stopped: what `yk-portal.service` runs |
| `database-status` | Shows the database in use (backend, version, file or server, role, TLS, locale), whether its migrations are applied and its audit log protected; exits with status 1 on a problem. Warnings, such as a role with privileges it doesn't need, don't change the status |
| `migrate` | Creates or updates the database's tables (spec §36's `database-migrate`) |
| `bootstrap-admin [USERNAME]` | Creates the first admin account; refused once any admin exists. Prompts for the username if it isn't given |
| `create-admin USERNAME [--email EMAIL]` | Creates another admin account |
| `reset-admin USERNAME` | Gives an admin account a new temporary password and puts it in PROVISIONING: the way back in when no admin can sign in |
| `radiator-export [--force] FILE\|-` | Writes every YubiKey in radiator-yubikey's export format (mode 0600), for `yubikey-db.sh import --from-export --replace`; prints which keys are exported inactive, and why |
| `backup-create [--force] FILE\|DIRECTORY\|-` | Backs up the database to an encrypted file (mode 0600); a directory gets `yk-portal-YYYYMMDDTHHMMSSZ.backup`. `-v 0` prints nothing, for cron |
| `backup-verify FILE\|-` | Checks a backup completely, as a restore does first, and that this installation can restore it; exits with status 1 if not |
| `backup-restore [--replace] [--no-input] FILE` | Restores a backup in one transaction, after checking it and asking for `restore` to be typed. A database with accounts, YubiKeys, groups or settings needs `--replace` |
| `radiator-import [--dry-run] [--skip-invalid] [--counters-only] FILE\|-` | Reads a `yubikey-db.sh export` file: creates the accounts and adds the YubiKeys yk-portal doesn't have, and moves counters forward for those it has. `--skip-invalid` also leaves out Radiator's reserved accounts (`svc.`, `anycast-`); `--counters-only` only moves counters, for cron |

New accounts start in PROVISIONING with the roles `user` (and `admin`), the
default group if one is set, and a generated temporary password that is
printed once and expires after the temporary password lifetime setting
(72 hours by default). Accounts that `radiator-import` creates start ACTIVE,
each YubiKey with its Radiator PIN (addendum §7).

Loading yk-portal's accounts into Radiator (addendum §6.5):

```bash
sudo -u yk-portal yk-portal radiator-export /var/lib/yk-portal/export/radiator.csv
sudo /opt/radiator-yubikey/yubikey-db.sh import --from-export --dry-run /var/lib/yk-portal/export/radiator.csv
sudo /opt/radiator-yubikey/yubikey-db.sh import --from-export --replace /var/lib/yk-portal/export/radiator.csv
sudo shred -u /var/lib/yk-portal/export/radiator.csv
```

Moving counters forward from Radiator's logins, for example from cron
(addendum §7.5):

```bash
sudo /opt/radiator-yubikey/yubikey-db.sh export - | sudo -u yk-portal yk-portal radiator-import --counters-only -
```

## Backup and restore

`backup-create` writes the whole database (accounts, YubiKeys, groups,
settings and the audit log) to one file, encrypted with AES-256-GCM under a
key derived from the master key (addendum §19). It reads one moment of the
database without holding up logins, so it can run while yk-portal runs, for
example nightly, keeping 30 days:

```bash
sudo install -d -m 0700 -o yk-portal -g yk-portal /var/backups/yk-portal
sudo tee /etc/cron.d/yk-portal-backup <<'CRON'
30 2 * * * yk-portal yk-portal backup-create -v 0 /var/backups/yk-portal && find /var/backups/yk-portal -name 'yk-portal-*.backup' -mtime +30 -delete
CRON
```

A backup can't be read without the master key that made it: keep a copy of
`/etc/yk-portal/master.key` somewhere safe and apart from the backups (a
backup stored with its key protects nothing). `head -n 2 FILE` shows which
backup a file is, when and by which version it was made, and the master
key's ID; `backup-verify` checks it completely.

To restore, stop the web service (logins would wait for the restore), then:

```bash
sudo -u yk-portal yk-portal backup-verify /var/backups/yk-portal/yk-portal-20261018T023000Z.backup
sudo -u yk-portal yk-portal backup-restore --replace /var/backups/yk-portal/yk-portal-20261018T023000Z.backup
```

The restore replaces the accounts, YubiKeys, groups and settings, and ends
every session. It never moves a YubiKey's OTP counters back, and keeps the
audit events recorded since the backup. A backup restores with the
yk-portal version that made it (the same migrations): on a new server,
install that version, put the master key in place, run `yk-portal migrate`,
restore, and upgrade afterwards. Counters of YubiKeys used since the backup
are then behind; move them forward from radiator-yubikey:

```bash
sudo /opt/radiator-yubikey/yubikey-db.sh export - | sudo -u yk-portal yk-portal radiator-import --counters-only -
```

A backup restores into either backend. To move from SQLite to PostgreSQL:
`backup-create` with SQLite configured, set up PostgreSQL ([docs/deployment.md](docs/deployment.md#postgresql)), change
`[database]` in the configuration, then `yk-portal migrate` and
`backup-restore` into the new, empty database.

## Layout

| Path | Responsibility |
|---|---|
| `src/yk_portal/settings/` | Django settings: `base`, `dev`, `test`, `production` |
| `src/yk_portal/core/` | Configuration, master key, AES-256-GCM encryption, SHA-512 crypt; where SQLite and PostgreSQL differ (`db.py`), and `database-status` |
| `src/yk_portal/accounts/` | Users, roles, account states, groups; onboarding and the admin user and group pages |
| `src/yk_portal/authentication/` | Login, PINs and temporary passwords, lockout, sessions, step-up |
| `src/yk_portal/yubikeys/` | YubiKey credentials, OTP validation, replay counters; the users' and admins' YubiKey pages |
| `src/yk_portal/audit/` | Immutable audit events (rewritten only by a restore), their journal copy, and the admin audit log page |
| `src/yk_portal/portal_settings/` | The admin settings page and run-time settings |
| `src/yk_portal/radiator/` | Export to and import from radiator-yubikey |
| `src/yk_portal/backup/` | Encrypted backup and restore |
| `src/yk_portal/web/` | Shared page layout, light and dark themes, static files; health checks, forwarded and security headers |
| `src/yk_portal/server.py` | `yk-portal serve`: gunicorn, configured from the configuration file |
| `packaging/deb/` | The Debian package: its build, maintainer scripts and lintian overrides |
| `deploy/` | `install`, the systemd unit, nginx examples |
| `lab/` | The Docker lab, and the systemd and package checks |
| `tests/` | Tests (pytest with pytest-django), run on both backends |
| `scripts/check` | Every check, and the tests on SQLite and PostgreSQL |
| `scripts/build_pages.py`, `.github/workflows/pages.yml` | The documents as a website, on GitHub Pages |
| `.github/workflows/release.yml` | A release from a tag: checks, the package, its checks, the GitHub release |

## License

[MIT](LICENSE).
