# yk-portal

A self-hosted web portal where network operations staff sign in with a
YubiKey's PIN and its OTP, and where admins manage user accounts, groups and
YubiKey OTP credentials. Accounts and keys are stored in SQLite (the default)
or PostgreSQL.

yk-portal runs alongside
[radiator-yubikey](https://github.com/robert-patrick-texas/radiator-yubikey),
which provides offline YubiKey OTP logins for Radiator RADIUS. yk-portal
exports its accounts in radiator-yubikey's CSV format, and imports and
syncs counters from it. It never changes radiator-yubikey itself.

**Status:** spec Phases 1 to 8 done: configuration file, master key,
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
SQLite, alike in behavior and schema, with `database-status`. Backup and
restore (spec Phase 9) come next.

## Documents

| Document | What it is |
|---|---|
| [docs/network_ops_yubikey_otp_tool_planning.md](docs/network_ops_yubikey_otp_tool_planning.md) | The planning and build specification: the functional baseline |
| [docs/requirements-addendum.md](docs/requirements-addendum.md) | Decisions made since; where it differs from the spec, the addendum wins |

## Requirements

- Ubuntu 26.04 LTS
- Python 3.14.4 or newer
- [uv](https://docs.astral.sh/uv/) 0.13.1 or newer
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

## Production configuration

The installed `yk-portal` command and `yk_portal.wsgi` use the production
settings, built from `/etc/yk-portal/config.toml` (or the file named by
`$YK_PORTAL_CONFIG`) and the master key it names:

```bash
sudo install -m 0640 -o root -g yk-portal config.example.toml /etc/yk-portal/config.toml
sudoedit /etc/yk-portal/config.toml                    # public_base_url, database
sudo yk-portal master-key-create                       # mode 0600; back it up safely
sudo chown yk-portal:yk-portal /etc/yk-portal/master.key
sudo -u yk-portal yk-portal migrate
sudo -u yk-portal yk-portal bootstrap-admin            # the first admin; prints a temporary password
```

Django's secret key is derived from the master key, so nothing starts
without it. Packaging, the service account and systemd come in spec Phase 10.

`yk-portal database-status` shows which database is in use and whether it is
ready; it exits with status 1 if not (addendum §18.6).

### PostgreSQL

SQLite suits a single server. For PostgreSQL (addendum §18.2), give
yk-portal a role of its own that owns its database and has no other
privileges, and a UTF-8 database with the `C.UTF-8` locale:

```bash
sudo -u postgres psql <<'SQL'
CREATE ROLE yk_portal LOGIN;
CREATE DATABASE yk_portal OWNER yk_portal
    ENCODING 'UTF8' LOCALE 'C.UTF-8' TEMPLATE template0;
REVOKE ALL ON DATABASE yk_portal FROM PUBLIC;
SQL
sudo -u postgres psql -c '\password yk_portal'   # prompts, so it stays out of shell history
```

Put the password in a passfile that only the service account can read, and
name it in the connection string, with TLS across the network:

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
user=yk-portal"`. Then:

```bash
sudo -u yk-portal yk-portal migrate
sudo -u yk-portal yk-portal database-status
```

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
| `database-status` | Shows the database in use (backend, version, file or server, role, TLS, locale), whether its migrations are applied and its audit log protected; exits with status 1 on a problem. Warnings, such as a role with privileges it doesn't need, don't change the status |
| `migrate` | Creates or updates the database's tables (spec §36's `database-migrate`) |
| `bootstrap-admin [USERNAME]` | Creates the first admin account; refused once any admin exists. Prompts for the username if it isn't given |
| `create-admin USERNAME [--email EMAIL]` | Creates another admin account |
| `reset-admin USERNAME` | Gives an admin account a new temporary password and puts it in PROVISIONING: the way back in when no admin can sign in |
| `radiator-export [--force] FILE\|-` | Writes every YubiKey in radiator-yubikey's export format (mode 0600), for `yubikey-db.sh import --from-export --replace`; prints which keys are exported inactive, and why |
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
| `src/yk_portal/web/` | Shared page layout, light and dark themes, static files |
| `tests/` | Tests (pytest with pytest-django), run on both backends |
| `scripts/check` | Every check, and the tests on SQLite and PostgreSQL |
