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

**Status:** spec Phases 1 to 5 done, except the radiator-yubikey import and
export: configuration file, master key, AES-256-GCM encryption, Argon2id and
SHA-512 crypt hashing; accounts and their states, temporary passwords, roles
with last-admin protection, groups, the database-backed settings and audit
events, and the `bootstrap-admin`, `create-admin` and `reset-admin`
commands; YubiKey credentials with encrypted secrets, a PIN each, and Yubico
OTP checking; the sign-in page, lockout counted per YubiKey, sessions and
themes; onboarding (email, then adding a YubiKey and its PIN, or testing one
an admin set up and choosing its PIN), and each user's YubiKey pages (add,
test, edit, set the PIN, disable, remove). The admin pages come next.

## Documents

| Document | What it is |
|---|---|
| [docs/network_ops_yubikey_otp_tool_planning.md](docs/network_ops_yubikey_otp_tool_planning.md) | The planning and build specification: the functional baseline |
| [docs/requirements-addendum.md](docs/requirements-addendum.md) | Decisions made since; where it differs from the spec, the addendum wins |

## Requirements

- Ubuntu 26.04 LTS
- Python 3.14.4 or newer
- [uv](https://docs.astral.sh/uv/) 0.13.1 or newer
- `libpq5` for PostgreSQL (used by `psycopg`)

## Development

```bash
uv sync                                          # create .venv with every dependency
uv run pytest                                    # tests, on SQLite
YK_PORTAL_TEST_DATABASE=postgresql uv run pytest # the same tests, on PostgreSQL
uv run ruff check .                              # lint
uv run ruff format .                             # format
uv run ty check                                  # type check
```

The PostgreSQL run connects with the usual libpq defaults and environment
(`PGHOST`, `PGUSER`, ...) as a role that may create databases; it creates and
drops `test_yk_portal`. It also runs the test that submits one OTP from
several threads at once.

`tests/yubikeys/test_radiator_crosscheck.py` checks OTP verdicts and stored
counters against radiator-yubikey's `tests/make-otp.sh` and `yubikey-db.sh
verify` (addendum §8.2), without changing radiator-yubikey. It uses the
checkout at `../radiator-yubikey` (or `$YK_PORTAL_RADIATOR_YUBIKEY`) and needs
`sqlite3`, `openssl` and `libcrypt-rijndael-perl`; without them it is skipped.

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

## Administrative commands

Run as the yk-portal service account (`sudo -u yk-portal yk-portal ...`), or
with `uv run python manage.py ...` in development. Each command records an
audit event naming the operating-system user (and the `sudo` caller).

| Command | What it does |
|---|---|
| `bootstrap-admin [USERNAME]` | Creates the first admin account; refused once any admin exists. Prompts for the username if it isn't given |
| `create-admin USERNAME [--email EMAIL]` | Creates another admin account |
| `reset-admin USERNAME` | Gives an admin account a new temporary password and puts it in PROVISIONING: the way back in when no admin can sign in |

New accounts start in PROVISIONING with the roles `user` (and `admin`), the
default group if one is set, and a generated temporary password that is
printed once and expires after the temporary password lifetime setting
(72 hours by default).

## Layout

| Path | Responsibility |
|---|---|
| `src/yk_portal/settings/` | Django settings: `base`, `dev`, `test`, `production` |
| `src/yk_portal/core/` | Configuration, master key, AES-256-GCM encryption, SHA-512 crypt |
| `src/yk_portal/accounts/` | Users, roles, account states, groups |
| `src/yk_portal/authentication/` | Login, PINs and temporary passwords, lockout, sessions, step-up |
| `src/yk_portal/yubikeys/` | YubiKey credentials, OTP validation, replay counters |
| `src/yk_portal/audit/` | Audit events |
| `src/yk_portal/portal_settings/` | The admin settings page and run-time settings |
| `src/yk_portal/radiator/` | Export to and import from radiator-yubikey |
| `src/yk_portal/backup/` | Encrypted backup and restore |
| `src/yk_portal/web/` | Shared page layout, light and dark themes, static files |
| `tests/` | Tests (pytest with pytest-django) |
