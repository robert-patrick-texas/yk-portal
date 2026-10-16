# yk-portal

A self-hosted web portal where network operations staff sign in with a
password and a YubiKey OTP, and where admins manage user accounts, groups and
YubiKey OTP credentials. Accounts and keys are stored in SQLite (the default)
or PostgreSQL.

yk-portal runs alongside
[radiator-yubikey](https://github.com/robert-patrick-texas/radiator-yubikey),
which provides offline YubiKey OTP logins for Radiator RADIUS. yk-portal
exports its accounts in radiator-yubikey's CSV format, and imports and
syncs counters from it. It never changes radiator-yubikey itself.

**Status:** spec Phase 1 (foundation) done: configuration file, master key,
AES-256-GCM encryption, Argon2id and SHA-512 crypt hashing, and the user and
role tables. No web pages yet.

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
drops `test_yk_portal`.

`manage.py` uses the development settings (`yk_portal.settings.dev`), with
files in the current directory: `dev.sqlite3` and `dev-master.key`.

```bash
uv run yk-portal master-key-create dev-master.key   # once
uv run python manage.py migrate
uv run python manage.py check
```

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
```

Django's secret key is derived from the master key, so nothing starts
without it. Packaging, the service account and systemd come in spec Phase 10.

## Layout

| Path | Responsibility |
|---|---|
| `src/yk_portal/settings/` | Django settings: `base`, `dev`, `test`, `production` |
| `src/yk_portal/core/` | Configuration, master key, AES-256-GCM encryption, SHA-512 crypt |
| `src/yk_portal/accounts/` | Users, roles, account states, groups |
| `src/yk_portal/authentication/` | Login, passwords, lockout, sessions, step-up |
| `src/yk_portal/yubikeys/` | YubiKey credentials, OTP validation, replay counters |
| `src/yk_portal/audit/` | Audit events |
| `src/yk_portal/portal_settings/` | The admin settings page and run-time settings |
| `src/yk_portal/radiator/` | Export to and import from radiator-yubikey |
| `src/yk_portal/backup/` | Encrypted backup and restore |
| `src/yk_portal/web/` | Shared page layout, light and dark themes, static files |
| `tests/` | Tests (pytest with pytest-django) |
