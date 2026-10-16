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

**Status:** project set up; no features yet. Building starts with spec Phase 1.

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
uv sync                          # create .venv with every dependency
uv run pytest                    # tests
uv run ruff check .              # lint
uv run ruff format .             # format
uv run python manage.py check    # Django's checks, with development settings
```

`manage.py` uses the development settings (`yk_portal.settings.dev`: a local
`dev.sqlite3` and a public secret key). The installed `yk-portal` command and
`yk_portal.wsgi` use the production settings, which refuse to load until the
configuration loader exists (spec Phase 1).

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
