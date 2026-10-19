# Changelog

What changed in each yk-portal release. Versions follow
[Semantic Versioning](https://semver.org/); the release workflow takes each
release's notes from its section here.

## 1.0.0 - 2026-10-19

The first release. It meets the planning document's definition of a complete
MVP (spec §53), with the changes in the requirements addendum.

### Signing in

- A PIN followed by a YubiKey one-time password (Yubico OTP), checked by
  yk-portal itself, without YubiCloud. Each YubiKey has its own PIN. A
  replayed OTP is refused.
- Accounts are provisioning, active, locked or disabled. Three failed sign-ins
  (a setting), counted per YubiKey and per account, lock the account; an
  address with too many failed sign-ins waits.
- New accounts start with a temporary password, valid 72 hours (a setting),
  and onboard by adding a YubiKey; an admin may pre-provision one for the user
  to test at the first sign-in.
- Sessions are kept on the server: 20 minutes idle and 12 hours at most
  (settings), several at once.

### YubiKeys

- Users add, test, rename, disable and remove up to 10 YubiKeys, and set each
  one's PIN with an OTP from it.
- Private IDs and AES keys are encrypted with AES-256-GCM under a key derived
  from the master key. Admins reveal them only by an explicit action, after
  signing in again, and the reveal is audited.

### Administration

- Admin pages for accounts (create, edit, lock and unlock, disable and enable,
  reset to provisioning, temporary passwords, delete), their YubiKeys, groups
  and settings. Light and dark themes.
- An audit log of every sensitive action: unchangeable in the database, also
  written to the system journal, and searchable on an admin page.

### radiator-yubikey

- `radiator-export` writes accounts and YubiKeys in radiator-yubikey's
  `export` CSV format, PINs as SHA-512 crypt; `radiator-import` imports its
  export and moves OTP counters forward.

### Operations

- SQLite, the default, or PostgreSQL, with the same behavior;
  `database-status` checks the database.
- Encrypted backups (AES-256-GCM): `backup-create`, `backup-verify` and
  `backup-restore`.
- `yk-portal serve` runs under a sandboxed systemd unit, behind a reverse
  proxy that provides HTTPS, on a host name of its own or under a path of a
  site; health checks; security headers.
- A Debian package for Ubuntu 26.04 LTS (amd64), whose upgrade backs the
  database up, migrates it and starts the service again; or an installation
  from source with `deploy/install`.
