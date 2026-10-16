# yk-portal: Requirements Addendum

**Status:** draft, 2026-10-16 (decisions of 2026-10-16 included)
**Baseline:** `network_ops_yubikey_otp_tool_planning.md` (the "spec")
**Related project:** `radiator-yubikey` 1.9.0 (not modified by this project)

This addendum records decisions made after the spec was written. Where the
two disagree, this addendum wins. Section references such as "spec §22" point
to the baseline document. Section 14 lists the decisions and where each one
is applied.

---

## 1. Project and its relationship to radiator-yubikey

1.1 yk-portal is a separate project with its own code, database, releases
and package. Its application name for paths and the CLI is `yk-portal`
(`/etc/yk-portal/`, `/var/lib/yk-portal/`, `/var/log/yk-portal/`, CLI
`yk-portal`, Python package `yk_portal`).

1.2 yk-portal does not change any file, table, role or setting of
radiator-yubikey. It treats these radiator-yubikey interfaces as fixed:

- the 12-column `export` CSV format, written by `yubikey-db.sh export` and
  read by `yubikey-db.sh import --from-export`;
- the username, group-name and key-field rules of `yubikey-db.sh`;
- the meaning of the OTP counters (section 8);
- the `yubikeys` table layout and the `yubikeys_counters_forward` trigger
  (relevant to the future live connector, section 11).

1.3 yk-portal keeps its own database (SQLite default, PostgreSQL optional,
spec §4.3). It never adds tables to radiator-yubikey's database.

1.4 **yk-portal owns the data of its users.** For a user who is in
yk-portal, yk-portal is the only place to change the account, its password
and its YubiKeys. A change made directly in Radiator's database with
`yubikey-db.sh` (for example disabling a key) is overwritten by the next load
of a yk-portal export. The one exception is counters: they only ever move
forward, in both systems (sections 6.4 and 7.5).

1.5 No radiator-yubikey database exists today. The export (section 6) and
the importer (section 7) are built now so either system can be loaded from
the other when one does.

---

## 2. Passwords: two hashes

Supersedes spec §12.1 and §22.1 where they say Argon2id is the only form.

2.1 Passwords are hashed, never stored reversibly (spec §52 item 4 stands).

2.2 Each account has two password hashes:

| Field | Algorithm | Used for |
|---|---|---|
| `password_hash` | Argon2id, unique random salt | yk-portal web login |
| `radius_password_hash` | SHA-512 crypt, stored as `{crypt}$6$<salt>$<hash>` | Export to radiator-yubikey (the PIN typed before the OTP in Radiator) |

2.3 Today both hashes come from the same password. Setting or changing a
permanent password (onboarding, user change) computes both at once from the
plaintext, which is then discarded. The schema keeps them separate so a
later version can let the RADIUS PIN differ from the web password.

2.4 SHA-512 crypt format must match what `yubikey-db.sh` produces:

- prefix `{crypt}`, then `$6$`, a 16-character salt from `a-z A-Z 0-9 . /`
  generated from a cryptographically secure source, `$`, and the hash;
- default rounds (5000, no `rounds=` field);
- generated with the system's crypt(3) (libxcrypt), which is what
  radiator-yubikey's Perl `crypt()` uses. Python 3.13 and later have no
  `crypt` module.
- Tests check results against `openssl passwd -6 -salt SALT PASSWORD`.

2.5 Temporary passwords get only an Argon2id hash. They are never exported
to Radiator.

2.6 Password policy stays as in spec §12 (8 to 80 characters, at least one
letter and one number), with one addition: a password must not end with `:`,
because Radiator accepts `PIN:OTP` and could read a trailing colon as the
separator.

2.7 `radius_password_hash` is stored as the `{crypt}` string itself, not
encrypted. (Decided: encrypting it with the master key was considered and
not adopted.)

2.8 An account imported from Radiator (section 7) may have only a
`radius_password_hash`. Its first web login goes through the normal login
flow (spec §16, including the OTP), with the password checked against the
SHA-512 hash; on success, the Argon2id `password_hash` is created from the
password typed. A failure counts toward lockout like any other.

---

## 3. Admin settings page

Changes spec §31, which put these values in the configuration file. Turns
the fixed values in spec §52 items 14 to 17 into defaults.

3.1 Admins have a settings page. Settings are stored in yk-portal's
database, validated against the ranges below, and every change creates a
`SETTING_CHANGED` audit event with the old and new values.

3.2 Settings and defaults:

| Setting | Default | Allowed |
|---|---|---|
| Portal name: replaces "yk-portal" everywhere users see the name | `yk-portal` | 1 to 64 characters |
| Login-page notice, such as an authorized-use banner | empty | up to 2,000 characters |
| Idle session timeout | 20 minutes | 5 to 240 minutes |
| Maximum session length | 12 hours | 1 to 24 hours |
| Temporary password lifetime | 72 hours | 1 to 336 hours |
| Failed logins before an account locks | 3 | 1 to 10 |
| Maximum YubiKeys per user | 10 | 1 to 10 |
| Require password + OTP again before revealing a key's private ID or AES key | on | on / off |
| Default group | none | none, or any group |
| Default theme | follow browser | follow browser / light / dark |

3.3 When changes apply: session settings on each session's next request;
temporary password lifetime to passwords issued afterwards; failed-login
limit to the next failed login; maximum YubiKeys to the next key added
(users above a lowered limit keep their keys but can't add more).

3.4 Text settings (portal name, login notice) are plain text, escaped on
output. No HTML.

3.5 These stay in `/etc/yk-portal/config.toml`, because they are needed
before the database is reachable or must not be changeable from a browser:
database backend and connection, master key path, listen address and port,
public base URL, trusted proxy addresses, log level and paths.

---

## 4. Light and dark themes

4.1 Every page supports a light and a dark theme. Colors are defined once,
as CSS variables with a light and a dark set, and both meet WCAG AA contrast.

4.2 With no choice made, the theme follows the browser's
`prefers-color-scheme`, or the admin's default theme setting if it is set to
light or dark.

4.3 A control in the page header (Browser / Light / Dark) saves the signed-in
user's choice to their account, so it follows them to other browsers. The
login page uses the last choice made in that browser, or the default.

4.4 No inline scripts or styles, so a strict Content-Security-Policy works.

---

## 5. Groups

New; the spec has none.

5.1 Admins create, rename, describe and delete groups in the admin settings
area.

5.2 Group names follow radiator-yubikey's rule, `^[A-Za-z0-9._-]{1,64}$`, so
a later version can load them into Radiator unchanged. Names are unique
regardless of case. Each group has an immutable internal ID, so a rename
changes only the name.

5.3 A user belongs to zero or more groups. Admins change membership from the
user page and from the group page. Users see their own groups, read-only, on
their account page.

5.4 Settings may name one default group, or none. A user created by an
admin, by the CLI or by the importer (section 7) gets the default group at
creation; on the web create form the admin can change that. Changing the
default later doesn't change existing users.

5.5 The default group can't be deleted until another default, or none, is
set. Deleting any other group removes its memberships after a confirmation
that shows how many members it has.

5.6 Groups grant nothing inside yk-portal. The `user` and `admin` roles
(spec §6) stay separate and are the only source of permissions.

5.7 Groups are internal to yk-portal in this version: they are not exported.

5.8 Audit events: `GROUP_CREATED`, `GROUP_UPDATED`, `GROUP_DELETED`,
`GROUP_MEMBER_ADDED`, `GROUP_MEMBER_REMOVED`. Changing the default group is a
`SETTING_CHANGED` event.

---

## 6. Export for radiator-yubikey (CSV, CLI only)

6.1 The CLI command `yk-portal radiator-export FILE|-` writes the CSV.
There is no web download in this version.

- It must run as the yk-portal service account or root, because it needs
  the master key to decrypt the AES keys and private IDs.
- `FILE` is created with mode `0600`. An existing file is replaced only with
  `--force`. `-` writes to standard output.
- It prints a summary to standard error: rows written, and how many keys are
  exported inactive and why (account PROVISIONING, LOCKED or DISABLED; key
  disabled), naming the accounts, so the admin sees before loading.
- Each run creates a `RADIATOR_EXPORT_CREATED` audit event with the row
  count and destination, never any secret.

6.2 The format is radiator-yubikey's `export` format, so it loads with
`yubikey-db.sh import --from-export`. Plain `import` would hash the already
hashed password a second time.

- Header, required and exact:
  `username,public_id,private_id,aes_key,password,active,created,accessed,counter,low,high,label`
- Standard CSV quoting (fields with a comma, quote or line break are quoted,
  with quotes doubled), UTF-8, LF line endings.

6.3 One row per YubiKey credential:

| Column | Value |
|---|---|
| `username` | The account's username |
| `public_id` | 12 modhex characters |
| `private_id` | 12 lowercase hex characters, decrypted |
| `aes_key` | 32 lowercase hex characters, decrypted (radiator-yubikey stores it as base64) |
| `password` | `radius_password_hash` (`{crypt}$6$...`), or empty if the account has none |
| `active` | `1` only if the account is ACTIVE and the key is enabled, otherwise `0` |
| `created` | The credential's creation time, UTC, `YYYY-MM-DD HH:MM:SS` |
| `accessed` | The key's last successful use known to yk-portal, same format, or empty |
| `counter`, `low`, `high` | yk-portal's last usage counter, last session counter, and `0` (section 8) |
| `label` | The key's label |

Accounts without keys produce no rows. Accounts in PROVISIONING, LOCKED or
DISABLED state are exported with `active` set to `0` on every key, so the next
load turns them off in Radiator too. For LOCKED accounts this is an interim
rule: whether a yk-portal lockout should reach Radiator is decided with the
live connector (section 11).

6.4 How radiator-yubikey loads it (`import --from-export --replace`), which
yk-portal relies on:

- counters never move backward: where Radiator's row is ahead, its counters
  and access time stay;
- a row with the same public ID or private ID is replaced, even if it
  belonged to another username;
- an empty label keeps the label already in Radiator, so clearing a label in
  yk-portal doesn't reach Radiator;
- rows in Radiator that aren't in the file are left alone.

6.5 Recommended procedure (to be documented in the yk-portal guide):

```bash
sudo -u yk-portal yk-portal radiator-export /var/lib/yk-portal/export/radiator.csv
sudo /opt/radiator-yubikey/yubikey-db.sh import --from-export --dry-run /var/lib/yk-portal/export/radiator.csv
# review the report, especially any "Replaced" line for a key under another username
sudo /opt/radiator-yubikey/yubikey-db.sh import --from-export --replace /var/lib/yk-portal/export/radiator.csv
sudo shred -u /var/lib/yk-portal/export/radiator.csv
```

With PostgreSQL, run `yubikey-db.sh -b pg ...` as a member of
`yubikey_admin`, against the primary.

6.6 Limits of the CSV export, until the live connector (section 11):

- **Deletions don't reach Radiator.** The import never removes rows. Until
  the live connector, removing a user or key from Radiator is a manual step:
  `yubikey-db.sh delete USER [PUBLIC_ID]`. yk-portal's delete confirmation
  pages show that command (username and public ID only) as a reminder.
- **Counters from RADIUS logins** reach yk-portal only when the importer's
  counter sync runs (section 7.5). Until it runs, an OTP already used through
  Radiator can still be accepted once at the yk-portal web login.
- The export file contains every AES key and private ID in clear text.

---

## 7. Import from radiator-yubikey (CLI)

New; covers spec §38 (migration) and counter sync.

7.1 Command:

```
yk-portal radiator-import [--dry-run] [--skip-invalid] [--counters-only] FILE|-
```

- Reads a file written by `yubikey-db.sh export`: the 12-column format, or
  the 11-column format of radiator-yubikey before 1.8.0 (no `label`). The
  header is required.
- Runs as the yk-portal service account or root (it needs the master key to
  encrypt private IDs and AES keys).
- Every row is validated first. If any row is invalid, nothing is imported
  unless `--skip-invalid` is given. The valid rows are loaded in one
  transaction. `--dry-run` reports what would happen and changes nothing.
- The report lists each row's outcome (user created, key added, counters
  moved forward, unchanged, skipped or invalid with the reason) by username
  and public ID, never a secret, then totals.
- Audit: a `RADIATOR_IMPORT_COMPLETED` event with the mode and totals, plus
  `ACCOUNT_CREATED` and `YUBIKEY_ADDED` for each account and key created.

7.2 Full import, for each row:

- **Username** must meet section 9 (lowercase, allowed characters, not
  `svc.` or `anycast-`). Otherwise the row is invalid. Usernames are not
  lowercased automatically, because Radiator matches them exactly.
- **Public ID already in yk-portal:**
  - same user, same private ID and AES key: only the counters move forward
    (section 7.5); nothing else changes (section 1.4);
  - another user, or a different private ID or AES key: the row is invalid
    (conflicts with yk-portal's data).
- **Public ID new to yk-portal:**
  - user not in yk-portal: the account is created in state ACTIVE, with the
    `user` role, the default group if one is set, no email and no Argon2id
    hash (section 2.8);
  - user in yk-portal: the key is added to that account, subject to the
    maximum YubiKeys per user;
  - the key gets `provisioning_method = MIGRATED`, `enabled` from `active`,
    the label, the slot from the label when it contains `slot 1` or `slot 2`
    (otherwise unset, for an admin to fill in), counters from `counter` and
    `low`, `created_at` from `created`, `last_used_at` from `accessed`, and
    its private ID and AES key encrypted with the master key. `high` is
    ignored (Radiator always stores 0).

7.3 Password column:

| Value | Result |
|---|---|
| `{crypt}$6$...` | Becomes `radius_password_hash` as is |
| empty | No password |
| plain text, or `{clear}...` | Hashed at import into both `password_hash` (Argon2id) and `radius_password_hash` (SHA-512 crypt); the plain text is not kept |
| any other format (`{SSHA}`, `$5$`, `$1$`, `$2a$`, ...) | Row invalid |

An account that already has a `radius_password_hash` in yk-portal keeps it.

7.4 Radiator stores a PIN per key, yk-portal one password per account. When
one user's rows carry different password strings (which is always the case
with `{crypt}` hashes, even for the same PIN, because each has its own salt),
the importer uses the one from the row with the latest `accessed` and warns
that after the next export all that user's keys will use that PIN.

7.5 **Counter sync** (`--counters-only`, and part of every full import):

- For each row whose public ID, private ID and AES key match a yk-portal
  credential, the stored counters move to Radiator's if Radiator's are ahead
  (section 8), and `last_used_at` moves to `accessed` if that is later.
  Nothing else changes.
- With `--counters-only`, rows that are unknown to yk-portal or don't match
  are reported and skipped, not errors.
- The update is conditional (only where the new pair is ahead), so a web
  login at the same moment can't be moved backward.
- Meant to run regularly, for example from cron:

  ```bash
  sudo /opt/radiator-yubikey/yubikey-db.sh export - | sudo -u yk-portal yk-portal radiator-import --counters-only -
  ```

---

## 8. OTP counters: one meaning in both systems

8.1 yk-portal stores and compares counters exactly as radiator-yubikey and
Radiator 4.30 do (radiator-yubikey guide, "How Radiator 4.30 checks a
login"):

- `last_usage_counter` holds the usage counter with its top bit (set when
  the OTP was triggered from a keyboard key) ignored; `last_session_counter`
  holds the session counter (radiator-yubikey's `low`); radiator-yubikey's
  `high` is always 0.
- An OTP is accepted only if its usage counter is above the stored one, or
  equal with a session counter above the stored one.

8.2 Tests cross-check this against radiator-yubikey without changing it:
OTPs made with its `tests/make-otp.sh` and test keys must give yk-portal the
same accept or reject result and the same stored counters as
`yubikey-db.sh verify`.

---

## 9. Usernames

Adds to spec §23.

9.1 Usernames are lowercase and must match radiator-yubikey's rule:
letters, digits and `. _ @ + -`, 1 to 255 characters (lowercase only in
yk-portal).

9.2 Usernames starting with `svc.` or `anycast-` are rejected. Radiator's
configuration sends those to service-account and anycast-check handling, so
they would never work as YubiKey logins.

---

## 10. Technology stack

Decides spec §50 items 1 to 4.

| Item | Decision |
|---|---|
| Operating system | Ubuntu 26.04 LTS |
| Python | 3.14.4 or newer (`requires-python = ">=3.14.4"`) |
| Project and environment tool | uv 0.13.1 or newer (`[tool.uv] required-version = ">=0.13.1"`); no pip |
| Web framework | Django, long-term-support release: 5.2 (`django>=5.2.18,<5.3`, security fixes until April 2028). Move to the next LTS (6.2) in a later release. |
| Pages | Server-rendered Django templates (no single-page app) |
| Data access | Django ORM and migrations, the same migrations for SQLite and PostgreSQL; psycopg 3 for PostgreSQL |
| Password hashing | Argon2id through Django's Argon2 hasher (argon2-cffi); SHA-512 crypt through the system's libxcrypt (section 2.4) |
| Encryption | `cryptography`: AES-256-GCM and HKDF for stored secrets and backups, AES-128 for the OTP decrypt |
| CLI | Django management commands, run as the `yk-portal` command |

To decide when the project is set up: test runner (proposed pytest with
pytest-django), linting and formatting, and the application server behind
the reverse proxy (proposed gunicorn under systemd).

---

## 11. Deferred to later versions

- **Live connector** to radiator-yubikey's database, run from a CLI command
  (for cron) and/or triggered by the web app. It would carry deletions,
  counters in both directions and account state, without a CSV file.
- Decided with the live connector:
  - removing deleted users and keys from Radiator (section 6.6);
  - whether a yk-portal lockout disables the user in Radiator (section 6.3);
  - whether failed RADIUS logins count toward the yk-portal lockout.
- Managing radiator-yubikey service accounts (`svc.*`), whose passwords would
  use the same SHA-512 crypt format in `service_accounts.password`.
- Exporting groups and memberships to radiator-yubikey, and managing its
  device access and TACACS+ rules.
- A RADIUS PIN that differs from the web password (section 2.3).
- A web download of the export.

---

## 12. Schema and audit additions

Adds to spec §25 and §27.

- `users`: `password_hash` may be empty (imported accounts, section 2.8);
  add `radius_password_hash` (nullable) and `theme` (`browser`, `light`,
  `dark`).
- `yubikey_credentials`: `slot_number` may be empty for imported keys; add
  `migration_source` (spec §21 optional field), set to
  `radiator-yubikey export` by the importer.
- `groups`: `id`, `name` (unique, case-insensitive), `description`,
  `created_at`, `updated_at`.
- `user_groups`: `user_id`, `group_id`, unique together; rows deleted with
  either side.
- `settings`: one row per setting (`key`, `value`, `updated_at`,
  `updated_by_user_id`); the application holds the defaults and validation.
- Audit events: `SETTING_CHANGED`, `GROUP_CREATED`, `GROUP_UPDATED`,
  `GROUP_DELETED`, `GROUP_MEMBER_ADDED`, `GROUP_MEMBER_REMOVED`,
  `RADIATOR_EXPORT_CREATED`, `RADIATOR_IMPORT_COMPLETED`.
- Encrypted values (spec §25.4's `encrypted_private_id`, `encrypted_aes_secret`
  and their nonces) are each stored as one self-describing value instead of a
  value and a nonce column: version, master key ID, nonce, ciphertext and tag.
  Each is bound to its table, column and row with AES-GCM associated data, so
  a value copied to another row or column fails to decrypt.
- Django's secret key is derived from the master key (spec §22.5), like the
  other keys, so there is no second secret to manage.

---

## 13. Spec §50 open decisions: defaults unless changed

| # | Decision | Default |
|---|---|---|
| 1-4 | Language, framework, data access, templates | Decided: section 10 |
| 5 | Reverse proxy | nginx example; any of the spec's three works |
| 6 | Primary keys | UUID |
| 7 | Maximum session length | 12 hours (setting) |
| 8 | Backup retention | The operator's policy; documented, not enforced |
| 9 | Email unique | No |
| 10 | Email verification | No |
| 11 | Step-up before revealing secrets | Yes (setting, default on) |
| 12 | VIP must test the pre-provisioned key at first login | Yes |
| 13 | Migrated keys without counters | Need a fresh OTP before use, unless an admin accepts the risk (spec §38). Keys from a radiator-yubikey export always carry counters. |
| 14 | Audit retention | Kept indefinitely; no automatic purge |
| 15 | Audit copy outside the database | Also written to the system journal |
| 16 | External API | No |
| 17 | Password rule | Spec §12, plus section 2.6 |

---

## 14. Decision log

| Date | Decision | Applied in |
|---|---|---|
| 2026-10-16 | Project name `yk-portal`; separate project; radiator-yubikey not modified | 1 |
| 2026-10-16 | Admin settings page; light and dark themes | 3, 4 |
| 2026-10-16 | Passwords hashed: Argon2id for web login, SHA-512 crypt for Radiator; same password today | 2 |
| 2026-10-16 | Groups: admin-defined, 0..n per user, default group; grant nothing in yk-portal; not exported yet | 5 |
| 2026-10-16 | Export now: CSV through the CLI, no web download | 6 |
| 2026-10-16 | No Radiator database exists today; build the importer anyway | 1.5, 7 |
| 2026-10-16 | Deleting from Radiator waits for the live connector | 6.6, 11 |
| 2026-10-16 | yk-portal owns the data of its users | 1.4 |
| 2026-10-16 | Lockout reaching Radiator waits for the live connector (interim rule in 6.3) | 6.3, 11 |
| 2026-10-16 | Counter sync from Radiator is part of the importer | 7.5 |
| 2026-10-16 | The SHA-512 hash is not additionally encrypted | 2.7 |
| 2026-10-16 | Python 3.14.4+, uv 0.13.1+, Django LTS, server-rendered pages | 10 |
