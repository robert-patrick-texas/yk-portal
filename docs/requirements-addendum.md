# yk-portal: Requirements Addendum

**Status:** draft, 2026-10-16 (decisions of 2026-10-16 included)
**Baseline:** `network_ops_yubikey_otp_tool_planning.md` (the "spec")
**Related project:** `radiator-yubikey` 1.9.0 (not modified by this project)

This addendum records decisions made after the spec was written. Where the
two disagree, this addendum wins. Section references such as "spec §22" point
to the baseline document. Section 15 lists the decisions and where each one
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
yk-portal, yk-portal is the only place to change the account, its YubiKeys
and their PINs. A change made directly in Radiator's database with
`yubikey-db.sh` (for example disabling a key) is overwritten by the next load
of a yk-portal export. The one exception is counters: they only ever move
forward, in both systems (sections 6.4 and 7.5).

1.5 No radiator-yubikey database exists today. The export (section 6) and
the importer (section 7) are built now so either system can be loaded from
the other when one does.

---

## 2. PINs, passwords and account states

Supersedes spec §12.1 and §22.1 where they say Argon2id is the only form,
and spec §16 where it says the password belongs to the account.

2.1 PINs and passwords are hashed, never stored reversibly (spec §52 item 4
stands).

2.2 **Each YubiKey has its own PIN**, typed before its OTP, at the yk-portal
web login (spec §16's "password") and in Radiator. A user may give all their
YubiKeys one PIN, or each its own. The PIN is stored on the YubiKey
credential as two hashes:

| Field | Algorithm | Used for |
|---|---|---|
| `pin_hash` | Argon2id, unique random salt | yk-portal web login |
| `radius_pin_hash` | SHA-512 crypt, stored as `{crypt}$6$<salt>$<hash>` | Export to radiator-yubikey (each row's password column) |

The web login checks the PIN of the YubiKey whose OTP ends the passcode. An
account has no password of its own, only a temporary password while it is
PROVISIONING (section 2.5).

2.3 Both hashes come from the same PIN, computed at once when it is set; the
plaintext is then discarded. Each YubiKey's hashes have their own salts, so
the stored hashes don't show which YubiKeys share a PIN.

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

2.6 PINs follow spec §12's password policy (8 to 80 characters, at least one
letter and one number), with these additions:

- a password must not end with `:`, because Radiator accepts `PIN:OTP` and
  could read a trailing colon as the separator;
- the limit of 80 is counted in bytes of UTF-8, where a character outside
  ASCII takes 2 to 4, because RADIUS carries at most 128 bytes of password,
  and the PIN, `:` and the 44-character OTP must fit;
- control characters, such as tab or line break, are rejected.

2.7 `radius_pin_hash` is stored as the `{crypt}` string itself, not
encrypted. (Decided: encrypting it with the master key was considered and
not adopted.)

2.8 A YubiKey imported from Radiator (section 7) may have only a
`radius_pin_hash`. Its first web login goes through the normal login flow
(spec §16, including the OTP), with the PIN checked against the SHA-512
hash; on success, the Argon2id `pin_hash` is created from the PIN typed. A
failure counts toward lockout like any other.

2.9 The web login also accepts `PIN:OTP`, as Radiator does: one `:` right
before the OTP is dropped before the PIN is checked (a PIN can't end with
`:`, section 2.6). The standard form, the one the login page asks for, stays
the PIN followed directly by the OTP; the colon form is tolerated, not
offered.

2.10 PROVISIONING accounts lock too. Consecutive failed logins with the
temporary password count toward the failed-login limit (section 3.2) as
spec §18.1 says, and reaching it moves the account from PROVISIONING to
LOCKED. This adds PROVISIONING -> LOCKED to the transitions of spec §7.1.
Unlocking an account that still has a temporary password (it never finished
provisioning) returns it to PROVISIONING, not ACTIVE.

2.11 The temporary password stays valid until onboarding completes
(PROVISIONING -> ACTIVE), which clears it (spec §11), or until it expires.

2.12 Enabling a DISABLED account (DISABLED -> ACTIVE) needs a YubiKey with a
PIN, either hash of section 2.2. An account disabled before it finished
provisioning has none: an admin resets it to provisioning instead.

2.13 An "enabled admin", which spec §9.1 keeps at least one of, is an
account with the admin role in any state but DISABLED. PROVISIONING and
LOCKED admins count.

2.14 **Failed logins count per YubiKey and per account** (adds to spec §18):

- A failure after the OTP's public ID named one of the account's enabled
  YubiKeys (a wrong PIN, an OTP that doesn't decrypt or carries another
  private ID, a replayed OTP) counts against that YubiKey.
- A failure that names none of them (a malformed OTP, an unknown public ID,
  another user's YubiKey, a disabled YubiKey, a wrong temporary password)
  counts against the account.
- The account locks when any one count reaches the failed-login limit
  (section 3.2). Each YubiKey gets that many PIN guesses; failures with
  different YubiKeys don't add up.
- A successful login clears the count of the YubiKey used and the account's.
  The other YubiKeys' counts stay, so a stolen YubiKey gets no more guesses
  while its owner keeps signing in with another one.
- Unlocking, enabling, resetting to provisioning, issuing a temporary
  password and completing onboarding clear every count.
- `LOGIN_FAILURE` events name the YubiKey (public ID) a failure counted
  against.

2.15 Users set or change a YubiKey's PIN on its page, with an OTP from that
YubiKey (they must hold it), and may give the same PIN to all their
YubiKeys at once. Their other sessions end (spec §19). An admin-provisioned
YubiKey gets its PIN from its owner: at the test during onboarding, or later
on its page. Each change records `PASSWORD_CHANGED` with the public IDs.

2.16 An admin can set the PIN of any user's YubiKey, without an OTP from it,
as root can set any user's password on Linux (the admin pages, spec Phase
6). It is audited like the user's own change. All of the user's sessions end
(an admin setting the PIN of their own YubiKey keeps the session they use).
The user isn't asked to change the PIN at the next sign-in.

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
| Failed logins before an account locks (section 2.14) | 3 | 1 to 10 |
| Failed sign-ins from one address before it must wait (section 20.4) | 10 | 1 to 100 |
| Wait for an address with too many failed sign-ins (section 20.4) | 15 minutes | 1 to 1,440 minutes |
| Maximum YubiKeys per user | 10 | 1 to 10 |
| Require password + OTP again before revealing a key's private ID or AES key | on | on / off |
| Default group | none | none, or any group |
| Default theme | follow browser | follow browser / light / dark |

3.3 When changes apply: session settings on each session's next request;
temporary password lifetime to passwords issued afterwards; failed-login
limit to the next failed login; the per-address limit and wait to the next
sign-in; maximum YubiKeys to the next key added
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
| `password` | The YubiKey's `radius_pin_hash` (`{crypt}$6$...`), or empty if it has no PIN |
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
- The report lists each row's outcome in a few words (added, new account,
  counters moved forward, unchanged, skipped or invalid with the reason,
  such as `skipped: reserved username`) by line, username and public ID,
  never a secret, then the totals that aren't zero.
- Audit: a `RADIATOR_IMPORT_COMPLETED` event with the mode and totals, plus
  `ACCOUNT_CREATED` and `YUBIKEY_ADDED` for each account and key created.
  The `RADIATOR_IMPORT_COMPLETED` event is recorded only when the import
  added YubiKeys (and created accounts). Moving counters forward is routine
  and isn't audited, so a counter sync records no event; neither does a run
  that changes nothing, or a dry run.

7.2 Full import, for each row:

- **Username** must meet section 9 (lowercase, allowed characters, not
  `svc.` or `anycast-`). Otherwise the row is invalid. Usernames are not
  lowercased automatically, because Radiator matches them exactly. With
  `--skip-invalid`, a row whose username is reserved for Radiator (`svc.`,
  `anycast-`, such as the anycast check's accounts) is reported as skipped,
  not invalid: `--skip-invalid` is how such rows are left out.
- **Public ID already in yk-portal:**
  - same user, same private ID and AES key: only the counters move forward
    (section 7.5); nothing else changes (section 1.4);
  - another user, or a different private ID or AES key: the row is invalid
    (conflicts with yk-portal's data).
- **Public ID new to yk-portal:**
  - user not in yk-portal: the account is created in state ACTIVE, with the
    `user` role, the default group if one is set and no email;
  - user in yk-portal: the key is added to that account, subject to the
    maximum YubiKeys per user;
  - the key gets `provisioning_method = MIGRATED`, `enabled` from `active`,
    the label, the slot from the label when it contains `slot 1` or `slot 2`
    (otherwise unset, for an admin to fill in), counters from `counter` and
    `low`, `created_at` from `created`, `last_used_at` from `accessed`, its
    PIN from `password` (section 7.3), and its private ID and AES key
    encrypted with the master key. `high` is ignored (Radiator always
    stores 0).

7.3 Password column, the YubiKey's PIN:

| Value | Result |
|---|---|
| `{crypt}$6$...` | Becomes `radius_pin_hash` as is (section 2.8) |
| empty | No PIN |
| plain text, or `{clear}...` | Hashed at import into both `pin_hash` (Argon2id) and `radius_pin_hash` (SHA-512 crypt); the plain text is not kept. Taken as Radiator has it: the password policy (section 2.6) isn't applied, as it can't be to a `{crypt}` hash. A control character makes the row invalid |
| any other format (`{SSHA}`, `$5$`, `$1$`, `$2a$`, ..., and `$6$...` without `{crypt}`) | Row invalid |

A YubiKey yk-portal has keeps its PIN (section 1.4).

7.4 Radiator and yk-portal both store a PIN per YubiKey (section 2.2): each
imported YubiKey keeps its own.

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

Decided since: tests with pytest and pytest-django; ruff for linting and
formatting, ty for types; gunicorn as the application server, run by
`yk-portal serve` under systemd (section 20.1); WhiteNoise for the static
files (section 20.5).

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
- A web download of the export.

---

## 12. Schema and audit additions

Adds to spec §25 and §27.

- `users`: no password hash (the PINs are on the YubiKeys, section 2.2);
  keep `failed_login_count` for failures that name no YubiKey (section
  2.14); add `theme` (`browser`, `light`, `dark`), and `display_name` and
  `comment` for admins (section 16.9).
- `yubikey_credentials`: `slot_number` may be empty for imported keys; add
  `pin_hash` and `radius_pin_hash` (both may be empty: no PIN yet, or an
  imported key, section 2.8), `failed_login_count` (section 2.14), and
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
  `RADIATOR_EXPORT_CREATED`, `RADIATOR_IMPORT_COMPLETED`, `LOGOUT` and
  `ACCESS_DENIED` (section 17.4), `LOGIN_THROTTLED` (section 20.4).
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
| 5 | Reverse proxy | nginx examples, for a host name of its own and for a path of a site (section 20.3); any of the spec's three works |
| 6 | Primary keys | UUID |
| 7 | Maximum session length | 12 hours (setting) |
| 8 | Backup retention | The operator's policy; documented, not enforced |
| 9 | Email unique | No |
| 10 | Email verification | No |
| 11 | Step-up before revealing secrets | Yes (setting, default on) |
| 12 | VIP must test the pre-provisioned key at first login | Yes |
| 13 | Migrated keys without counters | Need a fresh OTP before use, unless an admin accepts the risk (spec §38). Keys from a radiator-yubikey export always carry counters. |
| 14 | Audit retention | Kept indefinitely; no automatic purge |
| 15 | Audit copy outside the database | Also written to the system journal (section 17.6) |
| 16 | External API | No |
| 17 | PIN rule | Spec §12's password rule, plus section 2.6 |

---

## 14. Onboarding and YubiKey pages

Adds to spec §11, §13 and §20.

14.1 Temporary passwords are generated, never typed by an admin: 19
characters in four groups of four, such as `k7mq-3xwe-p9fa-h2nt`, from
lowercase letters and digits without the easily confused `0 o 1 i l`, with
at least one letter and one digit (about 79 bits).

14.2 Onboarding requires an email address: the YubiKey step, which sets the
YubiKey's PIN and completes onboarding, needs it first.

14.3 Users can't disable or remove their last enabled YubiKey while their
account is ACTIVE: without it they can't sign in. Admins can.

14.4 The page where users test a YubiKey says why an OTP was refused (for
example, a replayed OTP, or one from another YubiKey). The login page stays
generic (spec §39).

14.5 The page where users remove a YubiKey says nothing about Radiator. The
admin pages keep the `yubikey-db.sh delete` reminder of section 6.6 until the
live connector (section 11) carries removals.

---

## 15. Decision log

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
| 2026-10-16 | The web login tolerates `password:OTP`; password + OTP stays the standard form | 2.9 |
| 2026-10-16 | PROVISIONING accounts lock after consecutive failed logins reach the limit | 2.10 |
| 2026-10-16 | Unlocking an account that still has a temporary password returns it to PROVISIONING | 2.10 |
| 2026-10-16 | The password limit is 80 bytes of UTF-8; control characters are rejected | 2.6 |
| 2026-10-16 | The temporary password stays valid until onboarding completes | 2.11 |
| 2026-10-16 | Enabling a DISABLED account needs a permanent password (a YubiKey with a PIN since 2026-10-17) | 2.12 |
| 2026-10-16 | An enabled admin is an admin in any state but DISABLED | 2.13 |
| 2026-10-16 | Temporary passwords: generated, 19 characters, `xxxx-xxxx-xxxx-xxxx` | 14.1 |
| 2026-10-16 | Email is required during onboarding | 14.2 |
| 2026-10-16 | Users keep their last enabled YubiKey; admins can take it | 14.3 |
| 2026-10-16 | The key-test page says why an OTP was refused | 14.4 |
| 2026-10-16 | The user's remove page says nothing about Radiator | 14.5 |
| 2026-10-16 | Imported plain-text PINs are taken as Radiator has them, without the password policy | 7.3 |
| 2026-10-16 | A `$6$` hash without `{crypt}` is rejected at import | 7.3 |
| 2026-10-16 | With `--skip-invalid`, rows for usernames reserved for Radiator are skipped, not invalid | 7.2 |
| 2026-10-16 | The import's audit event is recorded only when the import changed something (narrowed 2026-10-17) | 7.1 |
| 2026-10-17 | Each YubiKey has its own PIN; the web login checks the PIN of the YubiKey used; accounts have no password but the temporary one | 2.2, 2.3 |
| 2026-10-17 | Failed logins count per YubiKey and per account; any one count at the limit locks the account; a success clears only its YubiKey's count and the account's | 2.14 |
| 2026-10-17 | Users change a YubiKey's PIN with an OTP from it, optionally on all their YubiKeys; other sessions end | 2.15 |
| 2026-10-17 | Admins can set any user's YubiKey PIN, as root can set any user's password | 2.16 |
| 2026-10-17 | Import report lines are short, such as `skipped: reserved username` | 7.1 |
| 2026-10-17 | The import's audit event is recorded only when YubiKeys were added; moving counters is routine | 7.1 |
| 2026-10-17 | A PIN set by an admin ends all the user's sessions; the user isn't asked to change it | 2.16 |
| 2026-10-18 | Admin pages: role checked at every request, never cached; admins may act on their own account within the last-admin rule | 16.1, 16.2 |
| 2026-10-18 | Pre-provisioning: optional OTP, no PIN; temporary passwords shown once | 16.4, 16.5 |
| 2026-10-18 | Hard delete is confirmed by entering the username (typed or pasted) | 16.6 |
| 2026-10-18 | Each reveal needs its own step-up; one can reveal both values; shown for 60 seconds | 16.7 |
| 2026-10-18 | Accounts get an optional display name and comment, for admins only | 12, 16.9 |
| 2026-10-18 | Audit events can't be changed or deleted, also refused by database triggers | 17.1 |
| 2026-10-19 | Backup and restore aren't hindered by the audit triggers or by permissions: a restore rewrites the audit log in one transaction, with no table ownership needed | 17.1 |
| 2026-10-18 | The audit log page: search, filters, an account's events by ID, a page per event | 17.3 |
| 2026-10-18 | New events: `LOGOUT`, `ACCESS_DENIED`; a refused OTP on the PIN page is recorded | 17.4 |
| 2026-10-18 | Reveal events record whether a step-up confirmed them | 17.5 |
| 2026-10-18 | The journal copy is apart from the application's log (`yk-portal-audit`, authpriv), at any log level, from the commands too | 17.6 |
| 2026-10-18 | A temporary password typed as the username isn't named in the audit log | 17.7 |
| 2026-10-19 | A PIN typed as the username is named if it is a valid username: unknown usernames tried must be visible | 17.7 |
| 2026-10-19 | PostgreSQL: one dedicated role that owns the database and has no other privileges; UTF-8 with the C.UTF-8 locale; connections kept for 60 seconds, no pool | 18.2 |
| 2026-10-19 | Both backends list in code-point order and search ignoring the case of every letter; audit details stored with their characters; lengths checked before writing | 18.3 |
| 2026-10-19 | Changes at the same moment end as on SQLite: the admin role's row and the account's row are locked first, a value taken meanwhile is "taken", settings changes take turns | 18.4 |
| 2026-10-19 | Tests check that the migrations build the models' schema on each backend, and undo and redo | 18.5 |
| 2026-10-19 | `database-status` command; `migrate` is spec §36's `database-migrate` | 18.6 |
| 2026-10-19 | Backups: every table but the sessions, read in one snapshot while yk-portal runs, as JSON Lines in AES-256-GCM segments behind a header anyone can read | 19.2, 19.3 |
| 2026-10-19 | `database-export` and `database-import` are `backup-create` and `backup-restore`: no unencrypted export; a backup moves a database between backends | 19.1 |
| 2026-10-19 | A backup restores only with the same schema and master key; `backup-verify` checks everything a restore checks | 19.4, 19.5 |
| 2026-10-19 | A restore needs `--replace` for a database with data and `restore` typed (or `--no-input`), and runs in one transaction | 19.6 |
| 2026-10-19 | A restore never moves OTP counters back, keeps the audit events, and ends every session | 19.7 |
| 2026-10-19 | psycopg's C implementation is an optional build for PostgreSQL installations (`--postgresql-c`), not a requirement or a bundled binary | 20.6 |
| 2026-10-19 | A lab: yk-portal in a Docker container, published on the host's 127.0.0.1, reached from the Internet only through the host's nginx, taken down when not in use | 20.11 |
| 2026-10-19 | yk-portal can be published under a path of a site, such as `https://www.example.com/yk/`, as the user's lab is | 20.2 |
| 2026-10-19 | `yk-portal serve` runs gunicorn from the configuration file, workers configurable (4), the application loaded before the workers, ready reported to systemd, no access log | 20.1 |
| 2026-10-19 | `X-Forwarded-Proto` is believed only from the trusted proxies; plain HTTP is redirected to `public_base_url`; HSTS for a year on a host name of its own, with the names under it, not preloaded | 20.3 |
| 2026-10-19 | Failed sign-ins are limited per address (10 in 15 minutes, settings), counted from the audit log; a waiting address isn't checked, so it can't lock accounts | 20.4 |
| 2026-10-19 | No page is cached; static files for a minute; requests over 256 KiB and file uploads are refused | 20.5 |
| 2026-10-19 | `/health/live` and `/health/ready` (database, migrations, master key), answered before the host name is checked | 20.7 |
| 2026-10-19 | Installed by `deploy/install` into a new `/opt/yk-portal/releases/VERSION-TIME` each time, with `current` pointing at the one in use; a sandboxed systemd unit that gives up after 5 failed starts in 2 minutes; every command's files at umask 077 | 20.9 |
| 2026-10-19 | Under a path: no HSTS header (the site's policy), and a CSRF cookie name of yk-portal's own (`yk_csrftoken`) | 20.2 |

---

## 16. Admin pages

Adds to spec §9, §10, §14, §20.2, §26 and §34 (spec Phase 6).

16.1 The admin pages are for ACTIVE accounts with the admin role, read at
every request, so a role taken away applies at the next one (spec §19).
Other accounts are refused (HTTP 403). No admin page is cached
(`Cache-Control: no-store`), since they show temporary passwords and YubiKey
secrets.

16.2 Admins may use the admin pages on their own account. The only limit is
spec §9.1: the last enabled admin can't be disabled, deleted or lose the
admin role.

16.3 The user list searches usernames and email addresses, filters by
state, role and group, and shows 50 accounts a page.

16.4 Creating an account takes the username, an optional email address, the
admin role and groups, with the default group ticked (section 5.4). The
temporary password (section 14.1) is shown once, on the page that follows,
and never again; so is a new one from a reset to provisioning (spec §15) or
from issuing another to a PROVISIONING account (spec §11).

16.5 Pre-provisioning a YubiKey (spec §14) takes its values, label and slot,
which may be "not known". An OTP is optional: if the admin has the YubiKey
at hand, it checks the values and its counters become the stored ones. The
admin sets no PIN there: the user chooses it (section 2.15), or an admin sets
it afterwards (section 2.16).

16.6 Hard delete (spec §26) is confirmed by entering the username, typed or
pasted. The confirmation and the page after it show the `yubikey-db.sh
delete USER` reminder (section 6.6); removing one YubiKey shows
`yubikey-db.sh delete USER PUBLIC_ID`. `ACCOUNT_DELETED` keeps the former ID
and username, the account's state and the public IDs of its YubiKeys, never
the email address.

16.7 Revealing a private ID or AES key (spec §20.2, §34):

- with the step-up setting on (section 3.2), each reveal needs the admin's
  PIN and a fresh OTP from one of the admin's YubiKeys, as at sign-in; a
  failure counts toward the admin's lockout like a failed login (section
  2.14);
- one step-up can reveal both values, recorded as two events;
- the value is only in the response to that request, never in a URL; the
  page hides it after 60 seconds and when it is left.

16.8 Renaming an account records `USERNAME_CHANGED` with the old and new
names. Radiator gets the new name with the next export, which replaces the
account's YubiKeys by public ID (section 6.4).

16.9 Each account has two optional fields for admins, both empty by default
(spec §10's "display label / comment"):

| Field | Holds | Rule |
|---|---|---|
| `display_name` | A name in whatever form the site uses: full name, first name, or "last, first" | One line, up to 255 characters |
| `comment` | Notes | Up to 1,000 characters; line breaks and tabs allowed |

Admins set them on the create and edit forms. They show on the admin pages
(the display name also in the user list and a group's members), and the
user list's search covers the display name. Users don't see them on their
own pages, and they aren't exported to Radiator. Both are plain text,
escaped on output, without control characters (beyond the comment's line
breaks and tabs). A change is an `ACCOUNT_UPDATED` event naming the field,
never its value, as for the email address (spec §26).

---

## 17. Audit

Adds to spec §9, §25.6, §27, §35 and §40 (spec Phase 7).

17.1 Audit events are immutable (spec §9). The application refuses to
change or delete one, and on both SQLite and PostgreSQL, database triggers
refuse `UPDATE` and `DELETE` on `audit_events` for SQL that goes around
it. A hard delete keeps the account's events (spec §26). `TRUNCATE` and
dropping the table need the table's owner and aren't blocked; the journal
copy (17.6) is the record that outlives them.

Backup and restore (spec Phase 9) are not hindered by immutability or by
permissions. No privilege on `audit_events` is granted or revoked: it is a
table like the others, and a backup reads it. A restore rewrites it inside
`yk_portal.audit.immutability.rewritable()`, which lets the model and the
triggers change and delete events for that one transaction: on PostgreSQL
through a transaction-local setting (`yk_portal.audit_rewrite`), which
needs no table ownership or other privilege beyond writing the table; on
SQLite by dropping the triggers and creating them again in the same
transaction. A failed restore rolls back with the triggers in place.
Nothing but a restore uses it. Django's JSON serializer keeps only
milliseconds of a time, so the backup format must keep microseconds.

17.2 Events are kept indefinitely (section 13, item 14): nothing in
yk-portal purges them.

17.3 The Audit log page (`/admin/audit/`, for admins) lists events newest
first, 50 a page, with times in UTC. Its search matches the actor's and
the target's usernames as they were at the time, the details (such as
public IDs, group and setting names, and reasons), and an IP address typed
in any form. Filters: event type, result, and a From and To date (UTC days,
both included). An account's page links to the account's events as actor
or target, found by account ID, so they're found after a rename or a hard
delete. Each event has a page showing every field, with links to the
accounts that still exist. The pages aren't cached; reading them isn't
audited.

17.4 Events added to spec §27:

- `LOGOUT` when a user signs out;
- `ACCESS_DENIED`, a failure, when a signed-in account without the admin
  role opens or posts to an admin page; it names the method and path,
  never the query string;
- a failed `PASSWORD_CHANGED` when the PIN page (section 2.15) refuses the
  OTP, for example a replayed one, with the reason. It doesn't count toward
  lockout.

A failed step-up was already recorded as `LOGIN_FAILURE` ("step-up: ...",
section 16.7); it now carries the admin's session, as every event from a
page does.

17.5 `YUBIKEY_PRIVATE_ID_REVEALED` and `YUBIKEY_AES_SECRET_REVEALED`
record `step_up`: whether the admin's PIN and OTP were checked for that
reveal, false when the step-up setting is off (section 3.2).

17.6 Once its transaction commits, each event is written to the local
syslog socket, which the system journal reads, as `yk-portal-audit` with
the authpriv facility: apart from the application's own log (standard
error), whatever the configured log level, and from the commands as from
the web application (`journalctl -t yk-portal-audit`). A line holds the
event type, event ID, actor, target, source IP, result and details. Until
now the commands printed these lines on standard error, and a log level
above INFO dropped them.

17.7 A username typed at sign-in that matches no account is named in the
audit log only if it could be a username (as before) and doesn't have the
form of a temporary password, which is also a valid username: a temporary
password typed into the username box isn't recorded. A PIN typed there is
recorded if it happens to be a valid username, as sshd logs "Invalid user"
names: mistakes happen, and attempts at unknown usernames must be visible.

---

## 18. PostgreSQL and the two backends

Adds to spec §4.3, §30, §36, §44.6 and §48 (spec Phase 8).

18.1 SQLite and PostgreSQL run the same code, models and migrations. Django
5.2 supports PostgreSQL 14 and newer; yk-portal is tested with 18, Ubuntu
26.04's, and with Ubuntu's SQLite (3.46).

18.2 PostgreSQL setup (docs/deployment.md, "PostgreSQL"):

- one dedicated role, which owns yk-portal's database and has no other
  privilege: not a superuser, no `CREATEDB`, `CREATEROLE`, `REPLICATION` or
  `BYPASSRLS` (spec §30's least privilege). Owning the database lets
  `yk-portal migrate` create and change the tables and the audit log's
  triggers; no privilege on a single table is granted or revoked (section
  17.1). A second role for migrations was not chosen: as the tables' owner,
  the application's role could drop them anyway, and migrations would need a
  second connection string;
- `PUBLIC` loses `CONNECT` on the database, so other roles can't connect;
- the database is UTF-8, created with the `C.UTF-8` locale, whose case
  folding knows every letter (section 18.3);
- the password is in a passfile, never in the configuration; across a
  network, `sslmode=verify-full` (spec §30);
- each worker keeps its connection for 60 seconds, checked before reuse, so
  a request doesn't pay for a new connection and TLS handshake. No pool is
  needed at the scale of spec §4.4. Connections show as `yk-portal` in
  `pg_stat_activity`, unless the connection string names them otherwise.

18.3 Where the backends behave differently, yk-portal makes them alike.
`yk_portal.core.db` is the one place with backend-specific SQL, besides the
audit log's triggers:

- lists (accounts, groups, members) are in Unicode code-point order, as
  SQLite sorts, whatever the PostgreSQL database's collation: `a-b`, `a.c`,
  `ab`; `Zeta` before `alpha`;
- searches ignore the case of every letter on SQLite too, whose `LIKE` folds
  only ASCII letters: "émile" finds "Émile". PostgreSQL does it with a UTF-8
  locale, which `database-status` checks;
- audit details are stored with their characters as they are, not as `\u`
  escapes, so the audit log's search finds "Clé" on SQLite too. Events
  recorded before keep their escapes;
- lengths are checked before writing, since SQLite stores a value longer
  than its column where PostgreSQL refuses it: email addresses up to 254
  characters (Django's own check allows 320), and YubiKey labels up to 255
  in every path, not only the forms.

18.4 Changes at the same moment. SQLite's writers take turns (IMMEDIATE
transactions); PostgreSQL's run together, and a check one transaction makes
can be overtaken by another. Where it changed the outcome, the outcome is
now the same on both:

- changes that count admins (removing the admin role, disabling, deleting,
  `bootstrap-admin`) first lock the admin role's row: two admins removing
  each other at once leave one (spec §9.1). Before, on PostgreSQL, both
  could succeed; and two `bootstrap-admin` runs at once could make two
  admins on either backend;
- changes to an account's YubiKeys first lock the account, as a login does:
  disabling or removing two YubiKeys at once can't take an ACTIVE account's
  last one (section 14.3), and PIN changes can't deadlock;
- a username, group name or YubiKey that another transaction takes at the
  same moment gets the same "is taken" error as on SQLite, not an error
  page;
- settings changes take turns, so each `SETTING_CHANGED` records the value
  it replaced;
- `radiator-import` reports an account renamed or deleted while it ran as
  "yk-portal changed during the import", like other changes.

Tests run each of these in threads released together, on both backends.

18.5 Migration parity: on each backend, tests check that the migrations
build exactly the schema the models describe (tables, columns and their
types, constraints, indexes), plus the audit log's triggers, and that they
undo to an empty database and redo to the same schema. With the check that
the migrations match the models, both backends hold the same logical schema
(spec §2, principle 4). A migration that changes only the model, not the
column, uses `SeparateDatabaseAndState`, as audit 0005 does: SQLite would
otherwise rebuild the table, dropping the audit log's triggers (migration
0004).

18.6 `yk-portal database-status` (spec §36) shows the backend and its
version, the database, and the result of each check: the migrations (none
missing, none this version doesn't know) and the audit log's triggers; for
SQLite, the file's mode and owner, WAL, synchronous FULL and foreign keys;
for PostgreSQL, TLS, the role's privileges, and the encoding and locale. It
exits with status 1 on a problem: the database unreachable or missing,
migrations missing, triggers missing, SQLite's settings not in effect, an
encoding other than UTF-8. Warnings leave the status 0: privileges the role
doesn't need, no TLS to another host, a file other users can open, a locale
that folds only ASCII letters. `yk-portal migrate` is spec §36's
`database-migrate`.

18.7 The tests run on SQLite and on PostgreSQL with the production database
settings; SQLite's test database is a file, with WAL and IMMEDIATE
transactions, so threads share it. `scripts/check` runs every check and both
test runs.

---

## 19. Backup and restore

Adds to spec §28, §29, §36 and §44.7 (spec Phase 9).

19.1 Three commands (spec §36), run as the service account like the others,
with the master key:

- `backup-create FILE|DIRECTORY|-` writes a backup (mode 0600); given a
  directory, it names the file `yk-portal-YYYYMMDDTHHMMSSZ.backup`;
- `backup-verify FILE|-` is spec §29's dry run (19.4);
- `backup-restore [--replace] [--no-input] FILE` restores one (19.6).

Spec §36's `database-export` and `database-import` are these two: an export
is never written unencrypted, since it holds PIN hashes and email
addresses. A backup restores into either backend, so `backup-create` with
SQLite and `backup-restore` with PostgreSQL move a database from one to the
other.

19.2 A backup holds every table but the sessions: accounts, roles and role
grants, groups and members, YubiKeys (their secrets as stored, still
encrypted with the master key), settings and the audit log. It is a logical
export in JSON Lines: for each table a line naming its columns, then a line
per row, parents first, rows in primary-key order, so the same database
always gives the same text (spec §28's "deterministic"); on either backend
the same values give the same text, but for the order of the keys in JSON
objects, which PostgreSQL chooses and SQLite keeps as written. Times keep
their microseconds (section 17.1); IP addresses are written as Django writes
them. Each row written is first read back as a restore would read it: a row
that a restore would refuse, which only SQL around yk-portal could store,
stops the backup with an error naming the row, rather than making a backup
that can't be restored. It is read in one snapshot that
doesn't make logins wait: on SQLite a read transaction in WAL mode, not a
copy of the file (spec §28.2); on PostgreSQL a read-only REPEATABLE READ
transaction (spec §28.3). Backups can be made while yk-portal runs.
Sessions are left out: a restore would otherwise bring back sessions that
had ended or been signed out since.

19.3 The file (spec §28.1): two lines anyone can read (`head -n 2 FILE`),
the magic `yk-portal-backup` with the format version, then JSON with the
backup's ID, the time, the yk-portal version, the backend, the schema (each
app's last migration), the cipher, the master key's ID, a salt and a nonce
prefix. They hold no name or count: what a backup holds is encrypted. The
contents follow in AES-256-GCM segments of 64 KiB, as Tink's streaming AEAD
does it: each backup has its own key, derived with HKDF-SHA256 from the
backup key (spec §22.5) and the salt; each segment's nonce is the prefix,
the segment's number and whether it is the last; the two header lines are
every segment's associated data, byte for byte. A changed header or
segment, segments moved, dropped or repeated, a file cut short or with
anything added, and another master key all fail authentication. Nothing is held whole in memory
or written unencrypted: the file is written under a temporary name in the
same directory, renamed when complete, and removed if the backup fails or
the command is stopped (spec §28, §44.7); every command stopped by SIGTERM,
from cron or systemd, ends as after Ctrl+C. It isn't compressed.

19.4 `backup-verify` checks what a restore checks before changing anything
(spec §29 1-4): the format, every segment's authentication, every row (this
version's tables and columns, each value of its column's type, each
reference to a row the backup holds), and that this installation can
restore it, with the same master key and schema. It exits with status 1 if
not. It reads nothing from the database and records no event.

19.5 A backup restores only into a database with the same migrations as
the one it was made from. To restore an older backup into a newer version:
install the version that made it (the header names it), restore, then
upgrade. Converting older backups was not chosen, since a migration can
change data as well as columns. A backup made with another master key is
refused, naming both keys' IDs; master key rotation (spec §37) will have to
keep older keys for older backups.

19.6 `backup-restore` (spec §29) checks the whole backup first (19.4). It
refuses a database holding accounts, YubiKeys, groups or settings without
`--replace` (spec §29 6), and asks for `restore` to be typed unless
`--no-input` is given (spec §29 5). Then, in one transaction, it checks
that the file is still the backup it verified and that the database is
migrated, empties the tables, writes the backup's rows as they are (IDs,
times and hashes unchanged), and records `BACKUP_RESTORED` (spec §29 7). A
failure at any point, such as a segment that fails authentication then,
changes nothing; if the database refuses a row (such as a value longer than
its column, which SQLite stored and PostgreSQL refuses), the error names the
table, never the row's values. Meanwhile other transactions read the tables
as they were and wait to change them. On PostgreSQL the tables are locked
`EXCLUSIVE`, all at once or not at all, tried again for up to 30 seconds:
waiting for one table while holding another could deadlock with a request
that locks them in the other order, such as removing an admin. On SQLite,
IMMEDIATE transactions already take turns. It may run while yk-portal runs,
but its pages and logins wait for it: on SQLite a login gives up after 5
seconds, so stop the service first.

19.7 What a restore keeps:

- **OTP counters never move back** (spec §17). For a YubiKey the database
  holds with the same public ID and private ID, the database's counters (and
  last use) are kept when they are ahead of the backup's. A database that is
  lost takes its counters with it: after restoring into an empty database,
  OTPs typed since the backup could be replayed until the counters move
  forward, which `radiator-import --counters-only` does from
  radiator-yubikey's export. The same holds for a YubiKey removed since the
  backup, which the restore brings back with the backup's counters.
- **The audit log** (section 17.2: never purged). The restore adds the
  backup's events the database lacks; an event that differs from the
  backup's, which only SQL around the triggers could do, is put back as the
  backup has it and reported. Events are compared as a backup writes them,
  so PostgreSQL's way of writing some IPv6 addresses isn't taken for a
  change. Events recorded since the backup stay.
- **No session**: every session ends; everyone signs in again.

19.8 Events: `BACKUP_CREATED` records the backup's ID, its destination, its
size, and how many accounts, YubiKeys and audit events it holds;
`BACKUP_RESTORED` records the backup's ID, when and by which version it was
made, whether it replaced data, the same counts, and how many YubiKeys kept
their counters and how many audit events were kept and put back. A backup or
restore that fails or is refused changes nothing and records nothing.

19.9 The backup key is derived from the master key, so a backup can't be
read without it: keep a copy of the master key somewhere safe, apart from
the backups. `backup-create` prints the key's ID, which the header carries.
Retention is the operator's choice (section 13, item 8); the README shows a
nightly backup that keeps 30 days.

19.10 At spec §4.4's largest scale (10,000 accounts, 100,000 YubiKeys) with
500,000 audit events, a backup is about 195 MB. On the development machine:
SQLite backed up in 28 seconds, verified in 8 and restored in 49 to 56;
PostgreSQL backed up in 46 seconds and restored in 83 to 98, most of it in
psycopg's pure-Python layer; memory stayed under 125 MB.

---

## 20. Production hardening

Adds to spec §3, §18.2, §32, §33, §40, §41, §45 and §49 (spec Phase 10).
`docs/deployment.md` is the deployment guide; `deploy/` holds the install
script, the systemd unit and nginx examples.

20.1 **The application server.** `yk-portal serve` runs gunicorn, configured
from `/etc/yk-portal/config.toml`: it listens on `listen_address` and
`listen_port` with `workers` worker processes (new key, 1 to 32, default 4;
each sign-in's Argon2id check uses about 100 MiB). It loads the application
before starting the workers, so a missing master key or a bad setting stops
it at once with the reason; problems that may pass, such as a database not
yet reachable, are logged and reported by `/health/ready`, and it starts
anyway. It reports ready to systemd (`Type=notify`). gunicorn's access log is
off: the reverse proxy logs requests, with the clients' addresses. Its
control socket is off. No request header chooses the path the application
sees: gunicorn takes a `SCRIPT_NAME` header from trusted proxies by default,
which through a proxy that passes headers with `_` in their names would let a
client get past the proxy's rules (found while reviewing: `/x/health/live`
with `SCRIPT_NAME: /x` reached the health check); that is off, and only
`X-Forwarded-Proto` says HTTPS, as Django reads it. The production settings pass Django's deployment
checks (`yk-portal check --deploy`), but for HSTS preloading (20.3).

20.2 **Under a path.** `public_base_url` may have a path, such as
`https://www.example.com/yk` (plain segments of letters, digits and `-._~`; a
trailing `/` is dropped). The reverse proxy strips the path before passing a
request on; yk-portal puts it back in its links, redirects, static files and
the paths of its cookies. The user asked for it for the lab (20.11). Under a
path, yk-portal shares the site's origin, so script on any page of the site
can read its pages with the user's session: the deployment guide recommends a
host name of its own for production. Under a path it sends no HSTS header,
whose policy would be the whole site's and every name under it, and its CSRF
cookie is `yk_csrftoken`, not Django's `csrftoken`, which another application
of the site could set for the whole site and the browser would send too. The
static files' URL is set whole (`PATH/static/`): Django adds the path to a
relative one only when first read, before any request, which left the pages
without their styles and scripts under a path (found by the review; a test
now runs `yk-portal serve` under a path).

20.3 **The reverse proxy and its headers** (spec §32). `X-Forwarded-For` was
already read only through the trusted proxies (sessions). `X-Forwarded-Proto`
is now believed only from them too: from any other address it is dropped, and
plain HTTP is redirected to `public_base_url`'s host, so a client that reaches
the application directly can't claim HTTPS. HSTS is sent for a year, with
`includeSubDomains` (the names under the public host name, not its siblings),
on a host name of its own only (20.2);
not preloaded, which is a decision for the enterprise's whole domain (Django's
check `security.W021` is silenced). The examples: `deploy/nginx/yk-portal.conf`
for a host name of its own, `deploy/nginx/yk-portal-path.conf` for a path of
a site. Both set `X-Forwarded-For` to the client's address, replacing what
the client sent, limit sign-in requests to 10 a minute per address (bursts of
10, answering 429), refuse bodies over 256 KiB, add no security headers
(yk-portal sets them) and answer 404 for `/health/`.

20.4 **Failed sign-ins per address** (spec §18.2, §43 item 6). An address
with as many failed sign-ins within the wait as the limit (settings: 10 within
15 minutes) must wait: its sign-ins are refused before anything is checked,
with HTTP 429 and "Too many failed sign-ins from your address. Try again in N
minutes.", until the oldest failure counted is older than the wait. Refused
sign-ins don't count against an account or its YubiKeys, so the lockout can't
be used from that address to lock accounts, and spend no password check.
Failures are `LOGIN_FAILURE` and `LOGIN_LOCKED` events of the audit log (which
records each with its address; new index on address and time), so every
worker and both backends count the same, and nothing more is stored. A refusal
is recorded as `LOGIN_THROTTLED` (no account, the address, the limit, the
wait, the seconds left) once per address and wait, so an address that keeps
trying doesn't fill the audit log, which is never purged. A trusted proxy's
own address means the proxy didn't send the client's: it is never counted,
since every client would share one count, and the operational log says so
once. Sign-ins checked at the same moment may each pass before the others'
failures are recorded, a few beyond the limit at most (one per worker); the
proxy's request limit adds to it. Addresses are counted one by one, IPv6
too: a client that can change its address within its network can try more
often, which the audit log shows.

20.5 **Headers, caching and request size** (spec §33). Every response gets
the Content-Security-Policy (as before), `Permissions-Policy` (no camera,
geolocation, microphone, payment or USB), `Cross-Origin-Resource-Policy:
same-origin`, and, unless it says otherwise, `Cache-Control: no-store`: every
page shows accounts, YubiKeys or secrets. Django adds `X-Frame-Options: DENY`,
`X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin` and
`Cross-Origin-Opener-Policy: same-origin`. Static files are served by the
application (WhiteNoise) from the installed package, so the proxy only
proxies and no `collectstatic` step exists; browsers may keep them for a
minute, without cross-origin access. Request bodies over 256 KiB and any file
upload are refused (400); the largest form is a few KiB. A form refused for
its CSRF token shows "Form not accepted" in the portal's layout (403);
tests check that every route refuses a POST without the token, that every
form in the templates carries it, and that only the two search forms use GET.

20.6 **psycopg's C implementation** (user's decision). PostgreSQL
installations may build it: `deploy/install --postgresql-c` (the
`postgresql-c` extra), with `build-essential`, `python3-dev` and `libpq-dev`.
It uses Ubuntu's libpq and OpenSSL, so their security updates apply; the
bundled binary wheel was not chosen. SQLite installations need nothing more.
Measured in the lab with 200,000 audit events: a backup in 7.6 s instead of
12.2, a restore in 11.6 s instead of 16.7. `database-status` shows the
implementation, with a warning for the pure-Python one.

20.7 **Health checks** (spec §41). `/health/live` answers `{"status":
"live"}` while the process runs. `/health/ready` answers `{"status":
"ready"}`, or 503 with `{"status": "not ready", "failed": [...]}` naming the
failed checks: `database` (unreachable, or no SQLite file yet; the check never
creates one), `migrations` (missing, or ones this version doesn't know),
`master key` (unreadable, or the file now holds another key than the one in
use: restart). The reasons go to the operational log only. They are answered
first, before the host name is checked and without a session, so monitoring
asks the application directly (`http://127.0.0.1:8000/health/ready`); the
proxy examples don't pass them on.

20.8 **Logging** (spec §40). The service's log goes to standard error, so to
the journal, as `LEVEL logger: message` (the journal adds the time and
process): startup (version, public address, backend), readiness problems,
request errors, warnings. The audit copy is apart, as before (section 17.6).
A test signs an account through its whole life with every logger at DEBUG
and finds no secret in any record.

20.9 **Installation** (spec §49). `deploy/install`, as root from a release's
source tree, creates the `yk-portal` system account (no login shell, home
`/var/lib/yk-portal`), `/etc/yk-portal` (`root:yk-portal` 0750) and
`/var/lib/yk-portal` and `/var/backups/yk-portal` (`yk-portal` 0700), installs
the release with uv, at umask 022 whatever root's, into a new directory each
time, `/opt/yk-portal/releases/VERSION-TIME` (root's: the service can't
change its code; never one that exists, which could be the one running),
from the lock file, without development tools, on the system's Python, then
points `/opt/yk-portal/current` and `/usr/local/bin/yk-portal` at it in one
step, installs `yk-portal.service`, and on a first install copies the example
configuration. A release that fails to install is removed. It never touches the configuration, the
master key or the database, and never starts or stops the service. Earlier
releases stay, for going back with the backup made before the upgrade (the
guide's "Upgrade" and "Go back"). The unit runs `yk-portal serve` as
`yk-portal` with umask 077 and a sandbox (no capabilities, read-only system,
private `/tmp` and `/dev`, a user namespace, system calls of
`@system-service`, no writable and executable memory, writes only to
`/var/lib/yk-portal`); `systemd-analyze security` rates it 1.1, "OK". A
start that fails is tried again after 5 seconds, 5 times in 2 minutes at
most; then the unit stays failed, rather than retrying a missing master key
for ever. Every
`yk-portal` command also sets umask 077, so the SQLite database `migrate`
creates is 0600 whatever the shell's or sudo's umask (found in the lab: it
was 0644). No `/var/log/yk-portal` (spec §49): the logs are the journal's.

20.10 Tests run `yk-portal serve` itself: it starts, answers through
"the proxy" (headers), redirects plain HTTP, refuses another host name,
serves static files, stops on SIGTERM, and stops at once without its master
key or with a bad configuration.

20.11 **The lab** (user's decision). `lab/lab up` builds an image of the
working tree (Ubuntu 26.04, uv, `deploy/install`) and runs it on a Docker
network of its own, published on the host's `127.0.0.1` only; the host's
nginx proxies a path of one of its sites to it (`lab/nginx/`, installed
once), and yk-portal trusts the network's gateway, where Docker's port
forwarding connects from. The lab's address and port are the machine's
own, in `lab/lab.env`, which git ignores (`lab/lab.env.example` has example
values): the repository names no real server.
`lab/lab up --postgresql` adds a PostgreSQL 18 container, set up as the guide
sets PostgreSQL up, and builds psycopg's C implementation. Nothing is kept;
`lab/lab down` removes it all, and nginx answers 502 at the lab's address
meanwhile.
`lab/lab systemd-check` starts the unit under systemd, with its sandbox, in a
privileged container with no network, signs in, checks the journal and the
database file, checks that the unit ends failed without its master key, and
removes the container. The lab is not for production.
