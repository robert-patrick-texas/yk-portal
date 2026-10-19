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
  `ACCESS_DENIED` (section 17.4).
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
