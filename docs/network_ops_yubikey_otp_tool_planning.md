# Network Operations YubiKey OTP Authentication Service
## AI/LLM Planning and Build Specification

**Document purpose:**  
This document is the authoritative planning baseline for an AI coding agent, software engineering team, or LLM-assisted development workflow to design and build a self-hosted network-operations authentication web service.

**Primary audience:**  
AI coding agents, software architects, application developers, security engineers, and network operations technical staff.

**Target deployment:**  
Ubuntu Linux 26.04 LTS or newer.

**Deployment model:**  
Single application server with an HTTPS web interface. SQLite is the default database. PostgreSQL is an optional runtime-selected backend.

---

# 1. Mission

Build an internal enterprise web application that allows network operations staff to authenticate using:

1. A username.
2. A password.
3. A YubiKey OTP credential generated from a user-programmed YubiKey OTP slot.

The application must also provide:

- administrator-managed user lifecycle functions;
- user onboarding;
- YubiKey OTP enrollment and management;
- support for multiple YubiKeys per user;
- role-based administration;
- account reset and re-provisioning;
- replay-resistant Yubico OTP validation;
- secure storage of YubiKey OTP secrets;
- audit logging;
- encrypted database export/backup;
- SQLite and PostgreSQL support through a common data-access model.

The application is intended for use from an enterprise network and is not designed as a public Internet-facing authentication service.

---

# 2. Core Design Principles

The implementation must follow these principles:

1. **Security-first implementation**
   - Minimize exposure of passwords, YubiKey secrets, session tokens, and decrypted OTP material.
   - Use modern authenticated encryption for application-managed secrets.
   - Never store user passwords in reversible form.

2. **Deterministic authentication**
   - A submitted YubiKey OTP identifies the specific enrolled token by Public ID.
   - The application must not attempt every YubiKey AES key belonging to a user.

3. **Replay protection**
   - Yubico OTP validation is stateful.
   - The application must persist and atomically update OTP counters.

4. **Database portability**
   - SQLite and PostgreSQL must use the same logical schema.
   - Application business logic must not depend on SQLite-specific behavior.

5. **Single-server simplicity**
   - Optimize the initial implementation for a single Ubuntu server.
   - PostgreSQL may be external or local.

6. **Explicit account lifecycle**
   - Model provisioning, active, locked, and disabled states explicitly.

7. **Administrative recoverability**
   - Administrators must be able to recover accounts without physical possession of a user’s YubiKey.

8. **Least secret exposure**
   - Private IDs and AES secrets are hidden by default.
   - Admin reveal actions require an explicit reveal control.
   - Prefer step-up authentication before revealing secrets.

9. **Auditable administrative actions**
   - Security-sensitive actions must create immutable audit events.

---

# 3. Deployment Architecture

```text
                         Enterprise Network

+----------------------+
| Operator Workstation |
| - Web Browser        |
| - ykman CLI          |
+----------+-----------+
           |
         HTTPS
           |
           v
+---------------------------+
| Reverse Proxy             |
| - TLS termination         |
| - Enterprise certificate  |
| - Request size limits     |
| - Basic HTTP hardening    |
+-------------+-------------+
              |
              v
+--------------------------------------+
| Network Operations Authentication App |
| Ubuntu Linux 26.04 LTS               |
|                                      |
| - Web UI                             |
| - Authentication                     |
| - Provisioning                       |
| - User Administration                |
| - YubiKey Management                 |
| - RBAC                               |
| - Session Management                 |
| - Audit Logging                      |
| - Backup/Restore                     |
| - Administrative CLI                 |
+------------------+-------------------+
                   |
             Data Access Layer
              /             \
             v               v
      +-------------+   +-------------+
      | SQLite      |   | PostgreSQL  |
      | Default     |   | Optional    |
      +-------------+   +-------------+

Application master key:
    /etc/<application>/master.key
```

---

# 4. Technology Constraints

## 4.1 Operating System

Required target:

```text
Ubuntu Linux 26.04 LTS
```

The implementation should avoid unnecessary dependencies on distribution-specific features unless they improve security or manageability.

## 4.2 Reverse Proxy

TLS is terminated at a reverse proxy.

Acceptable reverse proxies include:

- nginx;
- Caddy;
- Apache HTTP Server.

The application should not require direct public TLS termination in the application process.

TLS certificates are expected to be enterprise-managed.

## 4.3 Database

Runtime-selected through configuration:

```text
DATABASE_BACKEND=sqlite
```

or:

```text
DATABASE_BACKEND=postgresql
```

SQLite is the default.

PostgreSQL is the scale-out / higher-concurrency option.

## 4.4 Expected Scale

Design for:

```text
Initial users:          < 1,000
Maximum users:          10,000
Typical tokens/user:    1-2
Maximum tokens/user:    10
Maximum token records:  100,000
```

This scale must not require distributed application services.

---

# 5. YubiKey OTP Model

## 5.1 YubiKey Provisioning Model

Users self-program one YubiKey OTP slot using the `ykman` CLI on their workstations.

Users may select:

```text
Slot 1
or
Slot 2
```

The slot contains a Yubico OTP configuration with:

- Public ID;
- Private ID;
- AES-128 secret key.

The Yubico OTP protocol itself uses AES-128.

Do **not** attempt to change the Yubico OTP protocol to AES-256.

Use AES-256-GCM for application-managed encryption of stored secrets and encrypted backups.

## 5.2 OTP Structure

Assume the application uses the standard 44-character Yubico OTP format:

```text
12-character Public ID
+
32-character encrypted OTP payload
=
44 characters total
```

The 32-character encrypted payload contains information including:

- Private ID;
- usage counter;
- session counter;
- timestamp;
- random value;
- checksum/CRC.

## 5.3 OTP Parsing

When the user submits:

```text
<password><44-character-yubico-otp>
```

parse:

```python
otp = passcode[-44:]
password = passcode[:-44]

public_id = otp[:12]
encrypted_otp = otp[12:]
```

Validation must reject a passcode if the final 44 characters are not a syntactically valid Yubico OTP representation.

## 5.4 Public ID Uniqueness

The Public ID must be globally unique across all YubiKey credentials.

Enforce:

```text
UNIQUE(public_id)
```

The Public ID is used to identify the YubiKey credential record.

## 5.5 Maximum Tokens per User

Enforce:

```text
maximum 10 YubiKey credentials per user
```

---

# 6. Roles

The initial role model contains only:

```text
user
admin
```

All accounts receive:

```text
user
```

by default.

An administrator may add or remove:

```text
admin
```

The admin role is additive.

A user with the admin role is still a normal user.

---

# 7. User Account States

Use explicit account states.

Required states:

```text
PROVISIONING
ACTIVE
LOCKED
DISABLED
```

Do not model deletion as an account state.

Deletion is a hard database purge.

## 7.1 State Transitions

```text
Admin creates account
       |
       v
PROVISIONING
       |
       | successful onboarding
       v
ACTIVE
       |
       | 3 consecutive failed logins
       v
LOCKED
       |
       | admin unlock
       v
ACTIVE
```

Administrators may transition:

```text
ACTIVE       -> DISABLED
LOCKED       -> DISABLED
PROVISIONING -> DISABLED

DISABLED     -> ACTIVE
DISABLED     -> PROVISIONING
LOCKED       -> PROVISIONING
ACTIVE       -> PROVISIONING
```

Any existing account may be hard deleted by an administrator.

---

# 8. Administrative Bootstrap

The first administrator must be created through a local administrative CLI.

The web interface must not expose an unauthenticated bootstrap-admin page.

Example conceptual command:

```bash
<app-cli> bootstrap-admin
```

The command should:

1. Verify no initial admin exists or require an explicit override.
2. Prompt for username.
3. Normalize username to lowercase.
4. Create the account in provisioning state.
5. Assign roles:
   - user;
   - admin.
6. Set a temporary password.
7. Set temporary password expiration to 72 hours.
8. Write an audit event.

---

# 9. Admin User Management Requirements

Administrators must be able to:

- create users;
- list users;
- search/filter users;
- view user accounts;
- modify user accounts;
- change usernames;
- set or modify email addresses;
- add admin role;
- remove admin role;
- disable accounts;
- re-enable accounts;
- unlock accounts;
- reset accounts into provisioning mode;
- set temporary passwords;
- add YubiKey credential details;
- modify YubiKey credential metadata;
- disable YubiKey credentials;
- re-enable YubiKey credentials;
- delete YubiKey credentials;
- hard-delete user accounts.

## 9.1 Last Administrator Protection

Prevent accidental administrative lockout.

The application should block actions that would result in no enabled administrator remaining, including:

- deleting the last enabled admin;
- disabling the last enabled admin;
- removing the admin role from the last enabled admin.

---

# 10. User Creation

When an administrator creates a normal account, required initial fields are:

```text
username
temporary password
```

Optional/pre-provisionable fields include:

```text
email address
roles
YubiKey credential(s)
display label / comment
```

Automatically set:

```text
state = PROVISIONING
temporary_password_expires_at = created_at + 72 hours
role = user
failed_login_count = 0
```

The username must be normalized to lowercase.

---

# 11. Temporary Password Requirements

Temporary passwords:

- expire after 72 hours;
- are stored using the same password hashing mechanism as permanent passwords;
- are never stored in plaintext;
- are invalidated after successful provisioning;
- may be reset by an administrator;
- must force provisioning mode.

If the temporary password expires, an administrator must issue another one.

---

# 12. Password Policy

Current required policy:

```text
Minimum length: 8 characters
At least one letter
At least one number
Uppercase not required
Lowercase not required
Special characters allowed
```

Recommended implementation limit:

```text
Maximum length: 80 characters (password plus 44-character yubikey string must not exceed 128 characters)
```

Do not silently truncate passwords.

## 12.1 Password Storage

Use:

```text
Argon2id
```

Passwords must never be reversibly encrypted.

Use a unique random salt per password hash.

Do not log passwords.

---

# 13. Initial User Onboarding

A newly created account is placed in:

```text
PROVISIONING
```

The user signs in using:

```text
username
temporary password
```

No YubiKey OTP is required for the initial provisioning login unless the account already contains admin-provisioned YubiKey credentials and the selected workflow requires token verification.

The provisioning session is restricted.

## 13.1 Allowed Provisioning Functions

A provisioning session may only:

- set/update email address;
- set a permanent password;
- add the first YubiKey credential;
- test the YubiKey;
- complete provisioning;
- logout.

The provisioning session must not grant access to normal application functions.

## 13.2 Standard Self-Provisioning Workflow

```text
Admin creates account
      |
      v
User receives username + temporary password
      |
      v
User signs in
      |
      v
User sets email
      |
      v
User sets permanent password
      |
      v
User programs YubiKey with ykman
      |
      v
User enters:
    Public ID
    Private ID
    AES secret
    token label
    slot number
      |
      v
User generates test OTP
      |
      v
Application validates OTP
      |
      v
Application stores counter state
      |
      v
Account becomes ACTIVE
```

---

# 14. Admin-Provisioned / VIP Account Workflow

Administrators may pre-provision an account without physical possession of the YubiKey.

This supports:

- senior staff;
- VIP users;
- administrative migration;
- migration from another OTP validation system;
- operational recovery.

The administrator may enter:

- username;
- email;
- roles;
- YubiKey Public ID;
- YubiKey Private ID;
- YubiKey AES secret;
- slot number;
- token label.

No proof-of-possession is required for administrator-entered credentials.

Record the provisioning method.

Allowed values:

```text
SELF_PROVISIONED
ADMIN_PROVISIONED
MIGRATED
```

Recommended VIP first-login behavior:

1. User signs in using username and temporary password.
2. User must set a permanent password.
3. Existing admin-provisioned YubiKey remains attached.
4. Optionally require the user to test the pre-provisioned YubiKey.
5. Account transitions to ACTIVE.

An administrator must never need to know the user's permanent password.

---

# 15. Reset to Provisioning Mode

An administrator may reset any account to:

```text
PROVISIONING
```

Use cases include:

- lost token;
- replacement token;
- user recovery;
- re-onboarding;
- account repair.

The reset operation must:

1. Set account state to `PROVISIONING`.
2. Set `failed_login_count = 0`.
3. Create/set a new temporary password.
4. Set expiration to 72 hours.
5. Revoke all active sessions.
6. Create an audit event.

Recommended default:

```text
Disable all currently enrolled YubiKey credentials,
but do not automatically delete them.
```

This preserves administrative visibility while preventing use of lost tokens.

---

# 16. Authentication Flow for Active Users

Users enter:

```text
Username
Passcode
```

where:

```text
Passcode = password + YubiKey OTP
```

Processing order:

```text
1. Normalize username to lowercase.
2. Locate account.
3. Verify account state is ACTIVE.
4. Validate passcode is long enough to contain a 44-character OTP.
5. Split password and OTP.
6. Validate OTP ModHex syntax.
7. Extract 12-character Public ID.
8. Locate matching enabled YubiKey credential.
9. Verify password using Argon2id.
10. Decrypt stored Private ID.
11. Decrypt stored Yubico AES key.
12. AES-128 decrypt the OTP payload.
13. Validate OTP checksum/CRC.
14. Validate decrypted Private ID.
15. Read OTP usage/session counters.
16. Compare counters to stored state.
17. Reject replayed or stale OTPs.
18. Atomically update counter state.
19. Reset account failed_login_count to zero.
20. Update last-login / token-last-used timestamps.
21. Create authenticated web session.
22. Write LOGIN_SUCCESS audit event.
```

Do not reveal which authentication factor failed to the user.

Return a generic authentication failure message.

---

# 17. OTP Replay Protection

Replay protection is mandatory.

Store sufficient Yubico OTP state to determine whether a newly submitted OTP is newer than the previously accepted OTP.

At minimum store:

```text
last_usage_counter
last_session_counter
```

Validation and update must occur in a single database transaction.

Concurrency must not permit the same OTP to be accepted twice.

The exact validation implementation must follow the semantics of the Yubico OTP counter fields.

---

# 18. Login Failure and Lockout Policy

Required policy:

```text
Three consecutive failed login attempts -> LOCKED
```

Once locked:

- user authentication is denied;
- existing sessions should be revoked;
- only an administrator may unlock or reset the account.

A successful login resets:

```text
failed_login_count = 0
```

## 18.1 Failures That Count

For an ACTIVE account, count:

- bad password;
- malformed OTP;
- unknown Public ID;
- Public ID not belonging to the user;
- disabled YubiKey;
- invalid AES decrypt;
- Private ID mismatch;
- invalid CRC/checksum;
- stale/replayed OTP;
- invalid counter progression.

For a PROVISIONING account, count incorrect temporary-password attempts.

## 18.2 Rate Limiting

Because a three-failure lockout can be abused for denial of service, add:

- per-source-IP rate limiting;
- request throttling;
- source IP audit logging;
- generic login errors.

---

# 19. Session Management

Required:

```text
Idle session timeout: 20 minutes
Concurrent sessions: allowed
```

Recommended:

```text
Absolute session lifetime: 12 hours
```

Use server-side sessions.

Recommended cookie attributes:

```text
Secure
HttpOnly
SameSite=Strict
Path=/
```

Recommended session invalidation behavior:

| Event | Session behavior |
|---|---|
| Normal successful login | Other sessions remain active |
| User changes password | Invalidate other sessions |
| Reset to provisioning | Invalidate all sessions |
| Account locked | Invalidate all sessions |
| Account disabled | Invalidate all sessions |
| Account deleted | Invalidate all sessions |
| Admin role changed | Refresh/reissue authorization context |

---

# 20. YubiKey Credential Management

Each user may:

- list their enrolled YubiKeys;
- add new YubiKeys;
- update token label;
- disable a YubiKey;
- remove a YubiKey.

Administrators may perform the same actions on behalf of users.

## 20.1 User-Visible Token Fields

Users may view:

```text
label
Public ID
slot number
enabled/disabled
provisioning method
created date
last used date
```

Users should not normally see:

```text
Private ID
AES secret
```

## 20.2 Admin Secret Visibility

Administrators are allowed to reveal:

```text
Private ID
AES secret
```

Secrets must be hidden by default.

Example:

```text
Private ID: ************
AES Secret: ********************************
```

Controls:

```text
[Reveal Private ID]
[Reveal AES Secret]
```

Recommended:

Require administrator step-up authentication using the administrator's current password + YubiKey OTP before revealing secret values.

Every reveal action must create an audit event.

Never put the revealed value into the audit record.

---

# 21. Token Metadata

Recommended YubiKey credential fields:

```text
id
user_id
label
slot_number
public_id
encrypted_private_id
encrypted_aes_secret
enabled
last_usage_counter
last_session_counter
provisioning_method
created_by_user_id
created_at
updated_at
last_used_at
```

Optional future fields:

```text
comment
serial_number
migration_source
disabled_reason
```

---

# 22. Cryptographic Architecture

## 22.1 Passwords

Use:

```text
Argon2id
```

Do not encrypt passwords.

## 22.2 Yubico OTP

Use:

```text
AES-128
```

because this is fixed by the Yubico OTP protocol.

## 22.3 Stored Secrets

Protect recoverable application secrets using:

```text
AES-256-GCM
```

Use authenticated encryption.

Encrypt at minimum:

```text
YubiKey Private ID
YubiKey AES secret
```

## 22.4 Master Key

Store a random 256-bit application master key outside the database.

Recommended path:

```text
/etc/<application>/master.key
```

Recommended permissions:

```text
directory mode: 0700
file mode:      0600
owner:          dedicated application service account
```

The master key must not be stored:

- in the database;
- in source control;
- in logs;
- in browser-accessible configuration;
- in world-readable environment files.

## 22.5 Key Separation

Prefer deriving separate operational keys from the master key.

Conceptually:

```text
master key
   |
   +-- HKDF -> database secret-encryption key
   |
   +-- HKDF -> backup encryption key
```

Use unique context/info strings for each derived key.

## 22.6 Nonces

AES-GCM nonces must never be reused with the same key.

Generate cryptographically secure random nonces and store the nonce with each encrypted value.

---

# 23. Username Requirements

Usernames:

- are normalized to lowercase;
- are unique;
- may be changed by administrators;
- must not be used as relational primary keys.

Use an immutable internal user ID.

Recommended:

```text
UUID
```

or a database-generated integer.

All foreign-key relationships must use the immutable user ID.

Audit username changes.

---

# 24. Email Address

Users set their email address during onboarding unless pre-populated by an administrator.

At this stage email is informational unless future requirements add:

- verification;
- password reset;
- notifications.

Do not assume email can be trusted for authentication or recovery unless a future requirement explicitly enables it.

---

# 25. Recommended Database Schema

## 25.1 users

```text
id
username
email
password_hash
state
failed_login_count
temporary_password_hash
temporary_password_expires_at
created_at
updated_at
last_login_at
```

Constraints:

```text
UNIQUE(username)
```

## 25.2 roles

```text
id
name
```

Initial values:

```text
user
admin
```

## 25.3 user_roles

```text
user_id
role_id
```

Unique composite:

```text
UNIQUE(user_id, role_id)
```

## 25.4 yubikey_credentials

```text
id
user_id
label
slot_number
public_id
encrypted_private_id
private_id_nonce
encrypted_aes_secret
aes_secret_nonce
enabled
last_usage_counter
last_session_counter
provisioning_method
created_by_user_id
created_at
updated_at
last_used_at
```

Constraints:

```text
UNIQUE(public_id)
slot_number IN (1, 2)
```

## 25.5 sessions

```text
id
user_id
created_at
last_activity_at
absolute_expires_at
revoked_at
source_ip
user_agent
```

## 25.6 audit_events

```text
id
timestamp
event_type
actor_user_id
actor_username_snapshot
target_user_id
target_username_snapshot
source_ip
session_id
result
details
```

Do not store secrets in `details`.

---

# 26. Hard Delete Behavior

Administrator delete is a hard delete.

Delete from active database:

- user account;
- password hashes;
- temporary-password hashes;
- user-role mappings;
- YubiKey credentials;
- encrypted YubiKey secrets;
- active sessions;
- other security records directly owned by the user.

Recommended exception:

Retain sanitized immutable audit records.

Audit records may retain:

```text
timestamp
event type
actor ID
actor username snapshot
target former ID
target username snapshot
result
source IP
```

Audit records must not retain:

- Private ID;
- AES secret;
- password;
- email unless explicitly required;
- full OTP;
- decrypted OTP payload.

Historical encrypted backups may continue to contain deleted users until backup-retention expiration.

---

# 27. Audit Logging

Audit logging is mandatory.

Recommended event types include:

```text
LOGIN_SUCCESS
LOGIN_FAILURE
LOGIN_LOCKED
ACCOUNT_CREATED
ACCOUNT_UPDATED
ACCOUNT_DISABLED
ACCOUNT_ENABLED
ACCOUNT_LOCKED
ACCOUNT_UNLOCKED
ACCOUNT_RESET_TO_PROVISIONING
ACCOUNT_DELETED
USERNAME_CHANGED
PASSWORD_CHANGED
TEMPORARY_PASSWORD_SET
ADMIN_ROLE_GRANTED
ADMIN_ROLE_REVOKED
YUBIKEY_ADDED
YUBIKEY_UPDATED
YUBIKEY_DISABLED
YUBIKEY_ENABLED
YUBIKEY_REMOVED
YUBIKEY_PRIVATE_ID_REVEALED
YUBIKEY_AES_SECRET_REVEALED
BACKUP_CREATED
BACKUP_RESTORED
MASTER_KEY_ROTATED
ADMIN_BOOTSTRAPPED
```

Never log:

```text
password
temporary password
entire passcode
full OTP
Private ID
AES secret
decrypted OTP payload
master key
session cookie
```

---

# 28. Backup Design

Provide an administrative backup command.

The backup must export the database to a deterministic text-based representation and encrypt the export using:

```text
AES-256-GCM
```

The backup encryption key should be derived from the application master key.

Recommended process:

```text
Database
   |
   v
Logical text export
   |
   v
stream encryption
   |
   v
AES-256-GCM encrypted backup file
```

Avoid writing an unencrypted intermediate file when practical.

## 28.1 Backup Header

Recommended metadata:

```text
magic identifier
backup format version
application version
schema version
timestamp
cipher
nonce
encrypted payload
authentication tag
```

Do not store the master key in the backup.

## 28.2 SQLite Backup

Prefer:

- SQLite backup API;
- or safe logical export.

Do not naively copy an active SQLite file if doing so could produce an inconsistent backup.

## 28.3 PostgreSQL Backup

Use logical database export and then encrypt the result.

---

# 29. Restore Design

Restore must:

1. Verify backup format.
2. Verify AES-GCM authentication.
3. Reject tampered backups.
4. Check schema/application compatibility.
5. Require explicit administrative confirmation.
6. Restore into an empty or explicitly replaced database.
7. Create an audit event after successful restore.

Provide a dry-run validation mode if practical.

---

# 30. Database Portability

Use:

```text
Application
    |
Repository / ORM Layer
    |
    +-- SQLite
    |
    +-- PostgreSQL
```

Do not duplicate business logic by backend.

Provide database migrations that run against both backends.

Avoid database-specific SQL unless isolated behind a backend abstraction.

SQLite configuration should include:

```text
foreign_keys = ON
WAL mode where appropriate
restricted filesystem permissions
```

PostgreSQL should use:

```text
dedicated database role
least privileges
connection pooling if needed
TLS when database crosses trust boundaries
```

---

# 31. Configuration Model

Use a server-side configuration file.

Suggested location:

```text
/etc/<application>/config.toml
```

or:

```text
/etc/<application>/config.yaml
```

Example logical configuration:

```text
application:
  listen_address
  listen_port
  public_base_url

database:
  backend
  sqlite_path
  postgres_dsn

security:
  master_key_path
  idle_timeout_minutes
  absolute_session_hours
  failed_login_limit
  temp_password_hours

proxy:
  trusted_proxy_addresses

logging:
  level
  audit_path
```

Secrets should not be placed directly in world-readable configuration.

---

# 32. Reverse Proxy Requirements

The reverse proxy should:

- terminate TLS;
- use enterprise-managed certificate material;
- redirect HTTP to HTTPS if HTTP is enabled;
- pass the client IP using a trusted proxy header;
- reject oversized requests;
- add reasonable HTTP security headers;
- proxy only to a localhost/private application listener.

The application must trust forwarding headers only from explicitly configured proxy addresses.

---

# 33. Web Security Requirements

Implement:

- CSRF protection;
- secure cookies;
- server-side sessions;
- output escaping;
- input validation;
- SQL injection prevention through parameterized queries/ORM;
- clickjacking protection;
- content-type enforcement;
- request size limits;
- login throttling;
- secure cache headers for pages containing secrets;
- no secret values in browser URLs;
- no secret values in query strings.

Sensitive pages should use:

```text
Cache-Control: no-store
```

---

# 34. Secret Reveal UX

Default:

```text
AES Secret: ********************************
Private ID: ************
```

After explicit reveal:

- display temporarily;
- do not persist decrypted secret in client-side storage;
- do not expose via URL;
- use `Cache-Control: no-store`;
- clear/de-render when the page is left or timeout occurs.

Recommended:

Require step-up authentication before reveal.

---

# 35. API / Route Model

The application may use server-rendered HTML or an internal JSON API.

If a JSON API is implemented, it remains internal to the same web application unless a future requirement explicitly exposes a supported external API.

Suggested conceptual routes:

```text
POST /login
POST /logout

GET  /provision
POST /provision/profile
POST /provision/password
POST /provision/yubikey
POST /provision/yubikey/test
POST /provision/complete

GET    /account
POST   /account/password

GET    /account/yubikeys
POST   /account/yubikeys
PATCH  /account/yubikeys/{id}
DELETE /account/yubikeys/{id}

GET    /admin/users
POST   /admin/users
GET    /admin/users/{id}
PATCH  /admin/users/{id}
DELETE /admin/users/{id}

POST /admin/users/{id}/disable
POST /admin/users/{id}/enable
POST /admin/users/{id}/unlock
POST /admin/users/{id}/reset-provisioning

POST   /admin/users/{id}/yubikeys
PATCH  /admin/users/{id}/yubikeys/{token_id}
DELETE /admin/users/{id}/yubikeys/{token_id}

POST /admin/users/{id}/roles/admin
DELETE /admin/users/{id}/roles/admin

POST /admin/yubikeys/{id}/reveal-private-id
POST /admin/yubikeys/{id}/reveal-aes-secret

GET /admin/audit
```

These are planning routes, not mandatory final route names.

---

# 36. Administrative CLI

Provide a local CLI for operations that should not depend on web access.

Recommended commands:

```text
bootstrap-admin
create-admin
reset-admin
show-config
database-status
database-migrate
database-export
database-import
backup-create
backup-verify
backup-restore
master-key-status
master-key-rotate
health-check
```

CLI actions must use the same application services/business rules where practical.

---

# 37. Master Key Rotation

Provide a supported key-rotation process.

Conceptual flow:

```text
1. Load old master key.
2. Generate/load new master key.
3. Derive old/new data-encryption keys.
4. Decrypt every stored secret with old key.
5. Re-encrypt every stored secret with new key.
6. Commit transaction.
7. Verify.
8. Replace key file.
9. Audit rotation.
```

Design rotation so a failure does not leave half the database using one key and half using another.

A versioned key identifier may be used if needed.

---

# 38. Migration from Another System

Admins may import existing YubiKey credentials.

Required imported values:

```text
username or target user
Public ID
Private ID
AES secret
```

Optional:

```text
slot
label
existing counters
```

If prior OTP counters are available, import them.

If counters are unavailable, require a fresh OTP before considering the migrated credential fully validated, unless an administrator explicitly accepts the risk.

Record:

```text
provisioning_method = MIGRATED
```

---

# 39. Error Handling

User-facing login failures must remain generic.

Example:

```text
Authentication failed.
```

Do not reveal:

- whether username exists;
- whether password was correct;
- whether Public ID was found;
- whether YubiKey secret was wrong;
- whether the OTP was replayed.

Detailed reason may be written to the secure audit/system log without secret material.

---

# 40. Logging

Separate:

```text
application operational logs
audit/security logs
```

Application logs may include:

- startup;
- database connectivity;
- migrations;
- request errors;
- backup results;
- configuration warnings.

Audit logs contain security events.

Never write secrets to either log.

---

# 41. Health Checks

Provide health endpoints suitable for local monitoring.

Suggested:

```text
/health/live
/health/ready
```

`live` checks process availability.

`ready` may check:

- database connectivity;
- required schema version;
- master key readability;
- internal application readiness.

Do not expose sensitive configuration values.

---

# 42. Security Boundaries

Treat these as separate trust zones:

```text
Browser
Reverse Proxy
Application
Database
Filesystem master key
Backup files
```

The database must not alone contain everything necessary to decrypt YubiKey secrets.

An attacker obtaining only the database should not automatically obtain the application master key.

---

# 43. Threats the Design Must Address

At minimum model and mitigate:

1. Password database theft.
2. Database theft containing encrypted YubiKey secrets.
3. YubiKey OTP replay.
4. Concurrent replay attempts.
5. Brute-force login attempts.
6. Account lockout denial of service.
7. Stolen browser session.
8. CSRF.
9. XSS.
10. SQL injection.
11. Administrator misuse.
12. Unauthorized viewing of YubiKey secrets.
13. Master-key theft.
14. Backup theft.
15. Backup tampering.
16. Lost YubiKey.
17. User migration errors.
18. Username enumeration.
19. Stale admin privileges.
20. Reverse-proxy header spoofing.

---

# 44. Functional Acceptance Criteria

## 44.1 Authentication

- User can authenticate with username + password + valid YubiKey OTP.
- Wrong password fails.
- Wrong token fails.
- Token assigned to another user fails.
- Disabled token fails.
- Replayed OTP fails.
- Malformed OTP fails.
- Successful login resets failed-login count.
- Third consecutive failed login locks account.

## 44.2 Provisioning

- Admin can create a user with temporary password.
- Temporary password expires after 72 hours.
- Provisioning user can set email.
- Provisioning user can set permanent password.
- User can add first YubiKey.
- User can test OTP.
- Successful completion changes state to ACTIVE.

## 44.3 Admin Pre-Provisioning

- Admin can add YubiKey secrets without physical token.
- Admin can create VIP account.
- Admin can add or remove admin role.
- Admin can reset user to provisioning mode.
- Reset invalidates sessions.
- Reset creates a new 72-hour temporary password.

## 44.4 Token Management

- User can maintain multiple tokens.
- User cannot exceed 10 tokens.
- Public ID cannot exist twice.
- User can disable token.
- User can remove token.
- Admin can manage another user's tokens.
- Admin can reveal Private ID.
- Admin can reveal AES secret.
- Reveal is audited.

## 44.5 Sessions

- Sessions idle out after 20 minutes.
- Concurrent sessions are permitted.
- Locked/disabled/deleted accounts lose active sessions.
- Reset-to-provisioning revokes sessions.

## 44.6 Database

- Application runs with SQLite.
- Application runs with PostgreSQL.
- Same functional tests pass on both.
- Migrations support both.

## 44.7 Backup

- Backup creates encrypted text-based export.
- Backup uses AES-256-GCM.
- Tampered backup fails authentication.
- Restore recreates data correctly.
- Plaintext secrets are not left behind.

## 44.8 Hard Delete

- Hard delete removes active user record.
- User cannot log in afterward.
- Tokens are deleted.
- Sessions are revoked.
- Sanitized audit history remains.

---

# 45. Non-Functional Requirements

## Security

The application must prioritize secure defaults over convenience.

## Reliability

Authentication database updates, especially OTP counter updates, must be transactional.

## Maintainability

Separate:

- web/UI layer;
- authentication service;
- YubiKey validation service;
- user/account service;
- encryption/key service;
- database repositories;
- audit service;
- backup service.

## Portability

Application should be installable on Ubuntu Linux 26.04 LTS or newer.

## Testability

Business logic must be testable without running a browser.

## Observability

Provide useful logs and health checks without exposing secrets.

---

# 46. Recommended Internal Module Boundaries

A possible implementation structure:

```text
app/
  auth/
    password.py
    otp.py
    sessions.py
    lockout.py

  users/
    service.py
    models.py
    permissions.py

  yubikey/
    validator.py
    crypto.py
    counters.py
    service.py

  security/
    master_key.py
    encryption.py
    csrf.py

  audit/
    service.py
    models.py

  database/
    models.py
    repositories.py
    migrations/

  backup/
    export.py
    encrypt.py
    restore.py

  web/
    routes/
    templates/
    middleware/

  cli/
    commands/

  config/
    loader.py
    schema.py
```

Exact language/framework is not yet mandated by this planning document.

---

# 47. Development Sequence

Recommended build order:

## Phase 1 — Project Foundation

- select language/framework;
- configuration loader;
- SQLite database;
- migrations;
- user/role schema;
- master-key loader;
- AES-256-GCM utility;
- Argon2id password utility.

## Phase 2 — Account Lifecycle

- admin bootstrap CLI;
- create user;
- provisioning state;
- temporary passwords;
- password setup;
- roles;
- disable/enable;
- lock/unlock.

## Phase 3 — Yubico OTP

- ModHex codec;
- Public ID parser;
- AES-128 OTP decrypt;
- Private ID verification;
- CRC/checksum verification;
- counter parsing;
- replay checks;
- atomic counter update.

## Phase 4 — Authentication

- username + passcode form;
- password/OTP split;
- lockout logic;
- sessions;
- timeout behavior;
- logout.

## Phase 5 — YubiKey Management

- self-enrollment;
- token test;
- multiple tokens;
- admin pre-provisioning;
- migration support;
- secret reveal controls.

## Phase 6 — Administration

- user list/view/edit;
- roles;
- provisioning reset;
- hard delete;
- last-admin protection.

## Phase 7 — Audit

- immutable audit event service;
- admin audit viewer;
- sensitive action coverage.

## Phase 8 — PostgreSQL

- PostgreSQL backend;
- backend test matrix;
- migration parity.

## Phase 9 — Backup and Restore

- logical export;
- AES-256-GCM encryption;
- verification;
- restore;
- CLI commands.

## Phase 10 — Production Hardening

- reverse-proxy deployment;
- CSRF;
- rate limiting;
- security headers;
- logging;
- health checks;
- systemd service;
- filesystem permissions;
- deployment guide.

---

# 48. Test Strategy

## Unit Tests

Cover:

- username normalization;
- password policy;
- Argon2id verification;
- ModHex encoding/decoding;
- OTP parsing;
- AES-128 decrypt;
- Private ID comparison;
- CRC/checksum validation;
- counter comparisons;
- replay rejection;
- lockout transitions;
- state transitions;
- AES-256-GCM application encryption;
- backup encryption/decryption.

## Integration Tests

Run against both:

```text
SQLite
PostgreSQL
```

Cover:

- complete onboarding;
- complete login;
- replay prevention;
- multiple-token selection;
- account lockout;
- unlock;
- reset-to-provisioning;
- admin token enrollment;
- hard delete;
- session revocation;
- backup and restore.

## Concurrency Tests

Specifically test:

```text
same OTP submitted simultaneously
```

Exactly one authentication attempt may succeed.

## Security Tests

Include:

- CSRF;
- XSS;
- SQL injection attempts;
- session fixation;
- session replay;
- username enumeration;
- lockout abuse;
- unauthorized admin-route access;
- direct-object reference attacks;
- secret leakage to logs;
- secret leakage to browser URLs;
- malformed encrypted database values;
- tampered backup files.

---

# 49. Deployment Requirements

Provide:

```text
systemd service file
reverse-proxy example
application configuration example
database initialization command
bootstrap-admin command
backup command
restore command
upgrade/migration procedure
```

Run application using a dedicated unprivileged Linux service account.

Recommended filesystem ownership:

```text
/etc/<application>/
    root:<app-group>
    0750

/etc/<application>/master.key
    <app-user>:<app-group>
    0600

/var/lib/<application>/
    <app-user>:<app-group>
    0700

/var/log/<application>/
    <app-user>:<app-group>
    0750
```

Adjust exact ownership based on deployment design.

---

# 50. Open Decisions for the Build Team

The following items remain implementation choices unless separately specified:

1. Programming language.
2. Web framework.
3. ORM/data-access library.
4. HTML template framework vs SPA.
5. Reverse proxy product.
6. UUID vs integer primary keys.
7. Absolute session lifetime; recommended 12 hours.
8. Backup retention period.
9. Whether email must be unique.
10. Whether email verification will ever be required.
11. Whether admins must step-up authenticate before secret reveal.
12. Whether an admin-provisioned VIP must test the token at first login.
13. Exact behavior for migrated credentials without existing OTP counters.
14. Exact audit-log retention policy.
15. Whether audit records are stored only in the DB or additionally written to syslog/file.
16. Whether an external supported API is a future roadmap item.
17. Whether to retain the specified password letter/number composition rule or move to a modern blocklist-based password policy.

Unless otherwise directed, implement using the recommendations in this document.

---

# 51. Explicit Non-Goals for Initial Release

Do not add these unless explicitly approved:

- LDAP;
- Active Directory integration;
- SAML;
- OIDC;
- external identity provider;
- cloud authentication service;
- YubiCloud validation;
- WebAuthn/FIDO2 authentication;
- passwordless login;
- email-based password reset;
- SMS;
- TOTP;
- distributed application clustering;
- multi-region architecture;
- Kubernetes requirement;
- public Internet exposure;
- more than two initial roles;
- per-device network authorization;
- RADIUS server functionality.

These may be future extensions.

---

# 52. AI Coding Agent Instructions

An AI coding agent using this document should:

1. Treat this document as the functional baseline.
2. Do not weaken security requirements for implementation convenience.
3. Do not replace Yubico OTP with a different authentication protocol.
4. Do not store passwords reversibly.
5. Do not store YubiKey Private IDs or AES secrets in plaintext.
6. Do not store the application master key in the database.
7. Do not expose secrets in logs.
8. Do not remove OTP replay protection.
9. Do not make token validation stateless.
10. Do not make usernames database primary keys.
11. Do not hard-code SQLite behavior into business logic.
12. Keep SQLite and PostgreSQL functionally equivalent.
13. Preserve explicit account states.
14. Preserve three-failure lockout unless requirements are changed.
15. Preserve 72-hour temporary-password expiration.
16. Preserve 20-minute idle session timeout.
17. Preserve maximum ten YubiKey credentials per user.
18. Preserve admin pre-provisioning capability.
19. Preserve reset-to-provisioning capability.
20. Preserve hard-delete behavior for active user data.
21. Preserve immutable/sanitized audit history unless requirements change.
22. Write tests before considering security-sensitive features complete.
23. Prefer small, modular components over large files.
24. Keep OTP cryptography and counter validation isolated and extensively tested.
25. Ask for a decision only when an unresolved choice materially changes the architecture or security model.

---

# 53. Definition of MVP Complete

The MVP is complete when all of the following work on Ubuntu Linux 26.04 LTS:

- application installs and starts under systemd;
- reverse proxy provides HTTPS;
- initial administrator can be bootstrapped locally;
- admin can create normal users;
- admin can pre-provision VIP users;
- temporary passwords expire after 72 hours;
- users can onboard;
- users can register YubiKey OTP credentials;
- users can authenticate with password + YubiKey OTP;
- OTP replay is rejected;
- three failed logins lock the account;
- admin can unlock accounts;
- admin can reset users to provisioning mode;
- users can manage multiple YubiKeys;
- admins can reveal token secrets through an explicit action;
- user and admin permissions are enforced;
- sessions idle out after 20 minutes;
- concurrent sessions work;
- accounts can be disabled/re-enabled;
- accounts can be hard deleted;
- audit events are generated;
- SQLite works as the default database;
- PostgreSQL works as an alternate database;
- database export backup is encrypted with AES-256-GCM;
- encrypted backup can be verified and restored;
- automated unit and integration tests pass.

---

# 54. Future Roadmap Possibilities

Potential future capabilities may include:

- external API;
- syslog/SIEM integration;
- email notifications;
- password-compromise blocklist;
- WebAuthn/FIDO2;
- LDAP/Active Directory;
- OIDC/SAML;
- RADIUS integration;
- automation API;
- secrets vault integration;
- TPM/HSM master-key protection;
- HA PostgreSQL;
- application clustering;
- richer RBAC;
- administrative approval workflows;
- bulk user import/export;
- bulk token migration;
- policy-based token expiration;
- reporting dashboards.

These are not part of the initial build unless separately approved.

---

# 55. Final Build Intent

Build a small, maintainable, security-focused internal enterprise authentication service that gives network operations staff a controlled web interface for local user accounts protected by passwords and self-managed YubiKey OTP credentials.

The service must remain understandable and operable by an enterprise technical team without depending on an external authentication cloud service.

The initial architecture should favor:

```text
simple
auditable
secure
recoverable
database-portable
modular
testable
```

over unnecessary complexity.
