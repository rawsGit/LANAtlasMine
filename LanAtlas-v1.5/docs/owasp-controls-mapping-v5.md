# LAN Atlas — OWASP Security Controls Mapping

> **Version:** 1.5
> **Authors:** Raul, Claude
> **Created:** 2026-08-02
> **Revised:** 2026-08-02
> **Frameworks:** OWASP Top 10 (2025), OWASP API Security Top 10 (2023)
> **Database:** PostgreSQL (AWS RDS) — migrated from SQLite
> **Deployment Target:** AWS
> **Status:** Design Phase — Local Development

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture Security Summary](#2-architecture-security-summary)
3. [PostgreSQL Migration Security Notes](#3-postgresql-migration-security-notes)
4. [OWASP Top 10 (2025) — Web Dashboard](#4-owasp-top-10-2025--web-dashboard)
5. [OWASP API Security Top 10 (2023) — Agent-to-Cloud API](#5-owasp-api-security-top-10-2023--agent-to-cloud-api)
6. [Infrastructure Security Controls](#6-infrastructure-security-controls)
7. [Open Gaps and Recommendations](#7-open-gaps-and-recommendations)
8. [Control Status Summary](#8-control-status-summary)
9. [Version History](#9-version-history)

---

## 1. Overview

This document maps OWASP security controls to the LAN Atlas implementation. It covers two attack surfaces:

- **Web Dashboard** — The browser-based interface used by IT admins and analysts. Mapped against the OWASP Top 10 (2025).
- **Agent-to-Cloud API** — The REST API that receives signed observations from on-premises scanning agents. Mapped against the OWASP API Security Top 10 (2023).

### Authentication Model

LAN Atlas defers user authentication entirely to OAuth 2.0 / OIDC via social providers (Google, Microsoft, GitHub, Okta). The application never handles, stores, or manages passwords. The `users` table anchors identity to `(oauth_provider, oauth_subject)` — the provider's stable `sub` claim that survives email changes. All credential management is the OAuth provider's responsibility.

### Status Definitions

| Status | Meaning |
|---|---|
| ✅ Implemented | Control is in place in the current codebase or schema. |
| 🔵 Planned | Control is designed and documented but not yet coded. |
| 🟡 Partial | Control is partially implemented — gaps identified. |
| 🔴 Not Started | Control has not been addressed. Action required. |
| ➖ N/A | Control does not apply to LAN Atlas. |

---

## 2. Architecture Security Summary

### 2.1 Web Dashboard Surface

```
Browser → HTTPS → Cloud API → PostgreSQL (AWS RDS)
           ↑
     OAuth 2.0 / OIDC (Google / Microsoft / GitHub / Okta)
     JWT Access Token (short-lived, 15 min target)
     Refresh Token (rotated)
     HTTPOnly + Secure Cookie
     Server-side sessions table (token_hash, expires_at, revoked_at)
```

Users authenticate via OAuth social providers. LAN Atlas issues its own short-lived JWT and maintains a server-side session record in the `sessions` table. Sessions can be explicitly revoked by setting `revoked_at` — supporting logout, role changes, and account deprovisioning. The application never sees or stores a password.

### 2.2 Agent-to-Cloud API Surface

```
On-Prem Agent → HTTPS → Cloud API → PostgreSQL (AWS RDS)
                  ↑
           API Key (hex SHA-256 hash stored in agents.api_key_hash)
           token_version (incremented on rotation — old tokens rejected)
           HMAC-SHA256 payload hash (observations.payload_hash)
           UNIQUE (payload_hash) constraint — DB-level deduplication
```

Agents authenticate using API keys. Only the hex SHA-256 hash is stored. `token_version` with a CHECK constraint (`>= 1`) supports key rotation — the auth layer rejects tokens whose version is less than the current value. `payload_hash` has a `UNIQUE` constraint at the database level, making deduplication a schema guarantee rather than only an application-layer check.

### 2.3 Data Layer

```
PostgreSQL (AWS RDS)
  ↑
Encryption at rest  — AWS KMS (must be enabled at RDS creation)
Encryption in transit — ssl_mode=require enforced in connection string
Row-Level Security  — RLS scaffold present (commented), ready for post-MVP activation
Trigger-maintained updated_at — fn_set_updated_at() on all mutable tables
pgcrypto extension  — gen_random_uuid(), digest() available natively
```

> **Deployment Requirement:** RDS encryption at rest must be enabled at instance creation. It cannot be added to an existing unencrypted RDS instance without a snapshot-and-restore migration.

---

## 3. PostgreSQL Migration Security Notes

The migration from SQLite to PostgreSQL resolved several security gaps that were previously open. This section documents what the migration fixed and what new capabilities it introduced.

### 3.1 Issues Resolved by Migration

| Issue | SQLite State | PostgreSQL Resolution |
|---|---|---|
| `ON UPDATE CURRENT_TIMESTAMP` not supported | Removed — updated_at was manual | `fn_set_updated_at()` trigger on all mutable tables. Automatic and consistent. |
| REAL float comparison drift on confidence scores | `identity_strength REAL`, `confidence REAL` | `SMALLINT (0–100)` on `devices.identity_strength`, `device_fingerprint_signals.confidence`, `observations.match_confidence`. Eliminates float drift entirely. |
| No session revocation mechanism | Not present | `sessions` table with `token_hash`, `expires_at`, `revoked_at`. Explicit revocation on logout or deprovisioning. |
| No brute-force tracking | Not present | `users.failed_login_count` (SMALLINT, CHECK >= 0) and `users.lockout_until`. |
| Free-text `network_segment` on observations | Open string injection risk | `network_segments` lookup table with FK. Structured and validated. |
| `payload_hash` deduplication was app-layer only | No DB constraint | `UNIQUE (payload_hash)` constraint on `observations`. DB-level guarantee. |
| Row-level security not available | Not supported in SQLite | RLS scaffold present and commented. Ready for activation post-MVP. |
| Case-sensitive email storage | TEXT column | `CITEXT` extension — case-insensitive, normalized at write. |
| `PRAGMA foreign_keys = ON` required per connection | Manual in db.py | FK enforcement is the default in PostgreSQL. |
| Self-referencing FK on alert_type | Present (bug) | Removed. FIX-6.1 noted in schema. |
| Trailing comma on alerts | Present (syntax risk) | Removed. FIX-6.2 noted in schema. |

### 3.2 New Security Capabilities from PostgreSQL Schema

| Capability | Implementation |
|---|---|
| `pgcrypto` extension | `gen_random_uuid()` and `digest()` available natively for token generation and hashing. |
| `CITEXT` email storage | Prevents duplicate account creation via email case manipulation (e.g. User@example.com vs user@example.com). |
| `ck_alerts_resolved_consistency` CHECK | Enforces that `resolved_at` is always set when `alert_status = 'resolved'` and always NULL otherwise. Prevents inconsistent alert state. |
| Named constraints | All FKs, UNIQUEs, and CHECKs are named — makes error messages actionable and migrations readable. |
| `services` table | Active service state per observation, complementing `device_ports` (history). Enables per-observation port state tracking. |
| `network_segments` table | Structured CIDR and VLAN lookup replacing free-text. Enables structured queries like "all devices on VLAN 20". |
| MAC format CHECK constraints | `ck_device_mac_format` and `ck_observations_mac_format` enforce valid MAC format at the DB layer. |
| RLS scaffold | `ENABLE ROW LEVEL SECURITY` statements and example policy are present (commented). One-step activation post-MVP. |

---

## 3.5 Architecture-to-Control Mapping

The identity engine has been split from a single `identity_engine.py`
file into a layered architecture (`config/`, `database/`, `repositories/`,
`services/`) plus a new `audit_log` table and mechanism. This section
maps each layer to the specific OWASP controls it is now responsible
for enforcing — use this as the "where do I go" reference during
security review or when a new control needs implementing.

### Layer Responsibilities

| Layer | Owns | Controls Enforced Here |
|---|---|---|
| `config/identity.py`, `config/alerts.py` | All tuning constants — signal weights, thresholds, scan tier ceilings | A06 (Insecure Design) — scoring logic is centralized and auditable, not scattered through business logic |
| `database/audit.py` | AuditEvent shape, AuditAction names, secret redaction (`redact()`) | A09 (Logging/Alerting Failures) — defines what must be logged and guarantees secrets never enter the trail |
| `database/db.py` | Connection lifecycle, commit/rollback, `get_db()` / `get_test_db()` | A02 (Security Misconfiguration), A10 (Mishandling of Exceptional Conditions) — transaction boundary is centralized, never per-function |
| `repositories/devices.py`, `signals.py`, `observations.py`, `audit.py` | 100% of SQL in the identity + audit pipeline | A05 (Injection) — SQL is physically confined to these four files; a security review of injection risk reads these files only, not the whole codebase |
| `repositories/observations.py` — `insert_observation_if_new()` | Duplicate-submission rejection via `ON CONFLICT (payload_hash)` | API4 (Unrestricted Resource Consumption) — duplicate agent retries are rejected at the database layer, not just application logic |
| `services/identity.py` | Business logic — scoring, hardware-anchor checks, resolution decisions | A06 (Insecure Design) — no SQL permitted in this file by rule, keeps business logic auditable independent of data access |
| `services/deduplication.py` | `payload_hash` computation | A08 (Software/Data Integrity Failures) — payload integrity check happens before any DB write |
| `services/classification.py`, `thresholds.py` | Pure lookups, no side effects | N/A — supporting logic, no direct security control |
| `models/audit_log.py` + `migrations/manual/audit_log.sql` | Schema definition and immutability trigger | A08, A09 — `fn_prevent_audit_log_mutation()` makes the audit trail tamper-proof even against a compromised app server with valid DB credentials |

### What This Split Changes About Our Injection Posture (A05)

Before the split, SQL and business logic were interleaved throughout
one 330-line file. After the split, **every SQL statement in the
identity and audit pipeline lives in exactly four files**
(`repositories/devices.py`, `signals.py`, `observations.py`, `audit.py`).
A code review focused on injection risk now has a bounded, specific
scope instead of needing to read the entire codebase. `services/identity.py`
contains zero SQL by rule — if a future PR adds a `db.execute()` call
there, that's an immediate, easy-to-catch review flag.

### What the New audit_log Table Adds (A09)

Previously, `observations`, `alerts`, and `analyst_notes` gave us a
trail of machine activity and optional human notes, but nothing
captured "a human changed this record" as a mandatory, structured,
immutable event. `audit_log` closes that gap specifically for
tenant-owned data mutations (device renamed/deleted/authorized, alert
resolved, user role changed, agent key rotated).

Immutability is enforced by a database trigger
(`fn_prevent_audit_log_mutation`), not application code — this matters
because it means even a fully compromised application server with
valid database credentials cannot tamper with the audit trail after
the fact. This is a meaningful strengthening of A09 beyond what any
single layer of application code could guarantee on its own.

**Status:** schema, repository, and event-shape mechanism are built
(`✅ Implemented`). Wiring — actually calling `insert_audit_log()` from
the service functions that perform mutations (`rename_device`,
`delete_device`, and their future siblings for alerts/users/agents) —
is `🔵 Planned`, since those service functions and the API routes that
call them don't exist yet. `repositories/devices.py` includes
`rename_device()` and `delete_device()` as a worked example of the
return shape (`{"before": ..., "after": ...}`) a service function
needs to build an `AuditEvent`.

### What's Still Not Addressed by the Split

The architectural split closes gaps in **how code is organized** — it
does not by itself close gaps that require new code to be written.
Still open, unchanged by this restructure:

- RBAC enforcement (needs `api/middleware/rbac.py` — not yet built)
- Rate limiting (needs `api/middleware/rate_limit.py` — not yet built)
- Agent-site trust validation (needs `api/routes/agents.py` — not yet built)
- HTTP security headers, CORS (needs `api/` layer generally)

These remain tracked in Section 7 below.

---

## 3.6 Full Structural Alignment — cloud / agent / protocol Split

Section 3.5 above covers the identity and audit slice, which is
already built. This section extends that mapping to the full canonical
structure locked in `docs/directory-structure.md`, including the
`cloud/agent/protocol` repo split, the `api/` layer, `workers/`, and
`agent/` — most of which is still 🔵 planned. The distinction that
matters here: a folder existing means the codebase is **positioned**
to enforce a control; it does not mean the control is **active** until
the code inside it is written. Every row below is honest about which
of the two is true today.

### The Trust Boundary Itself Is a Control

The `cloud/agent/protocol` split with the no-cross-import rule
(`agent/` never imports from `cloud/`, and vice versa) is not just an
organizational choice — it is a structural implementation of two
controls at once:

- **A01:2025 (Broken Access Control)** — an agent binary running on a
  customer's network structurally cannot reach `cloud/app/database/db.py`,
  because the import doesn't exist anywhere in the codebase. There is
  no code path for a compromised or reverse-engineered agent to reach
  the database directly, only through the authenticated HTTPS API.
- **A06:2025 (Insecure Design)** — separating `cloud/.env` (database
  credentials, JWT secrets, OAuth secrets) from `agent/.env` (agent's
  own API key, cloud API URL only) means a stolen agent binary or a
  compromised customer endpoint yields, at worst, one agent's API key
  — never database access, never other tenants' data, never the
  ability to mint JWTs.

This is the single most consequential security property of the entire
restructure, and it is already ✅ locked into the directory structure
itself, independent of how much code inside each folder is written yet.

### Layer-by-Layer Alignment

| Directory | Status | OWASP Controls It Will Enforce | Notes |
|---|---|---|---|
| `cloud/agent/protocol` split (structural) | ✅ Locked | A01, A06 | See above — enforced by absence of cross-imports, not by code |
| `protocol/schemas/*.py` | 🔵 Planned | A05 (Injection), API10 (Unsafe Consumption) | Pydantic validation is the first checkpoint untrusted agent data passes through, on both sides of the wire |
| `cloud/app/config/` | ✅ Built | A06 | Scoring/threshold logic centralized, not scattered |
| `cloud/app/database/` | Partial (`db.py`, `audit.py` ✅; rest 🔵) | A02, A09, A10 | Transaction boundary and audit mechanism centralized |
| `cloud/app/repositories/` | Partial (identity + audit ✅; `agents.py`, `alerts.py`, `sites.py`, `users.py` 🔴/🔵) | A05 | SQL confinement — see 3.5 |
| `cloud/app/services/` | Partial (identity ✅; mutation services `devices.py`/`alerts.py`/`users.py`/`agents.py`/`sites.py` 🔴) | A06, A09 | Business logic layer; mutation services are where audit wiring happens — see 3.5 |
| `cloud/app/api/middleware/auth.py` | 🔵 Planned | A07 (Authentication Failures), API2 | JWT verification, session revocation check, `organization_id` injection into every request — see prior discussion on why this file still matters with OAuth |
| `cloud/app/api/middleware/rbac.py` | 🔵 Planned | A01, API5 | Single enforcement point for role checks — closes the RBAC gap tracked since the first OWASP mapping draft |
| `cloud/app/api/middleware/rate_limit.py` | 🔵 Planned | A06, API4 | Per-agent and per-user rate limiting |
| `cloud/app/api/routes/agents.py` | 🔵 Planned | API1 (Broken Object Level Authorization) | Must validate the authenticated agent's `site_id` matches the submitted payload's `site_id` — this is the specific fix for the API1 gap tracked since the original mapping |
| `cloud/app/api/schemas/` | 🔵 Planned | A05, API3 | Role-filtered response models (`DeviceOut` must not leak `fingerprint_hash` to a `viewer` role, for example) |
| `cloud/app/workers/alert_worker.py` | 🔵 Planned | A09 | Once built, this is also the thing that needs a watchdog — an alert engine that silently stops running is itself an A09 gap |
| `cloud/app/workers/identity_worker.py` | 🔵 Planned | A10 | Batch-processes unresolved observations; needs the retry/error-handling design discussed for A10 |
| `agent/signer.py` | 🔵 Planned | A04 (Cryptographic Failures), API2 | HMAC-SHA256 payload signing — the agent's half of proving payload integrity before the cloud ever sees the data |
| `agent/buffer.py` | 🔵 Planned | A06, A10 | Offline resilience; local persistence design still an open item per `docs/directory-structure.md` |
| `agent/config.py` | 🔵 Planned | A01 (indirectly) | Kept agent-owned specifically to avoid the cross-import boundary violation flagged during structure reconciliation |

### Gaps Mapped to the Controls They Block

Cross-referencing the 🔴 gaps named in `docs/directory-structure.md`
directly against the OWASP controls they are blocking, so this is
actionable rather than descriptive:

| 🔴 Gap (from directory-structure.md) | Blocks Control | Why |
|---|---|---|
| `repositories/agents.py` | API1 | Without agent lookup by `api_key_hash` and site-ownership validation, there is no way to implement the agent-site trust check at all |
| `services/devices.py`, `alerts.py`, `users.py`, `agents.py`, `sites.py` | A09 | These are exactly where `insert_audit_log()` gets called — until they exist, `audit_log` has a working mechanism with nothing feeding it |

### What Changes in Section 7 (Open Gaps) As a Result

Nothing in Section 7 below is resolved by this reconciliation — the
gaps listed there were already accurate. What this section adds is
**traceability**: every gap in Section 7 now has a specific file in
`docs/directory-structure.md` that will close it, rather than being an
abstract line item. Use this section when picking up a gap from
Section 7 to know exactly which file to start writing.

---

## 4. OWASP Top 10 (2025) — Web Dashboard

---

### A01:2025 — Broken Access Control

**Risk:** Users access data or functionality beyond their intended permissions. In 2025, SSRF (previously standalone A10 in 2021) is consolidated here — SSRF is treated as a specific manifestation of broken access control.

**LAN Atlas Implementation:**

- Every operational table carries `organization_id` and `site_id` with enforced FK constraints to `organization` and `sites`. No cross-tenant query path exists in the schema.
- `users.user_role` enforced by `ck_users_role` CHECK constraint (`admin`, `analyst`, `viewer`).
- `UNIQUE (oauth_provider, oauth_subject)` prevents duplicate identity linking — one user account per OAuth identity.
- `is_authorized` on `devices` provides an explicit device approval workflow. New devices are never trusted by default.
- Partial index `idx_alerts_org_unresolved` scopes unresolved alert queries to a single organization.
- RLS scaffold present and commented — `ENABLE ROW LEVEL SECURITY` and example tenant isolation policy ready for post-MVP activation.
- The observation API processes submitted data internally and makes no outbound HTTP calls based on agent-supplied data, eliminating the primary SSRF vector.
- `network_segments` table with FK on `observations.network_segment_id` replaces free-text `network_segment` — structured FK prevents arbitrary strings entering the pipeline (OWASP A03 overlap noted in schema comments).
- OUI vendor lookup for `vendor_name` must use a locally bundled IEEE OUI database — not a live HTTP call triggered by agent-supplied MAC addresses.

**Gaps:**

- RBAC enforcement exists in the schema but has not yet been implemented in API middleware. Every endpoint must validate the authenticated user's `organization_id` against the resource being accessed.
- RLS is scaffolded but not yet activated. Activation requires the application to set `app.current_org_id` via `current_setting()` on each connection.
- Agent-site trust validation — confirming an agent can only submit observations to its registered site — is not yet implemented in API middleware.

| Control | Status |
|---|---|
| Multi-tenant FK-enforced schema isolation | ✅ Implemented |
| Role definitions with CHECK constraint | ✅ Implemented |
| Unique OAuth identity anchor (provider + subject) | ✅ Implemented |
| Explicit device authorization (is_authorized) | ✅ Implemented |
| No outbound HTTP from observation data (SSRF) | ✅ Implemented by design |
| Structured network_segment FK (injection defense) | ✅ Implemented |
| RLS scaffold ready for activation | ✅ Implemented |
| RBAC enforcement in API middleware | 🔴 Not Started |
| Agent-site trust validation in API middleware | 🔴 Not Started |
| RLS policy activation (post-MVP) | 🔵 Planned |
| OUI lookup via local bundled file | 🔵 Planned |

---

### A02:2025 — Security Misconfiguration

**Risk:** Systems configured incorrectly, leaving them open. Rose from #5 in 2021 to #2 in 2025.

**LAN Atlas Implementation:**

- `fn_set_updated_at()` trigger on all mutable tables — `updated_at` is always correct, never silently stale.
- PostgreSQL enforces FK constraints by default — `PRAGMA foreign_keys = ON` workaround from SQLite is no longer needed.
- All constraints are named — error messages from violations are actionable, not cryptic.
- `ck_alerts_resolved_consistency` prevents `resolved_at` / `alert_status` from being set inconsistently.
- Secrets loaded from `.env` via `python-dotenv`. `.env` is in `.gitignore`.
- `db.py` validates `DATABASE_URL` format on startup and uses a context manager with rollback-on-exception.

**Gaps:**

- PostgreSQL `pg_hba.conf` hardening not yet defined for production.
- Debug mode and verbose error responses must be disabled in production.
- AWS security groups must restrict PostgreSQL port 5432 to the application layer only.
- Least-privilege IAM roles for the application not yet defined.
- HTTP security headers (CSP, X-Frame-Options, HSTS, X-Content-Type-Options) not yet configured.
- CORS policy not yet defined.
- In production, `DATABASE_URL` should move from `.env` to AWS Secrets Manager.

| Control | Status |
|---|---|
| fn_set_updated_at() trigger on all mutable tables | ✅ Implemented |
| Named constraints for actionable error messages | ✅ Implemented |
| alert_status / resolved_at consistency CHECK | ✅ Implemented |
| Secrets in .env, not source code | ✅ Implemented |
| DATABASE_URL validation on startup | ✅ Implemented |
| Rollback-on-exception in db.py | ✅ Implemented |
| PostgreSQL pg_hba.conf hardening | 🔵 Planned |
| Debug mode disabled in production | 🔵 Planned |
| AWS security group restrictions (port 5432) | 🔵 Planned |
| Least-privilege IAM roles | 🔵 Planned |
| HTTP security headers | 🔴 Not Started |
| CORS policy | 🔴 Not Started |
| DATABASE_URL in AWS Secrets Manager (production) | 🔵 Planned |

---

### A03:2025 — Software Supply Chain Failures

**Risk:** Breakdowns or compromises in building, distributing, or updating software. New in 2025, expanding A06 (Vulnerable and Outdated Components) from 2021.

**LAN Atlas Implementation:**

- `requirements.txt` tracks Python dependencies.
- Minimal external dependency surface — `python-dotenv` is the primary runtime dependency.
- PostgreSQL's `pgcrypto` extension is a first-party trusted extension — not a third-party dependency.

**Gaps:**

- No automated dependency vulnerability scanning (`pip-audit`, GitHub Dependabot).
- Dependency versions in `requirements.txt` need a full security audit.
- Python version not pinned in deployment configuration.
- No dependency hash verification (`pip install --require-hashes`).
- No signed commits policy.
- No CI/CD artifact signing.

| Control | Status |
|---|---|
| requirements.txt dependency tracking | 🟡 Partial — versions need audit |
| pgcrypto as first-party extension (no third-party crypto) | ✅ Implemented |
| Automated dependency scanning | 🔴 Not Started |
| Python version pinned in deployment | 🔴 Not Started |
| Dependency hash verification | 🔴 Not Started |
| Signed commits policy | 🔴 Not Started |
| CI/CD artifact signing | 🔴 Not Started |

---

### A04:2025 — Cryptographic Failures

**Risk:** Sensitive data exposed due to weak or missing encryption. Fell from #2 in 2021 to #4 in 2025.

**LAN Atlas Implementation:**

- **In transit:** HTTPS only. All communication encrypted via TLS.
- **At rest:** PostgreSQL on AWS RDS with encryption via AWS KMS at infrastructure level.
- **No password storage:** OAuth-only. `users` table has no `password_hash` column. Identity anchored to `(oauth_provider, oauth_subject)`. The application never touches credentials.
- **API keys:** `agents.api_key_hash` is hex SHA-256. Plain-text never stored. `pgcrypto`'s `digest()` function available for consistent hashing.
- **Session tokens:** `sessions.token_hash` is hex SHA-256 of the opaque bearer token. Plain-text token is never persisted.
- **Payload integrity:** `observations.payload_hash` (HMAC-SHA256) detects tampered or duplicate payloads.
- **Key rotation:** `token_version` on agents with CHECK `>= 1`. Auth layer rejects tokens below the current version.
- **Float elimination:** `identity_strength`, `confidence`, and `match_confidence` changed from REAL to SMALLINT (0–100). Eliminates float comparison drift in security-relevant scoring.

**Gaps:**

- TLS 1.2+ minimum must be enforced at the load balancer. TLS 1.0 and 1.1 must be explicitly disabled.
- RDS encryption must be explicitly enabled at creation — not on by default.
- `ssl_mode=require` must be set in the PostgreSQL connection string.

| Control | Status |
|---|---|
| HTTPS for all traffic | 🔵 Planned |
| PostgreSQL encryption at rest (AWS KMS) | 🔵 Planned — deployment requirement |
| ssl_mode=require in connection string | 🔵 Planned |
| TLS 1.2+ at load balancer | 🔵 Planned |
| No password storage — OAuth-only | ✅ Implemented by design |
| API key hashing (hex SHA-256 via pgcrypto) | ✅ Implemented |
| Session token hashing (token_hash) | ✅ Implemented |
| Payload integrity (HMAC-SHA256) | ✅ Implemented |
| Key rotation support (token_version CHECK >= 1) | ✅ Implemented |
| Float drift eliminated (SMALLINT scores) | ✅ Implemented |

---

### A05:2025 — Injection

**Risk:** Untrusted data sent to an interpreter causes unintended execution. Fell from #3 in 2021 to #5 in 2025.

**LAN Atlas Implementation:**

- SQL is now structurally confined to `repositories/` — `services/identity.py` contains zero SQL by rule, verifiable by code review. See Section 3.5.
- All database queries in `repositories/` use SQLAlchemy Core with `text()` and named `:param` placeholders. No string concatenation builds SQL statements anywhere in the codebase.
- Named CHECK constraints on all enum fields enforce valid values at the DB layer as a secondary defense.
- `network_segments` table with FK on `observations.network_segment_id` replaces the free-text `network_segment` column — arbitrary strings can no longer enter the observations pipeline via that field.
- `CITEXT` on `users.email` normalizes email at write — prevents case-manipulation injection attempts.
- MAC address format enforced by regex CHECK constraints on `device_mac_addresses` and `observations`.
- `UNIQUE (payload_hash)` on observations — `repositories/observations.py:insert_observation_if_new()` relies on `ON CONFLICT DO NOTHING`, making deduplication a schema guarantee rather than an application-layer check.

**Gaps:**

- API-layer input validation (field length limits, type enforcement) not yet implemented before data reaches the identity service — becomes `api/schemas/` once the API layer is built.
- `models/audit_log.py` was written against an assumed SQLAlchemy `Base` import since `models/` was empty at the time — needs alignment once the team's actual ORM base is established.

| Control | Status |
|---|---|
| SQL confined to repositories/ (structural, not just convention) | ✅ Implemented |
| Parameterized queries throughout (SQLAlchemy Core, named params) | ✅ Implemented |
| Named CHECK constraints on all enum fields | ✅ Implemented |
| network_segment FK (replaces free-text) | ✅ Implemented |
| CITEXT email normalization | ✅ Implemented |
| MAC address format CHECK constraints | ✅ Implemented |
| UNIQUE payload_hash enforced via ON CONFLICT in repository | ✅ Implemented |
| API-layer input validation | 🔴 Not Started |
| SQLAlchemy for dialect safety | ✅ Implemented — adopted directly rather than deferred |

---

### A06:2025 — Insecure Design

**Risk:** Missing or ineffective security controls baked into the architecture. Fell from #4 in 2021 to #6 in 2025.

**LAN Atlas Implementation:**

- Device identity computed from weighted signals — a rogue device cannot impersonate a known device by claiming the same MAC. `fingerprint_hash` is SHA-256 of normalized signals with a UNIQUE constraint per `(organization_id, site_id)`.
- `scan_tier` CHECK constraint. Confidence ceilings in the identity engine mean unauthenticated scans can never auto-link to existing devices.
- `seen_count` CHECK `>= 0`. Must reach minimum before missing-device alerts fire.
- `is_authorized` requires explicit human action — new devices never auto-authorized.
- `payload_hash` UNIQUE constraint at DB level prevents replay attacks — a resent observation is rejected by the DB before the identity engine even sees it.
- OAuth-only authentication eliminates credential-based attack surface at the design level.
- `token_version` CHECK `>= 1` — compromised agent keys can be rotated without downtime.
- `sessions` table with `revoked_at` — explicit session termination capability for logout and deprovisioning (OWASP ASVS V3.3).
- `failed_login_count` and `lockout_until` on `users` — brute-force tracking built into the schema.
- `ck_alerts_resolved_consistency` — alert lifecycle state machine enforced at DB level.
- `services` table tracks per-observation service state — enables detecting when a service changes state (open → closed → open) across scans.

**Gaps:**

- Rate limiting on the agent API endpoint not yet designed.
- No observation volume anomaly detection.
- Bulk alert resolution should require elevated role confirmation.

| Control | Status |
|---|---|
| Hardware-anchored identity with UNIQUE fingerprint_hash | ✅ Implemented |
| Scan tier confidence ceilings (CHECK constraint) | ✅ Implemented |
| seen_count threshold with CHECK >= 0 | ✅ Implemented |
| Explicit device authorization (is_authorized) | ✅ Implemented |
| Replay attack prevention (UNIQUE payload_hash at DB) | ✅ Implemented |
| OAuth-only auth (no credential attack surface) | ✅ Implemented by design |
| Key rotation by design (token_version CHECK >= 1) | ✅ Implemented |
| Session revocation (sessions.revoked_at) | ✅ Implemented |
| Brute-force tracking (failed_login_count, lockout_until) | ✅ Implemented |
| Alert lifecycle consistency CHECK | ✅ Implemented |
| API rate limiting | 🔴 Not Started |
| Observation volume anomaly detection | 🔴 Not Started |
| Bulk operation safeguards | 🔴 Not Started |

---

### A07:2025 — Authentication Failures

**Risk:** Authentication mechanisms implemented incorrectly. Renamed from "Identification and Authentication Failures" in 2021.

**LAN Atlas Implementation:**

- **Dashboard:** OAuth 2.0 / OIDC via social providers. LAN Atlas never handles passwords. The `(oauth_provider, oauth_subject)` UNIQUE constraint prevents duplicate account creation for the same OAuth identity.
- **Session management:** Server-side `sessions` table with `token_hash` (SHA-256), `expires_at`, and `revoked_at`. Sessions can be explicitly revoked on logout, role change, or `is_active = FALSE`. Satisfies OWASP ASVS V3.3.
- **JWT:** Short-lived access tokens (15 min target) with refresh token rotation planned.
- **HTTPOnly + Secure cookies** prevent JavaScript access and enforce HTTPS-only transmission.
- **Brute-force:** `failed_login_count` incremented on failure, reset on success. `lockout_until` set after N failures.
- **Agents:** SHA-256 hashed API keys. `is_active` on agents enables immediate decommissioning.
- `users.last_login_at` tracks authentication events.
- `users.is_active` and `agents.is_active` support immediate deactivation.

**Gaps:**

- JWT expiry and refresh token rotation not yet implemented in code — only designed.
- OAuth provider configuration (allowed domains, tenant restrictions per provider) not yet finalized.
- Brute-force lockout enforcement is in the schema but the auth layer logic implementing it has not yet been coded.

| Control | Status |
|---|---|
| OAuth via social providers (no credential storage) | 🔵 Planned |
| UNIQUE OAuth identity anchor (provider + subject) | ✅ Implemented |
| Server-side sessions with revocation (sessions table) | ✅ Implemented |
| Session revocation on deactivation (revoked_at) | ✅ Implemented |
| JWT + HTTPOnly + Secure cookie | 🔵 Planned |
| Short-lived JWT access tokens (15 min) | 🔵 Planned |
| Refresh token rotation | 🔵 Planned |
| API key hashing (SHA-256) | ✅ Implemented |
| Agent decommissioning (is_active) | ✅ Implemented |
| User deactivation (is_active) | ✅ Implemented |
| Login event tracking (last_login_at) | ✅ Implemented |
| Brute-force schema (failed_login_count, lockout_until) | ✅ Implemented |
| Brute-force enforcement in auth layer code | 🔴 Not Started |
| OAuth provider tenant restrictions | 🔵 Planned |

---

### A08:2025 — Software or Data Integrity Failures

**Risk:** Code and infrastructure not protected against integrity violations.

**LAN Atlas Implementation:**

- `payload_hash` UNIQUE constraint at DB level — tampered or replayed payloads are rejected by PostgreSQL before the identity engine processes them.
- `fingerprint_hash` on devices is SHA-256 of normalized signals with a UNIQUE constraint — identity integrity enforced at the DB layer.
- Named UNIQUE constraints throughout — `uq_devices_fingerprint_per_site`, `uq_observations_payload_hash`, `uq_device_mac_per_device`, `uq_users_oauth` — all prevent silent data corruption.
- `pgcrypto` extension provides `digest()` for consistent server-side hashing without relying on application-layer implementations.
- `fn_set_updated_at()` trigger ensures `updated_at` is always accurate — audit trail integrity (OWASP ASVS V1.2.1, cited in schema comments).
- `MAC format CHECK` constraints on `device_mac_addresses` and `observations` — malformed MAC values rejected at the DB layer.

**Gaps:**

- CI/CD pipeline integrity not yet designed — no signed commits, no artifact verification.
- Dependency hash verification (`pip install --require-hashes`) not yet implemented.
- OUI database file integrity check not yet implemented.

| Control | Status |
|---|---|
| Payload integrity at DB level (UNIQUE payload_hash) | ✅ Implemented |
| Device fingerprint integrity (UNIQUE fingerprint_hash) | ✅ Implemented |
| Named UNIQUE constraints preventing silent corruption | ✅ Implemented |
| pgcrypto for consistent server-side hashing | ✅ Implemented |
| Audit trail integrity (fn_set_updated_at trigger) | ✅ Implemented |
| MAC format validation at DB layer | ✅ Implemented |
| CI/CD pipeline integrity | 🔴 Not Started |
| Dependency hash verification | 🔴 Not Started |
| OUI database file integrity | 🔵 Planned |

---

### A09:2025 — Security Logging and Alerting Failures

**Risk:** Insufficient logging or alerting prevents breach detection. Renamed from "Security Logging and Monitoring Failures" in 2021 — emphasizing that logging without alerting provides minimal security value.

**LAN Atlas Implementation:**

- **New:** `audit_log` table records every human-initiated mutation to tenant-owned data — device renamed/deleted/authorized, alert acknowledged/resolved, user role changed, agent key rotated. Immutable at the database level via `fn_prevent_audit_log_mutation` trigger — not application convention. See `database/audit.py`, `repositories/audit.py`, `models/audit_log.py`, `migrations/manual/audit_log.sql`.
- `database/audit.py:redact()` strips hashed secrets (`api_key_hash`, `token_hash`) from before/after snapshots before they're persisted — the audit trail itself is never a secrets-exposure surface.
- `observations` table is an append-only audit log of all agent activity — every scan recorded with agent, site, timestamp, scan tier, and payload hash. This remains distinct from `audit_log` by design — machine activity vs. human-attributable mutations. See Section 3.5.
- `alerts` table records security-relevant events with full lifecycle (`open` → `acknowledged` → `resolved`). `ck_alerts_resolved_consistency` ensures `resolved_at` is always set accurately.
- `analyst_notes` records human review decisions — full audit trail of analyst actions.
- `sessions` table records session lifecycle — creation, expiry, and revocation timestamps.
- `users.last_login_at` and `users.failed_login_count` track authentication events.
- `agents.last_seen` tracks agent heartbeat.
- `fn_set_updated_at()` trigger on all mutable tables — every write produces an accurate `updated_at` timestamp (OWASP ASVS V1.2.1).
- `alert_status` with `acknowledged` state — distinguishes seen-but-not-resolved from unseen.

**Gaps:**

- `audit_log` is not yet wired to any mutation — the schema, repository, and event mechanism exist, but no service function calls `insert_audit_log()` yet since the API routes that would trigger renames/deletes/role changes don't exist. `repositories/devices.py:rename_device()` and `delete_device()` are a worked example of the pattern, awaiting a `services/devices.py` to orchestrate the audit call.
- No application-level structured logging framework configured (Python `logging` module or JSON to CloudWatch).
- Authentication failure events (failed OAuth exchanges, rejected API keys) not yet shipped to a log sink.
- No alerting on security-relevant system events — agent key rejection, unusual observation volume, admin privilege escalation.
- CloudWatch log aggregation and retention policy not yet designed.
- No alert engine watchdog — if the alert engine stops running, nothing detects it.

| Control | Status |
|---|---|
| audit_log schema with DB-enforced immutability | ✅ Implemented |
| AuditEvent shape and secret redaction (database/audit.py) | ✅ Implemented |
| audit_log SQL isolated to repositories/audit.py | ✅ Implemented |
| audit_log wired into mutation service functions | 🔴 Not Started — blocked on api/ and services/devices.py |
| Observation audit log (append-only) | ✅ Implemented |
| Alert lifecycle tracking with consistency CHECK | ✅ Implemented |
| Analyst action audit log (analyst_notes) | ✅ Implemented |
| Session lifecycle tracking (sessions table) | ✅ Implemented |
| Authentication event tracking (last_login_at, failed_login_count) | ✅ Implemented |
| Agent activity tracking (last_seen) | ✅ Implemented |
| Audit trail integrity (fn_set_updated_at) | ✅ Implemented |
| Application-level structured logging | 🔴 Not Started |
| Authentication failure log shipping | 🔴 Not Started |
| Security event alerting | 🔴 Not Started |
| CloudWatch integration | 🔵 Planned |
| Alert engine watchdog | 🔴 Not Started |

---

### A10:2025 — Mishandling of Exceptional Conditions

**Risk:** Improper error handling, logical errors, and failing open. New in 2025.

**LAN Atlas Implementation:**

- `db.py` context manager (`get_db()`) — rollback on any exception, connection always closed. The connection layer never fails open.
- `INSERT OR IGNORE` equivalent in PostgreSQL (`INSERT ... ON CONFLICT DO NOTHING`) handles UNIQUE constraint violations gracefully.
- `is_duplicate_observation()` checks `device_id IS NOT NULL` before treating an observation as a duplicate — prevents premature short-circuiting of unprocessed observations.
- `ck_alerts_resolved_consistency` CHECK — the DB rejects logically inconsistent alert states rather than storing corrupt data.
- Named constraints produce actionable error messages — `ERROR: duplicate key value violates unique constraint "uq_observations_payload_hash"` vs an anonymous constraint number.

**Two-Layer Error Handling Strategy:**

- **Identity engine functions** handle recoverable, context-specific errors (constraint violations, missing fields, unexpected signal types). Return `None` or a safe default rather than raising. Re-raise for systemic failures.
- **Alert engine and API layer** handle systemic failures — identity engine returned `None`, DB unreachable, observation failed after retries. Decide whether to log, retry, or fire a system alert.

**Gaps:**

- Identity engine functions (`create_device`, `update_signals`, `resolve_observation`) do not yet have structured `try/except` blocks. Unexpected DB errors propagate as unhandled exceptions.
- Alert engine orchestration-level error handling deferred until `alert_engine.py` is built.
- No observation retry mechanism — if `resolve_observation` raises, the observation is lost with no buffer.
- Stack traces must be suppressed in production API responses.
- `INSERT OR IGNORE` (SQLite) must be updated to `INSERT ... ON CONFLICT DO NOTHING` (PostgreSQL) across all engine files.

| Control | Status |
|---|---|
| Connection-layer error handling (db.py rollback) | ✅ Implemented |
| Logical consistency CHECK (ck_alerts_resolved_consistency) | ✅ Implemented |
| Named constraints for actionable error messages | ✅ Implemented |
| Duplicate observation safe logic (device_id IS NOT NULL) | ✅ Implemented |
| INSERT OR IGNORE → ON CONFLICT update for PostgreSQL | 🔴 Not Started — required before go-live |
| Identity engine function-level error handling | 🔴 Not Started |
| Alert engine orchestration-level error handling | 🔵 Planned |
| Observation retry mechanism | 🔴 Not Started |
| Stack traces suppressed in production responses | 🔵 Planned |

---

## 5. OWASP API Security Top 10 (2023) — Agent-to-Cloud API

---

### API1:2023 — Broken Object Level Authorization

**Risk:** API endpoints expose object identifiers that can be manipulated to access other users' data.

**LAN Atlas Implementation:**

- `observations` has FK constraints to `organization`, `sites`, and `agents` — the schema enforces the agent-to-org-to-site chain at the DB level.
- `agents` FK to `sites` enforces the agent-to-site relationship structurally.
- `UNIQUE (oauth_provider, oauth_subject)` prevents an OAuth identity from being linked to multiple accounts.

**Gap:** Agent-to-site trust validation is not yet implemented in API middleware. This is the highest-priority API security gap — without it, an agent with a valid key could submit observations for sites it does not belong to.

| Control | Status |
|---|---|
| Agent-site FK enforced in schema | ✅ Implemented |
| Observation-to-org/site FK chain | ✅ Implemented |
| Agent-site trust validation in API middleware | 🔴 Not Started |

---

### API2:2023 — Broken Authentication

**Risk:** Authentication mechanisms implemented incorrectly.

**LAN Atlas Implementation:**

- API keys stored as hex SHA-256 only via `pgcrypto digest()`.
- `token_version` CHECK `>= 1` — auth layer rejects tokens below current version.
- `is_active` on agents for immediate decommissioning.
- `sessions` table with `token_hash` and `revoked_at` for server-side session management.

**Gaps:** HTTPS-only enforcement at load balancer not yet configured. Key rotation API endpoint not yet built.

| Control | Status |
|---|---|
| API keys hashed at rest (SHA-256 via pgcrypto) | ✅ Implemented |
| Key rotation with version enforcement (CHECK >= 1) | ✅ Implemented |
| Agent decommissioning (is_active) | ✅ Implemented |
| Server-side session token hashing (sessions.token_hash) | ✅ Implemented |
| HTTPS-only enforcement at load balancer | 🔵 Planned |
| Key rotation API endpoint | 🔴 Not Started |

---

### API3:2023 — Broken Object Property Level Authorization

**Risk:** API exposes more properties than the caller should see, or allows mass assignment of protected fields.

**LAN Atlas Implementation:**

- No `password_hash` in schema — OAuth removes this attack surface entirely.
- `api_key_hash` and `sessions.token_hash` must never be returned in API responses.
- `pgcrypto` handles hashing server-side — plain-text secrets never pass through application code unnecessarily.

**Gaps:** Response field filtering by role not yet built. Mass assignment protection not yet implemented.

| Control | Status |
|---|---|
| No password storage (OAuth removes vector) | ✅ Implemented by design |
| Hashing server-side via pgcrypto | ✅ Implemented |
| api_key_hash / token_hash never in API responses | 🔵 Planned |
| Response field filtering by role | 🔴 Not Started |
| Mass assignment protection | 🔴 Not Started |

---

### API4:2023 — Unrestricted Resource Consumption

**Risk:** API does not limit resource usage, enabling denial-of-service.

**LAN Atlas Implementation:**

- `UNIQUE (payload_hash)` constraint on `observations` — duplicate observation submissions are rejected by PostgreSQL before any processing occurs.

**Gaps:** No rate limiting, per-agent quota, or maximum payload size enforcement.

| Control | Status |
|---|---|
| Duplicate rejection at DB level (UNIQUE payload_hash) | ✅ Implemented |
| API rate limiting | 🔴 Not Started |
| Per-agent submission quota | 🔴 Not Started |
| Maximum payload size enforcement | 🔴 Not Started |

---

### API5:2023 — Broken Function Level Authorization

**Risk:** API exposes admin functions to non-admin users.

**LAN Atlas Implementation:** `user_role` defined with `ck_users_role` CHECK constraint. Role definitions documented in schema reference.

**Gap:** Role enforcement middleware not yet implemented.

| Control | Status |
|---|---|
| Role definitions with CHECK constraint | ✅ Implemented |
| Role enforcement in API middleware | 🔴 Not Started |

---

### API6:2023 — Unrestricted Access to Sensitive Business Flows

**Risk:** Business flows exploited at scale, bypassing human review.

**LAN Atlas Implementation:**

- `is_authorized` requires explicit human action.
- `acknowledged` alert status creates a human checkpoint.
- `seen_count` threshold prevents premature missing-device alerts.
- `ck_alerts_resolved_consistency` enforces alert state machine at DB level.

**Gap:** Bulk alert resolution should require elevated role confirmation.

| Control | Status |
|---|---|
| Explicit device authorization (is_authorized) | ✅ Implemented |
| Human checkpoint in alert lifecycle (acknowledged) | ✅ Implemented |
| seen_count threshold | ✅ Implemented |
| Alert state machine enforced at DB (CHECK) | ✅ Implemented |
| Bulk operation safeguards | 🔴 Not Started |

---

### API7:2023 — Server-Side Request Forgery

**Risk:** API fetches remote resources using attacker-controlled input.

**LAN Atlas Implementation:** Observation API processes data internally. No outbound HTTP calls from submitted data. `network_segments` FK prevents arbitrary strings from entering the pipeline via the network segment field.

**Gap:** OUI vendor lookup must use a locally bundled IEEE OUI file.

| Control | Status |
|---|---|
| No outbound HTTP from observation data | ✅ Implemented by design |
| network_segments FK (structured segment data) | ✅ Implemented |
| OUI lookup via local bundled file | 🔵 Planned |

---

### API8:2023 — Security Misconfiguration

**Risk:** API misconfiguration exposes sensitive data or functionality.

**LAN Atlas Implementation:**

- PostgreSQL enforces FK constraints by default — no per-connection pragma required.
- Named constraints provide actionable error messages.
- Secrets in `.env`, not source code.

**Gaps:** CORS policy, HTTP security headers, and API versioning not yet defined.

| Control | Status |
|---|---|
| FK enforcement by default (PostgreSQL) | ✅ Implemented |
| Named constraints for actionable errors | ✅ Implemented |
| Secrets in .env | ✅ Implemented |
| CORS policy | 🔴 Not Started |
| HTTP security headers | 🔴 Not Started |
| API versioning (/api/v1/) | 🔴 Not Started |

---

### API9:2023 — Improper Inventory Management

**Risk:** Outdated or undocumented API versions expose unnecessary attack surface.

**LAN Atlas Implementation:**

- Schema reference (`docs/schema-reference.md`) and this document provide authoritative documentation.
- Schema version history maintained.

**Gaps:** No OpenAPI specification. No deprecation policy. `agents.version` column not present — agent version tracking needed for backward compatibility management.

| Control | Status |
|---|---|
| Schema documentation | ✅ Implemented |
| OWASP controls documentation | ✅ Implemented |
| OpenAPI specification | 🔴 Not Started |
| API deprecation policy | 🔴 Not Started |
| Agent version tracking column | 🔴 Not Started |

---

### API10:2023 — Unsafe Consumption of APIs

**Risk:** Trusting data from third-party APIs without validation.

**LAN Atlas Implementation:**

- All agent-submitted data treated as untrusted — passes through named CHECK constraints, parameterized queries, MAC format validation, and UNIQUE payload_hash verification before affecting device state.
- OAuth token validation handled by provider SDK — not a custom implementation.

**Gaps:** OUI data source must be bundled locally. PostgreSQL placeholder syntax (`%s`) must be audited across all engine files after migration.

| Control | Status |
|---|---|
| Agent data treated as untrusted | ✅ Implemented |
| Named CHECK constraints on all submitted fields | ✅ Implemented |
| OAuth handled by provider SDK | 🔵 Planned |
| OUI data bundled locally | 🔵 Planned |
| Third-party webhook response validation | ➖ N/A (post-MVP) |

---

## 6. Infrastructure Security Controls

| Control | Requirement | Status |
|---|---|---|
| HTTPS enforcement | TLS 1.2+ at ALB/API Gateway. HTTP rejected, not redirected. | 🔵 Planned |
| RDS encryption at rest | Enabled at RDS creation via AWS KMS. Cannot be added after. | 🔵 Planned |
| RDS encryption in transit | `ssl_mode=require` in PostgreSQL connection string. | 🔵 Planned |
| Security groups | PostgreSQL port 5432 accessible from app layer only. Never publicly exposed. | 🔵 Planned |
| Least-privilege IAM | App role: SELECT/INSERT/UPDATE/DELETE only. No DROP/CREATE/TRUNCATE in production. | 🔵 Planned |
| VPC isolation | RDS in private subnet. Application behind ALB in public subnet. | 🔵 Planned |
| AWS Secrets Manager | DATABASE_URL and API secrets in Secrets Manager in production — not .env. | 🔵 Planned |
| CloudWatch logging | Structured application logs. Retention policy ≥ 90 days. | 🔵 Planned |
| Automated RDS backups | Point-in-time recovery enabled. Retention ≥ 7 days. | 🔵 Planned |
| AWS WAF | WAF on ALB for SQLi, XSS, rate abuse patterns. | 🔵 Planned |
| RLS activation | `ENABLE ROW LEVEL SECURITY` + tenant isolation policy on tenant-scoped tables. | 🔵 Planned (post-MVP) |

---

## 7. Open Gaps and Recommendations

### 🔴 Critical — Must Fix Before Production

| Gap | Recommendation |
|---|---|
| Agent-site trust validation missing | Validate `agent_id` owns submitted `site_id` on every observation call. Reject mismatches with HTTP 403. |
| RBAC enforcement not implemented | Add authentication middleware validating `organization_id` on every request. Role checks on every endpoint. |
| `INSERT OR IGNORE` → `ON CONFLICT DO NOTHING` | Update all engine files for PostgreSQL syntax before go-live. SQLite `INSERT OR IGNORE` is not valid PostgreSQL. |
| Query placeholder audit (`?` → `%s`) | Audit all parameterized queries in identity engine files. SQLite uses `?`; psycopg2 uses `%s`. |
| Identity engine function-level error handling | Add `try/except` in `create_device`, `update_signals`, `resolve_observation`. Return safe defaults on recoverable errors. |
| Rate limiting absent | Implement per-agent rate limiting (e.g. 100 req/min). Return HTTP 429 on excess. |
| Brute-force lockout not yet enforced in code | Implement auth layer logic to check `lockout_until` and increment `failed_login_count`. Schema is ready. |
| HTTP security headers missing | Add CSP, X-Frame-Options, X-Content-Type-Options, HSTS at API gateway or middleware. |
| RDS encryption must be pre-configured | Enable at RDS instance creation. Cannot be added after. Document as deployment requirement. |

### 🟡 Important — Address in Production Hardening

| Gap | Recommendation |
|---|---|
| API versioning absent | Version all endpoints as `/api/v1/`. Agents in the field cannot be force-updated. |
| CORS policy undefined | Restrict to dashboard domain. Reject unknown origins. |
| OpenAPI specification missing | Document all endpoints. Use for input validation and client SDK generation. |
| Automated dependency scanning | Add `pip-audit` to CI. Enable GitHub Dependabot. |
| OUI lookup SSRF risk | Bundle IEEE OUI list locally. Never use agent-supplied data for outbound HTTP. |
| Alert engine error handling | Implement orchestration-level handling — catch `None` returns, log failures, buffer for retry. |
| Agent version tracking | Add `agent_version` column to `agents` table. Required for API backward compatibility. |
| Observation retry mechanism | Define retry queue for observations that fail identity resolution. |
| DATABASE_URL in Secrets Manager | Move from `.env` to AWS Secrets Manager for production deployments. |

### 🔵 Post-MVP

| Gap | Recommendation |
|---|---|
| RLS policy activation | Activate `ENABLE ROW LEVEL SECURITY` and deploy tenant isolation policies. Schema scaffold is ready. |
| SQLAlchemy adoption | Eliminates SQL dialect risk entirely. Enables safe PostgreSQL migration without manual placeholder audits. |
| Anomaly detection on observation volume | Alert when an agent submits at abnormal rates — potential compromise or misconfiguration. |
| Signed commits policy | Enforce GPG-signed commits to protect supply chain. |
| AWS WAF | Protect ALB from common attack patterns without application code changes. |
| alerts.metadata as JSONB | Upgrade from `VARCHAR(1000)` to `JSONB` for indexed JSON queries on alert metadata. |

---

## 8. Control Status Summary

### OWASP Top 10 (2025) — Web Dashboard

| # | Risk | Status |
|---|---|---|
| A01 | Broken Access Control (includes SSRF) | 🟡 Partial |
| A02 | Security Misconfiguration | 🟡 Partial |
| A03 | Software Supply Chain Failures | 🔴 Not Started |
| A04 | Cryptographic Failures | 🟡 Partial |
| A05 | Injection | 🟡 Partial |
| A06 | Insecure Design | 🟡 Partial |
| A07 | Authentication Failures | 🟡 Partial |
| A08 | Software or Data Integrity Failures | 🟡 Partial |
| A09 | Security Logging and Alerting Failures | 🟡 Partial |
| A10 | Mishandling of Exceptional Conditions | 🟡 Partial |

### OWASP API Security Top 10 (2023) — Agent-to-Cloud API

| # | Risk | Status |
|---|---|---|
| API1 | Broken Object Level Authorization | 🟡 Partial |
| API2 | Broken Authentication | 🟡 Partial |
| API3 | Broken Object Property Level Authorization | 🔴 Not Started |
| API4 | Unrestricted Resource Consumption | 🟡 Partial |
| API5 | Broken Function Level Authorization | 🟡 Partial |
| API6 | Unrestricted Access to Sensitive Business Flows | 🟡 Partial |
| API7 | Server-Side Request Forgery | 🟡 Partial |
| API8 | Security Misconfiguration | 🟡 Partial |
| API9 | Improper Inventory Management | 🟡 Partial |
| API10 | Unsafe Consumption of APIs | 🟡 Partial |

### Overall Security Posture

The PostgreSQL migration significantly strengthened LAN Atlas's security posture at the schema layer. Controls that were previously "Planned" or gaps are now "Implemented" — notably session revocation, brute-force tracking, float drift elimination, DB-level payload deduplication, structured network segment data, and the `updated_at` trigger.

The remaining gaps fall into three buckets:

1. **API middleware layer** — RBAC, agent-site trust validation, rate limiting, and role-based response filtering are designed but not yet implemented. These are pre-production requirements.
2. **PostgreSQL migration tasks** — `INSERT OR IGNORE` → `ON CONFLICT DO NOTHING` and `?` → `%s` placeholder updates are required before the engine will run against PostgreSQL.
3. **Supply chain and DevSecOps** — dependency scanning, signed commits, and CI/CD artifact integrity are not yet in place.

---

## 9. Version History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-05-10 | Initial mapping against OWASP Top 10 2021. SQLite schema. |
| 2.0 | 2026-05-10 | Updated to OWASP Top 10 2025. Removed password_hash — OAuth-only auth documented. SSRF consolidated into A01. A10 (Mishandling of Exceptional Conditions) added. Two-layer error handling strategy defined. |
| 3.0 | 2026-05-10 | Updated for PostgreSQL migration. Added Section 3 (Migration Security Notes). Updated all controls to reflect new schema capabilities: fn_set_updated_at trigger, sessions table, failed_login_count, CITEXT email, network_segments FK, UNIQUE payload_hash, SMALLINT score columns, pgcrypto extension, named constraints, RLS scaffold, ck_alerts_resolved_consistency, services table. Added INSERT OR IGNORE → ON CONFLICT and ? → %s as critical pre-go-live gaps. |
