# STRIDE Threat Modeling Worksheet — FastAPI / Flask

Use this worksheet during design review or code audit. For each flow, walk through each STRIDE
threat type and ask whether a control exists by design.

---

## How to Use

1. Identify the critical flow (auth, payment, file upload, admin action, etc.)
2. For each STRIDE threat, mark: **Mitigated / Partial / Missing**
3. For anything Partial or Missing, create a design task — not just a code fix

---

## Worksheet Template

### Flow: ____________________

| Threat | Question | Control Present? | Design Gap |
|--------|----------|-----------------|------------|
| Spoofing | Can an attacker impersonate another user or service? | | |
| Tampering | Can data be modified in transit or at rest without detection? | | |
| Repudiation | Can a user deny an action with no audit trail? | | |
| Information Disclosure | Can sensitive data leak through errors, logs, or responses? | | |
| Denial of Service | Can this flow be overwhelmed or exhausted? | | |
| Elevation of Privilege | Can a lower-privileged user reach higher-privileged actions? | | |

---

## Pre-filled Examples

### Flow: User Login

| Threat | Question | Control | Gap |
|--------|----------|---------|-----|
| Spoofing | Can attacker guess/brute-force credentials? | SlowAPI rate limit | None if configured |
| Tampering | Can JWT be forged? | HS256 with env secret | Gap if secret is hardcoded |
| Repudiation | Is failed auth logged? | logging.warning on 401 | Gap if not forwarded to SIEM |
| Info Disclosure | Does error reveal whether username or password was wrong? | Generic "Invalid credentials" | Gap if specific message returned |
| DoS | Can login endpoint be flooded? | Rate limiter | Gap if limit too high |
| EoP | Can user escalate to admin via JWT manipulation? | `algorithm=["HS256"]` pinned | Gap if `alg: none` accepted |

---

### Flow: File Upload

| Threat | Question | Control | Gap |
|--------|----------|---------|-----|
| Spoofing | Can attacker disguise a script as an image? | `python-magic` MIME check | Gap if only checking extension |
| Tampering | Can uploaded file be replaced after storage? | Immutable storage path with token name | Gap if predictable path |
| Repudiation | Is upload logged with user ID and filename? | Audit log entry | Gap if not logged |
| Info Disclosure | Can attacker read other users' uploads? | Auth check on file serving route | Gap if files served directly |
| DoS | Can attacker exhaust disk with large uploads? | 5 MB size cap + quotas | Gap if no per-user quota |
| EoP | Can attacker upload executable and trigger it? | Store outside web root, no execute | Gap if stored in `static/` |

---

## Quick Controls Reference

| Control | FastAPI | Flask |
|---------|---------|-------|
| Rate limiting | `slowapi` + `@limiter.limit()` | `flask_limiter` + `@limiter.limit()` |
| Auth dependency | `Depends(get_current_user)` | `@login_required` / `Flask-Security-Too` |
| MIME validation | `python-magic` | `python-magic` |
| Pydantic bounds | `Field(ge=1, le=100)` | WTForms validators / manual |
| Tenant scoping | `.filter(Model.tenant_id == user.tenant_id)` | same |
| Idempotency | Redis lock / DB unique constraint | same |
| Audit logging | `structlog` / `logging` with user context | same |