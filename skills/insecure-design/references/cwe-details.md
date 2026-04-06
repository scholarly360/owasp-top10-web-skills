# A06:2025 Insecure Design — CWE Reference

## Key CWEs (39 total in category)

### CWE-434 — Unrestricted Upload of File with Dangerous Type
Software allows upload of dangerous file types that can be processed automatically.  
**FastAPI/Flask:** Always validate MIME type via `python-magic`, never trust extension or `Content-Type` header.

### CWE-269 — Improper Privilege Management
Software does not properly assign/modify/track privileges.  
**FastAPI/Flask:** Tenant IDs and roles must come from server-side session/JWT, never from request body.

### CWE-362 — Concurrent Execution Using Shared Resource with Improper Synchronization (Race Condition)
Multiple threads/processes access shared data without proper locking.  
**FastAPI/Flask:** Use `SELECT ... FOR UPDATE` (SQLAlchemy with `with_for_update()`), Redis locks, or idempotency keys for concurrent transactions.

### CWE-799 — Improper Control of Interaction Frequency
Software does not implement sufficient controls to prevent excessive interactions.  
**FastAPI/Flask:** Use SlowAPI (FastAPI) or Flask-Limiter. Apply to login, register, reset, OTP, checkout.

### CWE-602 — Client-Side Enforcement of Server-Side Security
Server relies on client-side security controls that can be bypassed.  
**FastAPI/Flask:** Always re-validate permissions on API routes. Never trust headers, cookies, or body fields for authorization decisions.

### CWE-656 — Reliance on Security Through Obscurity
Relies on secrecy of implementation details as security mechanism.  
**Example:** Hiding admin panel at `/xJ3k_admin` without auth.

### CWE-657 — Violation of Secure Design Principles
Violates well-established secure design principles (least privilege, defense in depth, fail-safe defaults).

### CWE-284 (cross-listed with A01) — Improper Access Control
Lack of authorization check by design (no auth layer planned), not just a missing decorator.

---

## Additional CWEs Commonly Found in A06 Audits

| CWE | Name | Typical FastAPI/Flask Pattern |
|-----|------|-------------------------------|
| CWE-306 | Missing Authentication for Critical Function | Endpoint intentionally left public by design |
| CWE-307 | Brute Force Protection Missing | No rate limit by design |
| CWE-522 | Insufficiently Protected Credentials | Reset token stored in plaintext DB |
| CWE-640 | Weak Password Recovery Mechanism | Security questions, no token expiry |
| CWE-425 | Direct Request ('Forced Browsing') | Resources accessible without access check by design |
| CWE-841 | Improper Enforcement of Behavioral Workflow | Multi-step checkout allows skipping payment step |