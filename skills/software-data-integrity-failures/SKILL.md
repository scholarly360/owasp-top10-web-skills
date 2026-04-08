---
name: software-data-integrity-failures
description: >
  Security testing skill for OWASP A08:2025 — Software or Data Integrity Failures in Python
  web applications (FastAPI and Flask). Use this skill whenever the user wants to audit,
  detect, test, or fix integrity vulnerabilities including: insecure deserialization (pickle,
  yaml, jsonpickle, dill), mass assignment flaws, untrusted CDN/module inclusion, unsigned
  updates, CI/CD pipeline integrity, or Subresource Integrity (SRI) checks. Trigger this
  skill for ANY task involving pickle/deserialization security, CWE-502, CWE-915, CWE-829,
  CWE-345, or CWE-494, even if the user doesn't explicitly mention OWASP A08.
---

# A08:2025 — Software or Data Integrity Failures

## Overview

**OWASP rank:** #8 (2025) | **CWEs covered:** 14 | **Avg incidence:** 2.75%

This category focuses on **failure to verify integrity of software, code, and data artifacts within your own environment** — distinct from A03's upstream supply chain focus. The core concern is: *can you trust what you're loading, deserializing, or executing?*

**Key distinction from A03 (Supply Chain):**
- A03 = upstream integrity (your dependencies, CI/CD pipelines)
- A08 = runtime integrity (what you actually deserialize, include, or auto-update at runtime)

---

## Critical Risk Areas for Python

### 1. Insecure Deserialization — The #1 Python-Specific Risk

`pickle.loads()` on untrusted input **equals arbitrary code execution** via `__reduce__`. This is the single most dangerous A08 vector in Python.

**Dangerous functions/modules to flag:**

| Module / Function | Risk | Safe Alternative |
|---|---|---|
| `pickle.loads()` / `pickle.load()` | RCE via `__reduce__` | JSON + Pydantic |
| `cPickle.loads()` | Same as pickle | JSON + Pydantic |
| `dill.loads()` | Superset of pickle, same RCE risk | JSON + Pydantic |
| `jsonpickle.decode()` | Deserializes Python objects | `json.loads()` only |
| `shelve.open()` | Backed by pickle | Redis/SQL store |
| `yaml.load(data, Loader=None)` | Code execution via `!!python/object` | `yaml.safe_load()` |
| `numpy.load(f, allow_pickle=True)` | RCE via pickled arrays | `allow_pickle=False` |
| `torch.load(f)` | Pickle-backed by default | `weights_only=True` |

**Detection pattern (static analysis):**
```python
# Flag any of these patterns in source code
DANGEROUS_PATTERNS = [
    r'pickle\.loads?\(',
    r'cPickle\.loads?\(',
    r'dill\.loads?\(',
    r'jsonpickle\.decode\(',
    r'shelve\.open\(',
    r'yaml\.load\([^)]*(?!safe_load)',
    r'numpy\.load\([^)]*allow_pickle\s*=\s*True',
    r'torch\.load\([^)]*(?!weights_only\s*=\s*True)',
]
```

**If pickle is unavoidable — HMAC integrity check:**
```python
import hmac, hashlib, pickle, os

SECRET = os.environ["PICKLE_HMAC_SECRET"].encode()

def safe_serialize(obj) -> bytes:
    data = pickle.dumps(obj)
    mac = hmac.new(SECRET, data, hashlib.sha256).digest()
    return mac + data  # prepend 32-byte MAC

def safe_deserialize(payload: bytes):
    mac, data = payload[:32], payload[32:]
    expected = hmac.new(SECRET, data, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        raise ValueError("Integrity check failed — data tampered")
    return pickle.loads(data)
```

---

### 2. Mass Assignment (CWE-915)

Occurs when `request.json` or form data is passed directly into ORM `.update()` without field filtering — allowing attackers to set fields like `is_admin=True` or `role="superuser"`.

**Flask — Vulnerable pattern:**
```python
# ❌ DANGEROUS — attacker can inject any field
user = User.query.get(user_id)
user.__dict__.update(request.json)
db.session.commit()

# Also dangerous:
User.query.filter_by(id=user_id).update(request.json)
```

**Flask — Safe pattern:**
```python
# ✅ SAFE — explicit allowlist
ALLOWED_FIELDS = {"name", "email", "bio"}
data = {k: v for k, v in request.json.items() if k in ALLOWED_FIELDS}
User.query.filter_by(id=user_id).update(data)
```

**FastAPI — Pydantic prevents mass assignment by default:**
```python
# ✅ FastAPI with Pydantic — only declared fields accepted
class UserUpdate(BaseModel):
    name: str | None = None
    email: str | None = None
    bio: str | None = None
    # is_admin, role etc. cannot be set — they're not in the schema

@router.patch("/users/{user_id}")
async def update_user(user_id: int, body: UserUpdate, db: Session = Depends(get_db)):
    db.query(User).filter(User.id == user_id).update(body.model_dump(exclude_unset=True))
```

**Detection pattern:** In Flask, scan for `request.json` or `request.form` flowing into `.update()`, `__dict__.update()`, or ORM bulk-update calls without an intermediate allowlist filter.

---

### 3. Subresource Integrity (SRI) for External Scripts/Styles

If your Flask/FastAPI app renders HTML templates that load scripts or stylesheets from external CDNs, those resources must include SRI hashes to prevent CDN compromise from injecting malicious code.

**Vulnerable Jinja2 template:**
```html
<!-- ❌ No integrity check — CDN compromise = XSS -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
```

**Secure Jinja2 template:**
```html
<!-- ✅ SRI hash prevents tampered CDN delivery -->
<script
  src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"
  integrity="sha384-geWF76RCwLtnZ8qwWowPQNguL3RmwHVBC9FhGdlKrxdiJJigb/j/68SIy3Te4Bkz"
  crossorigin="anonymous">
</script>
```

**How to generate SRI hashes:**
```bash
# Using openssl
curl -sL https://cdn.example.com/lib.js | openssl dgst -sha384 -binary | openssl base64 -A

# Or use srihash.org / unpkg.com automatically provides them
```

**Detection:** Scan Jinja2/HTML templates for `<script src="https://...">` and `<link href="https://...">` tags missing `integrity=` attributes.

---

### 4. Auto-Update Without Verification (CWE-494)

Applications that download and execute code/config updates without verifying a cryptographic signature are vulnerable to man-in-the-middle attacks.

**Pattern to flag:**
```python
# ❌ Downloads and executes without verification
import urllib.request, subprocess
urllib.request.urlretrieve("https://example.com/update.sh", "/tmp/update.sh")
subprocess.run(["bash", "/tmp/update.sh"])

# ❌ Loads remote config without integrity check
import json, urllib.request
config = json.loads(urllib.request.urlopen("https://config.example.com/settings.json").read())
```

**Safe pattern — signature verification:**
```python
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import urllib.request

def download_and_verify(url: str, sig_url: str, public_key_path: str) -> bytes:
    data = urllib.request.urlopen(url).read()
    sig = urllib.request.urlopen(sig_url).read()
    with open(public_key_path, "rb") as f:
        pubkey = serialization.load_pem_public_key(f.read())
    pubkey.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())  # raises on failure
    return data
```

---

## Testing Checklist

Use this checklist when auditing a FastAPI or Flask application for A08 compliance:

### Deserialization
- [ ] No `pickle.loads()` / `pickle.load()` on untrusted input
- [ ] No `cPickle`, `dill`, `jsonpickle.decode()` on untrusted input
- [ ] `yaml.safe_load()` used instead of `yaml.load()`
- [ ] `numpy.load()` called with `allow_pickle=False`
- [ ] `torch.load()` called with `weights_only=True`
- [ ] `shelve` not used with untrusted keys/data
- [ ] If pickle unavoidable: HMAC pre-verification implemented

### Mass Assignment
- [ ] Flask: no `request.json` passed directly into ORM `.update()` without allowlist
- [ ] Flask: no `model.__dict__.update(untrusted_data)` patterns
- [ ] FastAPI: Pydantic models used for all request bodies (prevents by default)
- [ ] Privileged fields (`is_admin`, `role`, `balance`) not in public update schemas

### External Integrity
- [ ] All external `<script>` tags have `integrity=` SRI attributes
- [ ] All external `<link rel="stylesheet">` tags have `integrity=` SRI attributes
- [ ] Remote downloads verified with cryptographic signature or hash before execution
- [ ] No dynamic `eval()` or `exec()` on remotely fetched content

### CI/CD Integrity (boundary with A03)
- [ ] Code review required for all changes to deployment config/scripts
- [ ] Build artifacts signed and signature verified before deployment
- [ ] CI/CD secrets not accessible to pull request pipelines from forks

---

## Automated Scanning Tools

| Tool | What it catches | How to run |
|---|---|---|
| **Bandit** | `pickle`, `yaml.load`, `subprocess`, `eval` | `bandit -r . -t B301,B302,B506` |
| **Semgrep** | Deserialization, mass assignment patterns | `semgrep --config=p/python` |
| **pip-audit** | Known-vulnerable deserialization libs | `pip-audit` |
| **Manual grep** | Quick sweep for dangerous functions | See patterns in section 1 |

**Bandit rule IDs for A08:**
- `B301` — `pickle` usage
- `B302` — `marshal` usage (similar risk)
- `B506` — `yaml.load` without safe loader
- `B403` — `pickle` import (informational)

---

## Key CWEs

| CWE | Description | Primary Vector |
|---|---|---|
| CWE-502 | Deserialization of Untrusted Data | pickle, yaml, jsonpickle |
| CWE-915 | Improperly Controlled Modification of Dynamically-Determined Object Attributes | Mass assignment |
| CWE-829 | Inclusion of Functionality from Untrusted Control Sphere | CDN scripts without SRI |
| CWE-345 | Insufficient Verification of Data Authenticity | Missing HMAC/signature checks |
| CWE-494 | Download of Code Without Integrity Check | Auto-update without verification |

---

## References

- [OWASP A08:2025 — Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
- [Python Pickle Security](https://docs.python.org/3/library/pickle.html#restricting-globals)
- [SRI Hash Generator](https://www.srihash.org/)
- [Bandit SAST for Python](https://bandit.readthedocs.io/en/latest/)
- See `references/deserialization-exploits.md` for exploit PoCs and deeper analysis