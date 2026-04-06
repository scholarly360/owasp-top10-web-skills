---
name: injection
description: >
  Expert Python security testing skill for OWASP A05:2025 — Injection vulnerabilities in FastAPI and Flask applications.
  Use this skill whenever the user asks about: SQL injection, XSS, SSTI (Server-Side Template Injection), OS command injection,
  ORM injection, LLM prompt injection, input validation, parameterized queries, Jinja2 escaping, or any untrusted data
  reaching an interpreter (database, OS shell, template engine, or browser). Also trigger for security audits, pen testing,
  Bandit SAST scans, code review for injection flaws, or any request to "find injection bugs", "check for SQLi",
  "audit my Flask/FastAPI app", or "scan for command injection". This skill has the highest CVE count of all OWASP categories
  (62,445) — always apply it proactively when reviewing Python web application security.
---

# OWASP A05:2025 — Injection: Python Security Testing Skill

## Overview

Injection occurs when **untrusted user input reaches an interpreter** — a database, OS shell, template engine, or browser —
and is executed as part of a command or query. Despite dropping from #3 to #5 in 2025, Injection carries the **most CVEs
of any OWASP category: 62,445**, including 30,000+ for XSS alone.

**Injection types covered by this skill:**
- SQL Injection (SQLi) — CWE-89
- Cross-Site Scripting (XSS) — CWE-79
- Server-Side Template Injection (SSTI) — CWE-94
- OS Command Injection — CWE-78 / CWE-77
- ORM Injection
- Input Validation failures — CWE-20
- LLM Prompt Injection (related class, noted in OWASP 2025)

---

## Detection Checklist

### 1. SQL Injection (CWE-89)

**High-risk patterns to flag:**

```python
# ❌ VULNERABLE — f-string in raw SQL
db.execute(f"SELECT * FROM users WHERE email = '{email}'")

# ❌ VULNERABLE — .format() in SQLAlchemy text()
db.execute(text("SELECT * FROM users WHERE id = {}".format(user_id)))

# ❌ VULNERABLE — string concatenation in ORM raw query
User.query.filter(text("name = '" + name + "'"))
```

**Safe patterns to enforce:**

```python
# ✅ SAFE — bound parameters in SQLAlchemy text()
db.execute(text("SELECT * FROM users WHERE email = :email"), {"email": email})

# ✅ SAFE — ORM method (avoids interpreter entirely)
User.query.filter_by(email=email).first()

# ✅ SAFE — FastAPI with Pydantic + SQLAlchemy ORM
async def get_user(user_id: int, db: Session = Depends(get_db)):
    return db.query(User).filter(User.id == user_id).first()
```

**Testing approach:**
1. Search codebase for `text(`, `execute(`, `raw(`, `cursor.execute(` + string interpolation
2. Run Bandit: `bandit -r . -t B608` (hardcoded SQL expressions)
3. Inject payloads: `' OR '1'='1`, `'; DROP TABLE users; --`, `1 UNION SELECT null,null--`
4. Use OWASP ZAP active scan on all endpoints accepting string parameters

---

### 2. XSS — Cross-Site Scripting (CWE-79)

**High-risk patterns to flag:**

```python
# ❌ VULNERABLE — Jinja2 auto-escaping disabled globally
app = Flask(__name__)
# Missing: app.jinja_env.autoescape = True  (it IS on by default for .html — verify!)

# ❌ VULNERABLE — |safe filter on untrusted data
# In template: {{ user_comment | safe }}

# ❌ VULNERABLE — render_template_string with user input
@app.route("/greet")
def greet():
    name = request.args.get("name")
    return render_template_string(f"<h1>Hello {name}</h1>")  # Also SSTI risk!
```

**Safe patterns to enforce:**

```python
# ✅ SAFE — auto-escaping on (Flask default for .html/.htm/.xml/.xhtml)
# Verify: app.jinja_env.autoescape is True for the template extension

# ✅ SAFE — explicit escaping when rendering HTML from user input
from markupsafe import escape
safe_name = escape(request.args.get("name", ""))

# ✅ SAFE — Content-Security-Policy header
@app.after_request
def set_csp(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response
```

**Testing approach:**
1. Grep templates for `| safe` — each use needs manual review
2. Confirm `autoescape=True` in Jinja2 environment for all template types
3. Inject: `<script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`
4. Check Content-Security-Policy and X-XSS-Protection headers in responses

---

### 3. SSTI — Server-Side Template Injection (CWE-94)

The most critical Injection risk for Flask apps using Jinja2. User input rendered as a **template string** allows full
Python expression execution.

**High-risk patterns to flag:**

```python
# ❌ VULNERABLE — user input in template constructor
from jinja2 import Template
user_template = request.args.get("template")
return Template(user_template).render()

# ❌ VULNERABLE — render_template_string with user data in template itself
return render_template_string(user_provided_content)

# ❌ VULNERABLE — format string from user input
msg_template = user_input  # "Hello {user.name}"
msg_template.format(user=current_user)  # exposes user object attributes
```

**Safe patterns to enforce:**

```python
# ✅ SAFE — only render static template files; pass user input as context variables
return render_template("greet.html", name=user_name)  # name is escaped, not executed

# ✅ SAFE — if dynamic templates needed, use sandboxed environment
from jinja2.sandbox import SandboxedEnvironment
env = SandboxedEnvironment()
env.from_string(template_str).render(data=safe_data)
```

**Testing approach:**
1. Search for `render_template_string(`, `Template(`, `.format(` where source contains user data
2. Inject SSTI probes: `{{7*7}}` (expects `49`), `{{config}}`, `{{''.__class__.__mro__}}`
3. Escalation payload: `{{''.__class__.__mro__[1].__subclasses__()}}` to enumerate classes

---

### 4. OS Command Injection (CWE-78, CWE-77)

**High-risk patterns to flag:**

```python
# ❌ VULNERABLE — shell=True with user input
import subprocess
filename = request.args.get("file")
subprocess.call(f"cat {filename}", shell=True)

# ❌ VULNERABLE — os.system with any user-controlled string
os.system("convert " + user_filename + " output.jpg")

# ❌ VULNERABLE — os.popen
result = os.popen(f"ls {directory}").read()
```

**Safe patterns to enforce:**

```python
# ✅ SAFE — shell=False (default) with argument list
subprocess.run(["cat", filename], shell=False, capture_output=True)

# ✅ SAFE — validate and sanitize before passing to any subprocess
import re
if not re.match(r'^[a-zA-Z0-9._-]+$', filename):
    raise ValueError("Invalid filename")
subprocess.run(["convert", filename, "output.jpg"])

# ✅ SAFE — avoid shell entirely when possible (use Python libraries)
# Instead of: os.system("rm " + path)
import pathlib
pathlib.Path(path).unlink()
```

**Testing approach:**
1. Bandit: `bandit -r . -t B602,B603,B605,B606,B607` (subprocess and shell issues)
2. Grep: `os.system(`, `os.popen(`, `shell=True`
3. Inject: `; cat /etc/passwd`, `| id`, `&& whoami`, `` `id` ``

---

### 5. Input Validation Failures (CWE-20)

**FastAPI (Pydantic — preferred):**

```python
# ✅ SAFE — Pydantic enforces types, lengths, patterns at parse time
from pydantic import BaseModel, Field, constr

class UserCreate(BaseModel):
    username: constr(min_length=3, max_length=50, pattern=r'^[a-zA-Z0-9_]+$')
    age: int = Field(ge=0, le=150)
    email: str = Field(max_length=255)

@app.post("/users")
async def create_user(user: UserCreate):
    ...  # Input already validated
```

```python
# ❌ VULNERABLE — bypassing Pydantic by reading raw request body
body = await request.body()
data = json.loads(body)  # No validation!
```

**Flask (manual validation required):**

```python
# ✅ SAFE — explicit validation with WTForms or marshmallow
from marshmallow import Schema, fields, validate

class UserSchema(Schema):
    username = fields.Str(required=True, validate=validate.Length(min=3, max=50))
    age = fields.Int(validate=validate.Range(min=0, max=150))

# ❌ VULNERABLE — using request.args directly without validation
name = request.args.get("name")  # Could be anything
db.execute(text(f"SELECT * FROM users WHERE name = '{name}'"))
```

---

## Automated Scanning Pipeline

### SAST — Bandit

```bash
pip install bandit
bandit -r ./app -f json -o bandit_report.json

# Injection-specific test IDs:
# B608 — Hardcoded SQL expressions
# B602 — subprocess with shell=True
# B603 — subprocess without shell_injection check
# B605 — os.system call
# B606 — os.popen call
# B607 — partial executable path
# B701 — Jinja2 autoescape=False
```

### DAST — OWASP ZAP

```bash
docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t http://localhost:8000 \
  -r zap_report.html

# For active injection testing (more thorough but more aggressive):
docker run -t owasp/zap2docker-stable zap-full-scan.py \
  -t http://localhost:8000
```

### Combined pipeline (CI/CD):

```yaml
# .github/workflows/security.yml
- name: Run Bandit SAST
  run: bandit -r ./app -t B608,B602,B603,B605,B606,B701 --exit-zero -f json -o bandit.json

- name: Upload results
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: bandit.json
```

---

## Key CWEs Reference

| CWE | Name | Primary Risk |
|-----|------|-------------|
| CWE-89 | SQL Injection | DB data exfiltration/modification |
| CWE-79 | XSS | Session hijacking, phishing |
| CWE-78 | OS Command Injection | RCE, server takeover |
| CWE-77 | Command Injection | RCE via eval/exec |
| CWE-94 | Code Injection / SSTI | Full Python execution |
| CWE-20 | Improper Input Validation | Gateway to all other injection types |

---

## LLM Prompt Injection (2025 addition)

The 2025 OWASP list notes **LLM prompt injection** as a related class. For applications using AI APIs:

```python
# ❌ VULNERABLE — user input directly in system prompt
system_prompt = f"You are a helpful assistant. Context: {user_provided_context}"

# ✅ SAFER — separate user content from system instructions
messages = [
    {"role": "system", "content": STATIC_SYSTEM_PROMPT},
    {"role": "user", "content": user_input}  # Never injected into system role
]

# Additional mitigations:
# - Input/output filtering for prompt injection patterns
# - Least-privilege tool use (don't give LLM access to sensitive ops)
# - Structured outputs (JSON schema) to limit instruction-following surface
```

---

## Quick Reference: Severity by Attack Type

| Attack | Severity | Ease of Exploit | Typical Impact |
|--------|----------|-----------------|----------------|
| SSTI | Critical | Medium | RCE |
| OS Command Injection | Critical | Medium | RCE |
| SQL Injection | High | Easy–Medium | Data breach, auth bypass |
| XSS (Stored) | High | Easy | Session hijack |
| XSS (Reflected) | Medium | Medium | Phishing, credential theft |
| ORM Injection | High | Medium | Data exposure |
| Prompt Injection | Medium–High | Easy | Logic bypass, data exfil |

---

## References

- [OWASP A05:2025 Injection](https://owasp.org/Top10/A03_2021-Injection/) — official guidance
- [Bandit docs](https://bandit.readthedocs.io/) — Python SAST tool
- [Jinja2 Sandbox](https://jinja.palletsprojects.com/en/3.1.x/sandbox/) — safe template rendering
- See `references/payloads.md` for a full injection payload test library