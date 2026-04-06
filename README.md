# Agent Skills for OWASP Top 10:2025 Security Testing

This repository helps you build **Agent Skills** that test Python web applications (FastAPI and Flask) against OWASP Top 10:2025 risks.

Instead of vague prompts, these skills guide an agent to follow a **structured and repeatable security workflow**.

---

## Why this matters

If you ask an agent to "check security", results are usually generic.

With these skills, the agent:
- Runs targeted checks per OWASP category  
- Produces consistent findings  
- Maps issues to CWE and real attack patterns  

Think of this as giving your agent a **clear security playbook**.

---

## What are Agent Skills?

Agent Skills are modular instruction packages that tell an agent how to perform a task.

Each skill:
- Lives in its own folder  
- Contains a `SKILL.md` file  
- Includes metadata and step-by-step instructions  

A skill is essentially a reusable workflow that agents can load when needed. :contentReference[oaicite:0]{index=0}

---

## Repository Structure

```
skills/
├── broken-access-control/
├── injection/
├── security-misconfiguration/
├── cryptographic-failures/
└── ...
```

Each folder represents one OWASP category.

---

## Quick Start

### 1. Clone the repo
```bash
git clone <repo-url>
cd <repo>
```

### 2. Load skills into your agent
- Place the `skills/` folder where your agent can access it  
- Ensure SKILL.md loading is enabled  

### 3. Run a scan
```
Review my FastAPI app for security issues
```

The agent will:
1. Select relevant skills  
2. Load instructions  
3. Execute checks  
4. Return findings  

---

### Install with skills.sh :

```bash
npx skills add scholarly360/owasp-top10-web-skills
```

Or install a single skill:

```bash
npx skills add scholarly360/owasp-top10-web-skills@broken-access-control
```

---

## Skills Overview

- **Broken Access Control** → Missing authorization, IDOR  
- **Injection** → SQLi, XSS, command injection  
- **Security Misconfiguration** → Debug mode, headers, secrets  
- **Cryptographic Failures** → Weak hashing, key handling  
- **Supply Chain** → Vulnerable dependencies  
- **Authentication** → Weak login, session issues  
- **Integrity Failures** → Unsafe deserialization  
- **Logging Failures** → Missing logs and alerts  
- **Exceptional Conditions** → Error handling issues  

---

## Example Output

```
CRITICAL
- SQL Injection (CWE-89)
  Location: auth.py:42
  Fix: Use parameterized queries

HIGH
- Debug mode enabled
- Missing security headers
```

---

## How Skills Work

Each `SKILL.md` contains:

- **Metadata** → Name and when to use  
- **Instructions** → Step-by-step checks  
- **Output format** → Standardized findings  


---

## Extending

To add a new skill:
1. Create a folder  
2. Add `SKILL.md`  
3. Define triggers, steps, and output  

---

## Conclusion

This repo turns OWASP Top 10:2025 into **actionable workflows for AI agent skills**.

You get:
- Structured checks  
- Repeatable results  
- Practical security insights  

---

```
The [OWASP Foundation](https://owasp.org/) has made a tremendous contribution to global cybersecurity by providing a free, open, and community-driven ecosystem of standards, tools, and best practices that help organizations build secure software. As a nonprofit dedicated to improving application security, OWASP empowers developers, architects, and security professionals worldwide through widely adopted resources like the OWASP Top 10, testing guides, and verification standards, which collectively raise awareness of critical vulnerabilities and promote secure coding practices. Its vendor-neutral approach, global community, and commitment to openly accessible knowledge have made it a foundational pillar in shaping modern application security and embedding security into the software development lifecycle.
```