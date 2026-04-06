# OWASP A04:2025 — Cryptographic Failures: Extended Reference

Source: OWASP Top 10:2025 (dataset: 2.8M applications, ~220k CVEs)

## Position & Stats

- **Rank:** #4 (dropped from #2 in 2021)
- **Reason for drop:** Improved TLS adoption industry-wide
- **Incidence rate:** 3.80% of tested applications
- **Occurrences:** 1.6 million+
- **CWEs mapped:** 32

## Full Scope

### What Is Covered

- Old or weak algorithms: MD5, SHA1, ECB mode, DES, RC4
- Default or hardcoded cryptographic keys
- Missing encryption enforcement (data sent in clear)
- Improper certificate validation (verify=False)
- Reused IVs or nonces in stream/block cipher modes
- Passwords used as cryptographic keys without a KDF
- Deprecated hash functions used for passwords
- Algorithm downgrade attacks (e.g., forcing "none" JWT algorithm)
- Unpreparedness for post-quantum cryptography (target: 2030)

### What Is NOT Covered Here

- Broken Access Control via JWT manipulation → A01
- Session fixation, credential stuffing → A07 Authentication Failures
- Dependency vulnerabilities in crypto libraries → A03 Supply Chain
- Sensitive data logging → A09 Logging Failures

## Prevention Guidelines (OWASP Official)

1. Classify data by sensitivity; apply crypto proportionally
2. Store keys in HSMs or dedicated secrets managers (Vault, AWS SSM, GCP KMS)
3. Use TLS ≥1.2 with forward secrecy; enforce HSTS
4. Store passwords with Argon2, scrypt, bcrypt, or PBKDF2-HMAC-SHA-512 (≥600k iterations)
5. Use authenticated encryption: AES-GCM or ChaCha20-Poly1305
6. Never use `random` module for security operations — use `secrets`
7. Prepare migration paths for post-quantum algorithms

## Complete CWE List for A04

| CWE | Name |
|---|---|
| CWE-261 | Weak Encoding for Password |
| CWE-296 | Improper Following of Chain of Trust for Certificate Validation |
| CWE-310 | Cryptographic Issues |
| CWE-319 | Cleartext Transmission of Sensitive Information |
| CWE-321 | Use of Hard-coded Cryptographic Key |
| CWE-322 | Key Exchange Without Entity Authentication |
| CWE-323 | Reusing a Nonce, Key Pair in Encryption |
| CWE-324 | Use of a Key Past its Expiration Date |
| CWE-325 | Missing Cryptographic Step |
| CWE-326 | Inadequate Encryption Strength |
| CWE-327 | Use of a Broken or Risky Cryptographic Algorithm |
| CWE-328 | Use of Weak Hash |
| CWE-329 | Not Using a Random IV with CBC Mode |
| CWE-330 | Use of Insufficiently Random Values |
| CWE-331 | Insufficient Entropy |
| CWE-335 | Incorrect Usage of Seeds in PRNG |
| CWE-336 | Same Seed in PRNG |
| CWE-337 | Predictable Seed in PRNG |
| CWE-338 | Use of Cryptographically Weak PRNG |
| CWE-340 | Generation of Predictable Numbers or Identifiers |
| CWE-347 | Improper Verification of Cryptographic Signature |
| CWE-523 | Unprotected Transport of Credentials |
| CWE-720 | OWASP Top Ten 2007 Category A9 (Insecure Communications) |
| CWE-757 | Selection of Less-Secure Algorithm During Negotiation |
| CWE-759 | Use of a One-Way Hash Without a Salt |
| CWE-760 | Use of a One-Way Hash with a Predictable Salt |
| CWE-780 | Use of RSA Algorithm Without OAEP |
| CWE-818 | Insufficient Transport Layer Protection |
| CWE-916 | Use of Password Hash With Insufficient Computational Effort |

## Python Library Recommendations

### Password Hashing
```
passlib[argon2]   — preferred (Argon2id, memory-hard)
passlib[bcrypt]   — widely deployed, rounds≥12
argon2-cffi       — direct Argon2 bindings
```

### Token / Secret Generation
```
secrets           — stdlib, use exclusively for security tokens
                    secrets.token_urlsafe(32)   → URL-safe base64
                    secrets.token_hex(32)        → hex string
                    secrets.token_bytes(32)      → raw bytes
```

### Symmetric Encryption
```
cryptography      — pip install cryptography
                    AESGCM, ChaCha20Poly1305, Fernet (for simple symmetric)
PyCryptodome      — Crypto.Cipher.AES with MODE_GCM
```

### Asymmetric / Signing
```
cryptography      — hazmat.primitives (RSA-OAEP, ECDSA)
PyNaCl            — libsodium bindings; preferred for new code
```

### JWT
```
PyJWT             — pip install PyJWT
python-jose       — pip install python-jose[cryptography]
Always pin algorithms: algorithms=["HS256"] or ["RS256"]
Never allow: algorithms=["none"] or algorithms=[]
```

### TLS
```
ssl               — stdlib; use ssl.create_default_context()
requests          — verify=True (default); don't override
httpx             — verify=True (default); don't override
certifi           — updated CA bundle: requests.get(url, verify=certifi.where())
```