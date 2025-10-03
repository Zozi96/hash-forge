# Security Policy

## Supported Versions

We release patches for security vulnerabilities in the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 3.0.x   | :white_check_mark: |
| 2.1.x   | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in Hash Forge, please send an email to **zozi.fer96@gmail.com** with the following information:

- Type of vulnerability
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the vulnerability

You should receive a response within 48 hours. If the issue is confirmed, we will:

1. Acknowledge your email within 48 hours
2. Provide a more detailed response within 7 days
3. Work on a fix and release a security patch
4. Credit you in the CHANGELOG (unless you prefer to remain anonymous)

## Security Best Practices

### Recommended Algorithms

Hash Forge supports multiple algorithms. For **password hashing**, we recommend (in order of preference):

1. **Argon2** (Argon2id variant) - Winner of Password Hashing Competition
   ```python
   from hash_forge import HashManager

   # Recommended settings for web applications
   hash_manager = HashManager.from_algorithms(
       "argon2",
       time_cost=3,        # Number of iterations
       memory_cost=65536,  # 64 MB memory
       parallelism=4       # 4 parallel threads
   )
   ```

2. **BCrypt** - Industry standard, battle-tested
   ```python
   # Minimum 12 rounds, 14+ for high security
   hash_manager = HashManager.from_algorithms("bcrypt", rounds=14)
   ```

3. **PBKDF2-SHA256** - NIST approved, widely supported
   ```python
   # Minimum 150,000 iterations, 200,000+ recommended
   hash_manager = HashManager.from_algorithms("pbkdf2_sha256", iterations=200_000)
   ```

### ⚠️ Security Warnings

#### Do NOT use for password hashing:
- ❌ **Blake2/Blake3** - Fast, but not memory-hard (vulnerable to GPU attacks)
- ❌ **Whirlpool/RIPEMD-160** - Not designed for passwords
- ❌ **PBKDF2-SHA1** - SHA1 is deprecated, use SHA256 variant

These algorithms are included for **data integrity** and **legacy support** only.

#### BCrypt Limitations:
- **Max password length: 72 bytes** - BCrypt silently truncates longer passwords
- For longer passwords, use **BCrypt-SHA256** variant which pre-hashes with SHA256:
  ```python
  hash_manager = HashManager.from_algorithms("bcrypt_sha256")
  ```

### Minimum Security Parameters

Hash Forge enforces these minimum security thresholds:

| Algorithm | Parameter | Minimum | Recommended |
|-----------|-----------|---------|-------------|
| PBKDF2-SHA256 | iterations | 150,000 | 200,000+ |
| BCrypt | rounds | 12 | 14 |
| Scrypt | N (CPU cost) | 16384 | 32768 |
| Argon2 | time_cost | 2 | 3-4 |
| Argon2 | memory_cost | 65536 | 65536-131072 |

**Note**: Attempting to use weaker parameters will raise a validation error.

### Secure Implementation Patterns

#### 1. Always use async for web applications
```python
from hash_forge import HashManager
from fastapi import FastAPI

app = FastAPI()
hash_manager = HashManager.from_algorithms("argon2")

@app.post("/register")
async def register(password: str):
    # Non-blocking - won't freeze your web server
    hashed = await hash_manager.hash_async(password)
    # Save to database
    return {"status": "registered"}
```

#### 2. Implement rehashing for security upgrades
```python
@app.post("/login")
async def login(username: str, password: str):
    user = get_user(username)

    # Verify password
    is_valid = await hash_manager.verify_async(password, user.password_hash)
    if not is_valid:
        raise HTTPException(401, "Invalid credentials")

    # Check if hash needs upgrade
    if await hash_manager.needs_rehash_async(user.password_hash):
        # Rehash with new parameters and update DB
        new_hash = await hash_manager.hash_async(password)
        update_user_hash(username, new_hash)

    return {"status": "success"}
```

#### 3. Use multiple algorithms for migration
```python
# Support old hashes while moving to stronger algorithm
hash_manager = HashManager.from_algorithms(
    "argon2",        # New hashes use this (preferred)
    "bcrypt",        # Can still verify old BCrypt hashes
    "pbkdf2_sha256"  # Can still verify legacy PBKDF2 hashes
)
```

#### 4. Never log or expose hashes
```python
# ❌ BAD - Hashes in logs can be attacked
logger.info(f"User registered: {username} with hash {hashed}")

# ✅ GOOD - Never log sensitive data
logger.info(f"User registered: {username}")
```

#### 5. Use environment-based configuration
```python
import os
from hash_forge.config import HashForgeConfig

# Different security levels for dev vs prod
if os.getenv("ENV") == "production":
    config = HashForgeConfig(
        argon2_time_cost=5,        # Higher in prod
        argon2_memory_cost=131072  # More memory in prod
    )
else:
    config = HashForgeConfig(
        argon2_time_cost=2,        # Faster in dev
        argon2_memory_cost=65536   # Less memory in dev
    )

hash_manager = HashManager.from_config(config, "argon2")
```

### Common Vulnerabilities to Avoid

#### ❌ Timing Attacks
Hash Forge uses constant-time comparison internally, but ensure you:
- Don't short-circuit on username validation
- Use the same error message for "user not found" and "invalid password"

```python
# ❌ BAD - Reveals if user exists
user = get_user(username)
if not user:
    return {"error": "User not found"}  # Different error!

if not verify(password, user.hash):
    return {"error": "Invalid password"}

# ✅ GOOD - Same error for both cases
user = get_user(username)
if not user or not verify(password, user.hash):
    return {"error": "Invalid credentials"}
```

#### ❌ Rainbow Table Attacks
- Hash Forge automatically generates cryptographically secure salts
- Never implement your own salt generation
- Never use a static salt for all users

#### ❌ Brute Force Attacks
Hash Forge provides slow hashing by default, but you should also:
- Implement rate limiting on login endpoints
- Use CAPTCHA after N failed attempts
- Consider account lockout policies
- Monitor for suspicious login patterns

### Dependency Security

Hash Forge depends on well-maintained cryptographic libraries:
- `bcrypt` - Official BCrypt implementation
- `argon2-cffi` - CFFI bindings to reference C implementation
- `pycryptodome` - Maintained fork of PyCrypto
- `blake3` - Official Blake3 implementation

**Always keep dependencies updated:**
```bash
pip install --upgrade hash-forge[bcrypt,argon2,crypto,blake3]
```

### Security Audits

Hash Forge follows security best practices:
- ✅ No custom cryptography - uses proven libraries
- ✅ Type safety with mypy strict mode
- ✅ Comprehensive test coverage (114+ tests)
- ✅ Constant-time comparison for hash verification
- ✅ Cryptographically secure random salt generation
- ✅ Enforced minimum security parameters

### Additional Resources

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Argon2 RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)
- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

---

**Last Updated**: October 2024
**Hash Forge Version**: 3.0.1
