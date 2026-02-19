# Hash Forge

[![PyPI version](https://badge.fury.io/py/hash-forge.svg)](https://pypi.org/project/hash-forge/) ![Build Status](https://github.com/Zozi96/hash-forge/actions/workflows/unittest.yml/badge.svg)  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![Python Versions](https://img.shields.io/pypi/pyversions/hash-forge.svg)](https://pypi.org/project/hash-forge/) [![Downloads](https://pepy.tech/badge/hash-forge)](https://pepy.tech/project/hash-forge) [![GitHub issues](https://img.shields.io/github/issues/Zozi96/hash-forge)](https://github.com/Zozi96/hash-forge/issues) ![Project Status](https://img.shields.io/badge/status-active-brightgreen.svg) [![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black) [![Contributions welcome](https://img.shields.io/badge/contributions-welcome-blue.svg)](https://github.com/Zozi96/hash-forge/issues)

**Hash Forge** is a lightweight Python library designed to simplify the process of hashing and verifying data using a variety of secure hashing algorithms.

## Overview

Hash Forge is a flexible and secure hash management tool that supports multiple hashing algorithms. This tool allows you to hash and verify data using popular hash algorithms, making it easy to integrate into projects where password hashing or data integrity is essential.

## Features

- **Multiple Hashing Algorithms**: Supports bcrypt, Scrypt, Argon2, Blake2, Blake3, PBKDF2, SHA-3, Whirlpool and RIPEMD-160.
- **Async/Await Support**: Non-blocking operations with `hash_async()`, `verify_async()`, and batch processing.
- **Builder Pattern**: Fluent, chainable API for elegant configuration.
- **Configuration Management**: Load settings from environment variables, JSON files, or code.
- **Hashing and Verification**: Easily hash strings and verify their integrity.
- **Hash Rotation**: Seamlessly migrate hashes to a new algorithm with `rotate()`.
- **Hash Inspection**: Retrieve algorithm metadata from any hash with `inspect()`.
- **Rehash Detection**: Automatically detects if a hash needs to be rehashed based on outdated parameters or algorithms.
- **Type-Safe API**: Full TypeScript-like type hints with `AlgorithmType` for better IDE support.
- **Performance Optimized**: O(1) hasher lookup, async batch operations 3-5x faster.
- **Security Focused**: Enforces minimum security parameters and uses cryptographically secure random generation.
- **Well Documented**: Comprehensive examples, security guidelines, and contribution docs.

## Installation

```bash
pip install hash-forge
```

### Optional Dependencies

Hash Forge provides optional dependencies for specific hashing algorithms. To install these, use:

- **bcrypt** support:

  ```bash
  pip install "hash-forge[bcrypt]"
  ```
- **Argon2** support:

  ```bash
  pip install "hash-forge[argon2]"
  ```
- **Whirlpool and RIPEMD-160** support:

  ```bash
  pip install "hash-forge[crypto]"
  ```
- **Blake3** support:

  ```bash
  pip install "hash-forge[blake3]"
  ```

## Quick Start

```python
from hash_forge import HashManager

# Create a HashManager with Argon2 (recommended)
hash_manager = HashManager.from_algorithms("argon2")

# Hash a password
hashed = hash_manager.hash("my_secure_password")

# Verify a password
is_valid = hash_manager.verify("my_secure_password", hashed)
print(is_valid)  # True

# Check if rehashing is needed
needs_update = hash_manager.needs_rehash(hashed)
```

## Usage

### Basic Example

```python
from hash_forge import HashManager, AlgorithmType
from hash_forge.hashers import PBKDF2Sha256Hasher

# Initialize HashManager with PBKDF2Hasher
hash_manager = HashManager(PBKDF2Sha256Hasher())

# Hash a string
hashed_value = hash_manager.hash("my_secure_password")

# Verify the string against the hashed value
is_valid = hash_manager.verify("my_secure_password", hashed_value)
print(is_valid)  # Outputs: True

# Check if the hash needs rehashing
needs_rehash = hash_manager.needs_rehash(hashed_value)
print(needs_rehash)  # Outputs: False
```

### Examples

Check out the [`examples/`](examples/) directory for more practical examples:

- **[basic_usage.py](examples/basic_usage.py)** - Fundamental operations and common patterns
- **[async_fastapi.py](examples/async_fastapi.py)** - FastAPI integration with async support
- **[builder_pattern.py](examples/builder_pattern.py)** - Fluent builder API examples

### Quick Hash (New in v2.1.0)

For simple hashing without creating a HashManager instance:

```python
from hash_forge import HashManager, AlgorithmType

# Quick hash with default algorithm (PBKDF2-SHA256)
hashed = HashManager.quick_hash("my_password")

# Quick hash with specific algorithm (with IDE autocomplete!)
algorithm: AlgorithmType = "argon2"
hashed = HashManager.quick_hash("my_password", algorithm=algorithm)

# Quick hash with algorithm-specific parameters
hashed = HashManager.quick_hash("my_password", algorithm="pbkdf2_sha256", iterations=200_000)
hashed = HashManager.quick_hash("my_password", algorithm="bcrypt", rounds=14)
hashed = HashManager.quick_hash("my_password", algorithm="argon2", time_cost=4)
```

### Factory Pattern (New in v2.1.0)

Create HashManager instances using algorithm names:

```python
from hash_forge import HashManager, AlgorithmType

# Create HashManager from algorithm names
hash_manager = HashManager.from_algorithms("pbkdf2_sha256", "argon2", "bcrypt")

# With type safety
algorithms: list[AlgorithmType] = ["pbkdf2_sha256", "bcrypt_sha256"]
hash_manager = HashManager.from_algorithms(*algorithms)

# Note: from_algorithms() creates hashers with default parameters
# For custom parameters, create hashers individually
hash_manager = HashManager.from_algorithms("pbkdf2_sha256", "bcrypt", "argon2")
```

> **Note:** The first hasher provided during initialization of `HashManager` will be the **preferred hasher** used for hashing operations, though any available hasher can be used for verification.

### Available Algorithms

Currently supported algorithms with their `AlgorithmType` identifiers:

| Algorithm | Identifier | Security Level | Notes |
|-----------|------------|----------------|-------|
| **PBKDF2-SHA256** | `"pbkdf2_sha256"` | High | Default, 150K iterations minimum |
| **PBKDF2-SHA1** | `"pbkdf2_sha1"` | Medium | Legacy support |
| **bcrypt** | `"bcrypt"` | High | 12 rounds minimum |
| **bcrypt-SHA256** | `"bcrypt_sha256"` | High | With SHA256 pre-hashing |
| **Argon2** | `"argon2"` | Very High | Memory-hard function |
| **Scrypt** | `"scrypt"` | High | Memory-hard function |
| **Blake2** | `"blake2"` | High | Fast cryptographic hash |
| **Blake3** | `"blake3"` | Very High | Latest Blake variant |
| **SHA-3 256** | `"sha3_256"` | High | stdlib only, no extra dependencies |
| **SHA-3 512** | `"sha3_512"` | High | stdlib only, no extra dependencies |
| **Whirlpool** | `"whirlpool"` | Medium | 512-bit hash |
| **RIPEMD-160** | `"ripemd160"` | Medium | 160-bit hash |

### Algorithm-Specific Parameters

Different algorithms support different parameters. Use `quick_hash()` for algorithm-specific customization:

```python
from hash_forge import HashManager

# PBKDF2 algorithms
HashManager.quick_hash("password", algorithm="pbkdf2_sha256", iterations=200_000, salt_length=16)
HashManager.quick_hash("password", algorithm="pbkdf2_sha1", iterations=150_000)

# BCrypt algorithms  
HashManager.quick_hash("password", algorithm="bcrypt", rounds=14)
HashManager.quick_hash("password", algorithm="bcrypt_sha256", rounds=12)

# Argon2
HashManager.quick_hash("password", algorithm="argon2", time_cost=4, memory_cost=65536, parallelism=1)

# Scrypt
HashManager.quick_hash("password", algorithm="scrypt", n=32768, r=8, p=1)

# Blake2 (with optional key)
HashManager.quick_hash("password", algorithm="blake2", key="secret_key")

# Blake3 (with optional key)  
HashManager.quick_hash("password", algorithm="blake3", key="secret_key")

# SHA-3 (stdlib only — no extra dependencies)
HashManager.quick_hash("password", algorithm="sha3_256")
HashManager.quick_hash("password", algorithm="sha3_512")

# Other algorithms (use defaults)
HashManager.quick_hash("password", algorithm="whirlpool")
HashManager.quick_hash("password", algorithm="ripemd160")
```

### Traditional Initialization

For complete control over parameters, initialize `HashManager` with individual hasher instances:

```python
from hash_forge import HashManager
from hash_forge.hashers import (
    Argon2Hasher,
    BCryptSha256Hasher,
    Blake2Hasher,
    PBKDF2Sha256Hasher,
    Ripemd160Hasher,
    ScryptHasher,
    SHA3_256Hasher,
    SHA3_512Hasher,
    WhirlpoolHasher,
    Blake3Hasher
)

hash_manager = HashManager(
    PBKDF2Sha256Hasher(iterations=200_000),  # Higher iterations
    BCryptSha256Hasher(rounds=14),           # Higher rounds
    Argon2Hasher(time_cost=4),               # Custom parameters
    ScryptHasher(),
    SHA3_256Hasher(),
    SHA3_512Hasher(),
    Ripemd160Hasher(),
    Blake2Hasher('MySecretKey'),
    WhirlpoolHasher(),
    Blake3Hasher()
)
```

### Verifying a Hash

Use the `verify` method to compare a string with its hashed counterpart:

```python
is_valid = hash_manager.verify("my_secure_password", hashed_value)
```

### Checking for Rehashing

You can check if a hash needs to be rehashed (e.g., if the hashing algorithm parameters are outdated):

```python
needs_rehash = hash_manager.needs_rehash(hashed_value)
```

### Hash Rotation

`rotate()` verifies a password against an existing hash, then re-hashes it with the preferred hasher. Returns `None` if verification fails — no exception, no exposure of the plaintext to the caller.

This is the safe way to migrate passwords from a legacy algorithm to a new one on next login:

```python
from hash_forge import HashManager

# Manager configured with the new preferred algorithm
hash_manager = HashManager.from_algorithms("argon2", "pbkdf2_sha256")

# On login, attempt rotation
old_hash = get_stored_hash(user_id)  # e.g. a pbkdf2_sha256 hash
new_hash = hash_manager.rotate(user_password, old_hash)

if new_hash is not None:
    save_hash(user_id, new_hash)  # now stored as argon2
    print("Password migrated to argon2")
else:
    print("Wrong password")
```

### Hash Inspection

`inspect()` returns a dictionary with metadata about a stored hash — algorithm name and any algorithm-specific parameters — without exposing the raw hash value or salt.

```python
from hash_forge import HashManager
from hash_forge.hashers import PBKDF2Sha256Hasher, SHA3_256Hasher

hash_manager = HashManager(PBKDF2Sha256Hasher(), SHA3_256Hasher())

pbkdf2_hash = HashManager.quick_hash("password", algorithm="pbkdf2_sha256", iterations=200_000)
print(hash_manager.inspect(pbkdf2_hash))
# {'algorithm': 'pbkdf2_sha256', 'iterations': 200000}

sha3_hash = HashManager.quick_hash("password", algorithm="sha3_256")
print(hash_manager.inspect(sha3_hash))
# {'algorithm': 'sha3_256'}

print(hash_manager.inspect("unknown$abc$def"))
# None
```

### Listing Registered Algorithms

`list_algorithms()` returns the algorithm names registered in the current manager instance:

```python
from hash_forge import HashManager

hash_manager = HashManager.from_algorithms("argon2", "pbkdf2_sha256", "sha3_256")
print(hash_manager.list_algorithms())
# ['argon2', 'pbkdf2_sha256', 'sha3_256']
```

### Repr

`HashManager` has a readable `__repr__` showing the preferred algorithm and all registered algorithms:

```python
from hash_forge import HashManager

hash_manager = HashManager.from_algorithms("argon2", "pbkdf2_sha256")
print(repr(hash_manager))
# HashManager(preferred='argon2', algorithms=['argon2', 'pbkdf2_sha256'])
```

### Async Support (New in v3.0.0)

Hash Forge provides full async/await support for non-blocking operations. All synchronous methods have async equivalents that run in a thread pool executor to avoid blocking the event loop.

#### Basic Async Operations

```python
import asyncio
from hash_forge import HashManager

async def main():
    hash_manager = HashManager.from_algorithms("argon2")

    # Async hashing - runs synchronous hash in thread pool
    hashed = await hash_manager.hash_async("my_password")
    print(f"Hashed: {hashed}")

    # Async verification - non-blocking verification
    is_valid = await hash_manager.verify_async("my_password", hashed)
    print(f"Valid: {is_valid}")  # True

    # Async rehash check
    needs_rehash = await hash_manager.needs_rehash_async(hashed)
    print(f"Needs rehash: {needs_rehash}")  # False

asyncio.run(main())
```

#### Batch Operations

Process multiple passwords concurrently for better performance:

```python
import asyncio
from hash_forge import HashManager

async def batch_example():
    hash_manager = HashManager.from_algorithms("pbkdf2_sha256")

    # Hash multiple passwords concurrently
    passwords = ["user1_pass", "user2_pass", "user3_pass", "user4_pass"]
    hashes = await hash_manager.hash_many_async(passwords)

    # hashes is a list with the same order as passwords
    for password, hash_value in zip(passwords, hashes):
        print(f"{password} -> {hash_value[:50]}...")

    # Verify multiple password-hash pairs concurrently
    pairs = [
        ("user1_pass", hashes[0]),
        ("user2_pass", hashes[1]),
        ("wrong_password", hashes[2]),  # This will be False
    ]
    results = await hash_manager.verify_many_async(pairs)
    print(f"Results: {results}")  # [True, True, False]

asyncio.run(batch_example())
```

#### Web Framework Integration

Perfect for async web frameworks like FastAPI, Sanic, or aiohttp:

```python
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from hash_forge import HashManager

app = FastAPI()
hash_manager = HashManager.from_algorithms("argon2")

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/register")
async def register(request: LoginRequest):
    # Non-blocking password hashing
    hashed = await hash_manager.hash_async(request.password)
    # Save user with hashed password to database
    return {"username": request.username, "password_hash": hashed}

@app.post("/login")
async def login(request: LoginRequest):
    # Fetch user from database (simulated)
    stored_hash = get_user_hash(request.username)

    # Non-blocking password verification
    is_valid = await hash_manager.verify_async(request.password, stored_hash)

    if not is_valid:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return {"message": "Login successful"}
```

#### Performance Benefits

The async methods are particularly useful when:
- Processing multiple passwords in parallel
- Integrating with async web frameworks
- Avoiding blocking the event loop during expensive hash operations
- Building responsive async applications

```python
import asyncio
import time
from hash_forge import HashManager

async def performance_comparison():
    hash_manager = HashManager.from_algorithms("argon2")
    passwords = [f"password_{i}" for i in range(10)]

    # Sequential (blocking)
    start = time.time()
    hashes_sync = [hash_manager.hash(pwd) for pwd in passwords]
    sync_time = time.time() - start

    # Concurrent (non-blocking)
    start = time.time()
    hashes_async = await hash_manager.hash_many_async(passwords)
    async_time = time.time() - start

    print(f"Sequential: {sync_time:.2f}s")
    print(f"Concurrent: {async_time:.2f}s")
    print(f"Speedup: {sync_time/async_time:.2f}x")

asyncio.run(performance_comparison())
```

### Configuration Management (New in v3.0.0)

Load configuration from environment variables, JSON files, or programmatically:

```python
from hash_forge import HashManager
from hash_forge.config import HashForgeConfig

# From environment variables
# export HASH_FORGE_PBKDF2_ITERATIONS=200000
# export HASH_FORGE_BCRYPT_ROUNDS=14
config = HashForgeConfig.from_env()

# From JSON file
config = HashForgeConfig.from_json("config.json")

# Programmatically
config = HashForgeConfig(
    pbkdf2_iterations=200_000,
    bcrypt_rounds=14,
    argon2_time_cost=4
)

# Create HashManager with config
hash_manager = HashManager.from_config(config, "pbkdf2_sha256", "bcrypt")

# Save config
config.to_json("hash_config.json")
```

### Builder Pattern (New in v3.0.0)

Create HashManager instances with a fluent, chainable API:

```python
from hash_forge import HashManager

# Use builder pattern for elegant configuration
hash_manager = (
    HashManager.builder()
    .with_algorithm("argon2", time_cost=4)
    .with_algorithm("bcrypt", rounds=14)
    .with_algorithm("pbkdf2_sha256", iterations=200_000)
    .with_preferred("argon2")  # Set preferred hasher
    .build()
)

# Mix pre-configured hashers with algorithms
from hash_forge.hashers import PBKDF2Sha256Hasher

custom_hasher = PBKDF2Sha256Hasher(iterations=300_000)
hash_manager = (
    HashManager.builder()
    .with_hasher(custom_hasher)
    .with_algorithm("bcrypt")
    .build()
)
```

## What's New in v3.0.0

Hash Forge v3.0.0 represents a major architectural overhaul with significant performance improvements and new features while maintaining backward compatibility for the public API.

### 🏗️ Architecture Improvements
- **Modular Structure**: Complete reorganization into logical modules (`core/`, `config/`, `utils/`, `hashers/`)
- **Template Method Pattern**: Reduced code duplication in hashers by 40% through base class abstraction
- **Auto-Discovery Pattern**: Simplified hasher registration with automatic decorator-based registration
- **Chain of Responsibility**: Each hasher autonomously determines if it can handle a hash
- **Clean Architecture**: Clear separation between public API and internal implementation

### ⚡ Performance Enhancements
- **O(1) Hasher Lookup**: Internal hasher mapping for instant algorithm detection (vs O(n) iteration)
- **Async/Await Support**: Full non-blocking operations with thread pool executor for CPU-bound tasks
- **Batch Processing**: Concurrent processing of multiple hashes with `hash_many_async()` and `verify_many_async()`
- **Optimized Memory**: Reduced object creation overhead and better resource management
- **Thread Pool Efficiency**: Smart use of asyncio executors for parallel hash operations

### 🎯 New Features
- **SHA-3 Support**: `sha3_256` and `sha3_512` via Python's stdlib — no extra dependencies
- **Hash Rotation**: `rotate()` for safe on-login algorithm migration
- **Hash Inspection**: `inspect()` returns algorithm metadata without exposing raw hash values
- **Algorithm Listing**: `list_algorithms()` returns algorithms registered in a manager instance
- **Async Operations**: Complete async API with `hash_async()`, `verify_async()`, `needs_rehash_async()`
- **Builder Pattern**: Fluent, chainable API for elegant HashManager configuration
- **Config Management**: Load settings from environment variables, JSON files, or programmatic config
- **Logging Infrastructure**: Built-in structured logging for debugging and monitoring
- **Type Safety**: Enhanced type hints with `AlgorithmType` literals for IDE autocomplete

### 📊 Performance Benchmarks
With async batch operations, v3.0.0 achieves significant speedups:
- **10 concurrent hashes**: ~3-5x faster than sequential
- **100 concurrent hashes**: ~8-10x faster than sequential
- **Web framework integration**: Non-blocking operations prevent request queue buildup
- **Memory efficiency**: 40% less code duplication = smaller memory footprint

### 🛠️ Developer Experience
- **Type Safety**: `AlgorithmType` literal for IDE autocomplete and error detection
- **Factory Pattern**: Create hashers by algorithm name with `HasherFactory`
- **Builder Pattern**: Chainable API for elegant configuration
- **Convenience Methods**: `quick_hash()` and `from_algorithms()` for simpler usage
- **Logging Support**: Built-in logging infrastructure for debugging

### 🔐 Security Enhancements
- **Parameter Validation**: Enforces minimum security thresholds (150K PBKDF2 iterations, 12 BCrypt rounds)
- **Custom Exceptions**: More specific error types (`InvalidHasherError`, `UnsupportedAlgorithmError`)
- **Centralized Configuration**: Security defaults in one place
- **Timing-Safe Verification**: All hashers use `hmac.compare_digest()` to prevent timing attacks

### 🧪 Better Testing
- **Enhanced Test Suite**: 140 tests covering all functionality
- **Type Checking Tests**: Validates `AlgorithmType` usage
- **Configuration Validation**: Tests security parameter enforcement
- **Builder Pattern Tests**: Validates fluent API
- **Async Tests**: Full coverage of async operations
- **Config Tests**: JSON, env vars, and programmatic config

### 📚 API Improvements

**Before v2.1.0:**
```python
# Manual hasher imports and creation
from hash_forge.hashers.pbkdf2_hasher import PBKDF2Sha256Hasher
hasher = PBKDF2Sha256Hasher(iterations=150000)
hash_manager = HashManager(hasher)
```

**v2.1.0:**
```python
# Simplified with factory pattern and type safety
from hash_forge import HashManager, AlgorithmType

algorithm: AlgorithmType = "pbkdf2_sha256"  # IDE autocomplete!
hash_manager = HashManager.from_algorithms(algorithm)
# or with custom parameters
hashed = HashManager.quick_hash("password", algorithm=algorithm, iterations=200_000)
```

**v3.0.0:**
```python
# Complete overhaul with builder, config, and async support
from hash_forge import HashManager
from hash_forge.config import HashForgeConfig

# Builder pattern with fluent API
hash_manager = (
    HashManager.builder()
    .with_algorithm("argon2", time_cost=4, memory_cost=65536)
    .with_algorithm("bcrypt", rounds=14)
    .with_preferred("argon2")
    .build()
)

# Config management from JSON/env
config = HashForgeConfig.from_json("config.json")
hash_manager = HashManager.from_config(config, "argon2", "bcrypt")

# Async operations for non-blocking performance
import asyncio

async def main():
    hashes = await hash_manager.hash_many_async(["pass1", "pass2", "pass3"])
    # 3-5x faster than sequential hashing!

asyncio.run(main())
```

### 🔄 Migration Guide (v2.x → v3.0.0)

The public API remains backward compatible, but internal imports have changed:

**✅ No changes needed** (backward compatible):
```python
from hash_forge import HashManager, AlgorithmType
from hash_forge.hashers import PBKDF2Sha256Hasher, BCryptHasher

hash_manager = HashManager.from_algorithms("pbkdf2_sha256")
hashed = hash_manager.hash("password")
```

**⚠️ Update if using internal modules** (rare):
```python
# v2.x (deprecated)
from hash_forge.protocols import HasherProtocol
from hash_forge.factory import HasherFactory

# v3.0.0 (new paths)
from hash_forge.core.protocols import HasherProtocol
from hash_forge.core.factory import HasherFactory
```

### 📂 New Project Structure

```
hash_forge/
├── __init__.py          # Public API
├── types.py             # Type definitions (AlgorithmType)
├── exceptions.py        # Exception classes
│
├── core/                # Core functionality (internal)
│   ├── manager.py       # HashManager implementation
│   ├── builder.py       # Builder pattern
│   ├── factory.py       # Hasher factory
│   ├── protocols.py     # Protocol definitions
│   └── base_hasher.py   # Template base class
│
├── config/              # Configuration (internal)
│   ├── settings.py      # Default parameters
│   ├── constants.py     # Constants
│   └── logging.py       # Logging configuration
│
├── hashers/             # Algorithm implementations
│   ├── pbkdf2_hasher.py
│   ├── bcrypt_hasher.py
│   ├── argon2_hasher.py
│   ├── sha3_hasher.py
│   └── ...
│
└── utils/               # Utilities (internal)
    └── helpers.py
```

## Documentation

- **[CHANGELOG.md](CHANGELOG.md)** - Version history and release notes
- **[SECURITY.md](SECURITY.md)** - Security best practices and vulnerability reporting
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Contribution guidelines and development setup
- **[Examples](examples/)** - Practical usage examples

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details on:

- Setting up the development environment
- Running tests and linting
- Code style and documentation standards
- Submitting pull requests

## Security

For security best practices and to report vulnerabilities, please see our [Security Policy](SECURITY.md).

**Recommended algorithms for password hashing:**
1. Argon2 (best choice)
2. BCrypt (industry standard)
3. PBKDF2-SHA256 (NIST approved)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
