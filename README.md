# Hash Forge

[![PyPI version](https://badge.fury.io/py/hash-forge.svg)](https://pypi.org/project/hash-forge/) ![Build Status](https://github.com/Zozi96/hash-forge/actions/workflows/unittest.yml/badge.svg)  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![Python Versions](https://img.shields.io/pypi/pyversions/hash-forge.svg)](https://pypi.org/project/hash-forge/) [![Downloads](https://pepy.tech/badge/hash-forge)](https://pepy.tech/project/hash-forge) [![GitHub issues](https://img.shields.io/github/issues/Zozi96/hash-forge)](https://github.com/Zozi96/hash-forge/issues) ![Project Status](https://img.shields.io/badge/status-active-brightgreen.svg) [![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black) [![Contributions welcome](https://img.shields.io/badge/contributions-welcome-blue.svg)](https://github.com/Zozi96/hash-forge/issues)

**Hash Forge** is a lightweight Python library designed to simplify the process of hashing and verifying data using a variety of secure hashing algorithms.

## Overview

Hash Forge is a flexible and secure hash management tool that supports multiple hashing algorithms. This tool allows you to hash and verify data using popular hash algorithms, making it easy to integrate into projects where password hashing or data integrity is essential.

## Features

- **Multiple Hashing Algorithms**: Supports bcrypt, Scrypt, Argon2, Blake2, Blake3, PBKDF2, Whirlpool and RIPEMD-160.
- **Hashing and Verification**: Easily hash strings and verify their integrity.
- **Rehash Detection**: Automatically detects if a hash needs to be rehashed based on outdated parameters or algorithms.
- **Type-Safe API**: Full TypeScript-like type hints with `AlgorithmType` for better IDE support.
- **Factory Pattern**: Create hashers dynamically by algorithm name.
- **Performance Optimized**: O(1) hasher lookup with internal caching.
- **Security Focused**: Enforces minimum security parameters and uses cryptographically secure random generation.
- **Flexible Integration**: Extendible to add new hashing algorithms as needed.

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
    WhirlpoolHasher,
    Blake3Hasher
)

hash_manager = HashManager(
    PBKDF2Sha256Hasher(iterations=200_000),  # Higher iterations
    BCryptSha256Hasher(rounds=14),           # Higher rounds
    Argon2Hasher(time_cost=4),               # Custom parameters
    ScryptHasher(),
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

## What's New in v2.1.0

### 🚀 Performance Improvements
- **O(1) Hasher Lookup**: Internal hasher mapping for faster algorithm detection
- **Optimized Memory Usage**: Reduced object creation overhead

### 🛠️ Developer Experience  
- **Type Safety**: `AlgorithmType` literal for IDE autocomplete and error detection
- **Factory Pattern**: Create hashers by algorithm name with `HasherFactory`
- **Convenience Methods**: `quick_hash()` and `from_algorithms()` for simpler usage

### 🔐 Security Enhancements
- **Parameter Validation**: Enforces minimum security thresholds (150K PBKDF2 iterations, 12 BCrypt rounds)
- **Custom Exceptions**: More specific error types (`InvalidHasherError`, `UnsupportedAlgorithmError`)
- **Centralized Configuration**: Security defaults in one place

### 🧪 Better Testing
- **Enhanced Test Suite**: 81 tests covering new functionality
- **Type Checking Tests**: Validates `AlgorithmType` usage
- **Configuration Validation**: Tests security parameter enforcement

### 📚 API Improvements

**Before v2.1.0:**
```python
# Manual hasher imports and creation
from hash_forge.hashers.pbkdf2_hasher import PBKDF2Sha256Hasher
hasher = PBKDF2Sha256Hasher(iterations=150000)
hash_manager = HashManager(hasher)
```

**v2.1.0+:**
```python
# Simplified with factory pattern and type safety
from hash_forge import HashManager, AlgorithmType

algorithm: AlgorithmType = "pbkdf2_sha256"  # IDE autocomplete!
hash_manager = HashManager.from_algorithms(algorithm)
# or with custom parameters
hashed = HashManager.quick_hash("password", algorithm=algorithm, iterations=200_000)
```

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests to help improve the project.

## License

This project is licensed under the MIT License.
