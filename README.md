# Hash Forge

[![PyPI version](https://badge.fury.io/py/hash-forge.svg)](https://pypi.org/project/hash-forge/) ![Build Status](https://github.com/Zozi96/hash-forge/actions/workflows/unittest.yml/badge.svg)  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![Python Versions](https://img.shields.io/pypi/pyversions/hash-forge.svg)](https://pypi.org/project/hash-forge/) [![Downloads](https://pepy.tech/badge/hash-forge)](https://pepy.tech/project/hash-forge) [![GitHub issues](https://img.shields.io/github/issues/Zozi96/hash-forge)](https://github.com/Zozi96/hash-forge/issues) ![Project Status](https://img.shields.io/badge/status-active-brightgreen.svg) [![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black) [![Contributions welcome](https://img.shields.io/badge/contributions-welcome-blue.svg)](https://github.com/Zozi96/hash-forge/issues)

**Hash Forge** is a lightweight Python library designed to simplify the process of hashing and verifying data using a variety of secure hashing algorithms.

## Overview

Hash Forge is a flexible and secure hash management tool that supports multiple hashing algorithms. This tool allows you to hash and verify data using popular hash algorithms, making it easy to integrate into projects where password hashing or data integrity is essential.

## Features

- **Multiple Hashing Algorithms**: Supports bcrypt, Scrypt, Argon2, Blake2, PBKDF2, Whirlpool and RIPEMD-160.
- **Hashing and Verification**: Easily hash strings and verify their integrity.
- **Rehash Detection**: Automatically detects if a hash needs to be rehashed based on outdated parameters or algorithms.
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

## Usage

### Basic Example

```python
from hash_forge import HashManager, PBKDF2Hasher

# Initialize HashManager with PBKDF2Hasher
hash_manager = HashManager(PBKDF2Hasher())

# Hash a string
hashed_value = hash_manager.hash("my_secure_password")

# Verify the string against the hashed value
is_valid = hash_manager.verify("my_secure_password", hashed_value)
print(is_valid)  # Outputs: True

# Check if the hash needs rehashing
needs_rehash = hash_manager.needs_rehash(hashed_value)
print(needs_rehash)  # Outputs: False
```

> **Note:** The first hasher provided during initialization of `HashManager` will be the **preferred hasher** used for hashing operations, though any available hasher can be used for verification.

### Hashers

Currently supported hashers:

- **PBKDF2** (default)
- **bcrypt**
- **Argon2**
- **Scrypt**
- **Blake2**
- **Whirlpool**
- **RIPEMD-160**

You can initialize `HashManager` with one or more hashers:

```python
from hash_forge import (
    HashManager,
    PBKDF2Sha256Hasher,
    BCryptSha256Hasher,
    Argon2Hasher,
    ScryptHasher,
    Ripemd160Hasher,
    Blake2Hasher,
    WhirlpoolHasher,
)

hash_manager = HashManager(
    PBKDF2Sha256Hasher(iterations=150_000),
    BCryptSha256Hasher(),
    Argon2Hasher(),
    ScryptHasher(),
    Ripemd160Hasher(),
    Blake2Hasher('MySecretKey'),
    WhirlpoolHasher(),
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

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests to help improve the project.

## License

This project is licensed under the MIT License.
