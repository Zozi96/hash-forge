# Hash Forge

A simple tool to generate secure hashes.

## Overview

Hash Forge is a flexible and secure hash management tool that supports multiple hashing algorithms. This tool allows you to hash and verify data using popular hash algorithms, making it easy to integrate into projects where password hashing or data integrity is essential. The library supports bcrypt, Argon2, and PBKDF2 out of the box, and you can add more hashers as needed.

## Features

- **Multiple Hashing Algorithms**: Supports bcrypt, Argon2, and PBKDF2.
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

## Usage

### Basic Example

```python
from hash_forge import HashManager
from hash_forge.pbkdf2_hasher import PBKDF2Hasher

# Initialize HashManager with PBKDF2Hasher
hash_manager = HashManager(PBKDF2Hasher(iterations=150_000))

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

You can initialize `HashManager` with one or more hashers:

```python
from hash_forge import HashManager
from hash_forge.pbkdf2_hasher import PBKDF2Hasher
from hash_forge.bcrypt_hasher import BCryptHasher

hash_manager = HashManager(PBKDF2Hasher(iterations=150_000), BCryptHasher())
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