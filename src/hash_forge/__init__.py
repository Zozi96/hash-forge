"""Hash Forge - A flexible and secure hash management library.

This module provides the public API for Hash Forge. Users should import
from this module rather than from internal submodules.

Example:
    from hash_forge import HashManager, AlgorithmType

    # Create hash manager
    hash_manager = HashManager.from_algorithms("pbkdf2_sha256", "bcrypt")

    # Or use builder pattern
    hash_manager = (
        HashManager.builder()
        .with_algorithm("argon2", time_cost=4)
        .with_algorithm("bcrypt", rounds=14)
        .with_preferred("argon2")
        .build()
    )
"""
from hash_forge.core.builder import HashManagerBuilder
from hash_forge.core.manager import HashManager
from hash_forge.exceptions import (
    HasherNotFoundError,
    HashForgeError,
    InvalidHasherError,
    InvalidHashFormatError,
    UnsupportedAlgorithmError,
)
"""Hash Forge - A flexible and secure hash management library.

This module provides the public API for Hash Forge. Users should import
from this module rather than from internal submodules.

Example:
    from hash_forge import HashManager, AlgorithmType

    # Create hash manager
    hash_manager = HashManager.from_algorithms("pbkdf2_sha256", "bcrypt")

    # Or use builder pattern
    hash_manager = (
        HashManager.builder()
        .with_algorithm("argon2", time_cost=4)
        .with_algorithm("bcrypt", rounds=14)
        .with_preferred("argon2")
        .build()
    )
"""
from hash_forge.core.builder import HashManagerBuilder
from hash_forge.core.manager import HashManager
from hash_forge.exceptions import (
    HasherNotFoundError,
    HashForgeError,
    InvalidHasherError,
    InvalidHashFormatError,
    UnsupportedAlgorithmError,
)
from hash_forge.types import AlgorithmType

# Version
__version__ = "3.0.1"

# Public API
__all__ = [
    # Main classes
    "HashManager",
    "HashManagerBuilder",
    "AlgorithmType",
    # Exceptions
    "HashForgeError",
    "InvalidHasherError",
    "InvalidHashFormatError",
    "UnsupportedAlgorithmError",
    "HasherNotFoundError",
]
