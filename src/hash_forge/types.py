"""Type definitions for Hash Forge."""
from typing import Literal

# Available algorithm types for better IDE support and type safety
AlgorithmType = Literal[
    "pbkdf2_sha256",
    "pbkdf2_sha1", 
    "bcrypt",
    "bcrypt_sha256",
    "argon2",
    "scrypt",
    "blake2",
    "blake3",
    "whirlpool",
    "ripemd160"
]