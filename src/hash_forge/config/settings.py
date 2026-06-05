"""Configuration constants for Hash Forge library."""
from typing import Final

# Default parameters for hashers
DEFAULT_PBKDF2_ITERATIONS: Final[int] = 150_000
DEFAULT_PBKDF2_SALT_LENGTH: Final[int] = 16
DEFAULT_BCRYPT_ROUNDS: Final[int] = 12
DEFAULT_SCRYPT_N: Final[int] = 32768
DEFAULT_SCRYPT_R: Final[int] = 8
DEFAULT_SCRYPT_P: Final[int] = 1
DEFAULT_SCRYPT_MAX_N: Final[int] = 2**20
DEFAULT_SCRYPT_MAX_R: Final[int] = 16
DEFAULT_SCRYPT_MAX_P: Final[int] = 8
DEFAULT_ARGON2_TIME_COST: Final[int] = 3
DEFAULT_ARGON2_MEMORY_COST: Final[int] = 65536
DEFAULT_ARGON2_PARALLELISM: Final[int] = 1
DEFAULT_ARGON2_HASH_LEN: Final[int] = 32

# Security constraints
MIN_PBKDF2_ITERATIONS: Final[int] = 150_000
MIN_BCRYPT_ROUNDS: Final[int] = 12
MIN_SCRYPT_N: Final[int] = 16384
MIN_SCRYPT_R: Final[int] = 8
MIN_SCRYPT_P: Final[int] = 1
MIN_ARGON2_TIME_COST: Final[int] = 2
MIN_ARGON2_MEMORY_COST: Final[int] = 32768
