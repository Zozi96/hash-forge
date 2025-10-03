"""Configuration module for Hash Forge.

This module contains configuration settings, constants, and logging setup.
Users should not import directly from this module; configuration values
are used internally by the library.
"""
from hash_forge.config.config_loader import HashForgeConfig
from hash_forge.config.constants import RANDOM_STRING_CHARS
from hash_forge.config.logging import configure_logging, get_logger
from hash_forge.config.settings import (
    DEFAULT_ARGON2_HASH_LEN,
    DEFAULT_ARGON2_MEMORY_COST,
    DEFAULT_ARGON2_PARALLELISM,
    DEFAULT_ARGON2_TIME_COST,
    DEFAULT_BCRYPT_ROUNDS,
    DEFAULT_PBKDF2_ITERATIONS,
    DEFAULT_PBKDF2_SALT_LENGTH,
    DEFAULT_SCRYPT_N,
    DEFAULT_SCRYPT_P,
    DEFAULT_SCRYPT_R,
    MIN_ARGON2_MEMORY_COST,
    MIN_ARGON2_TIME_COST,
    MIN_BCRYPT_ROUNDS,
    MIN_PBKDF2_ITERATIONS,
    MIN_SCRYPT_N,
)

__all__ = [
    # Config loader
    "HashForgeConfig",
    # Constants
    "RANDOM_STRING_CHARS",
    # Logging
    "configure_logging",
    "get_logger",
    # Settings - Defaults
    "DEFAULT_PBKDF2_ITERATIONS",
    "DEFAULT_PBKDF2_SALT_LENGTH",
    "DEFAULT_BCRYPT_ROUNDS",
    "DEFAULT_SCRYPT_N",
    "DEFAULT_SCRYPT_R",
    "DEFAULT_SCRYPT_P",
    "DEFAULT_ARGON2_TIME_COST",
    "DEFAULT_ARGON2_MEMORY_COST",
    "DEFAULT_ARGON2_PARALLELISM",
    "DEFAULT_ARGON2_HASH_LEN",
    # Settings - Minimums
    "MIN_PBKDF2_ITERATIONS",
    "MIN_BCRYPT_ROUNDS",
    "MIN_SCRYPT_N",
    "MIN_ARGON2_TIME_COST",
    "MIN_ARGON2_MEMORY_COST",
]
