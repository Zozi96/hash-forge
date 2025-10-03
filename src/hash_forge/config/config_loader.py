"""Configuration loader for Hash Forge.

Provides flexible configuration loading from environment variables,
files (JSON/YAML), or programmatic setup.
"""
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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
)


@dataclass
class HashForgeConfig:
    """Configuration object for Hash Forge library.

    This class provides a centralized configuration system that can be
    loaded from various sources: environment variables, JSON/YAML files,
    or programmatic setup.

    Attributes:
        pbkdf2_iterations: Number of iterations for PBKDF2
        pbkdf2_salt_length: Length of salt for PBKDF2
        bcrypt_rounds: Number of rounds for BCrypt
        argon2_time_cost: Time cost for Argon2
        argon2_memory_cost: Memory cost for Argon2
        argon2_parallelism: Parallelism factor for Argon2
        argon2_hash_len: Hash length for Argon2
        scrypt_n: CPU/memory cost parameter for Scrypt
        scrypt_r: Block size parameter for Scrypt
        scrypt_p: Parallelization parameter for Scrypt
    """

    # PBKDF2 settings
    pbkdf2_iterations: int = DEFAULT_PBKDF2_ITERATIONS
    pbkdf2_salt_length: int = DEFAULT_PBKDF2_SALT_LENGTH

    # BCrypt settings
    bcrypt_rounds: int = DEFAULT_BCRYPT_ROUNDS

    # Argon2 settings
    argon2_time_cost: int = DEFAULT_ARGON2_TIME_COST
    argon2_memory_cost: int = DEFAULT_ARGON2_MEMORY_COST
    argon2_parallelism: int = DEFAULT_ARGON2_PARALLELISM
    argon2_hash_len: int = DEFAULT_ARGON2_HASH_LEN

    # Scrypt settings
    scrypt_n: int = DEFAULT_SCRYPT_N
    scrypt_r: int = DEFAULT_SCRYPT_R
    scrypt_p: int = DEFAULT_SCRYPT_P

    # Custom settings
    custom: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_env(cls, prefix: str = "HASH_FORGE_") -> "HashForgeConfig":
        """Load configuration from environment variables.

        Args:
            prefix: Prefix for environment variables (default: HASH_FORGE_)

        Returns:
            HashForgeConfig instance

        Example:
            # Set environment variables:
            # export HASH_FORGE_PBKDF2_ITERATIONS=200000
            # export HASH_FORGE_BCRYPT_ROUNDS=14

            config = HashForgeConfig.from_env()
        """
        def get_int(key: str, default: int) -> int:
            value = os.getenv(f"{prefix}{key}")
            return int(value) if value else default

        return cls(
            pbkdf2_iterations=get_int("PBKDF2_ITERATIONS", DEFAULT_PBKDF2_ITERATIONS),
            pbkdf2_salt_length=get_int("PBKDF2_SALT_LENGTH", DEFAULT_PBKDF2_SALT_LENGTH),
            bcrypt_rounds=get_int("BCRYPT_ROUNDS", DEFAULT_BCRYPT_ROUNDS),
            argon2_time_cost=get_int("ARGON2_TIME_COST", DEFAULT_ARGON2_TIME_COST),
            argon2_memory_cost=get_int("ARGON2_MEMORY_COST", DEFAULT_ARGON2_MEMORY_COST),
            argon2_parallelism=get_int("ARGON2_PARALLELISM", DEFAULT_ARGON2_PARALLELISM),
            argon2_hash_len=get_int("ARGON2_HASH_LEN", DEFAULT_ARGON2_HASH_LEN),
            scrypt_n=get_int("SCRYPT_N", DEFAULT_SCRYPT_N),
            scrypt_r=get_int("SCRYPT_R", DEFAULT_SCRYPT_R),
            scrypt_p=get_int("SCRYPT_P", DEFAULT_SCRYPT_P),
        )

    @classmethod
    def from_json(cls, path: str | Path) -> "HashForgeConfig":
        """Load configuration from a JSON file.

        Args:
            path: Path to JSON configuration file

        Returns:
            HashForgeConfig instance

        Example:
            # config.json:
            # {
            #   "pbkdf2_iterations": 200000,
            #   "bcrypt_rounds": 14,
            #   "custom": {"app_name": "MyApp"}
            # }

            config = HashForgeConfig.from_json("config.json")
        """
        path = Path(path)
        with path.open('r') as f:
            data = json.load(f)

        return cls(**data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HashForgeConfig":
        """Load configuration from a dictionary.

        Args:
            data: Configuration dictionary

        Returns:
            HashForgeConfig instance

        Example:
            config = HashForgeConfig.from_dict({
                "pbkdf2_iterations": 200000,
                "bcrypt_rounds": 14,
            })
        """
        return cls(**data)

    def to_dict(self) -> dict[str, Any]:
        """Export configuration to dictionary.

        Returns:
            Dictionary representation of the configuration
        """
        return {
            'pbkdf2_iterations': self.pbkdf2_iterations,
            'pbkdf2_salt_length': self.pbkdf2_salt_length,
            'bcrypt_rounds': self.bcrypt_rounds,
            'argon2_time_cost': self.argon2_time_cost,
            'argon2_memory_cost': self.argon2_memory_cost,
            'argon2_parallelism': self.argon2_parallelism,
            'argon2_hash_len': self.argon2_hash_len,
            'scrypt_n': self.scrypt_n,
            'scrypt_r': self.scrypt_r,
            'scrypt_p': self.scrypt_p,
            'custom': self.custom,
        }

    def to_json(self, path: str | Path) -> None:
        """Export configuration to JSON file.

        Args:
            path: Path to save JSON file

        Example:
            config.to_json("config.json")
        """
        path = Path(path)
        with path.open('w') as f:
            json.dump(self.to_dict(), f, indent=2)

    def get_hasher_config(self, algorithm: str) -> dict[str, Any]:
        """Get configuration for a specific algorithm.

        Args:
            algorithm: Algorithm name (e.g., 'pbkdf2_sha256', 'bcrypt')

        Returns:
            Dictionary with algorithm-specific configuration

        Example:
            pbkdf2_config = config.get_hasher_config('pbkdf2_sha256')
            # {'iterations': 200000, 'salt_length': 16}
        """
        if algorithm.startswith('pbkdf2'):
            return {
                'iterations': self.pbkdf2_iterations,
                'salt_length': self.pbkdf2_salt_length,
            }
        elif algorithm.startswith('bcrypt'):
            return {'rounds': self.bcrypt_rounds}
        elif algorithm == 'argon2':
            return {
                'time_cost': self.argon2_time_cost,
                'memory_cost': self.argon2_memory_cost,
                'parallelism': self.argon2_parallelism,
                'hash_len': self.argon2_hash_len,
            }
        elif algorithm == 'scrypt':
            return {
                'n': self.scrypt_n,
                'r': self.scrypt_r,
                'p': self.scrypt_p,
            }
        else:
            return {}
