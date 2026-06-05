"""Password hashing policy profiles and algorithm classification."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Literal

from hash_forge.config.settings import DEFAULT_PBKDF2_ITERATIONS
from hash_forge.types import AlgorithmType

AlgorithmCategory = Literal["password", "legacy", "digest", "deprecated"]

PASSWORD_ALGORITHMS: frozenset[str] = frozenset({"argon2", "bcrypt", "bcrypt_sha256", "pbkdf2_sha256", "scrypt"})
LEGACY_ALGORITHMS: frozenset[str] = frozenset({"pbkdf2_sha1", "ripemd160", "RIPEMD-160"})
DIGEST_ALGORITHMS: frozenset[str] = frozenset({"blake2", "blake2b", "blake3", "sha3_256", "sha3_512"})
DEPRECATED_ALGORITHMS: frozenset[str] = frozenset({"whirlpool"})


def canonical_algorithm(algorithm: str) -> str:
    """Return the canonical public algorithm identifier."""
    aliases = {
        "blake2b": "blake2",
        "RIPEMD-160": "ripemd160",
    }
    return aliases.get(algorithm, algorithm)


def classify_algorithm(algorithm: str) -> AlgorithmCategory:
    """Classify an algorithm by safe use in password hashing flows."""
    canonical = canonical_algorithm(algorithm)
    if canonical in DEPRECATED_ALGORITHMS:
        return "deprecated"
    if canonical in PASSWORD_ALGORITHMS:
        return "password"
    if canonical in LEGACY_ALGORITHMS:
        return "legacy"
    return "digest"


@dataclass(frozen=True)
class PasswordHashPolicy:
    """Versioned password-hashing policy used by HashManager."""

    preferred_algorithm: AlgorithmType
    algorithms: tuple[AlgorithmType, ...]
    algorithm_options: dict[str, dict[str, Any]] = field(default_factory=dict)
    allow_legacy_verify: bool = True
    allow_digest_password_hashing: bool = False
    allow_deprecated_hashing: bool = False
    max_verify_costs: dict[str, dict[str, int]] = field(default_factory=dict)

    @classmethod
    def recommended(cls) -> PasswordHashPolicy:
        """Modern default profile. Argon2 preferred, PBKDF2 retained for migration."""
        return cls(
            preferred_algorithm="argon2",
            algorithms=("argon2", "pbkdf2_sha256", "bcrypt_sha256", "scrypt"),
            algorithm_options={
                "argon2": {"time_cost": 3, "memory_cost": 65536, "parallelism": 1, "hash_len": 32},
                "pbkdf2_sha256": {"iterations": DEFAULT_PBKDF2_ITERATIONS},
            },
        )

    @classmethod
    def fips(cls) -> PasswordHashPolicy:
        """FIPS-friendly profile based on PBKDF2-HMAC-SHA256."""
        return cls(
            preferred_algorithm="pbkdf2_sha256",
            algorithms=("pbkdf2_sha256", "pbkdf2_sha1"),
            algorithm_options={"pbkdf2_sha256": {"iterations": 600_000}},
        )

    @classmethod
    def legacy_compat(cls) -> PasswordHashPolicy:
        """Compatibility profile that verifies legacy hashes but hashes with PBKDF2-SHA256."""
        return cls(
            preferred_algorithm="pbkdf2_sha256",
            algorithms=("pbkdf2_sha256", "pbkdf2_sha1", "bcrypt", "bcrypt_sha256", "scrypt", "ripemd160"),
            algorithm_options={"pbkdf2_sha256": {"iterations": DEFAULT_PBKDF2_ITERATIONS}},
            allow_legacy_verify=True,
        )

    @classmethod
    def calibrate(cls, target_ms: int = 250) -> PasswordHashPolicy:
        """Calibrate PBKDF2 iterations to a target runtime on this machine."""
        from hash_forge.hashers.pbkdf2_hasher import PBKDF2Sha256Hasher

        iterations = DEFAULT_PBKDF2_ITERATIONS
        sample = "hash-forge-policy-calibration"
        while iterations < 2_000_000:
            hasher = PBKDF2Sha256Hasher(iterations=iterations)
            start = time.perf_counter()
            hasher.hash(sample)
            elapsed_ms = (time.perf_counter() - start) * 1000
            if elapsed_ms >= target_ms:
                break
            iterations *= 2
        return cls(
            preferred_algorithm="pbkdf2_sha256",
            algorithms=("pbkdf2_sha256", "pbkdf2_sha1"),
            algorithm_options={"pbkdf2_sha256": {"iterations": iterations}},
        )

    def options_for(self, algorithm: str) -> dict[str, Any]:
        """Return constructor options for an algorithm."""
        options = dict(self.algorithm_options.get(algorithm, {}))
        if algorithm == "scrypt":
            options.update(self.max_verify_costs.get("scrypt", {}))
        return options

    def validate_for_hashing(self, algorithm: str) -> None:
        """Reject unsafe algorithms for new password hashes."""
        category = classify_algorithm(algorithm)
        if category == "deprecated" and not self.allow_deprecated_hashing:
            raise ValueError(f"Algorithm '{algorithm}' is deprecated for new password hashes")
        if category == "digest" and not self.allow_digest_password_hashing:
            raise ValueError(f"Algorithm '{algorithm}' is a fast digest, not a password hashing algorithm")
        if category == "legacy" and algorithm != self.preferred_algorithm:
            raise ValueError(f"Algorithm '{algorithm}' is legacy and should only be used for verification")

    def validate_for_verify(self, algorithm: str) -> None:
        """Reject verification categories disallowed by this policy."""
        category = classify_algorithm(algorithm)
        if category == "legacy" and not self.allow_legacy_verify:
            raise ValueError(f"Algorithm '{algorithm}' is not allowed for verification by this policy")

    def needs_update(self, algorithm: str, manager_needs_rehash: bool) -> bool:
        """Return True when a verified hash should be rotated."""
        canonical = canonical_algorithm(algorithm)
        return canonical != canonical_algorithm(self.preferred_algorithm) or manager_needs_rehash
