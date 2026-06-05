"""Hash Manager - Main orchestrator for hash operations."""

from typing import Any

from hash_forge.config.config_loader import HashForgeConfig
from hash_forge.config.logging import get_logger
from hash_forge.core.async_manager import AsyncHashMixin
from hash_forge.core.builder import HashManagerBuilder
from hash_forge.core.factory import HasherFactory
from hash_forge.core.protocols import PHasher, get_algorithm_token
from hash_forge.exceptions import InvalidHasherError
from hash_forge.policy import PasswordHashPolicy, canonical_algorithm, classify_algorithm
from hash_forge.types import AlgorithmType

logger = get_logger("manager")


class HashManager(AsyncHashMixin):
    """Main class for managing hash operations with multiple algorithms."""

    def __init__(self, *hashers: PHasher) -> None:
        """
        Initialize the HashManager instance with one or more hashers.

        Args:
            *hashers (PHasher): One or more hasher instances to be used by the HashManager.

        Raises:
            InvalidHasherError: If no hashers are provided.

        Attributes:
            hashers: ordered tuples containing the algorithm name and the hasher instance.
            hasher_map (Dict[str, PHasher]): A mapping of algorithm names to hasher instances for O(1) lookup.
            preferred_hasher (PHasher): The first hasher provided, used as the preferred hasher.
        """
        if not hashers:
            raise InvalidHasherError("At least one hasher is required.")
        self.hashers: tuple[tuple[str, PHasher], ...] = tuple((hasher.algorithm, hasher) for hasher in hashers)
        # Create a mapping for O(1) hasher lookup
        self.hasher_map: dict[str, PHasher] = {hasher.algorithm: hasher for hasher in hashers}
        self.preferred_hasher: PHasher = hashers[0]
        self.policy: PasswordHashPolicy | None = None
        logger.info(
            f"HashManager initialized with {len(hashers)} hasher(s), preferred: {self.preferred_hasher.algorithm}"
        )

    def hash(self, string: str) -> str:
        """
        Hashes the given string using the preferred hasher.

        Args:
            string (str): The string to be hashed.

        Returns:
            str: The hashed string.
        """
        if self.policy is not None:
            self.policy.validate_for_hashing(self.preferred_hasher.algorithm)
        return self.preferred_hasher.hash(string)

    def verify(self, string: str, hashed_string: str) -> bool:
        """
        Verifies if a given string matches a hashed string using the appropriate hashing algorithm.

        Args:
            string (str): The plain text string to verify.
            hashed_string (str): The hashed string to compare against.

        Returns:
            bool: True if the string matches the hashed string, False otherwise.
        """
        hasher: PHasher | None = self._get_hasher_by_hash(hashed_string)
        if hasher is None:
            logger.warning(f"No hasher found for hash string: {hashed_string[:20]}...")
            return False
        if self.policy is not None:
            try:
                self.policy.validate_for_verify(hasher.algorithm)
            except ValueError:
                logger.debug(f"Verification blocked by policy for {hasher.algorithm}")
                return False
        logger.debug(f"Verifying with {hasher.algorithm}")
        return hasher.verify(string, hashed_string)

    def needs_rehash(self, hashed_string: str) -> bool:
        """
        Determines if a given hashed string needs to be rehashed.

        This method checks if the hashing algorithm used for the given hashed string
        is the preferred algorithm or if the hashed string needs to be rehashed
        according to the hasher's criteria.

        Args:
            hashed_string (str): The hashed string to check.

        Returns:
            bool: True if the hashed string needs to be rehashed, False otherwise.
        """
        hasher: PHasher | None = self._get_hasher_by_hash(hashed_string)
        if hasher is None:
            return True
        manager_needs_rehash = hasher.needs_rehash(hashed_string)
        if self.policy is not None:
            return self.policy.needs_update(hasher.algorithm, manager_needs_rehash)
        return manager_needs_rehash

    def _get_hasher_by_hash(self, hashed_string: str) -> PHasher | None:
        """
        Retrieve the hasher instance that matches the given hashed string.

        This method uses the Chain of Responsibility pattern where each hasher
        decides if it can handle the given hash string.

        Args:
            hashed_string (str): The hashed string to match against available hashers.

        Returns:
            PHasher | None: The hasher instance that matches the hashed string, or
            None if no match is found.
        """
        algorithm = get_algorithm_token(hashed_string)
        if algorithm is not None:
            hasher = self.hasher_map.get(algorithm)
            if hasher is not None:
                logger.debug(f"Hasher {hasher.algorithm} can handle the hash")
                return hasher

        for _, hasher in self.hashers:
            if hasher.can_handle(hashed_string):
                logger.debug(f"Hasher {hasher.algorithm} can handle the hash")
                return hasher

        logger.warning(f"No hasher found to handle hash starting with: {hashed_string[:20]}...")
        return None

    @classmethod
    def from_algorithms(cls, *algorithms: AlgorithmType, **kwargs: Any) -> "HashManager":
        """
        Create a HashManager instance using algorithm names.

        Args:
            *algorithms: Algorithm names to create hashers for
            **kwargs: Additional arguments passed to hasher constructors

        Returns:
            HashManager: A new HashManager instance

        Raises:
            UnsupportedAlgorithmError: If any algorithm is not supported
        """
        hashers = []
        for algorithm in algorithms:
            hasher = HasherFactory.create(algorithm, **kwargs)
            hashers.append(hasher)
        return cls(*hashers)

    @classmethod
    def from_config(cls, config: "HashForgeConfig", *algorithms: AlgorithmType) -> "HashManager":
        """
        Create a HashManager instance using a configuration object.

        Args:
            config: HashForgeConfig instance with algorithm settings
            *algorithms: Algorithm names to create hashers for

        Returns:
            HashManager: A new HashManager instance

        Example:
            from hash_forge.config import HashForgeConfig

            config = HashForgeConfig.from_env()
            hash_manager = HashManager.from_config(config, "pbkdf2_sha256", "bcrypt")
        """

        hashers = []
        for algorithm in algorithms:
            hasher_config = config.get_hasher_config(algorithm)
            hasher = HasherFactory.create(algorithm, **hasher_config)
            hashers.append(hasher)
        return cls(*hashers)

    @classmethod
    def from_policy(cls, policy: PasswordHashPolicy) -> "HashManager":
        """
        Create a HashManager from a password hashing policy.

        Args:
            policy: PasswordHashPolicy instance with preferred algorithm, allowed algorithms,
                and algorithm-specific constructor options.
        """
        ordered_algorithms = (
            policy.preferred_algorithm,
            *tuple(a for a in policy.algorithms if a != policy.preferred_algorithm),
        )
        hashers = [HasherFactory.create(algorithm, **policy.options_for(algorithm)) for algorithm in ordered_algorithms]
        manager = cls(*hashers)
        manager.policy = policy
        return manager

    @staticmethod
    def quick_hash(string: str, algorithm: AlgorithmType = "pbkdf2_sha256", **kwargs: Any) -> str:
        """
        Quickly hash a string using the specified algorithm.

        Args:
            string: The string to hash
            algorithm: The algorithm to use (default: pbkdf2_sha256)
            **kwargs: Additional arguments for the hasher

        Returns:
            str: The hashed string
        """
        hasher = HasherFactory.create(algorithm, **kwargs)
        return hasher.hash(string)

    @staticmethod
    def builder() -> "HashManagerBuilder":
        """
        Create a HashManagerBuilder for fluent configuration.

        Returns:
            HashManagerBuilder: A new builder instance

        Example:
            hash_manager = (
                HashManager.builder()
                .with_algorithm("argon2", time_cost=4)
                .with_algorithm("bcrypt", rounds=14)
                .with_preferred("argon2")
                .build()
            )
        """
        from hash_forge.core.builder import HashManagerBuilder

        return HashManagerBuilder()

    def rotate(self, string: str, old_hash: str) -> str | None:
        """
        Re-hash a string if verification against the old hash succeeds.

        Useful for migrating hashes to a new preferred algorithm or updated
        parameters without exposing the plaintext password to the caller.

        Args:
            string: The plain text string to verify and re-hash.
            old_hash: The existing hash to verify against.

        Returns:
            A new hash produced by the preferred hasher, or ``None`` if
            verification fails.
        """
        if not self.verify(string, old_hash):
            return None
        return self.preferred_hasher.hash(string)

    def verify_and_update(self, string: str, hashed_string: str) -> tuple[bool, str | None]:
        """
        Verify a string and return a replacement hash when policy or parameters require it.
        """
        if not self.verify(string, hashed_string):
            return False, None
        if not self.needs_rehash(hashed_string):
            return True, None
        return True, self.hash(string)

    def inspect(self, hashed_string: str) -> dict[str, Any] | None:
        """
        Return metadata about a hashed string without exposing the raw hash.

        Args:
            hashed_string: The hashed string to inspect.

        Returns:
            A dictionary with at least an ``"algorithm"`` key and any
            algorithm-specific parameters (e.g. ``iterations``, ``rounds``),
            or ``None`` if no registered hasher recognises the hash.
        """
        hasher = self._get_hasher_by_hash(hashed_string)
        if hasher is None:
            return None
        canonical = canonical_algorithm(hasher.algorithm)
        category = classify_algorithm(hasher.algorithm)
        info: dict[str, Any] = {
            "algorithm": canonical,
            "category": category,
            "deprecated": category == "deprecated",
        }
        parse_hash = getattr(hasher, "_parse_hash", None)
        if callable(parse_hash):
            parsed = parse_hash(hashed_string)
            if parsed:
                skip = {"algorithm", "hash", "salt", "hashed_val", "parts"}
                info.update({k: v for k, v in parsed.items() if k not in skip})
        return info

    def list_algorithms(self) -> list[str]:
        """
        Return the algorithm names registered in this manager instance.

        Returns:
            A list of algorithm identifier strings in insertion order.
        """
        return [name for name, _ in self.hashers]

    def __repr__(self) -> str:
        algorithms = [name for name, _ in self.hashers]
        return f"HashManager(preferred={self.preferred_hasher.algorithm!r}, algorithms={algorithms!r})"
