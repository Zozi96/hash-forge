from hash_forge.exceptions import InvalidHasherError
from hash_forge.factory import HasherFactory
from hash_forge.protocols import PHasher
from hash_forge.types import AlgorithmType


class HashManager:
    def __init__(self, *hashers: PHasher) -> None:
        """
        Initialize the HashManager instance with one or more hashers.

        Args:
            *hashers (PHasher): One or more hasher instances to be used by the HashManager.

        Raises:
            InvalidHasherError: If no hashers are provided.

        Attributes:
            hashers (Set[Tuple[str, PHasher]]): A set of tuples containing the algorithm name and the hasher instance.
            hasher_map (Dict[str, PHasher]): A mapping of algorithm names to hasher instances for O(1) lookup.
            preferred_hasher (PHasher): The first hasher provided, used as the preferred hasher.
        """
        if not hashers:
            raise InvalidHasherError("At least one hasher is required.")
        self.hashers: set[tuple[str, PHasher]] = {(hasher.algorithm, hasher) for hasher in hashers}
        # Create a mapping for O(1) hasher lookup
        self.hasher_map: dict[str, PHasher] = {hasher.algorithm: hasher for hasher in hashers}
        self.preferred_hasher: PHasher = hashers[0]

    def hash(self, string: str) -> str:
        """
        Hashes the given string using the preferred hasher.

        Args:
            string (str): The string to be hashed.

        Returns:
            str: The hashed string.
        """
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
            return False
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
        return hasher.needs_rehash(hashed_string)

    def _get_hasher_by_hash(self, hashed_string: str) -> PHasher | None:
        """
        Retrieve the hasher instance that matches the given hashed string.

        This method uses the hasher mapping to find the appropriate hasher
        based on the algorithm prefix in the hashed string.

        Args:
            hashed_string (str): The hashed string to match against available hashers.

        Returns:
            PHasher | None: The hasher instance that matches the hashed string, or
            None if no match is found.
        """
        # Try to find matching algorithm by checking prefixes
        for algorithm in self.hasher_map:
            if hashed_string.startswith(algorithm):
                return self.hasher_map[algorithm]

    @classmethod
    def from_algorithms(cls, *algorithms: AlgorithmType, **kwargs) -> "HashManager":
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

    @staticmethod
    def quick_hash(string: str, algorithm: AlgorithmType = "pbkdf2_sha256", **kwargs) -> str:
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


__all__ = ["HashManager", "AlgorithmType"]
