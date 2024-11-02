from hash_forge.protocols import PHasher
from hash_forge.hashers.argon2_hasher import Argon2Hasher
from hash_forge.hashers.bcrypt_hasher import BCryptHasher, BCryptSha256Hasher
from hash_forge.hashers.pbkdf2_hasher import PBKDF2Sha256Hasher, PBKDF2Sha1Hasher
from hash_forge.hashers.scrypt_hasher import ScryptHasher
from hash_forge.hashers.blake2_hasher import Blake2Hasher
from hash_forge.hashers.ripemd160_hasher import Ripemd160Hasher
from hash_forge.hashers.whirlpool_hasher import WhirlpoolHasher


class HashManager:
    def __init__(self, *hashers: PHasher) -> None:
        """
        Initialize the HashForge instance with one or more hashers.

        Args:
            *hashers (PHasher): One or more hasher instances to be used by the HashForge.

        Raises:
            ValueError: If no hashers are provided.

        Attributes:
            hashers (Set[Tuple[str, PHasher]]): A set of tuples containing the algorithm name and the hasher instance.
            preferred_hasher (PHasher): The first hasher provided, used as the preferred hasher.
        """
        if not hashers:
            raise ValueError('At least one hasher is required.')
        self.hashers: set[tuple[str, PHasher]] = {(hasher.algorithm, hasher) for hasher in hashers}
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

        Raises:
            IndexError: If the hashed string does not contain a valid algorithm identifier.
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

        Raises:
            IndexError: If the hashed string format is invalid.
        """
        hasher: PHasher | None = self._get_hasher_by_hash(hashed_string)
        if hasher is None:
            return True
        return hasher.needs_rehash(hashed_string)

    def _get_hasher_by_hash(self, hashed_string: str) -> PHasher | None:
        """
        Retrieve the hasher instance that matches the given hashed string.

        This method iterates through the available hashers and returns the first
        hasher whose algorithm matches the beginning of the provided hashed string.

        Args:
            hashed_string (str): The hashed string to match against available hashers.

        Returns:
            PHasher | None: The hasher instance that matches the hashed string, or
            None if no match is found.
        """
        return next((hasher for algorithm, hasher in self.hashers if hashed_string.startswith(algorithm)), None)


__all__ = [
    'Argon2Hasher',
    'BCryptHasher',
    'BCryptSha256Hasher',
    'PBKDF2Sha256Hasher',
    'PBKDF2Sha1Hasher',
    'ScryptHasher',
    'Blake2Hasher',
    'Ripemd160Hasher',
    'WhirlpoolHasher',
    'HashManager',
]
