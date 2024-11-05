import binascii
import hashlib
import hmac

from typing import ClassVar

from hash_forge.protocols import PHasher


class Blake2Hasher(PHasher):
    algorithm: ClassVar[str] = 'blake2b'

    def __init__(self, key: str, digest_size: int = 64) -> None:
        """
        Initializes the Blake2Hasher with a key and an optional digest size.

        Args:
            key (str): The key to use for the hash function.
            digest_size (int, optional): The size of the digest in bytes. Defaults to 64.
        """
        self.digest_size = digest_size
        self.key = key

    __slots__ = ('digest_size', 'key')

    def hash(self, _string: str, /) -> str:
        """
        Hashes the given string using the BLAKE2b algorithm.

        Args:
            _string (str): The string to be hashed.

        Returns:
            str: The formatted hash string containing the algorithm, digest size, and hashed value.
        """
        hasher = hashlib.blake2b(digest_size=self.digest_size, key=self.key.encode())
        hasher.update(_string.encode())
        hashed: bytes = hasher.digest()
        hashed_hex: str = binascii.hexlify(hashed).decode('ascii')
        return '%s$%d$%s' % (self.algorithm, self.digest_size, hashed_hex)

    def verify(self, _string: str, _hashed_string: str, /) -> bool:
        """
        Verifies if a given string matches the hashed string using BLAKE2b.

        Args:
            _string (str): The plain text string to verify.
            _hashed_string (str): The hashed string to compare against.

        Returns:
            bool: True if the plain text string matches the hashed string, False otherwise.
        """
        try:
            algorithm, digest_size, hashed_val = _hashed_string.split('$', 2)
            if algorithm != self.algorithm or int(digest_size) != self.digest_size:
                return False
            hasher = hashlib.blake2b(digest_size=int(digest_size), key=self.key.encode())
            hasher.update(_string.encode())
            hashed_input: str = binascii.hexlify(hasher.digest()).decode('ascii')
            return hmac.compare_digest(hashed_val, hashed_input)
        except (ValueError, TypeError, IndexError):
            return False

    def needs_rehash(self, _hashed_string: str, /) -> bool:
        """
        Checks if the hashed string needs to be rehashed based on the digest size.

        Args:
            _hashed_string (str): The hashed string to check.

        Returns:
            bool: True if the hashed string needs to be rehashed, False otherwise.
        """
        try:
            _, digest_size, _ = _hashed_string.split('$', 2)
            return int(digest_size) != self.digest_size
        except ValueError:
            return False
