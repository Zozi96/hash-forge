import binascii
import hmac
from typing import ClassVar

from hash_forge.protocols import PHasher


class Blake3Hasher(PHasher):
    algorithm: ClassVar[str] = "blake3"
    library_module: ClassVar[str] = "blake3"

    def __init__(self) -> None:
        """
        Initializes the Blake3Hasher with a key and an optional digest size.

        Args:
            key (str): The key to use for the hash function.
        """
        self.module = self.load_library(self.library_module)

    def hash(self, _string: str, /) -> str:
        """
        Hashes the given string using the BLAKE3 algorithm and returns the result in a specific format.

        Args:
            _string (str): The input string to be hashed.

        Returns:
            str: The hashed string in the format "algorithm$hashed_hex".
        """
        hasher = self.module.blake3()
        hasher.update(_string.encode())
        hashed: bytes = hasher.digest()
        hashed_hex: str = binascii.hexlify(hashed).decode("ascii")
        return f"{self.algorithm}${hashed_hex}"

    def verify(self, _string: str, _hashed_string: str, /) -> bool:
        """
        Verify if a given string matches a hashed string using the BLAKE3 algorithm.

        Args:
            _string (str): The input string to verify.
            _hashed_string (str): The hashed string to compare against, in the format 'algorithm$hashed_value'.

        Returns:
            bool: True if the input string matches the hashed string, False otherwise.
        """
        try:
            algorithm, hashed_val = _hashed_string.split("$", 2)
            if algorithm != self.algorithm:
                return False
            hasher = self.module.blake3()
            hasher.update(_string.encode())
            hashed_input: str = binascii.hexlify(hasher.digest()).decode("ascii")
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
            algorithm, _ = _hashed_string.split("$", 2)
            return algorithm != self.algorithm
        except ValueError:
            return False
