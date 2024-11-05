import hmac
from typing import ClassVar

from hash_forge.protocols import PHasher


class Ripemd160Hasher(PHasher):
    algorithm: ClassVar[str] = 'RIPEMD-160'
    library_module: ClassVar[str] = 'Crypto.Hash.RIPEMD160'

    def __init__(self) -> None:
        """
        Initializes the RIPEMD-160 hasher instance.

        This method loads the RIPEMD-160 hashing library and assigns it to the
        instance variable `self.ripemd160`.
        """
        self.ripemd160 = self.load_library(self.library_module)

    def hash(self, _string: str, /) -> str:
        """
        Hashes the given string using the RIPEMD-160 algorithm.

        Args:
            _string (str): The input string to be hashed.

        Returns:
            str: The hashed string in the format 'algorithm$hashed_value'.
        """
        hashed = self.ripemd160.new()
        hashed.update(_string.encode())
        return '%s$%s' % (self.algorithm, hashed.hexdigest())

    def verify(self, _string: str, _hashed: str, /) -> bool:
        """
        Verify if the provided string matches the given hashed value.

        Args:
            _string (str): The original string to verify.
            _hashed (str): The hashed value to compare against, in the format 'algorithm$hash_value'.

        Returns:
            bool: True if the string matches the hashed value, False otherwise.
        """
        algorithm, hash_value = _hashed.split('$', 1)
        if algorithm != self.algorithm:
            return False
        hashed = self.ripemd160.new()
        hashed.update(_string.encode())
        return hmac.compare_digest(hash_value, hashed.hexdigest())

    def needs_rehash(self, _hashed_string: str, /) -> bool:
        """
        Determines if the given hashed string needs to be rehashed.

        Args:
            _hashed_string (str): The hashed string to check.

        Returns:
            bool: True if the algorithm used in the hashed string does not match
                  the current algorithm, indicating that a rehash is needed.
        """
        algorithm, _ = _hashed_string.split('$', 1)
        return algorithm != self.algorithm
