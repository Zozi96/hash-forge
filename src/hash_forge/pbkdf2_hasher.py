import hashlib
import os
import binascii

from contextlib import suppress

from hash_forge.protocols import PHasher


class PBKDF2Sha256Hasher(PHasher):
    algorithm: str = 'pbkdf2_sha256'

    def __init__(self, iterations: int = 100_000, salt: int = 16) -> None:
        self.iterations = iterations
        self.salt = salt

    __slots__ = ('iterations', 'salt')

    def hash(self, _string: str, /) -> str:
        """
        Hashes a given string using the PBKDF2 (Password-Based Key Derivation Function 2) algorithm.

        Args:
            _string (str): The input string to be hashed.

        Returns:
            str: The hashed string in the format 'algorithm$iterations$salt$hashed'.
        """
        salt: str = binascii.hexlify(os.urandom(self.salt)).decode('ascii')
        dk: bytes = hashlib.pbkdf2_hmac('sha256', _string.encode(), salt.encode(), self.iterations)
        hashed: str = binascii.hexlify(dk).decode('ascii')
        return '%s$%s$%s$%s' % (self.algorithm, self.iterations, salt, hashed)

    def verify(self, _string: str, _hashed_string: str, /) -> bool:
        """
        Verifies if a given string matches the hashed string using PBKDF2 algorithm.

        Args:
            _string (str): The plain text string to verify.
            _hashed_string (str): The hashed string to compare against, formatted as 'algorithm$iterations$salt$hashed'.

        Returns:
            bool: True if the string matches the hashed string, False otherwise.
        """
        with suppress(ValueError, AssertionError):
            algorithm, iterations, salt, hashed = _hashed_string.split('$')
            if algorithm != self.algorithm:
                return False
            dk: bytes = hashlib.pbkdf2_hmac('sha256', _string.encode(), salt.encode(), int(iterations))
            hashed_input: str = binascii.hexlify(dk).decode('ascii')
            return hashed == hashed_input
        return False

    def needs_rehash(self, _hashed_string: str, /) -> bool:
        """
        Determines if a hashed string needs to be rehashed based on the number of iterations.

        Args:
            _hashed_string (str): The hashed string to check.

        Returns:
            bool: True if the number of iterations in the hashed string does not match
                  the current number of iterations, indicating that a rehash is needed.
                  False otherwise.
        """
        with suppress(ValueError):
            _, iterations, *_ = _hashed_string.split('$')
            return int(iterations) != self.iterations
        return False
