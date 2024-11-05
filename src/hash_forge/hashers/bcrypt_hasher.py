import binascii
import hashlib

from contextlib import suppress
from typing import Any, Callable, ClassVar, Optional, cast

from hash_forge.protocols import PHasher


class BCryptSha256Hasher(PHasher):
    algorithm: ClassVar[str] = 'bcrypt_sha256'
    library_module: ClassVar[str] = 'bcrypt'
    digest: Callable[[bytes], Any] | None = cast(Callable[[bytes], Any], hashlib.sha256)

    def __init__(self, rounds: int = 12) -> None:
        """
        Initializes the BcryptHasher with the specified number of rounds.

        Args:
            rounds (int, optional): The number of rounds to use for hashing. Defaults to 12.
        """
        self.bcrypt = self.load_library(self.library_module)
        self.rounds = rounds

    __slots__ = ('rounds',)

    def hash(self, _string: str, /) -> str:
        """
        Hashes the given string using bcrypt algorithm.

        Args:
            _string (str): The string to be hashed.

        Returns:
            str: The formatted hash string containing the algorithm, rounds, salt, and hashed value.
        """
        encoded_string: bytes = _string.encode()
        if self.digest is not None:
            encoded_string = self._get_hexdigest(_string, self.digest)
        bcrypt_hashed: bytes = self.bcrypt.hashpw(encoded_string, self.bcrypt.gensalt(self.rounds))
        return self.algorithm + bcrypt_hashed.decode("ascii")

    def verify(self, _string: str, _hashed_string: str, /) -> bool:
        """
        Verify if a given string matches the hashed string using bcrypt.

        Args:
            _string (str): The plain text string to verify.
            _hashed_string (str): The hashed string to compare against.

        Returns:
            bool: True if the plain text string matches the hashed string, False otherwise.
        """
        try:
            algorithm, hashed_val = _hashed_string.split('$', 1)
            if algorithm != self.algorithm:
                return False
            encoded_string: bytes = _string.encode()
            if self.digest is not None:
                encoded_string = self._get_hexdigest(_string, self.digest)
            return cast(bool, self.bcrypt.checkpw(encoded_string, ('$' + hashed_val).encode('ascii')))
        except (ValueError, TypeError, IndexError):
            return False

    def needs_rehash(self, _hashed_string: str, /) -> bool:
        """
        Check if the hashed string needs to be rehashed.

        This method determines whether the provided hashed string needs to be rehashed
        based on the algorithm and the number of rounds used during hashing.

        Args:
            _hashed_string (str): The hashed string to check.

        Returns:
            bool: True if the hashed string needs to be rehashed, False otherwise.
        """
        with suppress(ValueError):
            algorithm, hashed_val = _hashed_string.split('$', 1)
            if algorithm != self.algorithm:
                return False
            parts: list[str] = hashed_val.split('$')
            if len(parts) < 3:
                return False
            return int(parts[2]) != self.rounds
        return False

    @staticmethod
    def _get_hexdigest(_string: str, digest: Callable[[bytes], Any]) -> bytes:
        """
        Generate a hexadecimal digest for a given string using the specified digest function.

        Args:
            _string (str): The input string to be hashed.
            digest (Callable): A callable digest function (e.g., hashlib.sha256).

        Returns:
            bytes: The hexadecimal representation of the digest.
        """
        return binascii.hexlify(digest(_string.encode()).digest())


class BCryptHasher(BCryptSha256Hasher):
    algorithm = 'bcrypt'
    digest = None
