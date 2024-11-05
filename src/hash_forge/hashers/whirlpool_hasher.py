import hmac
from typing import ClassVar

from hash_forge.protocols import PHasher


class WhirlpoolHasher(PHasher):
    algorithm: ClassVar[str] = 'whirlpool'
    library_module: ClassVar[str] = 'Crypto.Hash.SHA512'

    def __init__(self) -> None:
        """
        Initializes the WhirlpoolHasher instance.

        This constructor initializes the WhirlpoolHasher by loading the SHA-512
        hashing library module.

        Attributes:
            sha512: The loaded SHA-512 hashing library module.
        """
        self.sha512 = self.load_library(self.library_module)

    def hash(self, _string: str, /) -> str:
        """
        Computes the hash of the given string using the SHA-512 algorithm.

        Args:
            _string (str): The input string to be hashed.

        Returns:
            str: The resulting hash as a hexadecimal string prefixed with the algorithm name.
        """
        hashed = self.sha512.new()
        hashed.update(_string.encode())
        return '%s$%s' % (self.algorithm, hashed.hexdigest())

    def verify(self, _string: str, _hashed_string: str, /) -> bool:
        """
        Verifies if the given string matches the given hash.

        Args:
            _string (str): The input string to verify.
            _hashed_string (str): The hash to compare against.

        Returns:
            bool: True if the hash matches the input string, False otherwise.
        """
        algorithm, hashed_val = _hashed_string.split('$', 1)
        if algorithm != self.algorithm:
            return False
        hashed = self.sha512.new()
        hashed.update(_string.encode())
        return hmac.compare_digest(hashed_val, hashed.hexdigest())

    def needs_rehash(self, _hashed_string: str, /) -> bool:
        """
        Determines if the given hash needs to be rehashed.

        Args:
            _hashed_string (str): The hash to check.

        Returns:
            bool: True if the hash needs to be rehashed, False otherwise.
        """
        algorithm, _ = _hashed_string.split('$', 1)
        return algorithm != self.algorithm
