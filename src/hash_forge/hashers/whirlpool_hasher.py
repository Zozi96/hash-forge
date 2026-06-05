import hmac
from typing import ClassVar
from warnings import warn

from hash_forge.core.protocols import PHasher
from hash_forge.exceptions import InvalidHasherError


class WhirlpoolHasher(PHasher):
    algorithm: ClassVar[str] = 'whirlpool'
    library_module: ClassVar[str] = 'Crypto.Hash.SHA512'

    def __init__(self, allow_legacy_verify: bool = True, allow_legacy_hashing: bool = False) -> None:
        """
        Initializes the WhirlpoolHasher instance.

        This constructor initializes the WhirlpoolHasher by loading the SHA-512
        hashing library module.

        Attributes:
            sha512: The loaded SHA-512 hashing library module.
        """
        if not allow_legacy_verify and not allow_legacy_hashing:
            raise InvalidHasherError(
                "WhirlpoolHasher is deprecated because this implementation used SHA-512. "
                "Pass allow_legacy_verify=True to verify old hashes."
            )
        self.allow_legacy_verify = allow_legacy_verify
        self.allow_legacy_hashing = allow_legacy_hashing
        warn(
            "WhirlpoolHasher is deprecated; this legacy implementation uses SHA-512.",
            DeprecationWarning,
            stacklevel=2,
        )
        self.sha512 = self.load_library(self.library_module)

    def hash(self, _string: str, /) -> str:
        """
        Computes the hash of the given string using the SHA-512 algorithm.

        Args:
            _string (str): The input string to be hashed.

        Returns:
            str: The resulting hash as a hexadecimal string prefixed with the algorithm name.
        """
        if not self.allow_legacy_hashing:
            raise InvalidHasherError(
                "WhirlpoolHasher cannot create new hashes by default. "
                "Pass allow_legacy_hashing=True only when you explicitly need legacy SHA-512-backed hashes."
            )
        hashed = self.sha512.new()
        hashed.update(_string.encode())
        return f'{self.algorithm}${hashed.hexdigest()}'

    def verify(self, _string: str, _hashed_string: str, /) -> bool:
        """
        Verifies if the given string matches the given hash.

        Args:
            _string (str): The input string to verify.
            _hashed_string (str): The hash to compare against.

        Returns:
            bool: True if the hash matches the input string, False otherwise.
        """
        if not self.allow_legacy_verify:
            return False
        try:
            algorithm, hashed_val = _hashed_string.split('$', 1)
            if algorithm != self.algorithm:
                return False
            hashed = self.sha512.new()
            hashed.update(_string.encode())
            return hmac.compare_digest(hashed_val, hashed.hexdigest())
        except (ValueError, TypeError):
            return False

    def needs_rehash(self, _hashed_string: str, /) -> bool:
        """
        Determines if the given hash needs to be rehashed.

        Args:
            _hashed_string (str): The hash to check.

        Returns:
            bool: True if the hash needs to be rehashed, False otherwise.
        """
        try:
            algorithm, _ = _hashed_string.split('$', 1)
            return algorithm != self.algorithm
        except (ValueError, TypeError):
            return False
