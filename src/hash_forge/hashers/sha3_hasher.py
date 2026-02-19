"""SHA-3 hashers using Python's stdlib hashlib (no extra dependencies required)."""

import binascii
import hashlib
import hmac
import os
from typing import Any, ClassVar

from hash_forge.core.base_hasher import BaseHasher, SimpleHashParser


class SHA3Hasher(BaseHasher):
    """Base SHA-3 hasher using the Template Method pattern.

    Hash format: ``algorithm$salt$hash``

    Subclasses set :attr:`algorithm` and :attr:`_digest_name` to select the
    specific SHA-3 variant.  No optional dependencies are required — SHA-3 is
    part of Python's stdlib ``hashlib``.
    """

    algorithm: ClassVar[str]
    _digest_name: ClassVar[str]

    def __init__(self, salt_length: int = 16) -> None:
        """
        Initialize the SHA3Hasher.

        Args:
            salt_length: Number of random bytes used to generate the salt.
                         Defaults to 16.
        """
        self.salt_length = salt_length

    __slots__ = ("salt_length",)

    def _do_hash(self, string: str) -> str:
        """Hash a string with a random salt using SHA-3."""
        salt = binascii.hexlify(os.urandom(self.salt_length)).decode("ascii")
        h = hashlib.new(self._digest_name)
        h.update(string.encode())
        h.update(salt.encode())
        return f"{self.algorithm}${salt}${h.hexdigest()}"

    def _parse_hash(self, hashed_string: str) -> dict[str, Any] | None:
        """Parse hash format: ``algorithm$salt$hash``."""
        parsed = SimpleHashParser.parse_dollar_separated(hashed_string, 3)
        if parsed and len(parsed["parts"]) >= 2:
            return {
                "algorithm": parsed["algorithm"],
                "salt": parsed["parts"][0],
                "hash": parsed["parts"][1],
            }
        return None

    def _do_verify(self, string: str, parsed: dict[str, Any]) -> bool:
        """Re-derive the hash with the stored salt and compare in constant time."""
        h = hashlib.new(self._digest_name)
        h.update(string.encode())
        h.update(parsed["salt"].encode())
        return hmac.compare_digest(parsed["hash"], h.hexdigest())

    def _check_needs_rehash(self, parsed: dict[str, Any]) -> bool:
        """SHA-3 has no tunable cost parameters, so rehashing is never required."""
        return False


class SHA3_256Hasher(SHA3Hasher):
    algorithm: ClassVar[str] = "sha3_256"
    _digest_name: ClassVar[str] = "sha3_256"


class SHA3_512Hasher(SHA3Hasher):
    algorithm: ClassVar[str] = "sha3_512"
    _digest_name: ClassVar[str] = "sha3_512"
