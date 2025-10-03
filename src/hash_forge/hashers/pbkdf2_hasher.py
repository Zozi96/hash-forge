import binascii
import hashlib
import hmac
import os
from collections.abc import Callable
from typing import Any, ClassVar

from hash_forge.config.settings import DEFAULT_PBKDF2_ITERATIONS, DEFAULT_PBKDF2_SALT_LENGTH, MIN_PBKDF2_ITERATIONS
from hash_forge.core.base_hasher import BaseHasher, SimpleHashParser
from hash_forge.exceptions import InvalidHasherError


class PBKDF2Sha256Hasher(BaseHasher):
    algorithm: ClassVar[str] = 'pbkdf2_sha256'
    digest: ClassVar[Callable[..., Any]] = hashlib.sha256

    def __init__(
        self,
        iterations: int = DEFAULT_PBKDF2_ITERATIONS,
        salt_length: int = DEFAULT_PBKDF2_SALT_LENGTH
    ) -> None:
        if iterations < MIN_PBKDF2_ITERATIONS:
            raise InvalidHasherError(f"PBKDF2 iterations must be at least {MIN_PBKDF2_ITERATIONS}")
        self.iterations = iterations
        self.salt_length = salt_length

    __slots__ = ('iterations', 'salt_length')

    def _do_hash(self, string: str) -> str:
        """Hash using PBKDF2 algorithm."""
        salt: str = binascii.hexlify(os.urandom(self.salt_length)).decode('ascii')
        dk: bytes = hashlib.pbkdf2_hmac(self.digest().name, string.encode(), salt.encode(), self.iterations)
        hashed: str = binascii.hexlify(dk).decode('ascii')
        return f'{self.algorithm}${self.iterations}${salt}${hashed}'

    def _parse_hash(self, hashed_string: str) -> dict[str, Any] | None:
        """Parse PBKDF2 hash format: algorithm$iterations$salt$hash."""
        parsed = SimpleHashParser.parse_dollar_separated(hashed_string, 4)
        if parsed and len(parsed['parts']) >= 3:
            return {
                'algorithm': parsed['algorithm'],
                'iterations': int(parsed['parts'][0]),
                'salt': parsed['parts'][1],
                'hash': parsed['parts'][2]
            }
        return None

    def _do_verify(self, string: str, parsed: dict[str, Any]) -> bool:
        """Verify using PBKDF2 algorithm."""
        dk: bytes = hashlib.pbkdf2_hmac(
            self.digest().name,
            string.encode(),
            parsed['salt'].encode(),
            parsed['iterations']
        )
        hashed_input: str = binascii.hexlify(dk).decode('ascii')
        return hmac.compare_digest(parsed['hash'], hashed_input)

    def _check_needs_rehash(self, parsed: dict[str, Any]) -> bool:
        """Check if iterations count has changed."""
        return parsed['iterations'] != self.iterations


class PBKDF2Sha1Hasher(PBKDF2Sha256Hasher):
    algorithm = "pbkdf2_sha1"
    digest = hashlib.sha1
