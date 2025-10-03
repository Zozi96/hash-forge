import binascii
import hashlib
from collections.abc import Callable
from typing import Any, ClassVar, cast

from hash_forge.config.settings import DEFAULT_BCRYPT_ROUNDS, MIN_BCRYPT_ROUNDS
from hash_forge.core.base_hasher import BaseHasher, SimpleHashParser
from hash_forge.exceptions import InvalidHasherError


class BCryptSha256Hasher(BaseHasher):
    algorithm: ClassVar[str] = 'bcrypt_sha256'
    library_module: ClassVar[str] = 'bcrypt'
    digest: Callable[[bytes], Any] | None = cast(Callable[[bytes], Any], hashlib.sha256)

    def __init__(self, rounds: int = DEFAULT_BCRYPT_ROUNDS) -> None:
        """Initialize BCrypt hasher with specified rounds."""
        if rounds < MIN_BCRYPT_ROUNDS:
            raise InvalidHasherError(f"BCrypt rounds must be at least {MIN_BCRYPT_ROUNDS}")
        self.bcrypt = self.load_library(self.library_module)
        self.rounds = rounds

    __slots__ = ('rounds', 'bcrypt')

    def _do_hash(self, string: str) -> str:
        """Hash using BCrypt algorithm."""
        encoded_string: bytes = string.encode()
        if self.digest is not None:
            encoded_string = self._get_hexdigest(string, self.digest)
        bcrypt_hashed: bytes = self.bcrypt.hashpw(encoded_string, self.bcrypt.gensalt(self.rounds))
        return self.algorithm + bcrypt_hashed.decode("ascii")

    def _parse_hash(self, hashed_string: str) -> dict[str, Any] | None:
        """Parse BCrypt hash format: algorithm$version$rounds$salt_hash."""
        parsed = SimpleHashParser.parse_dollar_separated(hashed_string, 2)
        if parsed:
            parts = parsed['parts']
            if len(parts) >= 3:
                # BCrypt format: version$rounds$salt_hash
                # parts[0] = version (e.g., '2b')
                # parts[1] = rounds (e.g., '12')
                # parts[2] = salt_hash
                return {
                    'algorithm': parsed['algorithm'],
                    'hashed_val': '$'.join(parts),
                    'rounds': int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
                }
        return None

    def _do_verify(self, string: str, parsed: dict[str, Any]) -> bool:
        """Verify using BCrypt algorithm."""
        encoded_string: bytes = string.encode()
        if self.digest is not None:
            encoded_string = self._get_hexdigest(string, self.digest)
        return cast(bool, self.bcrypt.checkpw(encoded_string, ('$' + parsed['hashed_val']).encode('ascii')))

    def _check_needs_rehash(self, parsed: dict[str, Any]) -> bool:
        """Check if rounds count has changed."""
        return parsed.get('rounds') != self.rounds if parsed.get('rounds') is not None else False

    @staticmethod
    def _get_hexdigest(_string: str, digest: Callable[[bytes], Any]) -> bytes:
        """Generate hexadecimal digest for a string."""
        return binascii.hexlify(digest(_string.encode()).digest())


class BCryptHasher(BCryptSha256Hasher):
    algorithm = 'bcrypt'
    digest = None
