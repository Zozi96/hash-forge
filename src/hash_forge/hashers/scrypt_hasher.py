import base64
import hashlib
import hmac
import secrets
from functools import lru_cache
from typing import ClassVar

from hash_forge.protocols import PHasher


@lru_cache
def _generate_salt(salt: int) -> str:
    """
    Generates a base64-encoded salt string.

    Args:
        salt (int): The number of bytes to generate for the salt.

    Returns:
        str: A base64-encoded string representation of the generated salt.
    """
    return base64.b64encode(secrets.token_bytes(salt)).decode("ascii")


class ScryptHasher(PHasher):
    algorithm: ClassVar[str] = "scrypt"

    def __init__(
        self,
        work_factor: int = 2**14,
        block_size: int = 8,
        parallelism: int = 5,
        maxmem: int = 0,
        dklen: int = 64,
        salt_length: int = 16,
    ) -> None:
        """
        Initialize the ScryptHasher with the given parameters.

        Args:
            work_factor (int): The CPU/memory cost parameter. Default is 2**14.
            block_size (int): The block size parameter. Default is 8.
            parallelism (int): The parallelization parameter. Default is 5.
            maxmem (int): The maximum memory to use in bytes. Default is 0 (no limit).
            dklen (int): The length of the derived key. Default is 64.
            salt_length (int): The length of the salt. Default is 16.
        """
        self.work_factor = work_factor
        self.block_size = block_size
        self.parallelism = parallelism
        self.maxmem = maxmem
        self.dklen = dklen
        self.salt_length = salt_length

    __slots__ = ("work_factor", "block_size", "parallelism", "maxmem", "dklen", "salt_length")

    def hash(self, _string: str) -> str:
        """
        Hashes the given string using the scrypt algorithm.

        Args:
            _string (str): The input string to be hashed.

        Returns:
            str: The hashed string in the format 'algorithm$work_factor$salt$block_size$parallelism$hashed_value'.
        """
        salt = self.generate_salt()
        hashed = hashlib.scrypt(
            _string.encode(),
            salt=salt.encode(),
            n=self.work_factor,
            r=self.block_size,
            p=self.parallelism,
            maxmem=self.maxmem,
            dklen=self.dklen,
        )
        hashed_string = base64.b64encode(hashed).decode("ascii").strip()
        return f"{self.algorithm}${self.work_factor}${salt}${self.block_size}${self.parallelism}${hashed_string}"

    def verify(self, _string: str, _hashed_string: str) -> bool:
        """
        Verify if a given string matches the hashed string.

        Args:
            _string (str): The original string to verify.
            _hashed_string (str): The hashed string to compare against.

        Returns:
            bool: True if the original string matches the hashed string, False otherwise.
        """
        encoded = self.hash(_string)
        return hmac.compare_digest(_hashed_string, encoded)

    def needs_rehash(self, _hashed_string: str) -> bool:
        """
        Determines if the given hashed string needs to be rehashed based on the current
        work factor, block size, and parallelism parameters.

        Args:
            _hashed_string (str): The hashed string to check, expected to be in the format
                                  "$<prefix>$<n>$<r>$<p>$<hash>".

        Returns:
            bool: True if the hashed string needs to be rehashed, False otherwise.
        """
        _, n, _, r, p, _ = _hashed_string.split("$", 5)
        return int(n) != self.work_factor or int(r) != self.block_size or int(p) != self.parallelism

    def generate_salt(self) -> str:
        """
        Generates a cryptographic salt.

        Returns:
            str: A string representing the generated salt.
        """
        return _generate_salt(self.salt_length)
