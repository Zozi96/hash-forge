import base64
import hashlib
import hmac
import secrets
from typing import ClassVar

from hash_forge.config.settings import (
    DEFAULT_SCRYPT_MAX_N,
    DEFAULT_SCRYPT_MAX_P,
    DEFAULT_SCRYPT_MAX_R,
    DEFAULT_SCRYPT_N,
    DEFAULT_SCRYPT_P,
    DEFAULT_SCRYPT_R,
    MIN_SCRYPT_N,
    MIN_SCRYPT_P,
    MIN_SCRYPT_R,
)
from hash_forge.core.protocols import PHasher
from hash_forge.exceptions import InvalidHasherError


class ScryptHasher(PHasher):
    algorithm: ClassVar[str] = "scrypt"

    def __init__(
        self,
        work_factor: int = DEFAULT_SCRYPT_N,
        block_size: int = DEFAULT_SCRYPT_R,
        parallelism: int = DEFAULT_SCRYPT_P,
        maxmem: int = 0,
        dklen: int = 64,
        salt_length: int = 16,
        max_work_factor: int = DEFAULT_SCRYPT_MAX_N,
        max_block_size: int = DEFAULT_SCRYPT_MAX_R,
        max_parallelism: int = DEFAULT_SCRYPT_MAX_P,
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
        self._validate_params(work_factor, block_size, parallelism, max_work_factor, max_block_size, max_parallelism)
        if dklen <= 0:
            raise InvalidHasherError("Scrypt dklen must be positive")
        if salt_length <= 0:
            raise InvalidHasherError("Scrypt salt_length must be positive")
        self.work_factor = work_factor
        self.block_size = block_size
        self.parallelism = parallelism
        self.maxmem = maxmem
        self.dklen = dklen
        self.salt_length = salt_length
        self.max_work_factor = max_work_factor
        self.max_block_size = max_block_size
        self.max_parallelism = max_parallelism

    __slots__ = (
        "work_factor",
        "block_size",
        "parallelism",
        "maxmem",
        "dklen",
        "salt_length",
        "max_work_factor",
        "max_block_size",
        "max_parallelism",
    )

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
            maxmem=self._effective_maxmem(self.work_factor, self.block_size, self.parallelism),
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
        try:
            parts = _hashed_string.split("$", 5)
            if len(parts) != 6:
                return False
            _, n_str, salt, r_str, p_str, stored_hash = parts
            n, r, p = int(n_str), int(r_str), int(p_str)
            self._validate_stored_params(n, r, p)
            hashed = hashlib.scrypt(
                _string.encode(),
                salt=salt.encode(),
                n=n,
                r=r,
                p=p,
                maxmem=self._effective_maxmem(n, r, p),
                dklen=self.dklen,
            )
            computed = base64.b64encode(hashed).decode("ascii").strip()
            return hmac.compare_digest(stored_hash, computed)
        except (ValueError, TypeError):
            return False

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
        try:
            _, n, _, r, p, _ = _hashed_string.split("$", 5)
            n_int, r_int, p_int = int(n), int(r), int(p)
            self._validate_stored_params(n_int, r_int, p_int)
            return n_int != self.work_factor or r_int != self.block_size or p_int != self.parallelism
        except (ValueError, TypeError):
            return False

    def generate_salt(self) -> str:
        """
        Generates a cryptographic salt.

        Returns:
            str: A string representing the generated salt.
        """
        return base64.b64encode(secrets.token_bytes(self.salt_length)).decode("ascii")

    @staticmethod
    def _is_power_of_two(value: int) -> bool:
        return value > 0 and (value & (value - 1)) == 0

    @classmethod
    def _validate_params(
        cls,
        work_factor: int,
        block_size: int,
        parallelism: int,
        max_work_factor: int,
        max_block_size: int,
        max_parallelism: int,
    ) -> None:
        if not cls._is_power_of_two(work_factor):
            raise InvalidHasherError("Scrypt work_factor must be a power of two")
        if work_factor < MIN_SCRYPT_N:
            raise InvalidHasherError(f"Scrypt work_factor must be at least {MIN_SCRYPT_N}")
        if block_size < MIN_SCRYPT_R:
            raise InvalidHasherError(f"Scrypt block_size must be at least {MIN_SCRYPT_R}")
        if parallelism < MIN_SCRYPT_P:
            raise InvalidHasherError(f"Scrypt parallelism must be at least {MIN_SCRYPT_P}")
        if max_work_factor < work_factor or max_block_size < block_size or max_parallelism < parallelism:
            raise InvalidHasherError("Scrypt verification caps must be at least configured hash parameters")

    def _validate_stored_params(self, work_factor: int, block_size: int, parallelism: int) -> None:
        if not self._is_power_of_two(work_factor):
            raise ValueError("stored scrypt work_factor must be a power of two")
        if (
            work_factor < MIN_SCRYPT_N
            or block_size < MIN_SCRYPT_R
            or parallelism < MIN_SCRYPT_P
            or work_factor > self.max_work_factor
            or block_size > self.max_block_size
            or parallelism > self.max_parallelism
        ):
            raise ValueError("stored scrypt parameters outside verification bounds")

    def _effective_maxmem(self, work_factor: int, block_size: int, parallelism: int) -> int:
        if self.maxmem > 0:
            return self.maxmem
        return 256 * work_factor * block_size * parallelism
