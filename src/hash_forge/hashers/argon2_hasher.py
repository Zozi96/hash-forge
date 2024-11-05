from functools import partial
from contextlib import suppress
from typing import ClassVar, cast, Any

from hash_forge.protocols import PHasher


class Argon2Hasher(PHasher):
    algorithm: ClassVar[str] = 'argon2'
    library_module: ClassVar[str] = 'argon2'

    def __init__(
        self,
        time_cost: int | None = None,
        salt_len: int | None = None,
        memory_cost: int | None = None,
        parallelism: int | None = None,
        hash_len: int | None = None,
    ) -> None:
        """
        Initialize the Argon2Hasher with optional parameters for hashing configuration.

        Args:
            time_cost (int | None): The time cost parameter for Argon2. Defaults to None.
            salt_len (int | None): The length of the salt. Defaults to None.
            memory_cost (int | None): The memory cost parameter for Argon2. Defaults to None.
            parallelism (int | None): The degree of parallelism for Argon2. Defaults to None.
            hash_len (int | None): The length of the resulting hash. Defaults to None.
        """
        self.argon2 = self.load_library(self.library_module)
        self.time_cost = time_cost
        self.memory_cost = memory_cost
        self.parallelism = parallelism
        self.hash_len = hash_len
        self.salt_len = salt_len
        self.ph = self._get_hasher()

    __slots__ = ('argon2', 'time_cost', 'memory_cost', 'parallelism', 'hash_len', 'salt_len')

    def hash(self, _string: str, /) -> str:
        """
        Hashes the given string using Argon2 algorithm.

        Args:
            _string (str): The string to be hashed.

        Returns:
            str: The formatted hash string containing the algorithm, time cost, memory cost, parallelism, salt, and hashed value.
        """

        return self.algorithm + cast(str, self.ph.hash(_string))

    def verify(self, _string: str, _hashed_string: str, /) -> bool:
        """
        Verifies if a given string matches the provided hashed string using Argon2.

        Args:
            _string (str): The plain string to verify.
            _hashed_string (str): The hashed string to compare against.

        Returns:
            bool: True if the string matches the hashed string, False otherwise.
        """
        with suppress(self.argon2.exceptions.VerifyMismatchError, self.argon2.exceptions.InvalidHash, Exception):
            _, _hashed_string = _hashed_string.split('$', 1)
            return cast(bool, self.ph.verify('$' + _hashed_string, _string))
        return False

    def needs_rehash(self, _hashed_string: str, /) -> bool:
        """
        Determines if the given hashed string needs to be rehashed based on the current time cost.

        Args:
            _hashed_string (str): The hashed string to check.

        Returns:
            bool: True if the hashed string needs to be rehashed, False otherwise.
        """
        with suppress(self.argon2.exceptions.InvalidHash, Exception):
            _, _hashed_string = _hashed_string.split('$', 1)
            return cast(bool, self.ph.check_needs_rehash('$' + _hashed_string))
        return False

    def _get_hasher(self) -> Any:
        """
        Creates and returns a configured instance of argon2.PasswordHasher.

        This method uses the provided configuration parameters to set up the
        PasswordHasher instance. The parameters that can be configured are:
        - time_cost: The time cost parameter for the Argon2 algorithm.
        - memory_cost: The memory cost parameter for the Argon2 algorithm.
        - parallelism: The parallelism parameter for the Argon2 algorithm.
        - hash_len: The length of the generated hash.
        - salt_len: The length of the salt.

        Returns:
            argon2.PasswordHasher: A configured instance of the PasswordHasher.
        """
        hasher_partial = partial(self.argon2.PasswordHasher)
        if self.time_cost:
            hasher_partial.keywords['time_cost'] = self.time_cost
        if self.memory_cost:
            hasher_partial.keywords['memory_cost'] = self.memory_cost
        if self.parallelism:
            hasher_partial.keywords['parallelism'] = self.parallelism
        if self.hash_len:
            hasher_partial.keywords['hash_len'] = self.hash_len
        if self.salt_len:
            hasher_partial.keywords['salt_len'] = self.salt_len
        return hasher_partial()
