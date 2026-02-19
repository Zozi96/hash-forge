"""Async support for HashManager operations."""
import asyncio
from typing import TYPE_CHECKING

from hash_forge.config.logging import get_logger

if TYPE_CHECKING:
    from hash_forge.core.protocols import PHasher

logger = get_logger('async_manager')


class AsyncHashMixin:
    """Mixin to add async support to HashManager.

    This mixin provides async versions of hash, verify, and needs_rehash
    methods that run the synchronous operations in a thread pool executor.

    Note: This mixin expects the following attributes/methods from the mixing class:
        - hash(string: str) -> str
        - verify(string: str, hashed_string: str) -> bool
        - needs_rehash(hashed_string: str) -> bool
        - preferred_hasher: PHasher
    """

    if TYPE_CHECKING:
        # Type hints for attributes that will be provided by HashManager
        preferred_hasher: "PHasher"

        def hash(self, string: str) -> str: ...
        def verify(self, string: str, hashed_string: str) -> bool: ...
        def needs_rehash(self, hashed_string: str) -> bool: ...

    async def hash_async(self, string: str) -> str:
        """
        Asynchronously hash a string using the preferred hasher.

        This method runs the synchronous hash operation in a thread pool
        to avoid blocking the event loop.

        Args:
            string: The string to be hashed

        Returns:
            str: The hashed string

        Example:
            hash_manager = HashManager.from_algorithms("argon2")
            hashed = await hash_manager.hash_async("my_password")
        """
        loop = asyncio.get_running_loop()
        logger.debug(f"Async hashing with {self.preferred_hasher.algorithm}")
        return await loop.run_in_executor(None, self.hash, string)

    async def verify_async(self, string: str, hashed_string: str) -> bool:
        """
        Asynchronously verify if a string matches a hashed string.

        This method runs the synchronous verify operation in a thread pool
        to avoid blocking the event loop.

        Args:
            string: The plain text string to verify
            hashed_string: The hashed string to compare against

        Returns:
            bool: True if the string matches the hashed string, False otherwise

        Example:
            is_valid = await hash_manager.verify_async("my_password", hashed)
        """
        loop = asyncio.get_running_loop()
        logger.debug("Async verification")
        return await loop.run_in_executor(None, self.verify, string, hashed_string)

    async def needs_rehash_async(self, hashed_string: str) -> bool:
        """
        Asynchronously check if a hashed string needs to be rehashed.

        This method runs the synchronous needs_rehash operation in a thread pool
        to avoid blocking the event loop.

        Args:
            hashed_string: The hashed string to check

        Returns:
            bool: True if the hashed string needs to be rehashed, False otherwise

        Example:
            needs_update = await hash_manager.needs_rehash_async(hashed)
        """
        loop = asyncio.get_running_loop()
        logger.debug("Async rehash check")
        return await loop.run_in_executor(None, self.needs_rehash, hashed_string)

    async def hash_many_async(self, strings: list[str]) -> list[str]:
        """
        Asynchronously hash multiple strings concurrently.

        Args:
            strings: List of strings to hash

        Returns:
            list[str]: List of hashed strings in the same order

        Example:
            hashes = await hash_manager.hash_many_async(["pass1", "pass2", "pass3"])
        """
        logger.info(f"Async hashing {len(strings)} strings concurrently")
        tasks = [self.hash_async(s) for s in strings]
        return await asyncio.gather(*tasks)

    async def verify_many_async(
        self,
        pairs: list[tuple[str, str]]
    ) -> list[bool]:
        """
        Asynchronously verify multiple string-hash pairs concurrently.

        Args:
            pairs: List of (string, hashed_string) tuples to verify

        Returns:
            list[bool]: List of verification results in the same order

        Example:
            results = await hash_manager.verify_many_async([
                ("pass1", hash1),
                ("pass2", hash2),
            ])
        """
        logger.info(f"Async verifying {len(pairs)} pairs concurrently")
        tasks = [self.verify_async(string, hashed) for string, hashed in pairs]
        return await asyncio.gather(*tasks)
