"""Base hasher with Template Method pattern to reduce code duplication."""
from abc import abstractmethod
from contextlib import suppress
from typing import Any, ClassVar

from hash_forge.config.logging import get_logger
from hash_forge.core.protocols import PHasher

logger = get_logger('base_hasher')


class BaseHasher(PHasher):
    """Base hasher implementing common functionality using Template Method pattern.

    This class provides default implementations for common operations like
    error handling, parsing, and logging. Subclasses only need to implement
    the core hashing logic.
    """

    algorithm: ClassVar[str]
    library_module: ClassVar[str | None] = None

    def hash(self, _string: str, /) -> str:
        """Hash a string using the specific algorithm.

        Args:
            _string: The string to hash

        Returns:
            The hashed string with algorithm prefix
        """
        try:
            hashed = self._do_hash(_string)
            logger.debug(f"Successfully hashed string using {self.algorithm}")
            return hashed
        except Exception as e:
            logger.error(f"Failed to hash string with {self.algorithm}: {e}")
            raise

    def verify(self, _string: str, _hashed_string: str, /) -> bool:
        """Verify if a string matches a hashed string.

        Args:
            _string: The plain string to verify
            _hashed_string: The hashed string to compare against

        Returns:
            True if the string matches, False otherwise
        """
        try:
            # Parse the hash components
            parsed = self._parse_hash(_hashed_string)
            if parsed is None:
                logger.debug(f"Failed to parse hash with {self.algorithm}")
                return False

            # Verify algorithm matches
            if not self._verify_algorithm(parsed):
                logger.debug(f"Algorithm mismatch for {self.algorithm}")
                return False

            # Perform actual verification
            result = self._do_verify(_string, parsed)
            logger.debug(f"Verification {'succeeded' if result else 'failed'} for {self.algorithm}")
            return result

        except Exception as e:
            logger.debug(f"Verification error with {self.algorithm}: {e}")
            return False

    def needs_rehash(self, _hashed_string: str, /) -> bool:
        """Check if a hashed string needs to be rehashed.

        Args:
            _hashed_string: The hashed string to check

        Returns:
            True if rehashing is needed, False otherwise
        """
        try:
            parsed = self._parse_hash(_hashed_string)
            if parsed is None:
                return False

            if not self._verify_algorithm(parsed):
                return False

            needs_rehash = self._check_needs_rehash(parsed)
            if needs_rehash:
                logger.info(f"Hash needs rehashing with {self.algorithm}")
            return needs_rehash

        except Exception as e:
            logger.debug(f"Error checking rehash for {self.algorithm}: {e}")
            return False

    @abstractmethod
    def _do_hash(self, string: str) -> str:
        """Perform the actual hashing operation.

        Args:
            string: The string to hash

        Returns:
            The hashed string with algorithm prefix
        """
        raise NotImplementedError

    @abstractmethod
    def _parse_hash(self, hashed_string: str) -> dict[str, Any] | None:
        """Parse a hashed string into its components.

        Args:
            hashed_string: The hashed string to parse

        Returns:
            A dictionary of parsed components or None if parsing fails
        """
        raise NotImplementedError

    @abstractmethod
    def _do_verify(self, string: str, parsed: dict[str, Any]) -> bool:
        """Perform the actual verification operation.

        Args:
            string: The plain string to verify
            parsed: The parsed hash components

        Returns:
            True if verification succeeds, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    def _check_needs_rehash(self, parsed: dict[str, Any]) -> bool:
        """Check if the parsed hash needs rehashing.

        Args:
            parsed: The parsed hash components

        Returns:
            True if rehashing is needed, False otherwise
        """
        raise NotImplementedError

    def _verify_algorithm(self, parsed: dict[str, Any]) -> bool:
        """Verify the algorithm in the parsed hash matches this hasher.

        Args:
            parsed: The parsed hash components

        Returns:
            True if algorithm matches, False otherwise
        """
        return parsed.get('algorithm') == self.algorithm


class SimpleHashParser:
    """Utility class for parsing standard hash formats."""

    @staticmethod
    def parse_dollar_separated(hashed_string: str, expected_parts: int) -> dict[str, Any] | None:
        """Parse a dollar-separated hash string.

        Args:
            hashed_string: The hash string to parse
            expected_parts: Minimum number of expected parts

        Returns:
            Dictionary with 'algorithm' and 'parts' keys, or None if parsing fails
        """
        with suppress(ValueError, IndexError):
            parts = hashed_string.split('$')
            if len(parts) >= expected_parts:
                return {
                    'algorithm': parts[0],
                    'parts': parts[1:]
                }
        return None
