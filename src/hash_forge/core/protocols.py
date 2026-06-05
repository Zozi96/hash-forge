import importlib
from abc import abstractmethod
from types import ModuleType
from typing import ClassVar, Protocol

EXTRA_BY_MODULE: dict[str, str] = {
    "argon2": "argon2",
    "bcrypt": "bcrypt",
    "blake3": "blake3",
    "Crypto.Hash.RIPEMD160": "crypto",
    "Crypto.Hash.SHA512": "crypto",
}


def get_algorithm_token(hashed_string: str) -> str | None:
    """Return the exact algorithm token from a dollar-delimited hash."""
    algorithm, separator, _ = hashed_string.partition("$")
    if not separator or not algorithm:
        return None
    return algorithm


class PHasher(Protocol):
    algorithm: ClassVar[str]
    library_module: ClassVar[str | None] = None

    def can_handle(self, hashed_string: str) -> bool:
        """
        Check if this hasher can handle the given hashed string.

        Args:
            hashed_string: The hashed string to check

        Returns:
            bool: True if this hasher can handle the hash, False otherwise
        """
        return get_algorithm_token(hashed_string) == self.algorithm

    @abstractmethod
    def hash(self, _string: str, /) -> str:
        """
        Computes the hash of the given string.

        Args:
            _string (str): The input string to be hashed.

        Returns:
            str: The resulting hash as a string.

        Raises:
            NotImplementedError: This method should be implemented by subclasses.
        """
        raise NotImplementedError

    @abstractmethod
    def verify(self, _string: str, _hashed_string: str, /) -> bool:
        """
        Verify if the provided string matches the hashed string.

        Args:
            _string (str): The original string to verify.
            _hashed_string (str): The hashed string to compare against.

        Returns:
            bool: True if the original string matches the hashed string, False otherwise.

        Raises:
            NotImplementedError: This method should be implemented by subclasses.
        """
        raise NotImplementedError

    @abstractmethod
    def needs_rehash(self, _hashed_string: str, /) -> bool:
        """
        Determine if a hashed string needs to be rehashed.

        Args:
            _hashed_string (str): The hashed string to check.

        Returns:
            bool: True if the hashed string needs to be rehashed, False otherwise.

        Raises:
            NotImplementedError: This method should be implemented by subclasses.
        """
        raise NotImplementedError

    def load_library(self, name: str) -> ModuleType:
        """
        Loads a library module by its name.

        This function attempts to import a module specified by the `name` parameter.
        If the module is not found, it raises an ImportError with a message indicating
        the required third-party library to install.

        Args:
            name (str): The name of the module to import.

        Returns:
            ModuleType: The imported module.

        Raises:
            ImportError: If the module cannot be imported, with a message suggesting
                        the required third-party library to install.
        """
        try:
            return importlib.import_module(name=name)
        except ImportError:
            extra = EXTRA_BY_MODULE.get(name, name)
            raise ImportError(
                f"{name} is not installed. Please install hash-forge[{extra}] to use this hasher."
            ) from None
