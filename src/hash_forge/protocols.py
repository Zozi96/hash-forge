import importlib

from types import ModuleType
from typing import Protocol
from abc import abstractmethod


class PHasher(Protocol):
    algorithm: str
    library_module: str | None = None

    @abstractmethod
    def hash(self, _string: str, /) -> str:
        raise NotImplementedError

    @abstractmethod
    def verify(self, _string: str, _hashed_string: str, /) -> bool:
        raise NotImplementedError

    @abstractmethod
    def needs_rehash(self, _hashed_string: str, /) -> bool:
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
            raise ImportError(
                f'{name} is not installed. Please install {name} to use this hasher. (pip install hash-forge[{name}])'
            )
