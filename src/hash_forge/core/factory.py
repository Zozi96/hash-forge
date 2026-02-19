"""Factory for creating hashers."""

from collections.abc import Sequence
from typing import Any, TypeVar, cast

from hash_forge.core.protocols import PHasher
from hash_forge.exceptions import UnsupportedAlgorithmError
from hash_forge.types import AlgorithmType

T = TypeVar("T", bound=type[PHasher])


class HasherFactory:
    """Factory class for creating hasher instances."""

    _registry: dict[str, type[PHasher]] = {}

    @classmethod
    def register(cls, algorithm: AlgorithmType) -> Any:
        """Decorator to register a hasher class for a specific algorithm.

        Args:
            algorithm: The algorithm name to register

        Returns:
            Decorator function that registers the hasher class

        Example:
            @HasherFactory.register('pbkdf2_sha256')
            class PBKDF2Sha256Hasher(PHasher):
                ...
        """

        def decorator(hasher_class: T) -> T:
            cls._registry[algorithm] = hasher_class
            return hasher_class

        return decorator

    @classmethod
    def register_class(cls, algorithm: AlgorithmType, hasher_class: type[PHasher]) -> None:
        """Register a hasher class for a specific algorithm (functional style).

        Args:
            algorithm: The algorithm name to register
            hasher_class: The hasher class to associate with the algorithm
        """
        cls._registry[algorithm] = hasher_class

    @classmethod
    def create(cls, algorithm: AlgorithmType, **kwargs: Any) -> PHasher:
        """Create a hasher instance for the specified algorithm.

        Args:
            algorithm: The algorithm name
            **kwargs: Additional arguments to pass to the hasher constructor

        Returns:
            A hasher instance

        Raises:
            UnsupportedAlgorithmError: If the algorithm is not supported
        """
        if algorithm not in cls._registry:
            raise UnsupportedAlgorithmError(f"Algorithm '{algorithm}' is not supported")

        hasher_class = cls._registry[algorithm]
        return hasher_class(**kwargs)

    @classmethod
    def list_algorithms(cls) -> Sequence[AlgorithmType]:
        """List all registered algorithms.

        Returns:
            A sequence of supported algorithm names
        """
        return cast(Sequence[AlgorithmType], list(cls._registry.keys()))


def register_default_hashers() -> None:
    """Register all default hashers with the factory using auto-discovery."""
    hasher_imports = [
        ("hash_forge.hashers.pbkdf2_hasher", ["PBKDF2Sha256Hasher", "PBKDF2Sha1Hasher"]),
        ("hash_forge.hashers.bcrypt_hasher", ["BCryptHasher", "BCryptSha256Hasher"]),
        ("hash_forge.hashers.argon2_hasher", ["Argon2Hasher"]),
        ("hash_forge.hashers.scrypt_hasher", ["ScryptHasher"]),
        ("hash_forge.hashers.blake2_hasher", ["Blake2Hasher"]),
        ("hash_forge.hashers.blake3_hasher", ["Blake3Hasher"]),
        ("hash_forge.hashers.whirlpool_hasher", ["WhirlpoolHasher"]),
        ("hash_forge.hashers.ripemd160_hasher", ["Ripemd160Hasher"]),
        ("hash_forge.hashers.sha3_hasher", ["SHA3_256Hasher", "SHA3_512Hasher"]),
    ]

    for module_path, hasher_classes in hasher_imports:
        try:
            module = __import__(module_path, fromlist=hasher_classes)
            for hasher_name in hasher_classes:
                hasher_class = getattr(module, hasher_name)
                # Auto-register using the hasher's algorithm attribute
                if hasattr(hasher_class, "algorithm"):
                    HasherFactory.register_class(hasher_class.algorithm, hasher_class)
        except ImportError:
            # Silently skip if optional dependencies are not installed
            pass


# Register default hashers on import
register_default_hashers()
