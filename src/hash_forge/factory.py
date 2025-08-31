"""Factory for creating hashers."""
from typing import Any

from hash_forge.exceptions import UnsupportedAlgorithmError
from hash_forge.protocols import PHasher
from hash_forge.types import AlgorithmType


class HasherFactory:
    """Factory class for creating hasher instances."""
    
    _registry: dict[str, type[PHasher]] = {}
    
    @classmethod
    def register(cls, algorithm: AlgorithmType, hasher_class: type[PHasher]) -> None:
        """Register a hasher class for a specific algorithm.
        
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
    def list_algorithms(cls) -> list[AlgorithmType]:
        """List all registered algorithms.
        
        Returns:
            A list of supported algorithm names
        """
        return list(cls._registry.keys())


def register_default_hashers() -> None:
    """Register all default hashers with the factory."""
    try:
        from hash_forge.hashers.pbkdf2_hasher import PBKDF2Sha1Hasher, PBKDF2Sha256Hasher
        HasherFactory.register('pbkdf2_sha256', PBKDF2Sha256Hasher)
        HasherFactory.register('pbkdf2_sha1', PBKDF2Sha1Hasher)
    except ImportError:
        pass
    
    try:
        from hash_forge.hashers.bcrypt_hasher import BCryptHasher, BCryptSha256Hasher
        HasherFactory.register('bcrypt', BCryptHasher)
        HasherFactory.register('bcrypt_sha256', BCryptSha256Hasher)
    except ImportError:
        pass
    
    try:
        from hash_forge.hashers.argon2_hasher import Argon2Hasher
        HasherFactory.register('argon2', Argon2Hasher)
    except ImportError:
        pass
    
    try:
        from hash_forge.hashers.scrypt_hasher import ScryptHasher
        HasherFactory.register('scrypt', ScryptHasher)
    except ImportError:
        pass
    
    try:
        from hash_forge.hashers.blake2_hasher import Blake2Hasher
        HasherFactory.register('blake2', Blake2Hasher)
    except ImportError:
        pass
    
    try:
        from hash_forge.hashers.blake3_hasher import Blake3Hasher
        HasherFactory.register('blake3', Blake3Hasher)
    except ImportError:
        pass
    
    try:
        from hash_forge.hashers.whirlpool_hasher import WhirlpoolHasher
        HasherFactory.register('whirlpool', WhirlpoolHasher)
    except ImportError:
        pass
    
    try:
        from hash_forge.hashers.ripemd160_hasher import Ripemd160Hasher
        HasherFactory.register('ripemd160', Ripemd160Hasher)
    except ImportError:
        pass


# Register default hashers on import
register_default_hashers()