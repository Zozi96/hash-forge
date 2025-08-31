"""Custom exceptions for Hash Forge library."""


class HashForgeError(Exception):
    """Base exception for Hash Forge library."""
    pass


class InvalidHasherError(HashForgeError):
    """Raised when an invalid hasher is provided."""
    pass


class InvalidHashFormatError(HashForgeError):
    """Raised when a hash string has an invalid format."""
    pass


class UnsupportedAlgorithmError(HashForgeError):
    """Raised when an unsupported algorithm is requested."""
    pass


class HasherNotFoundError(HashForgeError):
    """Raised when no hasher is found for a given hash."""
    pass