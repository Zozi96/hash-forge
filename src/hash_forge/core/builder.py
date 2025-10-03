"""Builder pattern for HashManager configuration."""
from typing import Any

from hash_forge.core.factory import HasherFactory
from hash_forge.core.protocols import PHasher
from hash_forge.types import AlgorithmType


class HashManagerBuilder:
    """Builder for creating HashManager instances with fluent API.

    Example:
        hash_manager = (
            HashManagerBuilder()
            .with_algorithm("argon2", time_cost=4)
            .with_algorithm("bcrypt", rounds=14)
            .with_preferred("argon2")
            .build()
        )
    """

    def __init__(self) -> None:
        """Initialize the builder."""
        self._hashers: list[tuple[str, PHasher]] = []
        self._preferred_algorithm: str | None = None

    def with_algorithm(self, algorithm: AlgorithmType, **kwargs: Any) -> "HashManagerBuilder":
        """Add an algorithm with optional configuration.

        Args:
            algorithm: The algorithm to add
            **kwargs: Algorithm-specific configuration parameters

        Returns:
            Self for method chaining
        """
        hasher = HasherFactory.create(algorithm, **kwargs)
        self._hashers.append((algorithm, hasher))
        return self

    def with_hasher(self, hasher: PHasher) -> "HashManagerBuilder":
        """Add a pre-configured hasher instance.

        Args:
            hasher: The hasher instance to add

        Returns:
            Self for method chaining
        """
        self._hashers.append((hasher.algorithm, hasher))
        return self

    def with_preferred(self, algorithm: AlgorithmType) -> "HashManagerBuilder":
        """Set the preferred algorithm for hashing.

        Args:
            algorithm: The algorithm to use as preferred

        Returns:
            Self for method chaining
        """
        self._preferred_algorithm = algorithm
        return self

    def build(self) -> Any:
        """Build the HashManager instance.

        Returns:
            A configured HashManager instance

        Raises:
            ValueError: If no hashers were added
        """
        # Import here to avoid circular dependency
        from hash_forge.core.manager import HashManager

        if not self._hashers:
            raise ValueError("At least one hasher must be added to the builder")

        # Reorder hashers to put preferred first
        hashers_dict = dict(self._hashers)

        if self._preferred_algorithm:
            if self._preferred_algorithm not in hashers_dict:
                raise ValueError(f"Preferred algorithm '{self._preferred_algorithm}' was not added to the builder")

            # Put preferred first
            ordered_hashers = [hashers_dict[self._preferred_algorithm]]
            ordered_hashers.extend([h for alg, h in hashers_dict.items() if alg != self._preferred_algorithm])
        else:
            # Use the order they were added
            ordered_hashers = [h for _, h in self._hashers]

        return HashManager(*ordered_hashers)
