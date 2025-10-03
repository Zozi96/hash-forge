"""Tests for high priority architecture improvements."""
import pytest

from hash_forge import HashManager
from hash_forge.core.factory import HasherFactory
from hash_forge.hashers import PBKDF2Sha256Hasher


class TestBuilderPattern:
    """Test the Builder pattern implementation."""

    def test_builder_basic_usage(self) -> None:
        """Test basic builder usage."""
        hash_manager = (
            HashManager.builder()
            .with_algorithm("pbkdf2_sha256")
            .with_algorithm("bcrypt")
            .build()
        )

        assert hash_manager is not None
        assert len(hash_manager.hasher_map) == 2
        assert hash_manager.preferred_hasher.algorithm == "pbkdf2_sha256"

    def test_builder_with_custom_params(self) -> None:
        """Test builder with custom parameters."""
        hash_manager = (
            HashManager.builder()
            .with_algorithm("pbkdf2_sha256", iterations=200_000)
            .with_algorithm("bcrypt", rounds=14)
            .build()
        )

        # Hash and verify
        password = "test_password"
        hashed = hash_manager.hash(password)
        assert hash_manager.verify(password, hashed)

    def test_builder_with_preferred_algorithm(self) -> None:
        """Test builder with preferred algorithm setting."""
        hash_manager = (
            HashManager.builder()
            .with_algorithm("pbkdf2_sha256")
            .with_algorithm("bcrypt")
            .with_preferred("bcrypt")
            .build()
        )

        assert hash_manager.preferred_hasher.algorithm == "bcrypt"

    def test_builder_with_hasher_instance(self) -> None:
        """Test builder with pre-configured hasher instances."""
        custom_hasher = PBKDF2Sha256Hasher(iterations=300_000)

        hash_manager = (
            HashManager.builder()
            .with_hasher(custom_hasher)
            .with_algorithm("bcrypt")
            .build()
        )

        assert hash_manager.preferred_hasher.iterations == 300_000

    def test_builder_empty_raises_error(self) -> None:
        """Test that building without hashers raises an error."""
        with pytest.raises(ValueError, match="At least one hasher must be added"):
            HashManager.builder().build()

    def test_builder_invalid_preferred_raises_error(self) -> None:
        """Test that setting invalid preferred algorithm raises an error."""
        with pytest.raises(ValueError, match="Preferred algorithm.*was not added"):
            (
                HashManager.builder()
                .with_algorithm("pbkdf2_sha256")
                .with_preferred("argon2")
                .build()
            )


class TestAutoRegistration:
    """Test the auto-registration decorator system."""

    def test_decorator_registration(self) -> None:
        """Test that hashers can be registered using decorator."""
        # The decorator is already being used in the factory
        # Let's verify it works by checking registered algorithms
        algorithms = HasherFactory.list_algorithms()

        assert "pbkdf2_sha256" in algorithms
        assert "bcrypt" in algorithms
        assert "argon2" in algorithms

    def test_create_from_registered(self) -> None:
        """Test creating hashers from registered algorithms."""
        from hash_forge.hashers.pbkdf2_hasher import PBKDF2Sha256Hasher

        hasher = HasherFactory.create("pbkdf2_sha256", iterations=150_000)

        assert hasher.algorithm == "pbkdf2_sha256"
        assert isinstance(hasher, PBKDF2Sha256Hasher)
        assert hasher.iterations == 150_000


class TestTemplateMethodPattern:
    """Test the Template Method pattern in BaseHasher."""

    def test_base_hasher_error_handling(self) -> None:
        """Test that base hasher handles errors gracefully."""
        hasher = PBKDF2Sha256Hasher()

        # Verify with invalid format should return False, not raise
        assert hasher.verify("test", "invalid_format") is False

        # needs_rehash with invalid format should return False
        assert hasher.needs_rehash("invalid_format") is False

    def test_base_hasher_algorithm_mismatch(self) -> None:
        """Test algorithm mismatch in verification."""
        hasher = PBKDF2Sha256Hasher()

        # Create a hash with wrong algorithm prefix
        fake_hash = "pbkdf2_sha1$150000$salt$hash"

        assert hasher.verify("test", fake_hash) is False


class TestLogging:
    """Test logging infrastructure."""

    def test_logging_import(self) -> None:
        """Test that logging module can be imported."""
        from hash_forge.config.logging import get_logger

        logger = get_logger("test")
        assert logger is not None
        assert logger.name == "hash_forge.test"

    def test_configure_logging(self) -> None:
        """Test logging configuration."""
        import logging

        from hash_forge.config.logging import configure_logging

        configure_logging(logging.DEBUG)
        logger = logging.getLogger("hash_forge")

        assert logger.level == logging.DEBUG


class TestIntegration:
    """Integration tests for all improvements."""

    def test_full_workflow_with_builder(self) -> None:
        """Test complete workflow using builder pattern."""
        # Create hash manager with builder
        hash_manager = (
            HashManager.builder()
            .with_algorithm("pbkdf2_sha256", iterations=200_000)
            .with_algorithm("bcrypt", rounds=12)
            .with_algorithm("argon2", time_cost=3)
            .with_preferred("argon2")
            .build()
        )

        # Hash password
        password = "secure_password_123"
        hashed = hash_manager.hash(password)

        # Verify it starts with preferred algorithm
        assert hashed.startswith("argon2")

        # Verify password
        assert hash_manager.verify(password, hashed)

        # Check needs rehash (should be False since we just hashed it)
        assert not hash_manager.needs_rehash(hashed)

    def test_mixed_builder_and_factory(self) -> None:
        """Test using builder with factory-created hashers."""
        pbkdf2 = HasherFactory.create("pbkdf2_sha256", iterations=180_000)

        hash_manager = (
            HashManager.builder()
            .with_hasher(pbkdf2)
            .with_algorithm("bcrypt")
            .build()
        )

        password = "test123"
        hashed = hash_manager.hash(password)

        assert hash_manager.verify(password, hashed)
