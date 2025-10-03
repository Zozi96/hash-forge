"""Tests for the new improvements in Hash Forge."""
import pytest

from hash_forge import AlgorithmType, HashManager
from hash_forge.core.factory import HasherFactory
from hash_forge.exceptions import InvalidHasherError, UnsupportedAlgorithmError
from hash_forge.hashers.pbkdf2_hasher import PBKDF2Sha256Hasher


class TestHashManagerImprovements:
    """Test the improvements to HashManager."""

    def test_invalid_hasher_error_on_empty_init(self):
        """Test that InvalidHasherError is raised when no hashers are provided."""
        with pytest.raises(InvalidHasherError, match="At least one hasher is required"):
            HashManager()

    def test_from_algorithms_creation(self):
        """Test creating HashManager from algorithm names."""
        hash_manager = HashManager.from_algorithms("pbkdf2_sha256", "pbkdf2_sha1")
        assert len(hash_manager.hashers) == 2
        assert "pbkdf2_sha256" in hash_manager.hasher_map
        assert "pbkdf2_sha1" in hash_manager.hasher_map

    def test_from_algorithms_with_invalid_algorithm(self):
        """Test that UnsupportedAlgorithmError is raised for invalid algorithms."""
        with pytest.raises(UnsupportedAlgorithmError, match="Algorithm 'invalid_algo' is not supported"):
            HashManager.from_algorithms("invalid_algo") # type: ignore

    def test_quick_hash(self):
        """Test the quick_hash static method."""
        hashed = HashManager.quick_hash("test_password")
        assert hashed.startswith("pbkdf2_sha256")
        
        # Test with different algorithm
        hashed_pbkdf2_sha1 = HashManager.quick_hash("test_password", algorithm="pbkdf2_sha1")
        assert hashed_pbkdf2_sha1.startswith("pbkdf2_sha1")

    def test_quick_hash_with_custom_params(self):
        """Test quick_hash with custom parameters."""
        hashed = HashManager.quick_hash("test_password", iterations=150000)
        assert hashed.startswith("pbkdf2_sha256")

    def test_hasher_map_performance(self):
        """Test that hasher lookup is optimized with the map."""
        hasher = PBKDF2Sha256Hasher()
        hash_manager = HashManager(hasher)
        
        # The hasher_map should provide direct access
        assert hash_manager.hasher_map["pbkdf2_sha256"] is hasher

    def test_verify_with_optimized_lookup(self):
        """Test that verification works with the optimized lookup."""
        hash_manager = HashManager(PBKDF2Sha256Hasher())
        hashed = hash_manager.hash("test_password")
        
        # Verification should work correctly
        assert hash_manager.verify("test_password", hashed)
        assert not hash_manager.verify("wrong_password", hashed)


class TestFactory:
    """Test the HasherFactory."""

    def test_list_algorithms(self):
        """Test listing available algorithms."""
        algorithms = HasherFactory.list_algorithms()
        assert "pbkdf2_sha256" in algorithms
        assert "pbkdf2_sha1" in algorithms

    def test_create_hasher(self):
        """Test creating a hasher through the factory."""
        hasher = HasherFactory.create("pbkdf2_sha256", iterations=200000)
        assert hasher.algorithm == "pbkdf2_sha256"
        assert hasher.iterations == 200000 # type: ignore

    def test_create_invalid_hasher(self):
        """Test creating an invalid hasher raises exception."""
        with pytest.raises(UnsupportedAlgorithmError):
            HasherFactory.create("invalid_algorithm") # type: ignore


class TestConfigValidation:
    """Test configuration validation."""

    def test_pbkdf2_minimum_iterations(self):
        """Test that PBKDF2 enforces minimum iterations."""
        with pytest.raises(InvalidHasherError, match="PBKDF2 iterations must be at least"):
            PBKDF2Sha256Hasher(iterations=50000)  # Below minimum

    def test_pbkdf2_valid_iterations(self):
        """Test that PBKDF2 accepts valid iterations."""
        hasher = PBKDF2Sha256Hasher(iterations=150000)
        assert hasher.iterations == 150000


class TestAlgorithmType:
    """Test AlgorithmType literal."""

    def test_algorithm_type_usage(self):
        """Test that AlgorithmType provides proper type hints."""
        # This test mainly ensures the type is importable and usable
        algorithm: AlgorithmType = "pbkdf2_sha256"
        hasher = HasherFactory.create(algorithm)
        assert hasher.algorithm == "pbkdf2_sha256"

    def test_quick_hash_with_typed_algorithm(self):
        """Test quick_hash with typed algorithm parameter."""
        algorithm: AlgorithmType = "pbkdf2_sha1" 
        hashed = HashManager.quick_hash("test", algorithm=algorithm)
        assert hashed.startswith("pbkdf2_sha1")

    def test_from_algorithms_with_types(self):
        """Test from_algorithms with typed parameters."""
        alg1: AlgorithmType = "pbkdf2_sha256"
        alg2: AlgorithmType = "pbkdf2_sha1"
        hash_manager = HashManager.from_algorithms(alg1, alg2)
        assert len(hash_manager.hashers) == 2