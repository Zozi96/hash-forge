"""Tests for medium priority features: Chain of Responsibility, Async, Config."""
import asyncio
import json
import os
import tempfile
from pathlib import Path

import pytest

from hash_forge import HashManager
from hash_forge.config.config_loader import HashForgeConfig
from hash_forge.hashers import PBKDF2Sha256Hasher


class TestChainOfResponsibility:
    """Test Chain of Responsibility pattern for hash detection."""

    def test_can_handle_method(self) -> None:
        """Test that hashers can determine if they can handle a hash."""
        hasher = PBKDF2Sha256Hasher()

        # Should handle hashes starting with its algorithm
        assert hasher.can_handle("pbkdf2_sha256$150000$salt$hash")

        # Should not handle other algorithms
        assert not hasher.can_handle("bcrypt$2b$12$hash")
        assert not hasher.can_handle("argon2$v=19$...")

    def test_hash_manager_uses_can_handle(self) -> None:
        """Test that HashManager uses can_handle for detection."""
        hash_manager = HashManager.from_algorithms("pbkdf2_sha256", "bcrypt")

        # Hash with pbkdf2
        pbkdf2_hash = hash_manager.hash("test_password")
        assert pbkdf2_hash.startswith("pbkdf2_sha256")

        # Manager should find the right hasher for verification
        assert hash_manager.verify("test_password", pbkdf2_hash)

    def test_multiple_hashers_chain(self) -> None:
        """Test chain with multiple hashers."""
        from hash_forge.hashers import BCryptHasher

        pbkdf2 = PBKDF2Sha256Hasher()
        bcrypt = BCryptHasher()

        hash_manager = HashManager(pbkdf2, bcrypt)

        # Create hash with each
        pbkdf2_hash = pbkdf2.hash("test")
        bcrypt_hash = bcrypt.hash("test")

        # Manager should correctly identify and verify each
        assert hash_manager.verify("test", pbkdf2_hash)
        assert hash_manager.verify("test", bcrypt_hash)


class TestAsyncSupport:
    """Test async operations."""

    @pytest.mark.asyncio
    async def test_hash_async(self) -> None:
        """Test async hashing."""
        hash_manager = HashManager.from_algorithms("pbkdf2_sha256")

        hashed = await hash_manager.hash_async("test_password")

        assert hashed.startswith("pbkdf2_sha256")
        assert hash_manager.verify("test_password", hashed)

    @pytest.mark.asyncio
    async def test_verify_async(self) -> None:
        """Test async verification."""
        hash_manager = HashManager.from_algorithms("pbkdf2_sha256")

        # First hash synchronously
        hashed = hash_manager.hash("test_password")

        # Then verify asynchronously
        is_valid = await hash_manager.verify_async("test_password", hashed)
        assert is_valid

        is_invalid = await hash_manager.verify_async("wrong_password", hashed)
        assert not is_invalid

    @pytest.mark.asyncio
    async def test_needs_rehash_async(self) -> None:
        """Test async rehash check."""
        hash_manager = HashManager.from_algorithms("pbkdf2_sha256")

        hashed = hash_manager.hash("test_password")

        needs_rehash = await hash_manager.needs_rehash_async(hashed)
        assert not needs_rehash

    @pytest.mark.asyncio
    async def test_hash_many_async(self) -> None:
        """Test concurrent hashing of multiple strings."""
        hash_manager = HashManager.from_algorithms("pbkdf2_sha256")

        passwords = ["pass1", "pass2", "pass3", "pass4", "pass5"]

        hashes = await hash_manager.hash_many_async(passwords)

        assert len(hashes) == len(passwords)
        for i, hashed in enumerate(hashes):
            assert hash_manager.verify(passwords[i], hashed)

    @pytest.mark.asyncio
    async def test_verify_many_async(self) -> None:
        """Test concurrent verification of multiple pairs."""
        hash_manager = HashManager.from_algorithms("pbkdf2_sha256")

        # Create pairs
        pairs = [
            ("pass1", hash_manager.hash("pass1")),
            ("pass2", hash_manager.hash("pass2")),
            ("pass3", hash_manager.hash("pass3")),
        ]

        results = await hash_manager.verify_many_async(pairs)

        assert all(results)
        assert len(results) == len(pairs)

    @pytest.mark.asyncio
    async def test_async_performance(self) -> None:
        """Test that async operations don't block."""
        hash_manager = HashManager.from_algorithms("pbkdf2_sha256")

        # Hash multiple strings concurrently
        tasks = [hash_manager.hash_async(f"password_{i}") for i in range(3)]

        hashes = await asyncio.gather(*tasks)

        assert len(hashes) == 3
        for h in hashes:
            assert h.startswith("pbkdf2_sha256")


class TestConfigLoader:
    """Test HashForgeConfig."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = HashForgeConfig()

        assert config.pbkdf2_iterations == 150_000
        assert config.bcrypt_rounds == 12
        assert config.argon2_time_cost == 3

    def test_config_from_dict(self) -> None:
        """Test loading from dictionary."""
        config = HashForgeConfig.from_dict({
            'pbkdf2_iterations': 200_000,
            'bcrypt_rounds': 14,
        })

        assert config.pbkdf2_iterations == 200_000
        assert config.bcrypt_rounds == 14

    def test_config_from_env(self) -> None:
        """Test loading from environment variables."""
        # Set environment variables
        os.environ['HASH_FORGE_PBKDF2_ITERATIONS'] = '250000'
        os.environ['HASH_FORGE_BCRYPT_ROUNDS'] = '15'

        try:
            config = HashForgeConfig.from_env()

            assert config.pbkdf2_iterations == 250_000
            assert config.bcrypt_rounds == 15
        finally:
            # Clean up
            del os.environ['HASH_FORGE_PBKDF2_ITERATIONS']
            del os.environ['HASH_FORGE_BCRYPT_ROUNDS']

    def test_config_from_json(self) -> None:
        """Test loading from JSON file."""
        config_data = {
            'pbkdf2_iterations': 300_000,
            'bcrypt_rounds': 16,
            'custom': {'app_name': 'TestApp'}
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name

        try:
            config = HashForgeConfig.from_json(temp_path)

            assert config.pbkdf2_iterations == 300_000
            assert config.bcrypt_rounds == 16
            assert config.custom['app_name'] == 'TestApp'
        finally:
            os.unlink(temp_path)

    def test_config_to_dict(self) -> None:
        """Test exporting config to dictionary."""
        config = HashForgeConfig(pbkdf2_iterations=200_000)

        data = config.to_dict()

        assert data['pbkdf2_iterations'] == 200_000
        assert 'bcrypt_rounds' in data

    def test_config_to_json(self) -> None:
        """Test exporting config to JSON file."""
        config = HashForgeConfig(pbkdf2_iterations=200_000)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / 'config.json'
            config.to_json(path)

            # Read back
            loaded = HashForgeConfig.from_json(path)
            assert loaded.pbkdf2_iterations == 200_000

    def test_get_hasher_config(self) -> None:
        """Test getting algorithm-specific config."""
        config = HashForgeConfig(
            pbkdf2_iterations=200_000,
            bcrypt_rounds=14,
        )

        pbkdf2_config = config.get_hasher_config('pbkdf2_sha256')
        assert pbkdf2_config['iterations'] == 200_000

        bcrypt_config = config.get_hasher_config('bcrypt')
        assert bcrypt_config['rounds'] == 14

    def test_hash_manager_from_config(self) -> None:
        """Test creating HashManager from config."""
        config = HashForgeConfig(
            pbkdf2_iterations=200_000,
            bcrypt_rounds=14,
        )

        hash_manager = HashManager.from_config(config, "pbkdf2_sha256", "bcrypt")

        assert len(hash_manager.hashers) == 2

        # Test that config was applied
        hashed = hash_manager.hash("test")
        assert hash_manager.verify("test", hashed)


class TestIntegrationMediumPriority:
    """Integration tests for medium priority features."""

    @pytest.mark.asyncio
    async def test_config_with_async(self) -> None:
        """Test using config with async operations."""
        config = HashForgeConfig(pbkdf2_iterations=180_000)

        hash_manager = HashManager.from_config(config, "pbkdf2_sha256")

        hashed = await hash_manager.hash_async("test_password")
        is_valid = await hash_manager.verify_async("test_password", hashed)

        assert is_valid

    def test_chain_with_config(self) -> None:
        """Test Chain of Responsibility with config."""
        config = HashForgeConfig(
            pbkdf2_iterations=200_000,
            bcrypt_rounds=14,
        )

        hash_manager = HashManager.from_config(config, "pbkdf2_sha256", "bcrypt")

        # Each hasher should handle its own algorithm
        pbkdf2_hash = "pbkdf2_sha256$200000$salt$hash"
        bcrypt_hash = "bcrypt$2b$14$hash"

        # Find correct hasher using chain
        pbkdf2_hasher = hash_manager._get_hasher_by_hash(pbkdf2_hash)
        bcrypt_hasher = hash_manager._get_hasher_by_hash(bcrypt_hash)

        assert pbkdf2_hasher is not None
        assert pbkdf2_hasher.algorithm == "pbkdf2_sha256"

        assert bcrypt_hasher is not None
        assert bcrypt_hasher.algorithm == "bcrypt"
