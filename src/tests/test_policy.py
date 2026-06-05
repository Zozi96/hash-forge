import pytest

from hash_forge import HashManager, PasswordHashPolicy, canonical_algorithm, classify_algorithm
from hash_forge.config.config_loader import HashForgeConfig
from hash_forge.hashers import BCryptHasher, BCryptSha256Hasher, PBKDF2Sha256Hasher, SHA3_256Hasher


def test_classify_algorithm_categories() -> None:
    assert classify_algorithm("argon2") == "password"
    assert classify_algorithm("pbkdf2_sha1") == "legacy"
    assert classify_algorithm("sha3_256") == "digest"
    assert classify_algorithm("whirlpool") == "deprecated"
    assert canonical_algorithm("RIPEMD-160") == "ripemd160"


def test_from_policy_hashes_with_preferred() -> None:
    policy = PasswordHashPolicy.fips()
    manager = HashManager.from_policy(policy)
    hashed = manager.hash("password")
    assert hashed.startswith("pbkdf2_sha256$")


def test_verify_and_update_rotates_legacy_hash() -> None:
    policy = PasswordHashPolicy.fips()
    manager = HashManager.from_policy(policy)
    old_hash = HashManager(PBKDF2Sha256Hasher(iterations=150_000)).hash("password")
    ok, new_hash = manager.verify_and_update("password", old_hash)
    assert ok is True
    assert new_hash is not None
    assert new_hash.startswith("pbkdf2_sha256$600000$")


def test_verify_and_update_noop_when_current() -> None:
    manager = HashManager.from_policy(PasswordHashPolicy.fips())
    current_hash = manager.hash("password")
    ok, new_hash = manager.verify_and_update("password", current_hash)
    assert ok is True
    assert new_hash is None


def test_policy_rejects_digest_for_password_hashing() -> None:
    policy = PasswordHashPolicy(
        preferred_algorithm="sha3_256",
        algorithms=("sha3_256",),
    )
    manager = HashManager(SHA3_256Hasher())
    manager.policy = policy
    with pytest.raises(ValueError):
        manager.hash("password")


def test_policy_blocks_legacy_verify_when_disabled() -> None:
    policy = PasswordHashPolicy(
        preferred_algorithm="pbkdf2_sha256",
        algorithms=("pbkdf2_sha256", "pbkdf2_sha1"),
        allow_legacy_verify=False,
    )
    manager = HashManager.from_policy(policy)
    legacy_hash = "pbkdf2_sha1$150000$salt$de6bbd7fd101a1973be1155c620dc31af9a740b6"
    assert manager.verify("password", legacy_hash) is False


def test_verify_and_update_respects_hash_policy() -> None:
    policy = PasswordHashPolicy(
        preferred_algorithm="sha3_256",
        algorithms=("sha3_256", "pbkdf2_sha256"),
    )
    manager = HashManager(SHA3_256Hasher(), PBKDF2Sha256Hasher())
    manager.policy = policy
    old_hash = HashManager(PBKDF2Sha256Hasher()).hash("password")
    with pytest.raises(ValueError):
        manager.verify_and_update("password", old_hash)


def test_manager_order_is_stable() -> None:
    manager = HashManager(PBKDF2Sha256Hasher(), SHA3_256Hasher())
    assert manager.list_algorithms() == ["pbkdf2_sha256", "sha3_256"]


def test_bcrypt_sha256_dispatch_exact() -> None:
    manager = HashManager(BCryptHasher(), BCryptSha256Hasher())
    hashed = manager.hasher_map["bcrypt_sha256"].hash("password")
    assert manager.verify("password", hashed) is True


def test_ripemd160_legacy_prefix_still_verifies() -> None:
    manager = HashManager.from_algorithms("ripemd160")
    hashed = manager.hash("password").replace("ripemd160$", "RIPEMD-160$", 1)
    assert manager.verify("password", hashed) is True
    assert manager.needs_rehash(hashed) is True


def test_hash_manager_from_config_scrypt() -> None:
    manager = HashManager.from_config(HashForgeConfig(), "scrypt")
    hashed = manager.hash("password")
    assert manager.verify("password", hashed) is True
