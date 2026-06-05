from hash_forge.hashers import PBKDF2Sha256Hasher, ScryptHasher, SHA3_256Hasher


def test_pbkdf2_rejects_trailing_fields() -> None:
    hasher = PBKDF2Sha256Hasher()
    hashed = hasher.hash("password")
    assert hasher.verify("password", hashed + "$ignored") is False


def test_sha3_rejects_trailing_fields() -> None:
    hasher = SHA3_256Hasher()
    hashed = hasher.hash("password")
    assert hasher.verify("password", hashed + "$ignored") is False


def test_scrypt_needs_rehash_malformed_returns_false() -> None:
    assert ScryptHasher().needs_rehash("malformed") is False
