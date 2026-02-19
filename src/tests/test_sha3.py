import pytest

from hash_forge.hashers import SHA3_256Hasher, SHA3_512Hasher


@pytest.fixture
def sha3_256_hasher() -> SHA3_256Hasher:
    return SHA3_256Hasher()


@pytest.fixture
def sha3_512_hasher() -> SHA3_512Hasher:
    return SHA3_512Hasher()


def test_sha3_256_hash_format(sha3_256_hasher: SHA3_256Hasher) -> None:
    hashed = sha3_256_hasher.hash("example_password")
    parts = hashed.split("$")
    assert parts[0] == "sha3_256"
    assert len(parts) == 3


def test_sha3_512_hash_format(sha3_512_hasher: SHA3_512Hasher) -> None:
    hashed = sha3_512_hasher.hash("example_password")
    parts = hashed.split("$")
    assert parts[0] == "sha3_512"
    assert len(parts) == 3


def test_sha3_256_verify_correct(sha3_256_hasher: SHA3_256Hasher) -> None:
    hashed = sha3_256_hasher.hash("example_password")
    assert sha3_256_hasher.verify("example_password", hashed) is True


def test_sha3_256_verify_incorrect(sha3_256_hasher: SHA3_256Hasher) -> None:
    hashed = sha3_256_hasher.hash("example_password")
    assert sha3_256_hasher.verify("wrong_password", hashed) is False


def test_sha3_512_verify_correct(sha3_512_hasher: SHA3_512Hasher) -> None:
    hashed = sha3_512_hasher.hash("example_password")
    assert sha3_512_hasher.verify("example_password", hashed) is True


def test_sha3_512_verify_incorrect(sha3_512_hasher: SHA3_512Hasher) -> None:
    hashed = sha3_512_hasher.hash("example_password")
    assert sha3_512_hasher.verify("wrong_password", hashed) is False


def test_sha3_256_needs_rehash_always_false(sha3_256_hasher: SHA3_256Hasher) -> None:
    hashed = sha3_256_hasher.hash("example_password")
    assert sha3_256_hasher.needs_rehash(hashed) is False


def test_sha3_512_needs_rehash_always_false(sha3_512_hasher: SHA3_512Hasher) -> None:
    hashed = sha3_512_hasher.hash("example_password")
    assert sha3_512_hasher.needs_rehash(hashed) is False


def test_sha3_256_can_handle(sha3_256_hasher: SHA3_256Hasher) -> None:
    hashed = sha3_256_hasher.hash("example_password")
    assert sha3_256_hasher.can_handle(hashed) is True
    assert sha3_256_hasher.can_handle("sha3_512$salt$hash") is False


def test_sha3_512_can_handle(sha3_512_hasher: SHA3_512Hasher) -> None:
    hashed = sha3_512_hasher.hash("example_password")
    assert sha3_512_hasher.can_handle(hashed) is True
    assert sha3_512_hasher.can_handle("sha3_256$salt$hash") is False


def test_sha3_256_hashes_are_unique(sha3_256_hasher: SHA3_256Hasher) -> None:
    hashed1 = sha3_256_hasher.hash("example_password")
    hashed2 = sha3_256_hasher.hash("example_password")
    assert hashed1 != hashed2


def test_sha3_256_via_factory() -> None:
    from hash_forge import HashManager

    manager = HashManager.from_algorithms("sha3_256")
    hashed = manager.hash("example_password")
    assert hashed.startswith("sha3_256$")
    assert manager.verify("example_password", hashed) is True


def test_sha3_512_via_factory() -> None:
    from hash_forge import HashManager

    manager = HashManager.from_algorithms("sha3_512")
    hashed = manager.hash("example_password")
    assert hashed.startswith("sha3_512$")
    assert manager.verify("example_password", hashed) is True
