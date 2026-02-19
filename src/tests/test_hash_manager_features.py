import pytest

from hash_forge import HashManager
from hash_forge.hashers import PBKDF2Sha256Hasher, SHA3_256Hasher, SHA3_512Hasher


@pytest.fixture
def manager() -> HashManager:
    return HashManager(PBKDF2Sha256Hasher(), SHA3_256Hasher(), SHA3_512Hasher())


def test_rotate_returns_new_hash(manager: HashManager) -> None:
    hashed = manager.hash("my_password")
    new_hash = manager.rotate("my_password", hashed)
    assert new_hash is not None
    assert new_hash != hashed
    assert manager.verify("my_password", new_hash) is True


def test_rotate_returns_none_on_wrong_password(manager: HashManager) -> None:
    hashed = manager.hash("my_password")
    assert manager.rotate("wrong_password", hashed) is None


def test_rotate_upgrades_old_hash_to_preferred(manager: HashManager) -> None:
    sha3_hasher = SHA3_256Hasher()
    old_hash = sha3_hasher.hash("my_password")
    new_hash = manager.rotate("my_password", old_hash)
    assert new_hash is not None
    assert new_hash.startswith("pbkdf2_sha256$")


def test_inspect_returns_algorithm(manager: HashManager) -> None:
    hashed = manager.hash("my_password")
    info = manager.inspect(hashed)
    assert info is not None
    assert info["algorithm"] == "pbkdf2_sha256"


def test_inspect_returns_none_for_unknown_hash(manager: HashManager) -> None:
    assert manager.inspect("unknown_algo$abc$def") is None


def test_inspect_does_not_expose_raw_hash(manager: HashManager) -> None:
    hashed = manager.hash("my_password")
    info = manager.inspect(hashed)
    assert info is not None
    assert "hash" not in info
    assert "salt" not in info
    assert "hashed_val" not in info
    assert "parts" not in info


def test_inspect_sha3_returns_algorithm(manager: HashManager) -> None:
    sha3_hasher = SHA3_256Hasher()
    hashed = sha3_hasher.hash("my_password")
    info = manager.inspect(hashed)
    assert info is not None
    assert info["algorithm"] == "sha3_256"


def test_list_algorithms_returns_registered(manager: HashManager) -> None:
    algorithms = manager.list_algorithms()
    assert "pbkdf2_sha256" in algorithms
    assert "sha3_256" in algorithms
    assert "sha3_512" in algorithms


def test_list_algorithms_count(manager: HashManager) -> None:
    algorithms = manager.list_algorithms()
    assert len(algorithms) == 3


def test_repr_contains_preferred(manager: HashManager) -> None:
    r = repr(manager)
    assert "preferred='pbkdf2_sha256'" in r


def test_repr_contains_algorithms(manager: HashManager) -> None:
    r = repr(manager)
    assert "HashManager(" in r
    assert "algorithms=" in r


def test_single_hasher_list_algorithms() -> None:
    m = HashManager(SHA3_512Hasher())
    assert m.list_algorithms() == ["sha3_512"]


def test_single_hasher_repr() -> None:
    m = HashManager(SHA3_512Hasher())
    assert repr(m) == "HashManager(preferred='sha3_512', algorithms=['sha3_512'])"
