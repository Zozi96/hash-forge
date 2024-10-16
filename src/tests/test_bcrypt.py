import pytest
import re

from hash_forge.bcrypt_hasher import BCryptHasher


@pytest.fixture
def bcrypt_hasher() -> BCryptHasher:

    return BCryptHasher(rounds=12)


def test_bcrypt_hash_format(bcrypt_hasher) -> None:
    data = "TestData123!"
    hashed = bcrypt_hasher.hash(data)
    pattern = r'^bcrypt_sha256\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$'
    assert hashed.startswith('bcrypt_sha256$'), "Hash should start with 'bcrypt_sha256$'"
    assert re.match(pattern, hashed) is not None, "Hash should match the expected format"


def test_bcrypt_verify_correct_data(bcrypt_hasher) -> None:
    data = "TestData123!"
    hashed = bcrypt_hasher.hash(data)
    assert bcrypt_hasher.verify(data, hashed) is True, "Verification should succeed for correct data"


def test_bcrypt_verify_incorrect_data(bcrypt_hasher) -> None:
    data = "TestData123!"
    wrong_data = "WrongData456!"
    hashed = bcrypt_hasher.hash(data)
    assert bcrypt_hasher.verify(wrong_data, hashed) is False, "Verification should fail for incorrect data"


def test_bcrypt_needs_rehash_false(bcrypt_hasher) -> None:
    data = "TestData123!"
    hashed = bcrypt_hasher.hash(data)
    assert bcrypt_hasher.needs_rehash(hashed) is False, "Hash should not need rehashing if rounds match"


def test_bcrypt_invalid_hash_format(bcrypt_hasher):
    data = "TestData123!"
    invalid_hashed = "invalid$hash$format"
    assert bcrypt_hasher.verify(data, invalid_hashed) is False, "Verification should fail for invalid hash format"
    assert (
        bcrypt_hasher.needs_rehash(invalid_hashed) is False
    ), "needs_rehash should return False for invalid hash format"


def test_bcrypt_unknown_algorithm(bcrypt_hasher):
    data = "TestData123!"
    unknown_hashed = f"unknown_algo$2b$12$abcdefghijklmnopqrstuv$hashvalue1234567"
    assert bcrypt_hasher.verify(data, unknown_hashed) is False, "Verification should fail for unknown algorithm"
    assert bcrypt_hasher.needs_rehash(unknown_hashed) is False, "needs_rehash should return False for unknown algorithm"
