import re

import pytest

from hash_forge.hashers import BCryptHasher


@pytest.fixture
def bcrypt_hasher() -> BCryptHasher:
    """
    Creates and returns an instance of BCryptHasher with a specified number of rounds.

    Returns:
        BCryptHasher: An instance of BCryptHasher configured with 12 rounds.
    """
    return BCryptHasher(rounds=12)


def test_bcrypt_hash_format(bcrypt_hasher: BCryptHasher) -> None:
    """
    Test the format of the hash generated by the BCryptHasher.

    This test ensures that the hash generated by the BCryptHasher
    follows the expected format. The hash should start with 'bcrypt$'
    and match the regular expression pattern for a valid bcrypt_sha256 hash.

    Args:
        bcrypt_hasher (BCryptHasher): An instance of the BCryptHasher.

    Raises:
        AssertionError: If the hash does not start with 'bcrypt$' or
                        does not match the expected format.
    """
    data = "TestData123!"
    hashed = bcrypt_hasher.hash(data)
    pattern = r'^bcrypt\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$'
    assert hashed.startswith('bcrypt$'), "Hash should start with 'bcrypt$'"
    assert re.match(pattern, hashed) is not None, "Hash should match the expected format"


def test_bcrypt_verify_correct_data(bcrypt_hasher: BCryptHasher) -> None:
    """
    Test the BCryptHasher's verify method with correct data.

    This test ensures that the verify method returns True when provided with
    the correct data that was previously hashed using the BCryptHasher.

    Args:
        bcrypt_hasher (BCryptHasher): An instance of the BCryptHasher.

    Asserts:
        The verify method should return True when the correct data is provided.
    """
    data = "TestData123!"
    hashed = bcrypt_hasher.hash(data)
    assert bcrypt_hasher.verify(data, hashed) is True, "Verification should succeed for correct data"


def test_bcrypt_verify_incorrect_data(bcrypt_hasher: BCryptHasher) -> None:
    """
    Test the verification of incorrect data using the BCryptHasher.

    This test ensures that the `verify` method of the `BCryptHasher` class
    returns `False` when provided with data that does not match the original hashed data.

    Args:
        bcrypt_hasher (BCryptHasher): An instance of the BCryptHasher class.

    Asserts:
        The `verify` method should return `False` when the wrong data is provided.
    """
    data = "TestData123!"
    wrong_data = "WrongData456!"
    hashed = bcrypt_hasher.hash(data)
    assert bcrypt_hasher.verify(wrong_data, hashed) is False, "Verification should fail for incorrect data"


def test_bcrypt_needs_rehash_false(bcrypt_hasher: BCryptHasher) -> None:
    """
    Test that the `needs_rehash` method of `BCryptHasher` returns False.

    This test verifies that when a password is hashed using the `BCryptHasher`
    and the number of rounds matches the expected configuration, the `needs_rehash`
    method correctly identifies that the hash does not need to be rehashed.

    Args:
        bcrypt_hasher (BCryptHasher): An instance of the BCryptHasher.

    Raises:
        AssertionError: If the `needs_rehash` method returns True, indicating that
                        the hash needs rehashing when it should not.
    """
    data = "TestData123!"
    hashed = bcrypt_hasher.hash(data)
    assert bcrypt_hasher.needs_rehash(hashed) is False, "Hash should not need rehashing if rounds match"


def test_bcrypt_invalid_hash_format(bcrypt_hasher: BCryptHasher) -> None:
    """
    Test the behavior of the BCryptHasher when provided with an invalid hash format.

    Args:
        bcrypt_hasher (BCryptHasher): An instance of the BCryptHasher.

    Asserts:
        - The `verify` method should return False when the hash format is invalid.
        - The `needs_rehash` method should return False when the hash format is invalid.
    """
    data = "TestData123!"
    invalid_hashed = "invalid$hash$format"
    assert bcrypt_hasher.verify(data, invalid_hashed) is False, "Verification should fail for invalid hash format"
    assert (
        bcrypt_hasher.needs_rehash(invalid_hashed) is False
    ), "needs_rehash should return False for invalid hash format"


def test_bcrypt_unknown_algorithm(bcrypt_hasher: BCryptHasher) -> None:
    """
    Test the behavior of BCryptHasher when an unknown algorithm is used in the hashed value.

    Args:
        bcrypt_hasher (BCryptHasher): An instance of the BCryptHasher.

    Asserts:
        - The verification should fail when the hashed value uses an unknown algorithm.
        - The needs_rehash method should return False when the hashed value uses an unknown algorithm.
    """
    data = "TestData123!"
    unknown_hashed = "unknown_algo$2b$12$abcdefghijklmnopqrstuv$hashvalue1234567"
    assert bcrypt_hasher.verify(data, unknown_hashed) is False, "Verification should fail for unknown algorithm"
    assert bcrypt_hasher.needs_rehash(unknown_hashed) is False, "needs_rehash should return False for unknown algorithm"
