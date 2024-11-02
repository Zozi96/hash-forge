import pytest

from hash_forge import Argon2Hasher


@pytest.fixture
def argon2_hasher() -> Argon2Hasher:
    """
    Creates and returns an instance of Argon2Hasher.

    Returns:
        Argon2Hasher: An instance of the Argon2Hasher class.
    """
    return Argon2Hasher()

def test_argon2_verify_correct_data(argon2_hasher: Argon2Hasher) -> None:
    """
    Test the Argon2Hasher's verify method with correct data.

    This test ensures that the `verify` method of the `Argon2Hasher` class
    returns `True` when provided with the correct data and its corresponding hash.

    Args:
        argon2_hasher (Argon2Hasher): An instance of the Argon2Hasher class.

    Asserts:
        The `verify` method should return `True` when the correct data and its hash are provided.
    """
    data = "TestData123!"
    hashed: str = argon2_hasher.hash(data)
    assert argon2_hasher.verify(data, hashed) is True, "Verification should succeed for correct data"

def test_argon2_verify_incorrect_data(argon2_hasher: Argon2Hasher) -> None:
    """
    Test the Argon2Hasher's verify method with incorrect data.

    This test ensures that the verify method returns False when provided with
    data that does not match the original hashed data.

    Args:
        argon2_hasher (Argon2Hasher): An instance of the Argon2Hasher class.

    Asserts:
        The verify method should return False when the wrong data is provided.
    """
    data = "TestData123!"
    wrong_data = "WrongData456!"
    hashed: str = argon2_hasher.hash(data)
    assert argon2_hasher.verify(wrong_data, hashed) is False, "Verification should fail for incorrect data"

def test_argon2_needs_rehash_false(argon2_hasher: Argon2Hasher) -> None:
    """
    Test that the `needs_rehash` method of the `Argon2Hasher` class returns False.

    This test verifies that when data is hashed using the `Argon2Hasher` class,
    the resulting hash does not require rehashing with the current parameters.

    Args:
        argon2_hasher (Argon2Hasher): An instance of the Argon2Hasher class.

    Raises:
        AssertionError: If the `needs_rehash` method returns True, indicating that
                        the hashed data needs rehashing.
    """
    data = "TestData123!"
    hashed = argon2_hasher.hash(data)
    assert argon2_hasher.needs_rehash(hashed) is False, "Hashed data should not need rehashing with current parameters"

def test_argon2_needs_rehash_true(argon2_hasher: Argon2Hasher) -> None:
    """
    Test if the Argon2Hasher correctly identifies that a hash needs rehashing.

    This test checks whether the `needs_rehash` method of the `Argon2Hasher` class
    returns `True` when the hash was generated with a lower time cost than the current
    hasher's configuration.

    Args:
        argon2_hasher (Argon2Hasher): An instance of Argon2Hasher with the current configuration.

    Raises:
        AssertionError: If the `needs_rehash` method does not return `True` for a hash
                        generated with a lower time cost.
    """
    data = "TestData123!"
    old_hasher = Argon2Hasher(time_cost=1)
    old_hashed = old_hasher.hash(data)
    assert argon2_hasher.needs_rehash(old_hashed) is True, "Hashed data should need rehashing due to increased time_cost"


def test_argon2_invalid_hash_format(argon2_hasher: Argon2Hasher) -> None:
    """
    Test the Argon2Hasher's behavior with an invalid hash format.

    This test ensures that the Argon2Hasher correctly identifies and handles
    an invalid hash format. Specifically, it verifies that:
    1. The `verify` method returns False when provided with an invalid hash format.
    2. The `needs_rehash` method returns False when provided with an invalid hash format.

    Args:
        argon2_hasher (Argon2Hasher): An instance of the Argon2Hasher class.

    Raises:
        AssertionError: If the `verify` method does not return False for an invalid hash format.
        AssertionError: If the `needs_rehash` method does not return False for an invalid hash format.
    """
    data = "TestData123!"
    invalid_hashed = "invalid$hash$format"
    assert argon2_hasher.verify(data, invalid_hashed) is False, "Verification should fail for invalid hash format"
    assert argon2_hasher.needs_rehash(invalid_hashed) is False, "needs_rehash should return False for invalid hash format"

