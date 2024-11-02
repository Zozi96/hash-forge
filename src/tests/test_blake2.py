import pytest
import secrets

from hash_forge import Blake2Hasher


@pytest.fixture
def blake2_hasher() -> Blake2Hasher:
    """
    Fixture to create an instance of Blake2Hasher.

    Returns:
        Blake2Hasher: An instance of Blake2Hasher initialized with a random key.
    """
    """Fixture para crear una instancia de Blake2Hasher."""
    return Blake2Hasher(key=secrets.token_urlsafe())


def test_hash_creation(blake2_hasher: Blake2Hasher) -> None:
    """
    Test the creation of a hash using the Blake2Hasher.

    This test verifies that the hashed value of a given string starts with the
    expected prefix "blake2b$" and that the hashed value is correctly formatted
    with three parts separated by the '$' character.

    Args:
        blake2_hasher (Blake2Hasher): An instance of the Blake2Hasher class.

    Raises:
        AssertionError: If the hashed value does not start with "blake2b$" or
                        if the hashed value does not contain exactly three parts
                        separated by the '$' character.
    """
    _string = "example_password"
    hashed_value = blake2_hasher.hash(_string)

    assert hashed_value.startswith("blake2b$")
    assert len(hashed_value.split('$')) == 3


def test_verify_hash_correct(blake2_hasher: Blake2Hasher) -> None:
    """
    Tests the `verify` method of the `Blake2Hasher` class to ensure that it correctly verifies a hashed value.

    Args:
        blake2_hasher (Blake2Hasher): An instance of the `Blake2Hasher` class.

    Test Steps:
    1. Hashes a sample string using the `hash` method of `Blake2Hasher`.
    2. Verifies that the original string matches the hashed value using the `verify` method.

    Asserts:
        The `verify` method returns True when the original string matches the hashed value.
    """
    _string = "example_password"
    hashed_value = blake2_hasher.hash(_string)

    assert blake2_hasher.verify(_string, hashed_value) is True


def test_verify_hash_incorrect(blake2_hasher: Blake2Hasher) -> None:
    """
    Test the `verify` method of the `Blake2Hasher` class with an incorrect string.

    This test ensures that the `verify` method returns `False` when provided with
    a string that does not match the original hashed value.

    Args:
        blake2_hasher (Blake2Hasher): An instance of the Blake2Hasher class.

    Asserts:
        The `verify` method returns `False` when the incorrect string is provided.
    """
    _string = "example_password"
    incorrect_string = "wrong_password"
    hashed_value = blake2_hasher.hash(_string)

    assert blake2_hasher.verify(incorrect_string, hashed_value) is False


def test_needs_rehash_false(blake2_hasher: Blake2Hasher) -> None:
    """
    Test that the `needs_rehash` method of the `Blake2Hasher` class returns False
    for a freshly hashed value.

    Args:
        blake2_hasher (Blake2Hasher): An instance of the Blake2Hasher class.

    Asserts:
        The `needs_rehash` method should return False for the given hashed value.
    """
    _string = "example_password"
    hashed_value = blake2_hasher.hash(_string)

    assert blake2_hasher.needs_rehash(hashed_value) is False


def test_needs_rehash_true() -> None:
    """
    Test the `needs_rehash` method of the `Blake2Hasher` class.

    This test verifies that the `needs_rehash` method correctly identifies
    when a hashed value needs to be rehashed due to a different digest size.

    Steps:
    1. Generate a random key using `secrets.token_urlsafe()`.
    2. Create two instances of `Blake2Hasher` with the same key but different digest sizes (32 and 64).
    3. Hash a sample string using the 32-byte hasher.
    4. Assert that the 64-byte hasher's `needs_rehash` method returns `True` when passed the 32-byte hashed value.

    Expected Result:
    The `needs_rehash` method should return `True` indicating that the hashed value needs to be rehashed to match the 64-byte digest size.
    """
    key: str = secrets.token_urlsafe()
    blake2_hasher_32 = Blake2Hasher(key, digest_size=32)
    blake2_hasher_64 = Blake2Hasher(key, digest_size=64)

    _string = "example_password"
    hashed_value_32 = blake2_hasher_32.hash(_string)

    assert blake2_hasher_64.needs_rehash(hashed_value_32) is True


def test_hash_with_key() -> None:
    """
    Test the Blake2Hasher class with a key.

    This test generates a random key using `secrets.token_urlsafe()`, 
    creates an instance of `Blake2Hasher` with the generated key, 
    and hashes a sample string. It then verifies that the hashed 
    value matches the original string and does not match an incorrect string.

    Assertions:
        - The hashed value should be verified as True for the correct string.
        - The hashed value should be verified as False for an incorrect string.
    """
    key: str = secrets.token_urlsafe()
    blake2_hasher_with_key = Blake2Hasher(key=key)

    _string = "example_password"
    hashed_value = blake2_hasher_with_key.hash(_string)

    assert blake2_hasher_with_key.verify(_string, hashed_value) is True
    assert blake2_hasher_with_key.verify("wrong_password", hashed_value) is False


def test_verify_fails_on_modified_hash(blake2_hasher: Blake2Hasher) -> None:
    """
    Test that the `verify` method of `Blake2Hasher` fails when the hash has been modified.
    This test ensures that the `verify` method returns `False` when the hash of a given
    string is altered. It first hashes a sample string, then modifies the resulting hash
    by replacing the first occurrence of the character 'a' with 'b'. Finally, it verifies
    that the `verify` method correctly identifies the modified hash as invalid.
    Args:
        blake2_hasher (Blake2Hasher): An instance of the Blake2Hasher class.
    Returns:
        None
    """
    _string = "example_password"
    hashed_value = blake2_hasher.hash(_string)
    modified_hash = hashed_value.replace('a', 'b', 1)
    
    assert blake2_hasher.verify(_string, modified_hash) is False
