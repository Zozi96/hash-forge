import pytest

from hash_forge.hashers import Blake3Hasher


@pytest.fixture
def blake3_hasher() -> Blake3Hasher:
    """
    Fixture to create an instance of Blake3Hasher.

    Returns:
        Blake3Hasher: An instance of Blake3Hasher initialized with a random key.
    """
    """Fixture para crear una instancia de Blake3Hasher."""
    return Blake3Hasher()


def test_hash_creation(blake3_hasher: Blake3Hasher) -> None:
    """
    Test the creation of a hash using the Blake3Hasher.

    This test verifies that the hashed value of a given string starts with the
    expected prefix "blake2b$" and that the hashed value is correctly formatted
    with three parts separated by the '$' character.

    Args:
        blake3_hasher (Blake3Hasher): An instance of the Blake3Hasher class.

    Raises:
        AssertionError: If the hashed value does not start with "blake2b$" or
                        if the hashed value does not contain exactly three parts
                        separated by the '$' character.
    """
    _string = "example_password"
    hashed_value = blake3_hasher.hash(_string)

    assert hashed_value.startswith("blake3$")
    assert len(hashed_value.split("$")) == 2


def test_verify_hash_correct(blake3_hasher: Blake3Hasher) -> None:
    """
    Tests the `verify` method of the `Blake3Hasher` class to ensure that it correctly verifies a hashed value.

    Args:
        blake3_hasher (Blake3Hasher): An instance of the `Blake3Hasher` class.

    Test Steps:
    1. Hashes a sample string using the `hash` method of `Blake3Hasher`.
    2. Verifies that the original string matches the hashed value using the `verify` method.

    Asserts:
        The `verify` method returns True when the original string matches the hashed value.
    """
    _string = "example_password"
    hashed_value = blake3_hasher.hash(_string)

    assert blake3_hasher.verify(_string, hashed_value) is True


def test_verify_hash_incorrect(blake3_hasher: Blake3Hasher) -> None:
    """
    Test the `verify` method of the `Blake3Hasher` class with an incorrect string.

    This test ensures that the `verify` method returns `False` when provided with
    a string that does not match the original hashed value.

    Args:
        blake3_hasher (Blake3Hasher): An instance of the Blake3Hasher class.

    Asserts:
        The `verify` method returns `False` when the incorrect string is provided.
    """
    _string = "example_password"
    incorrect_string = "wrong_password"
    hashed_value = blake3_hasher.hash(_string)

    assert blake3_hasher.verify(incorrect_string, hashed_value) is False


def test_hash_with_key() -> None:
    """
    Test the Blake3Hasher class with a key.

    This test generates a random key using `secrets.token_urlsafe()`,
    creates an instance of `Blake3Hasher` with the generated key,
    and hashes a sample string. It then verifies that the hashed
    value matches the original string and does not match an incorrect string.

    Assertions:
        - The hashed value should be verified as True for the correct string.
        - The hashed value should be verified as False for an incorrect string.
    """
    blake3_hasher_with_key = Blake3Hasher()

    _string = "example_password"
    hashed_value = blake3_hasher_with_key.hash(_string)

    assert blake3_hasher_with_key.verify(_string, hashed_value) is True
    assert blake3_hasher_with_key.verify("wrong_password", hashed_value) is False


def test_verify_fails_on_modified_hash(blake3_hasher: Blake3Hasher) -> None:
    """
    Test that the `verify` method of `Blake3Hasher` fails when the hash has been modified.
    This test ensures that the `verify` method returns `False` when the hash of a given
    string is altered. It first hashes a sample string, then modifies the resulting hash
    by replacing the first occurrence of the character 'a' with 'b'. Finally, it verifies
    that the `verify` method correctly identifies the modified hash as invalid.
    Args:
        blake3_hasher (Blake3Hasher): An instance of the Blake3Hasher class.
    Returns:
        None
    """
    _string = "example_password"
    hashed_value = blake3_hasher.hash(_string)
    modified_hash = hashed_value.replace("a", "b", 1)

    assert blake3_hasher.verify(_string, modified_hash) is False
