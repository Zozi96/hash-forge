"""Builder Pattern examples for Hash Forge.

This example demonstrates the fluent builder API for creating
HashManager instances with elegant, chainable syntax.
"""

from hash_forge import HashManager
from hash_forge.hashers import PBKDF2Sha256Hasher

print("=" * 60)
print("Builder Pattern Examples")
print("=" * 60)
print()

# Example 1: Basic builder usage
print("Example 1: Basic Builder")
print("-" * 40)

hash_manager = (
    HashManager.builder()
    .with_algorithm("argon2")
    .with_algorithm("bcrypt")
    .build()
)

hashed = hash_manager.hash("password123")
print(f"Hash created: {hashed[:50]}...")
print(f"Preferred algorithm: {hash_manager.preferred_hasher.algorithm}")
print()

# Example 2: Builder with custom parameters
print("Example 2: Builder with Custom Parameters")
print("-" * 40)

hash_manager_custom = (
    HashManager.builder()
    .with_algorithm("argon2", time_cost=4, memory_cost=65536, parallelism=2)
    .with_algorithm("bcrypt", rounds=14)
    .with_algorithm("pbkdf2_sha256", iterations=200_000)
    .build()
)

hashed_custom = hash_manager_custom.hash("secure_password")
print(f"High security hash: {hashed_custom[:50]}...")
print()

# Example 3: Set preferred algorithm
print("Example 3: Setting Preferred Algorithm")
print("-" * 40)

# By default, first algorithm is preferred
# But you can explicitly set it
hash_manager_preferred = (
    HashManager.builder()
    .with_algorithm("pbkdf2_sha256")
    .with_algorithm("argon2")
    .with_algorithm("bcrypt")
    .with_preferred("argon2")  # Override to use Argon2
    .build()
)

hashed_preferred = hash_manager_preferred.hash("password")
print(f"Preferred: {hash_manager_preferred.preferred_hasher.algorithm}")
print(f"Hash: {hashed_preferred[:50]}...")
print()

# Example 4: Mix pre-configured hashers with algorithms
print("Example 4: Mix Hasher Instances and Algorithms")
print("-" * 40)

# Create a custom-configured hasher instance
custom_pbkdf2 = PBKDF2Sha256Hasher(iterations=300_000, salt_length=32)

hash_manager_mixed = (
    HashManager.builder()
    .with_hasher(custom_pbkdf2)  # Add pre-configured instance
    .with_algorithm("bcrypt", rounds=12)  # Add by name
    .with_algorithm("argon2")
    .build()
)

hashed_mixed = hash_manager_mixed.hash("password")
print(f"Mixed configuration hash: {hashed_mixed[:50]}...")
print()

# Example 5: Migration scenario (old + new algorithms)
print("Example 5: Migration Scenario")
print("-" * 40)

# Support legacy PBKDF2 hashes while moving to Argon2
migration_manager = (
    HashManager.builder()
    .with_algorithm("argon2")  # New hashes use this
    .with_algorithm("pbkdf2_sha256")  # Can still verify old hashes
    .with_algorithm("bcrypt")  # Also support BCrypt legacy
    .with_preferred("argon2")  # Explicitly prefer Argon2
    .build()
)

# New user registration uses Argon2
new_user_hash = migration_manager.hash("new_user_password")
print(f"New user (Argon2): {new_user_hash[:50]}...")

# Can still verify old PBKDF2 hashes
old_pbkdf2_hash = "pbkdf2_sha256$150000$..."  # Example old hash
# migration_manager.verify("old_password", old_pbkdf2_hash)  # Would work

print()

# Example 6: Error handling
print("Example 6: Error Handling")
print("-" * 40)

try:
    # This will raise an error (no hashers provided)
    empty_manager = HashManager.builder().build()
except Exception as e:
    print(f"❌ Error (expected): {e}")

try:
    # This will raise an error (preferred algorithm not in list)
    invalid_manager = (
        HashManager.builder()
        .with_algorithm("bcrypt")
        .with_preferred("argon2")  # argon2 not added!
        .build()
    )
except Exception as e:
    print(f"❌ Error (expected): {e}")

print()

# Example 7: Web application configuration
print("Example 7: Web Application Setup")
print("-" * 40)

# Typical web app: high security, support legacy
web_app_manager = (
    HashManager.builder()
    .with_algorithm("argon2", time_cost=3, memory_cost=65536)  # Primary
    .with_algorithm("bcrypt", rounds=12)  # Fallback/legacy
    .with_preferred("argon2")
    .build()
)

# Register new user
user_password = "WebAppSecurePass123!"
user_hash = web_app_manager.hash(user_password)
print(f"User registered with: {web_app_manager.preferred_hasher.algorithm}")

# Verify login
is_valid = web_app_manager.verify(user_password, user_hash)
print(f"Login successful: {is_valid}")

# Check if needs rehashing
needs_update = web_app_manager.needs_rehash(user_hash)
print(f"Needs rehash: {needs_update}")

print()
print("✅ All builder examples completed!")
