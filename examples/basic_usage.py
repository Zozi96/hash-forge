"""Basic usage examples for Hash Forge.

This example demonstrates the fundamental operations of Hash Forge:
- Creating a HashManager
- Hashing passwords
- Verifying passwords
- Checking if rehashing is needed
"""

from hash_forge import HashManager

# Example 1: Simple hash and verify
print("=" * 60)
print("Example 1: Basic Hash and Verify")
print("=" * 60)

# Create a HashManager with PBKDF2-SHA256 (default, secure)
hash_manager = HashManager.from_algorithms("pbkdf2_sha256")

# Hash a password
password = "my_secure_password_123"
hashed = hash_manager.hash(password)
print(f"Original: {password}")
print(f"Hashed:   {hashed}")

# Verify the password
is_valid = hash_manager.verify(password, hashed)
print(f"Valid:    {is_valid}")  # True

# Try with wrong password
is_valid_wrong = hash_manager.verify("wrong_password", hashed)
print(f"Wrong pw: {is_valid_wrong}")  # False

print()

# Example 2: Multiple algorithms with fallback
print("=" * 60)
print("Example 2: Multiple Algorithms (Migration Scenario)")
print("=" * 60)

# Support both new (Argon2) and legacy (PBKDF2) hashes
hash_manager_multi = HashManager.from_algorithms("argon2", "pbkdf2_sha256")

# New hashes will use Argon2 (first algorithm = preferred)
new_hash = hash_manager_multi.hash("new_user_password")
print(f"New hash (Argon2): {new_hash[:50]}...")

# Old hash with PBKDF2 can still be verified
old_hash = "pbkdf2_sha256$150000$salt$hash..."
# hash_manager_multi.verify("old_password", old_hash)  # Would work if valid

print()

# Example 3: Check if rehashing is needed
print("=" * 60)
print("Example 3: Check if Rehashing is Needed")
print("=" * 60)

# Create hasher with higher security params
from hash_forge.hashers import PBKDF2Sha256Hasher

old_hasher = PBKDF2Sha256Hasher(iterations=150_000)  # Old standard
new_hasher = PBKDF2Sha256Hasher(iterations=200_000)  # New standard

# Hash with old params
old_hash = old_hasher.hash("password")
print(f"Old hash: {old_hash[:50]}...")

# Check if needs rehashing with new params
hash_manager_new = HashManager(new_hasher, old_hasher)
needs_update = hash_manager_new.needs_rehash(old_hash)
print(f"Needs rehash: {needs_update}")  # True (old iterations)

print()

# Example 4: Quick hash (one-liner)
print("=" * 60)
print("Example 4: Quick Hash for Simple Use Cases")
print("=" * 60)

# No need to create HashManager instance
quick_hash = HashManager.quick_hash("simple_password")
print(f"Quick hash: {quick_hash[:50]}...")

# With specific algorithm
quick_hash_bcrypt = HashManager.quick_hash(
    "password",
    algorithm="bcrypt",
    rounds=12
)
print(f"BCrypt hash: {quick_hash_bcrypt[:50]}...")

print()

# Example 5: Custom parameters
print("=" * 60)
print("Example 5: Custom Security Parameters")
print("=" * 60)

from hash_forge.hashers import BCryptHasher, Argon2Hasher

# High security configuration
hash_manager_secure = HashManager(
    Argon2Hasher(time_cost=4, memory_cost=65536),  # High security Argon2
    BCryptHasher(rounds=14),  # High security BCrypt
)

secure_hash = hash_manager_secure.hash("ultra_secure_password")
print(f"High security hash: {secure_hash[:50]}...")

print()
print("✅ All examples completed successfully!")
