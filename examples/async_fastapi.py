"""Async Hash Forge integration with FastAPI.

This example shows how to integrate Hash Forge with FastAPI for
non-blocking password hashing and verification in a web application.

Requirements:
    pip install fastapi uvicorn pydantic
"""

import asyncio
from typing import Optional

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

from hash_forge import HashManager

# Initialize FastAPI app
app = FastAPI(title="Hash Forge Auth API", version="1.0.0")

# Initialize HashManager with Argon2 (recommended for web apps)
hash_manager = HashManager.from_algorithms("argon2")

# In-memory user database (use real DB in production)
users_db: dict[str, dict] = {}


# Request/Response models
class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    email: str


class UserLogin(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    username: str
    email: str
    message: str


# Routes
@app.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user: UserRegister):
    """Register a new user with async password hashing."""

    # Check if user already exists
    if user.username in users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )

    # Hash password asynchronously (non-blocking!)
    password_hash = await hash_manager.hash_async(user.password)

    # Store user in database
    users_db[user.username] = {
        "email": user.email,
        "password_hash": password_hash,
    }

    return UserResponse(
        username=user.username,
        email=user.email,
        message="User registered successfully"
    )


@app.post("/login", response_model=UserResponse)
async def login(credentials: UserLogin):
    """Login user with async password verification."""

    # Get user from database
    user = users_db.get(credentials.username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    # Verify password asynchronously (non-blocking!)
    is_valid = await hash_manager.verify_async(
        credentials.password,
        user["password_hash"]
    )

    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    # Check if password needs rehashing (security upgrade)
    needs_rehash = await hash_manager.needs_rehash_async(user["password_hash"])
    if needs_rehash:
        # Rehash with new parameters and update DB
        new_hash = await hash_manager.hash_async(credentials.password)
        users_db[credentials.username]["password_hash"] = new_hash
        print(f"🔄 Rehashed password for {credentials.username}")

    return UserResponse(
        username=credentials.username,
        email=user["email"],
        message="Login successful"
    )


@app.post("/batch-register")
async def batch_register(users: list[UserRegister]):
    """Register multiple users with concurrent password hashing.

    This demonstrates the performance benefits of async batch operations.
    """

    # Check for duplicates
    for user in users:
        if user.username in users_db:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Username {user.username} already exists"
            )

    # Hash all passwords concurrently (much faster than sequential!)
    passwords = [user.password for user in users]
    password_hashes = await hash_manager.hash_many_async(passwords)

    # Store users in database
    registered = []
    for user, password_hash in zip(users, password_hashes):
        users_db[user.username] = {
            "email": user.email,
            "password_hash": password_hash,
        }
        registered.append(user.username)

    return {
        "message": f"Successfully registered {len(registered)} users",
        "users": registered
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "users_count": len(users_db)}


# Example usage
if __name__ == "__main__":
    import uvicorn

    print("🚀 Starting FastAPI server with Hash Forge async support...")
    print("📖 API docs available at: http://localhost:8000/docs")
    print()
    print("Try these curl commands:")
    print()
    print('# Register a user')
    print('curl -X POST "http://localhost:8000/register" \\')
    print('  -H "Content-Type: application/json" \\')
    print('  -d \'{"username":"john","password":"secure123","email":"john@example.com"}\'')
    print()
    print('# Login')
    print('curl -X POST "http://localhost:8000/login" \\')
    print('  -H "Content-Type: application/json" \\')
    print('  -d \'{"username":"john","password":"secure123"}\'')
    print()

    # Run the server
    uvicorn.run(app, host="0.0.0.0", port=8000)
