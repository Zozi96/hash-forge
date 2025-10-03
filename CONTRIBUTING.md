# Contributing to Hash Forge

Thank you for considering contributing to Hash Forge! This document provides guidelines and instructions for contributing.

## Code of Conduct

This project follows a simple code of conduct: **Be respectful, be constructive, and be collaborative.**

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check the [issue tracker](https://github.com/Zozi96/hash-forge/issues) to avoid duplicates.

When creating a bug report, include:
- **Clear title** describing the issue
- **Python version** and **Hash Forge version**
- **Minimal code example** to reproduce the issue
- **Expected behavior** vs **actual behavior**
- **Error messages** or stack traces (if applicable)
- **Environment details** (OS, dependencies, etc.)

**Template:**
```markdown
**Bug Description**
A clear description of what the bug is.

**To Reproduce**
```python
from hash_forge import HashManager
# Your code here
```

**Expected Behavior**
What you expected to happen.

**Actual Behavior**
What actually happened.

**Environment**
- Python version: 3.11
- Hash Forge version: 3.0.1
- OS: macOS 14.0
```

### Suggesting Enhancements

Enhancement suggestions are welcome! Please:
- Use a clear and descriptive title
- Provide a detailed description of the proposed feature
- Explain why this enhancement would be useful
- Include code examples if applicable

### Pull Requests

1. **Fork the repository** and create your branch from `develop`:
   ```bash
   git checkout -b feature/my-new-feature develop
   ```

2. **Make your changes**:
   - Write clear, documented code
   - Follow the existing code style
   - Add tests for new functionality
   - Update documentation as needed

3. **Test your changes**:
   ```bash
   # Run all tests
   pytest src/tests/ -v

   # Run linting
   ruff check src/

   # Run type checking (if mypy is installed)
   mypy src/hash_forge
   ```

4. **Commit your changes**:
   ```bash
   git commit -m "feat: add new feature X"
   ```

   We follow [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` - New feature
   - `fix:` - Bug fix
   - `docs:` - Documentation changes
   - `test:` - Test additions/changes
   - `refactor:` - Code refactoring
   - `perf:` - Performance improvements
   - `chore:` - Maintenance tasks

5. **Push to your fork**:
   ```bash
   git push origin feature/my-new-feature
   ```

6. **Open a Pull Request** against the `develop` branch

## Development Setup

### Prerequisites

- Python 3.10 or higher
- [uv](https://github.com/astral-sh/uv) (recommended) or pip

### Setup Instructions

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Zozi96/hash-forge.git
   cd hash-forge
   ```

2. **Create a virtual environment**:
   ```bash
   # Using uv (recommended)
   uv venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate

   # Or using venv
   python -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   # Using uv
   uv pip install -e ".[bcrypt,argon2,crypto,blake3]"
   uv pip install -r requirements-dev.txt

   # Or using pip
   pip install -e ".[bcrypt,argon2,crypto,blake3]"
   pip install pytest pytest-asyncio ruff mypy
   ```

4. **Verify installation**:
   ```bash
   python -c "from hash_forge import HashManager; print('✅ Setup complete!')"
   ```

## Project Structure

```
hash-forge/
├── src/hash_forge/          # Source code
│   ├── __init__.py          # Public API
│   ├── core/                # Core functionality
│   │   ├── manager.py       # HashManager implementation
│   │   ├── builder.py       # Builder pattern
│   │   ├── factory.py       # Hasher factory
│   │   ├── protocols.py     # Protocol definitions
│   │   ├── base_hasher.py   # Base hasher class
│   │   └── async_manager.py # Async support
│   ├── config/              # Configuration
│   │   ├── settings.py      # Default parameters
│   │   ├── constants.py     # Constants
│   │   ├── logging.py       # Logging setup
│   │   └── config_loader.py # Config management
│   ├── hashers/             # Algorithm implementations
│   │   ├── pbkdf2_hasher.py
│   │   ├── bcrypt_hasher.py
│   │   ├── argon2_hasher.py
│   │   └── ...
│   ├── types.py             # Type definitions
│   └── exceptions.py        # Custom exceptions
├── src/tests/               # Test suite
│   ├── test_hash_manager.py
│   ├── test_argon2.py
│   └── ...
├── examples/                # Usage examples
│   ├── basic_usage.py
│   ├── async_fastapi.py
│   └── ...
└── docs/                    # Documentation
```

## Code Style

### Python Style Guide

- Follow [PEP 8](https://pep8.org/)
- Use type hints for all functions and methods
- Maximum line length: 120 characters
- Use double quotes for strings
- Use 4 spaces for indentation (no tabs)

### Type Hints

All code must include type hints:

```python
from hash_forge.core.protocols import PHasher

def hash_password(password: str, hasher: PHasher) -> str:
    """Hash a password using the provided hasher.

    Args:
        password: The password to hash
        hasher: The hasher instance to use

    Returns:
        The hashed password string
    """
    return hasher.hash(password)
```

### Documentation

- All public functions/classes must have docstrings
- Use Google-style docstrings:

```python
def my_function(param1: str, param2: int) -> bool:
    """Short description of the function.

    Longer description if needed. Explain what the function does,
    any important considerations, etc.

    Args:
        param1: Description of param1
        param2: Description of param2

    Returns:
        Description of return value

    Raises:
        ValueError: When param2 is negative

    Example:
        >>> my_function("test", 42)
        True
    """
    if param2 < 0:
        raise ValueError("param2 must be positive")
    return len(param1) > param2
```

## Testing

### Running Tests

```bash
# Run all tests
pytest src/tests/ -v

# Run specific test file
pytest src/tests/test_argon2.py -v

# Run tests with coverage
pytest src/tests/ --cov=hash_forge --cov-report=html

# Run only async tests
pytest src/tests/ -k "async" -v
```

### Writing Tests

1. **Test file naming**: `test_<module>.py`
2. **Test function naming**: `test_<functionality>`
3. **Use fixtures** for common setup
4. **Test edge cases** and error conditions
5. **Use parametrize** for multiple similar tests

Example:

```python
import pytest
from hash_forge import HashManager

class TestHashManager:
    """Test HashManager functionality."""

    def test_hash_creates_valid_hash(self):
        """Test that hash() creates a valid hash string."""
        hash_manager = HashManager.from_algorithms("pbkdf2_sha256")
        hashed = hash_manager.hash("password")

        assert hashed.startswith("pbkdf2_sha256$")
        assert len(hashed) > 50

    @pytest.mark.asyncio
    async def test_async_hash_matches_sync(self):
        """Test that async hash produces same result as sync."""
        hash_manager = HashManager.from_algorithms("argon2")

        sync_hash = hash_manager.hash("password")
        async_hash = await hash_manager.hash_async("password")

        # Both should be verifiable
        assert hash_manager.verify("password", sync_hash)
        assert await hash_manager.verify_async("password", async_hash)

    @pytest.mark.parametrize("algorithm", ["pbkdf2_sha256", "bcrypt", "argon2"])
    def test_all_algorithms(self, algorithm):
        """Test that all algorithms work correctly."""
        hash_manager = HashManager.from_algorithms(algorithm)
        hashed = hash_manager.hash("test")
        assert hash_manager.verify("test", hashed)
```

## Adding a New Hasher

To add a new hashing algorithm:

1. **Create hasher file** in `src/hash_forge/hashers/`:

```python
from hash_forge.core.base_hasher import BaseHasher
from hash_forge.core.factory import HasherFactory

@HasherFactory.register("my_algorithm")
class MyAlgorithmHasher(BaseHasher):
    """My new hashing algorithm."""

    algorithm = "my_algorithm"

    def __init__(self, custom_param: int = 1000):
        self.custom_param = custom_param

    def _do_hash(self, string: str, salt: str) -> str:
        """Implement hashing logic."""
        # Your implementation here
        pass

    def _parse_hash(self, hashed_string: str) -> dict:
        """Parse hash string into components."""
        # Your implementation here
        pass

    def _do_verify(self, string: str, hashed_string: str, parsed: dict) -> bool:
        """Verify password against hash."""
        # Your implementation here
        pass

    def _check_needs_rehash(self, parsed: dict) -> bool:
        """Check if hash needs rehashing."""
        return parsed.get("custom_param") != self.custom_param
```

2. **Add to types** in `src/hash_forge/types.py`:

```python
AlgorithmType = Literal[
    # ... existing algorithms ...
    "my_algorithm",
]
```

3. **Write tests** in `src/tests/test_my_algorithm.py`

4. **Update documentation** in README.md

## Release Process

Releases are managed by project maintainers:

1. Update version in `pyproject.toml` and `src/hash_forge/__init__.py`
2. Update `CHANGELOG.md` with changes
3. Create a release branch: `release/vX.Y.Z`
4. Test thoroughly
5. Merge to `main` and tag: `git tag vX.Y.Z`
6. GitHub Actions will automatically publish to PyPI

## Getting Help

- **Documentation**: Check the [README](README.md) and [examples/](examples/)
- **Issues**: Browse [existing issues](https://github.com/Zozi96/hash-forge/issues)
- **Discussions**: Start a [discussion](https://github.com/Zozi96/hash-forge/discussions)
- **Email**: Contact zozi.fer96@gmail.com

## Recognition

Contributors will be recognized in:
- GitHub contributors page
- CHANGELOG.md (for significant contributions)
- Release notes

Thank you for contributing to Hash Forge! 🎉
