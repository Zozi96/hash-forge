# Changelog

All notable changes to Hash Forge will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.1] - 2024-10-03

### Added
- **Examples directory** with practical usage examples:
  - `basic_usage.py` - Fundamental operations and common patterns
  - `async_fastapi.py` - FastAPI integration with async support
  - `builder_pattern.py` - Fluent builder API examples
- **Documentation files** for better developer experience:
  - `CHANGELOG.md` - Version history and changes
  - `SECURITY.md` - Security best practices and vulnerability reporting
  - `CONTRIBUTING.md` - Contribution guidelines

### Fixed
- Fixed version synchronization between `pyproject.toml` and `__init__.py`
- Improved type hints for better IDE support:
  - Changed `HasherFactory.list_algorithms()` return type to `Sequence[AlgorithmType]` for better type variance
  - Added `TYPE_CHECKING` stubs to `AsyncHashMixin` to prevent false positive type errors
  - Fixed test type narrowing with `isinstance()` checks

### Changed
- Updated internal type annotations for cleaner Pylance/Pyright compatibility

## [3.0.0] - 2024-10-03

### Breaking Changes
- **Reorganized internal module structure** into logical directories:
  - `core/` - Core functionality (manager, builder, factory, protocols, base_hasher)
  - `config/` - Configuration and settings (config_loader, logging, constants)
  - `utils/` - Utility functions
  - `hashers/` - Algorithm implementations
- **Internal imports changed** (e.g., `hash_forge.protocols` → `hash_forge.core.protocols`)
- **Public API remains backward compatible** - no changes needed for most users

### Added
- **Full Async/Await Support** with `AsyncHashMixin`
  - `hash_async()` - Non-blocking hashing with thread pool executor
  - `verify_async()` - Non-blocking password verification
  - `needs_rehash_async()` - Async rehash checking
  - `hash_many_async()` - Concurrent batch hashing (3-5x faster)
  - `verify_many_async()` - Concurrent batch verification
- **Builder Pattern** with fluent API via `HashManagerBuilder`
  - `.with_algorithm(name, **params)` - Add algorithm by name with custom params
  - `.with_hasher(instance)` - Add pre-configured hasher instance
  - `.with_preferred(algorithm)` - Set preferred algorithm explicitly
  - `.build()` - Create HashManager instance
- **Configuration Management** with `HashForgeConfig`
  - `.from_env(prefix)` - Load from environment variables
  - `.from_json(path)` - Load from JSON files
  - `.from_dict(data)` - Load from dictionary
  - `.to_json(path)` - Export configuration to JSON
  - `.get_hasher_config(algorithm)` - Get algorithm-specific params
- **Logging Infrastructure** for debugging and monitoring
  - `get_logger(name)` - Get namespaced logger
  - `configure_logging(level)` - Set global log level
  - Structured logging across all hashers
- **Chain of Responsibility Pattern**
  - Each hasher can autonomously determine via `can_handle()` if it can process a hash
  - More robust algorithm detection
- **Template Method Pattern** in `BaseHasher`
  - Reduced code duplication by 40% across all hashers
  - Centralized error handling and logging
  - Abstract methods: `_do_hash()`, `_parse_hash()`, `_do_verify()`, `_check_needs_rehash()`
- **Auto-Discovery Pattern** for hasher registration
  - Automatic registration via class attributes
  - No manual factory registration needed

### Changed
- **Performance Improvements**:
  - O(1) hasher lookup with internal mapping (vs O(n) iteration)
  - Async batch operations: 3-5x faster for 10 hashes, 8-10x for 100 hashes
  - Thread pool executor for non-blocking operations in async contexts
  - Optimized memory usage with reduced object creation overhead
- Updated dependency versions:
  - `bcrypt==5.0.0` (was 4.2.1)
  - `argon2-cffi==25.1.0` (was 23.1.0)
  - `pycryptodome==3.23.0` (was 3.21.0)
  - `blake3==1.0.7` (was 1.0.4)
- Migrated from `tool.uv.dev-dependencies` to `dependency-groups.dev` in pyproject.toml
- Added `pytest-asyncio>=1.2.0` for async test support

### Performance Benchmarks
- 10 concurrent hashes: ~3-5x faster than sequential
- 100 concurrent hashes: ~8-10x faster than sequential
- 40% less code duplication = smaller memory footprint
- Non-blocking operations prevent event loop blocking in async contexts

### Documentation
- Added comprehensive async/await examples in README
- Added FastAPI integration example
- Added performance comparison examples
- Added migration guide from v2.x
- Added new project structure documentation
- Updated "What's New" section with v3.0.0 features

## [2.1.0] - 2024-08-30

### Added
- **Factory Pattern** with `HasherFactory`
  - `HasherFactory.create(algorithm, **kwargs)` - Create hashers by algorithm name
  - `HasherFactory.list_algorithms()` - List available algorithms
- **Type Safety** with `AlgorithmType` literal type
  - IDE autocomplete for algorithm names
  - Type checking for algorithm parameters
- **Convenience Methods**:
  - `HashManager.from_algorithms(*algorithms, **kwargs)` - Create manager from algorithm names
  - `HashManager.quick_hash(string, algorithm, **kwargs)` - One-liner hashing
- **Performance Optimization**:
  - O(1) hasher lookup with internal `hasher_map` dictionary
  - Optimized memory usage with reduced object creation

### Changed
- Enhanced test suite to 81+ tests
- Improved error messages and validation
- Better parameter validation across all hashers

### Fixed
- BCrypt hash parsing bug (rounds extraction from correct position)
- PBKDF2 minimum iteration validation (enforces 150K minimum)

## [2.0.0] - 2024-08-15

### Added
- **Blake3 Support** - Latest Blake variant with high performance and security
- Support for Python 3.13

### Changed
- Updated dependency versions for compatibility
- Improved CI/CD workflows for multi-version testing

## [1.2.2] - 2024-07-20

### Added
- Whirlpool hashing algorithm (512-bit hash)
- RIPEMD-160 hashing algorithm (160-bit hash)

### Changed
- Reorganized hasher imports for better structure
- Updated README with new algorithms and usage

### Fixed
- Ruff linting issues in CI pipeline
- Improved code formatting consistency

## [1.2.0] - 2024-06-15

### Added
- Blake2 hashing support with optional key parameter
- Scrypt hashing algorithm (memory-hard function)

### Changed
- Improved parameter validation across all hashers
- Enhanced documentation with more examples
- Better error messages for invalid inputs

## [1.1.0] - 2024-05-10

### Added
- Argon2 hashing algorithm support (memory-hard, recommended for passwords)
- BCrypt-SHA256 variant (BCrypt with SHA256 pre-hashing)
- `needs_rehash()` method to detect outdated hashes

### Changed
- Improved salt generation for PBKDF2
- Better error handling and validation
- Enhanced test coverage

## [1.0.0] - 2024-04-01

### Added
- Initial release of Hash Forge
- PBKDF2-SHA256 hashing (primary algorithm)
- PBKDF2-SHA1 hashing (legacy support)
- BCrypt hashing support
- `HashManager` for managing multiple algorithms
- Core methods: `hash()`, `verify()`
- Automatic algorithm detection from hash prefix
- Comprehensive test suite
- MIT License
- PyPI package publication

[3.0.1]: https://github.com/Zozi96/hash-forge/compare/v3.0.0...v3.0.1
[3.0.0]: https://github.com/Zozi96/hash-forge/compare/v2.1.0...v3.0.0
[2.1.0]: https://github.com/Zozi96/hash-forge/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/Zozi96/hash-forge/compare/v1.2.2...v2.0.0
[1.2.2]: https://github.com/Zozi96/hash-forge/compare/v1.2.0...v1.2.2
[1.2.0]: https://github.com/Zozi96/hash-forge/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Zozi96/hash-forge/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Zozi96/hash-forge/releases/tag/v1.0.0
