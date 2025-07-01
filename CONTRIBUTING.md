# Contributing to SecureIoT-Sim
Thank you for your interest in contributing to SecureIot-Sim! This document outlines the development and contribution standards for the project.

## Development Standards
### C Style & Linting
* **C Standard:** Use C99
* **Safety:** Follow MISRA-C like safety practices
    * No implicit casts
    * No unitiliazed variables
    * Check all return values, include ``fclose()``
* **Formating:** 
    * Indent with 4 spaces, not tabs
    * Brace all `if`/`else`/`for` blocks, even one-liners
    * One decleration per line (`int a; int b;` not `int a, b;`)
* **Headers:**
    * Use header guards: `#ifndef SRC_TLS_CLIENT_H`
    * Organize: stdlib headers first, then project headers
* **Variables:**
    * Avoid global variables unless for const configuration
    * Use descriptive names for clarity

### Testing Rules
* Use assert-style tests (custom assertions, cmocka, or pure C)
* Every module in `src/` must have at least one unit test file
* Include integration test: `test_mtls_connection` that runs full stack
* Test edge cases: expired certs, wrong CA, missing keys

### Security Requirements
* Zero sensitive memory before free: `memset(key, 0, key_len);
* Use constant-time comparison for cert fingerprint validation
* Check all return values from system and library calls
* No hardcoded credentials or keys in source code

### Build & CI
* Use CMake with options:
    * `-DSTATIC_BUILD=ON` for static linking
    * `-DWITH_TLS=ON` for TLS support
* GitHub Actions CI must:
    * Build the project on Linux and macOS
    * Run all tests (unit + integration)
    * Perform static analysis with clang-tidy or cppcheck

## Commit Guidelines
Use convential commits format:
* `feat:` for new features
    * Example: `feat: add mbedTLS connection handler`
* `fix:` for bug fixes
    * Example: `fix: correct certificate validation logic`
* `docs:` for documentation changes
    * Example `docs: update build instructions for Windows`
* `refactor:` for internal cleanups or reorganization
    * Example: `refactor: extract cert loading into seperate function`
* `test:` for test-only changes
    * Example: `test: add expired certificate test case`

Guidelines:
* Use clear, concise, lowercase titles
* Keep the subject line under 50 characters
* Body is optional unless complex changes need explanation
* Reference issue when applicable: `fix: memory leak in TLS handler (#42)`

## Documentation
### Code Documentation
* Every `.c` file must start with a block comment:
```c
/**
 * module_name.c - Brief description
 * 
 * Longer description if needed
 * 
 * Author: Your Name
 * Date: Current Date
*/
```

* Use Doxygen-style comments for all public functions:
```c
/**
 * Brief description of function
 * 
 * @param param1 Description of parameter
 * @param param2 Description of parameter
 * @return Description of return value
*/
```

### Project Documentation
* Keep `README.md` updated as features are added
* Each module should have documentation in `/docs/` or README section
* Include examples for common use cases

## Code Review Process
1. Fork the repository
2. Create feature branch: `git checkout -b feat/your-feature`
3. Make your changes following the standards above
4. Add tests for new functionality
5. Ensure all tests pass: `make test`
6. Update documentation as needed
7. Submit a pull request

### PR Requirements
* All CI checks must pass
* Code coverage should not decrease
* At least one reviewer approval required
* Resolve all review comments

## Questions?
If you have questions about contributing, please open an issue for discussion.