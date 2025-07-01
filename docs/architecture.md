# SecureIoT-Sim Architecture
### Overview
SecureIoT-Sim is designed to emulate a secure embedded IoT device with TLS/mTLS communication capabilities. The architecture follows embedded software best practices with static memory allocation, minimal dependencies, and clear module separation.

## Design Principles
1. **No Dynamic Memory:** All memory is statically allocaed to emulate embedded constraints
2. **Error Propagation:** Explicit error codes with no exceptions
3. **Security First:** Secure memory handling, certificate validation, constant-time operations
4. **Testability:** Each module has clear interfaces and unit testing
5. **Portability:** Pure C99 with minimal platform dependencies

## Module Architecture
```bash
┌─────────────────┐
│     main.c      │  Entry point, CLI parsing
└────────┬────────┘
         │
    ┌────┴────┐
    │         │
┌───▼───┐  ┌──▼─────────┐
│ Key   │  │    TLS     │
│ Store │  │   Client   │
└───┬───┘  └──┬─────────┘
    │         │
    └────┬────┘
         │
    ┌────▼────┐
    │   Msg   │
    │ Protocol│
    └─────────┘
```

## Modules
### Main (`main.c`)
* Program entry point
* Command-line argument parsing
* Signal handling for graceful shutdown
* Orchestrates the connection flow

### TLS Client (`tls_client.c/h`)
* Manages TLS/mTLS connections using mbedTLS
* Handles certificate loading and validation
* Provides send/receive interface
* Implements:
    * TLS 1.2/1.3 support
    * Server certificate validation
    * Client certificate authentication (mTLS)
    * Secure session management

### Key Store (`key_store.c/h`)
* Simulates embedded flash storage
* Stores certificates and private keys
* Features:
    * Fixed-size entries
    * CRC32 integrity checking
    * Secure memory wiping
    * File-based persistence (simulating flash)

### Message Protocol (`msg_protocol.c/h`)
* Formats and parses JSON messages
* Message types:
    * Telemetry data
    * Commands
    * Responses
    * Error messages
* Handles message ID generation and timestamps

## Data Flow
1. **Initialization**
    * Load certificates from key store
    * Initialize TLS context
    * Configure connection parameters
2. **Connection**
    * TCP socket connection
    * TLS handshake with certificate exchange
    * Mutual authentication (if configured)

3. **Communication**
    * Format telemetry data as JSON
    * Encrypt and send via TLS
    * Receive and decrypt response
    * Parse response JSON

4. **Cleanup**
    * Close TLS connection
    * Zero sensitive memory
    * Release resources

## Security Considerations
### Certificate Management
* X.509 certificates for authentication
* CA certificate for server validation
* Client certificate for device authentication
* Private key protection with secure erasure

### TLS Configuration
* Minimum TLS 1.2
* Strong cipher suites only
* Certificate validation required
* Hostname verification

### Memory Security 
* No dynamic allocation (prevents heap attacks)
* Sensitive data zeroes after use
* Stack-based buffers with bounds checking
* Constant time operations for crypto

## Error Handling
All functions return `error_code_t`:
* `ERR_OK`(0) for success
* Negative values for errors
* Errors propogate up the call stack
* No silent failures

Common patterns:
```c
CHECK_PARAM(ptr); // Returns ERR_INVALID_PARAM if NULL
CHECK_ERROR(func()); // Returns error if func() fials
CHECK_ERROR_GOTO(func(), cleanup); // Jumps to cleanup on error
```

## Testing Strategy
### Unit Tests
* Each module has dedicated test file
* Tests cover:
    * Normal operation
    * Error conditions
    * Boundary cases
    * Parameter validation

### Integration Tests
* `test_mtls_connection`: Full TLS handshake
* Certificate validation scenarios
* Message exchange verification

### Security Tests
* Expired certificates
* Wrong CA certificates
* Missing certificates
* Malformed messages

## Build System
CMake-based build with options:
* `STATIC_BUILD`: Static linking (default ON)
* `WITH_TLS`: Enable TLS support (default ON)
* `DEBUG` : Debug build
* `ENABLE_TESTS` : Build tests (default ON)

## Dependencies
* **mbedTLS:** TLS implementation
    * Included as git submodule
    * Built as static library
    * Version 3.6.4

* **Standard C Library:** C99 compliant
    * stdio, stdlib, string
    * time for timestamps
    * Platform sockets

## Future Enhancements
1. **Protocol Support**
    * MQTT over TLS
    * CoAP with DTLS
    * JSON-RPC
2. **Security Features**
    * Firmware update simulation
    * Secure boot emulation
    * Hardware security module (HSM) simulation
3. **Testing**
    * Fuzzing harness
    * Performance benchmarks
    * Memory usage profiling