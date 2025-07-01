# SecureIoT-Sim
A secure embedded system simulator demonstrating TLS/mTLS communication using X.509 certificates, implemented in pure C with embedded constraints.

## Overview
SecureIoT-Sim emulates a resource-constrained IoT device performing secure communication over TLS. Demonstrated is:
* X.509 certificate-based authentication (mTLS)
* TLS 1.2/1.3 client implementation using mbedTLS
* Simulated flash-based key storage
* Static memory allocation
* Telemetry message exchange over secure channels
* Comprehensive error handling and testing

## Features
* **Mutual TLS Authentication:** Client and server certificate validation
* **Simulated Flash Storage:** Emulates embedded certificate/key storage
* **Static Memory Model:** No dynamic allocation, fixed size buffers
* **Cross-Platform:** Runs on Linux, macOS, and Windows
* **Comprehensive Testing:** Unit tests, integration tests, and security scenarios
* **CI/CD Ready:** GitHub Actions integration

## Quick Start
```bash
git clone https://github.com/yourusername/SecureIoT-Sim.git
cd SecureIoT-Sim

# Initialize submodules (mbedTLS)
git submodule update --init --recursive

# Build mbedTLS (using CMake - recommended)
cd third_party/mbedtls
mkdir build && cd build
cmake .. -DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF -DUSE_SHARED_MBEDTLS_LIBRARY=OFF
make
cd ../../..

# Generate certificates
python3 tools/gen_cert.py

# Build the project
mkdir build && cd build
cmake .. -DSTATIC_BUILD=ON -DWITH_TLS=ON
make

# Run tests
make test

# Start test server (in another terminal)
python3 ../test_server/server.py

# Run the simulator
./secureiot_sim
```

## Project Structure
```bash
SecureIoT-Sim/
├── certs/
├── src/            # Core implementation
├── test_server/    # Python TLS test server
├── tests/          # Unit and integration tests
├── tools/          # Certificate generation utilities
└── third_party/    # mbedTLS library
```

## Building from Source
### Prerequisites
* Cmake 3.10+
* C99 compiler (gcc, clang)
* Python 3.7+ (for test server and cert generation)
* Git (for submodules)

### Build Options
```bash
cmake .. -DSTATIC_BUILD=ON    # Static linking (default: ON)
         -DWITH_TLS=ON         # Enable TLS support (default: ON)
         -DDEBUG=ON            # Debug build (default: OFF)
         -DENABLE_TESTS=ON     # Build tests (default: ON)
```

## Module Documentation
### TLS Client (`src/tls_client.h`)
Handles TLS connection establishment, certificate validation, and secure communication

### Key Store (`src/key_store.h`)
Simulates flash-based storage for device certificates and private keys

### Message Protocol (`src/msg_protocol.h`)
Formats and parses telemetry messages (JSON format)

## Testing
Includes comprehensive test coverage:
* **Unit Tests:** Test individual modules
* **Integration Tests:** Full TLS handshake and communication
* **Security Tests:** Certificate validation, expired certs, wrong CA

Run all tests:
```bash
make test
```

Run specific test:
```bash
./tests/test_mtls_connection
```

## Security Considerations
* Certificates are validated against trusted CA
* Private keys are zeroed after use
* Constant-time comparison for sensitive operations
* No dynamic memory allocation reduces attack surface
* All return values checked

## Contributing
See CONTRIBUTING.md for development standards and guidelines

## License
MIT License - See LICENSE file for details

## Author
Ryan Tobin

## Acknowledgments
* mbedTLS for the TLS implementation
* MISRA-C for guidelines for secure coding practices