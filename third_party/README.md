# Third Party Libraries
This directory contains third-party libraries used by SecureIoT-Sim

## mbedTLS
The proect uses mbedTLS for TLS/mTLS implementation. It is included as a git submodule

### Setup
To initialize the mbedTLS submodule:
```bash
git submodule update --init --recursive
```
### Building
To build mbedTLS as a new static library:
```bash
cd mbedtls
make lib SHARED=0
```
### Version
The project is configured to use mbedTLS version v3.6.4. To update:
```bash
cd mbedtls
git checkout v.3.6.4
cd ..
git add mbedtls
git commit -m "Update mbedTLS to v3.6.4"
```

### License
mbedTLS is distributed under the Apache License 2.0. See the LICENSE file in the mbedtls directory for details.

## Adding new Libraries
When adding new third-party libraries:
1. Prefer git submodules for source dependencies
2. Document the version used
3. Include build instructions
4. Note the license
5. Update the main CMakeLists.txt file