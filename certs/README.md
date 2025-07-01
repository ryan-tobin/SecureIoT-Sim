# Certificates Directory
This directory contains X.509 certificates and private keys for testing TLS/mTLS connections

## Files
After running `python3 ../tools/gen_cert.py``, this directory will contain:

### Core Certificates
* `ca_cert.pem` - Certificate Authority (CA) certificate
* `ca_key.pem` - CA private key
* `server_cert.pem` - TLS server certificate
* `server_key.pem` - Server private key
* `device_cert.pem` - IoT device client certificate
* `device_key.pem` - Device private key

### Test certificates (with --generate-test-certs)
* `device_expired_cert.pem` - Expired device certificate
* `device_expired_key.pem` - Key for expired certificate
* `untrusted_ca_cert.pem` - Different CA for testing
* `untrusted_ca_key.pem` - Untrusted CA key
* `device_wrong_ca_cert.pem` - Certificate from wrong CA
* `device_wrong_ca_key.pem` - Key for wrong CA certificate

## Security Note
These certificates are for **testing only.** Never use them in production environments

## Viewing Certificates
To view certificate details:
```bash
openssl x509 -in device_cert.pem -text -noout
```

To verify certificate chain:
```bash
openssl verify -CAfile ca_cert.pem device_cert.pem
```