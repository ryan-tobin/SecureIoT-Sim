#!/usr/bin/env python3
"""
gen_cert.py - X.509 certificate generator for SecureIoT-Sim

Generates CA, server, and device certificates for testing TLS/mTLS.

Author: Ryan Tobin
Date: 2025
"""

import os
import sys
import argparse
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from ipaddress import ip_address

def generate_private_key(key_size=2048):
    """Generate RSA private key"""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

def save_private_key(key, filename, password=None):
    """Save private key to PEM file"""
    encryption = serialization.NoEncryption()
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode())
    
    with open(filename, 'wb') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption,
        ))
    print(f"Saved private key: {filename}")

def save_certificate(cert, filename):
    """Save certificate to PEM file"""
    with open(filename, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Saved certificate: {filename}")

def generate_ca_certificate(cn="SecureIoT-Sim CA", valid_days=3650):
    """Generate self-signed CA certificate"""
    print("\nGenerating CA certificate...")
    
    # Generate private key
    ca_key = generate_private_key()
    
    # Create certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Test State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Test City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureIoT-Sim"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=valid_days)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).sign(ca_key, hashes.SHA256())
    
    return ca_key, cert

def generate_certificate(cn, ca_key, ca_cert, is_server=False, valid_days=365, 
                        san_dns=None, san_ip=None):
    """Generate certificate signed by CA"""
    print(f"\nGenerating {'server' if is_server else 'client'} certificate for: {cn}")
    
    # Generate private key
    key = generate_private_key()
    
    # Create certificate
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Test State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Test City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureIoT-Sim"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    
    builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=valid_days)
    )
    
    # Add extensions
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    
    # Key usage
    if is_server:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_agreement=True,
                content_commitment=False,
                data_encipherment=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=True,
        )
    else:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True,
        )
    
    # Subject Alternative Names
    san_list = []
    if san_dns:
        for dns in san_dns:
            san_list.append(x509.DNSName(dns))
    if san_ip:
        for ip in san_ip:
            san_list.append(x509.IPAddress(ip_address(ip)))
    
    if san_list:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        )
    
    cert = builder.sign(ca_key, hashes.SHA256())
    
    return key, cert

def generate_expired_certificate(cn, ca_key, ca_cert):
    """Generate an expired certificate for testing"""
    print(f"\nGenerating expired certificate for: {cn}")
    
    key = generate_private_key()
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureIoT-Sim"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    
    # Certificate valid in the past
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=400)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=30)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).sign(ca_key, hashes.SHA256())
    
    return key, cert

def main():
    parser = argparse.ArgumentParser(description='Generate X.509 certificates for SecureIoT-Sim')
    parser.add_argument('--output-dir', default='../certs', help='Output directory')
    parser.add_argument('--ca-days', type=int, default=3650, help='CA validity days')
    parser.add_argument('--cert-days', type=int, default=365, help='Certificate validity days')
    parser.add_argument('--generate-test-certs', action='store_true', 
                       help='Generate additional test certificates (expired, etc.)')
    
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Generate CA
    ca_key, ca_cert = generate_ca_certificate(valid_days=args.ca_days)
    save_private_key(ca_key, os.path.join(args.output_dir, 'ca_key.pem'))
    save_certificate(ca_cert, os.path.join(args.output_dir, 'ca_cert.pem'))
    
    # Generate server certificate
    server_key, server_cert = generate_certificate(
        "secureiot-server",
        ca_key, ca_cert,
        is_server=True,
        valid_days=args.cert_days,
        san_dns=["localhost", "secureiot-server"],
        san_ip=["127.0.0.1", "::1"]
    )
    save_private_key(server_key, os.path.join(args.output_dir, 'server_key.pem'))
    save_certificate(server_cert, os.path.join(args.output_dir, 'server_cert.pem'))
    
    # Generate device certificate
    device_key, device_cert = generate_certificate(
        "device-001",
        ca_key, ca_cert,
        is_server=False,
        valid_days=args.cert_days
    )
    save_private_key(device_key, os.path.join(args.output_dir, 'device_key.pem'))
    save_certificate(device_cert, os.path.join(args.output_dir, 'device_cert.pem'))
    
    # Generate test certificates if requested
    if args.generate_test_certs:
        # Expired certificate
        expired_key, expired_cert = generate_expired_certificate("device-expired", ca_key, ca_cert)
        save_private_key(expired_key, os.path.join(args.output_dir, 'device_expired_key.pem'))
        save_certificate(expired_cert, os.path.join(args.output_dir, 'device_expired_cert.pem'))
        
        # Different CA for testing
        ca2_key, ca2_cert = generate_ca_certificate(cn="Untrusted CA", valid_days=args.ca_days)
        save_private_key(ca2_key, os.path.join(args.output_dir, 'untrusted_ca_key.pem'))
        save_certificate(ca2_cert, os.path.join(args.output_dir, 'untrusted_ca_cert.pem'))
        
        # Certificate from different CA
        wrong_ca_key, wrong_ca_cert = generate_certificate(
            "device-wrong-ca",
            ca2_key, ca2_cert,
            is_server=False,
            valid_days=args.cert_days
        )
        save_private_key(wrong_ca_key, os.path.join(args.output_dir, 'device_wrong_ca_key.pem'))
        save_certificate(wrong_ca_cert, os.path.join(args.output_dir, 'device_wrong_ca_cert.pem'))
    
    print(f"\nCertificates generated in: {args.output_dir}")
    print("\nTo view a certificate:")
    print(f"  openssl x509 -in {args.output_dir}/device_cert.pem -text -noout")

if __name__ == '__main__':
    main()