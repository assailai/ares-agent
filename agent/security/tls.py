"""
Ares Docker Agent - TLS Certificate Generation
"""
import os
from datetime import datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from agent.config import settings


def generate_self_signed_cert(
    cert_path: Path = None,
    key_path: Path = None,
    common_name: str = "Ares Docker Agent",
    valid_days: int = 365
) -> tuple:
    """
    Generate a self-signed TLS certificate.
    Returns (cert_path, key_path)
    """
    cert_path = cert_path or settings.tls_cert_path
    key_path = key_path or settings.tls_key_path

    # Ensure directory exists
    cert_path.parent.mkdir(parents=True, exist_ok=True)

    # Generate RSA private key (4096 bits)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )

    # Certificate subject and issuer
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Ares Enterprise"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Docker Agent"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    # Build certificate
    now = datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=valid_days))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("ares-agent"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
                key_cert_sign=False,
                crl_sign=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    # Write private key
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    os.chmod(key_path, 0o600)  # Restrict permissions

    # Write certificate
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(cert_path, 0o644)

    return cert_path, key_path


def cert_exists() -> bool:
    """Check if TLS certificate already exists"""
    return settings.tls_cert_path.exists() and settings.tls_key_path.exists()


def ensure_tls_cert():
    """Ensure TLS certificate exists, generate if needed"""
    if not cert_exists():
        generate_self_signed_cert()


# Import for IP address handling
import ipaddress
