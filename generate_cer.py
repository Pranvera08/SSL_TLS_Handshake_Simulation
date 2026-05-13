from datetime import datetime, timedelta, timezone
from importlib.resources import path
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


BASE_DIR = Path(__file__).resolve().parent
CERT_DIR = BASE_DIR / "certificates"



def write_private_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

def write_certificate(path: Path, certificate: x509.Certificate) -> None:
path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


def main() -> None:
    CERT_DIR.mkdir(exist_ok=True)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    now = datetime.now(timezone.utc)

    ca_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "AL"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Demo University"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Demo University Trusted CA"),
        ]
    )

  ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                content_commitment=False,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )
 server_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "AL"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SSL TLS Simulation Server"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]
    )

server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.DNSName("127.0.0.1"),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                content_commitment=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    write_private_key(CERT_DIR / "ca_key.pem", ca_key)
    write_certificate(CERT_DIR / "ca_cert.pem", ca_cert)
    write_private_key(CERT_DIR / "server_key.pem", server_key)
    write_certificate(CERT_DIR / "server_cert.pem", server_cert)

    print("Certificates generated successfully.")
    print(f"CA certificate: {CERT_DIR / 'ca_cert.pem'}")
    print(f"Server certificate: {CERT_DIR / 'server_cert.pem'}")


if __name__ == "__main__":
    main()