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