# Importet nga libraria cryptography për menaxhimin e certifikatave X.509 dhe çelësave RSA
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# Përcaktimi i direktorisë ku do të ruhen certifikatat
BASE_DIR = Path(__file__).resolve().parent
CERT_DIR = BASE_DIR / "certificates"

# Funksion për të shkruar çelësin privat në një skedar .pem
def write_private_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

# Funksion për të shkruar certifikatën publike në një skedar .pem
def write_certificate(path: Path, certificate: x509.Certificate) -> None:
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


def main() -> None:
    # Krijon dosjen "certificates" nëse nuk ekziston
    CERT_DIR.mkdir(exist_ok=True)

    # 1. GJENERIMI I ÇELËSAVE RSA (2048-bit)
    # Gjeneron çelësin për Autoritetin Certifikues (CA)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Gjeneron çelësin për Serverin tonë
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    now = datetime.now(timezone.utc)



    # 2. KRIJIMI I CERTIFIKATËS SË CA (ROOT CA)
    # Përcaktimi i identitetit të Autoritetit Certifikues
    ca_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "AL"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Demo University"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Demo University Trusted CA"),
        ]
    )

    # Ndërtimi i certifikatës vetë-nënshkruar të CA-së
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject) # Pasi është Root CA, lëshuesi është vetvetja
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)) # Vlefshmëria fillon dje
        .not_valid_after(now + timedelta(days=365)) # Vlefshmëria zgjat 1 vit
        # Specifikon që kjo certifikatë ËSHTË një CA (mund të nënshkruajë të tjera)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True, # Lejon nënshkrimin e certifikatave të tjera
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
        .sign(private_key=ca_key, algorithm=hashes.SHA256()) # Nënshkruhet me çelësin e vetë CA-së
    )

    server_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "AL"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SSL TLS Simulation Server"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]
    )

    # 3. KRIJIMI I CERTIFIKATËS SË SERVERIT (E nënshkruar nga CA)
    # Përcaktimi i identitetit të Serverit (p.sh. localhost)

    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_subject) # Lëshuesi është CA-ja që krijuam më lart
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90)) # Certifikata e serverit zgjat 90 ditë
        # Specifikon që kjo NUK është një CA
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        # SAN (Subject Alternative Name) - e nevojshme për browser-at modernë
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
                key_encipherment=True, # Lejon enkriptimin e çelësave për TLS
                data_encipherment=False,
                key_agreement=False,
                content_commitment=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        # E rëndësishme: Nënshkruhet me çelësin privat të CA-së (ca_key)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    # 4. RUAJTJA E SKEDARËVE
    write_private_key(CERT_DIR / "ca_key.pem", ca_key)      # Ruajmë çelësin e CA
    write_certificate(CERT_DIR / "ca_cert.pem", ca_cert)    # Ruajmë certifikatën e CA
    write_private_key(CERT_DIR / "server_key.pem", server_key) # Ruajmë çelësin e Serverit
    write_certificate(CERT_DIR / "server_cert.pem", server_cert) # Ruajmë certifikatën e Serverit

    print("Certificates generated successfully.")
    print(f"CA certificate: {CERT_DIR / 'ca_cert.pem'}")
    print(f"Server certificate: {CERT_DIR / 'server_cert.pem'}")

if __name__ == "__main__":
    main()