from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtensionOID, NameOID


BASE_DIR = Path(__file__).resolve().parent
CERT_DIR = BASE_DIR / "certificates"
LOG_DIR = BASE_DIR / "logs"
EXPECTED_SERVER_NAME = "localhost"


class CertificateValidationError(Exception):
    pass

def write_log(message: str) -> None:
    LOG_DIR.mkdir(exist_ok=True)
    with (LOG_DIR / "certificate_inspector_log.txt").open("a", encoding="utf-8") as file:
        file.write(message + "\n")
    print(message)


def load_certificate(filename: str) -> x509.Certificate:
    path = CERT_DIR / filename
    if not path.exists():
        raise FileNotFoundError(f"Certificate not found: {path}")
    return x509.load_pem_x509_certificate(path.read_bytes())


def get_common_name(certificate: x509.Certificate) -> str:
    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not common_names:
        return "N/A"
    return common_names[0].value


def get_dns_names(certificate: x509.Certificate) -> list[str]:
    try:
        extension = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        return extension.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return []


def verify_validity_period(certificate: x509.Certificate) -> None:
    now = datetime.now(timezone.utc)
    if not (certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc):
        raise CertificateValidationError("Certificate is expired or not yet valid.")


def verify_server_identity(certificate: x509.Certificate) -> None:
    common_name_valid = get_common_name(certificate) == EXPECTED_SERVER_NAME
    dns_names = get_dns_names(certificate)
    san_valid = EXPECTED_SERVER_NAME in dns_names

    if not (common_name_valid or san_valid):
        raise CertificateValidationError("Certificate identity does not match localhost.")


def verify_ca_signature(ca_certificate: x509.Certificate, server_certificate: x509.Certificate) -> None:
    ca_public_key = ca_certificate.public_key()
    if not isinstance(ca_public_key, rsa.RSAPublicKey):
        raise CertificateValidationError("Trusted CA public key is not RSA.")

    try:
        ca_public_key.verify(
            server_certificate.signature,
            server_certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            server_certificate.signature_hash_algorithm,
        )
    except InvalidSignature as exc:
        raise CertificateValidationError("Server certificate signature is invalid.") from exc


def print_certificate_details(title: str, certificate: x509.Certificate) -> None:
    write_log(f"\n=== {title} ===")
    write_log(f"Subject CN: {get_common_name(certificate)}")
    write_log(f"Issuer: {certificate.issuer.rfc4514_string()}")
    write_log(f"Serial Number: {certificate.serial_number}")
    write_log(f"Valid From: {certificate.not_valid_before_utc}")
    write_log(f"Valid To: {certificate.not_valid_after_utc}")

    dns_names = get_dns_names(certificate)
    if dns_names:
        write_log(f"Subject Alternative Names: {', '.join(dns_names)}")


def main() -> None:
    write_log("Certificate Inspector started.")
    write_log("Checking trusted CA and server certificate...")

    try:
        ca_certificate = load_certificate("ca_cert.pem")
        server_certificate = load_certificate("server_cert.pem")

        print_certificate_details("Trusted CA Certificate", ca_certificate)
        print_certificate_details("Server Certificate", server_certificate)

        write_log("\nVerification steps:")

        verify_validity_period(server_certificate)
        write_log("[OK] Certificate validity period is correct.")

        verify_server_identity(server_certificate)
        write_log("[OK] Certificate identity matches localhost.")

        verify_ca_signature(ca_certificate, server_certificate)
        write_log("[OK] Server certificate was signed by the trusted CA.")

        write_log("\nResult: Server certificate is valid and trusted.")

    except Exception as exc:
        write_log(f"\nResult: Certificate verification failed: {exc}")




if __name__ == "__main__":
    main()