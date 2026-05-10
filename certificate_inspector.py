from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID


BASE_DIR = Path(__file__).resolve().parent
CERT_DIR = BASE_DIR / "certificates"
LOG_DIR = BASE_DIR / "logs"


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

    ca_certificate = load_certificate("ca_cert.pem")
    server_certificate = load_certificate("server_cert.pem")

    print_certificate_details("Trusted CA Certificate", ca_certificate)
    print_certificate_details("Server Certificate", server_certificate)


if __name__ == "__main__":
    main()