from pathlib import Path

from cryptography import x509


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


def main() -> None:
    write_log("Certificate Inspector started.")
    write_log("Checking trusted CA and server certificate...")

    ca_certificate = load_certificate("ca_cert.pem")
    server_certificate = load_certificate("server_cert.pem")

    write_log("CA certificate loaded successfully.")
    write_log("Server certificate loaded successfully.")


if __name__ == "__main__":
    main()