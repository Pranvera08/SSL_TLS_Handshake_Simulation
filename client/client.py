import base64
import json
import os
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import ExtensionOID, NameOID

BASE_DIR = Path(__file__).resolve().parents[1]
CERT_DIR = BASE_DIR / "certificates"
LOG_DIR = BASE_DIR / "logs"

HOST = "127.0.0.1"
PORT = 8443
EXPECTED_SERVER_NAME = "localhost"

class SecurityError(Exception):
    pass

def write_log(message):
    LOG_DIR.mkdir(exist_ok=True)
    with (LOG_DIR / "client_log.txt").open("a", encoding="utf-8") as file:
        file.write(message + "\n")
    print(message)

def b64encode(data):
    return base64.b64encode(data).decode("ascii")

def b64decode(data):
    return base64.b64decode(data.encode("ascii"))

def send_message(sock, message_type, **fields):
    message = {"type": message_type, **fields}
    data = json.dumps(message, separators=(",", ":")).encode("utf-8") + b"\n"
    sock.sendall(data)

def receive_message(sock):
    buffer = bytearray()
    while True:
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("Connection closed by peer")
        if chunk == b"\n":
            return json.loads(buffer.decode("utf-8"))
        buffer.extend(chunk)

def require_type(message, expected_type):
    received_type = message.get("type")
    if received_type != expected_type:
        raise ValueError(f"Expected {expected_type}, received {received_type}")

def load_trusted_ca_certificate():
    ca_path = CERT_DIR / "ca_cert.pem"
    return x509.load_pem_x509_certificate(ca_path.read_bytes())

def verify_server_certificate(certificate_pem):
    ca_certificate = load_trusted_ca_certificate()
    server_certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
    now = datetime.now(timezone.utc)

    if not (server_certificate.not_valid_before_utc <= now <= server_certificate.not_valid_after_utc):
        raise SecurityError("Server certificate is expired or not yet valid.")

    common_names = server_certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    common_name_valid = any(name.value == EXPECTED_SERVER_NAME for name in common_names)

    try:
        san_extension = server_certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        san_names = san_extension.value.get_values_for_type(x509.DNSName)
        san_valid = EXPECTED_SERVER_NAME in san_names
    except x509.ExtensionNotFound:
        san_valid = False

    if not (common_name_valid or san_valid):
        raise SecurityError("Server certificate subject does not match localhost.")

    ca_public_key = ca_certificate.public_key()
    if not isinstance(ca_public_key, rsa.RSAPublicKey):
        raise SecurityError("Trusted CA public key is not RSA.")

    try:
        ca_public_key.verify(
            server_certificate.signature,
            server_certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            server_certificate.signature_hash_algorithm,
        )
    except InvalidSignature as exc:
        raise SecurityError("Server certificate signature is invalid.") from exc

    return server_certificate