import argparse
import base64
import json
import os
import socket
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


BASE_DIR = Path(__file__).resolve().parents[1]
CERT_DIR = BASE_DIR / "certificates"
LOG_DIR = BASE_DIR / "logs"

HOST = "127.0.0.1"
PORT = 8443

def write_log(message):
    LOG_DIR.mkdir(exist_ok=True)
    with (LOG_DIR / "server_log.txt").open("a", encoding="utf-8") as file:
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


    def load_server_private_key():
        key_path = CERT_DIR / "server_key.pem"
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)

    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("Server private key must be RSA.")

    return key


def load_server_certificate(tamper_cert=False):
    certificate_path = CERT_DIR / "server_cert.pem"
    certificate_pem = certificate_path.read_text(encoding="ascii")

    if not tamper_cert:
        return certificate_pem

    original_certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
    fake_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Krijohet nje certifikate e rreme per testim.
    fake_certificate = (
        x509.CertificateBuilder()
        .subject_name(original_certificate.subject)
        .issuer_name(original_certificate.issuer)
        .public_key(original_certificate.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(original_certificate.not_valid_before_utc)
        .not_valid_after(original_certificate.not_valid_after_utc)
        .sign(private_key=fake_key, algorithm=hashes.SHA256())
    )

    return fake_certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")

def public_key_to_pem(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def public_key_from_pem(public_key_pem):
    public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))

    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise TypeError("ECDH public key expected.")

    return public_key


def sign_server_key_exchange(private_key, payload):
    signature = private_key.sign(
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return b64encode(signature)


def derive_session_key(shared_secret, client_nonce, server_nonce):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=(client_nonce + server_nonce).encode("utf-8"),
        info=b"ssl-tls-simulation-session-key",
    )
    return hkdf.derive(shared_secret)

def encrypt_message(session_key, plaintext):
    aesgcm = AESGCM(session_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    return {
        "nonce": b64encode(nonce),
        "ciphertext": b64encode(ciphertext),
    }


def decrypt_message(session_key, payload):
    aesgcm = AESGCM(session_key)
    nonce = b64decode(payload["nonce"])
    ciphertext = b64decode(payload["ciphertext"])
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")