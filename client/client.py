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

def public_key_to_pem(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

def public_key_from_pem(public_key_pem):
    public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise SecurityError("ECDH public key expected.")
    return public_key

def verify_server_key_exchange(certificate, ecdh_public_key_pem, client_nonce, server_nonce, signature_b64):
    public_key = certificate.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise SecurityError("Server certificate public key is not RSA.")

    try:
        public_key.verify(
            b64decode(signature_b64),
            (ecdh_public_key_pem + client_nonce + server_nonce).encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise SecurityError("Server Key Exchange signature is invalid.") from exc

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

def transcript_hash(*parts):
    digest = hashes.Hash(hashes.SHA256())
    for part in parts:
        digest.update(part.encode("utf-8"))
    return b64encode(digest.finalize())

def main():
    if not (CERT_DIR / "ca_cert.pem").exists():
        print("CA certificate not found. Run first: py generate_cer.py")
        sys.exit(1)

    try:
        write_log("Welcome to the SSL/TLS Handshake Simulation Client.")
        write_log("Attempting to establish a secure connection with the server...")

        with socket.create_connection((HOST, PORT), timeout=10) as sock:
            client_nonce = b64encode(os.urandom(16))

            send_message(
                sock,
                "CLIENT_HELLO",
                version="TLS 1.3 simulated",
                cipher_suites=["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"],
                nonce=client_nonce,
            )
            write_log("Client Hello sent.")

            server_hello = receive_message(sock)
            require_type(server_hello, "SERVER_HELLO")
            server_nonce = server_hello["nonce"]
            write_log(f"Server Hello received. Cipher suite: {server_hello['cipher_suite']}")

            certificate_message = receive_message(sock)
            require_type(certificate_message, "CERTIFICATE")
            write_log("Server certificate received. Verifying...")

            server_certificate = verify_server_certificate(certificate_message["certificate_pem"])
            write_log("Server certificate is valid.")

            server_key_exchange = receive_message(sock)
            require_type(server_key_exchange, "SERVER_KEY_EXCHANGE")

            verify_server_key_exchange(
                server_certificate,
                server_key_exchange["ecdh_public_key_pem"],
                client_nonce,
                server_nonce,
                server_key_exchange["signature"],
            )
            write_log("Server Key Exchange signature verified.")

            server_ecdh_public_key = public_key_from_pem(server_key_exchange["ecdh_public_key_pem"])

            certificate_request = receive_message(sock)
            require_type(certificate_request, "CERTIFICATE_REQUEST")
            write_log("Certificate Request received.")

            server_hello_done = receive_message(sock)
            require_type(server_hello_done, "SERVER_HELLO_DONE")
            write_log("Server Hello Done received.")

            send_message(sock, "CLIENT_CERTIFICATE", mode="anonymous-demo-client")
            write_log("Client Certificate message sent.")

            client_ecdh_private_key = ec.generate_private_key(ec.SECP256R1())
            client_ecdh_public_pem = public_key_to_pem(client_ecdh_private_key.public_key())

            send_message(
                sock,
                "CLIENT_KEY_EXCHANGE",
                ecdh_public_key_pem=client_ecdh_public_pem,
            )
            write_log("Client Key Exchange sent.")

            shared_secret = client_ecdh_private_key.exchange(ec.ECDH(), server_ecdh_public_key)
            session_key = derive_session_key(shared_secret, client_nonce, server_nonce)
            write_log("Derived symmetric AES session key.")

            send_message(sock, "CERTIFICATE_VERIFY", status="server-certificate-verified")
            write_log("Certificate Verify sent.")

            send_message(sock, "CHANGE_CIPHER_SPEC")
            write_log("Change Cipher Spec sent.")

            transcript = transcript_hash(
                client_nonce,
                server_nonce,
                certificate_message["certificate_pem"],
                server_key_exchange["ecdh_public_key_pem"],
            )

            send_message(sock, "FINISHED", transcript_hash=transcript)
            write_log("Finished message sent.")

            server_change_cipher_spec = receive_message(sock)
            require_type(server_change_cipher_spec, "CHANGE_CIPHER_SPEC")

            server_finished = receive_message(sock)
            require_type(server_finished, "FINISHED")

            if server_finished["transcript_hash"] != transcript:
                raise SecurityError("Finished transcript hash mismatch.")

            write_log("SSL/TLS handshake successful. Secure communication channel established.")

            secure_payload = encrypt_message(session_key, "Pershendetje nga klienti!")
            send_message(sock, "SECURE_DATA", payload=secure_payload)
            write_log("Encrypted application data sent to server.")

            secure_response = receive_message(sock)
            require_type(secure_response, "SECURE_DATA")
            plaintext_response = decrypt_message(session_key, secure_response["payload"])
            write_log(f"Secure server response: {plaintext_response}")

    except Exception as error:
        write_log(f"Handshake failed: {error}")

if __name__ == "__main__":
    main()