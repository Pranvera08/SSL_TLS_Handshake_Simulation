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