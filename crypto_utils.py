import base64
import json
import os
import socket
import struct
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


REALM = "KERBEROS-DEMO.UNB"
KDF_ITERATIONS = 200_000
AES_KEY_SIZE_BYTES = 32
AES_GCM_NONCE_SIZE_BYTES = 12
MAX_CLOCK_SKEW_SECONDS = 120


def now_ts():
    return int(time.time())


def is_timestamp_fresh(timestamp, max_skew_seconds=MAX_CLOCK_SKEW_SECONDS):
    return abs(now_ts() - int(timestamp)) <= max_skew_seconds


def b64_encode(raw_bytes):
    return base64.b64encode(raw_bytes).decode("ascii")


def b64_decode(text):
    return base64.b64decode(text.encode("ascii"))


def generate_symmetric_key():
    return os.urandom(AES_KEY_SIZE_BYTES)


def derive_client_key(username, password):
    salt = f"{REALM}:{username}".encode("utf-8")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE_BYTES,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )

    return kdf.derive(password.encode("utf-8"))


def encrypt_json(key, payload):
    nonce = os.urandom(AES_GCM_NONCE_SIZE_BYTES)
    plaintext = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    return {
        "nonce": b64_encode(nonce),
        "ciphertext": b64_encode(ciphertext),
    }


def decrypt_json(key, encrypted_payload):
    nonce = b64_decode(encrypted_payload["nonce"])
    ciphertext = b64_decode(encrypted_payload["ciphertext"])

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return json.loads(plaintext.decode("utf-8"))


def send_json(sock, payload):
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    size = struct.pack("!I", len(data))
    sock.sendall(size + data)


def recv_exact(sock, size):
    chunks = []

    while size > 0:
        chunk = sock.recv(size)

        if not chunk:
            raise ConnectionError("Conexao encerrada antes de receber todos os dados.")

        chunks.append(chunk)
        size -= len(chunk)

    return b"".join(chunks)


def recv_json(sock):
    size_data = recv_exact(sock, 4)
    size = struct.unpack("!I", size_data)[0]
    data = recv_exact(sock, size)

    return json.loads(data.decode("utf-8"))


def send_request(host, port, payload):
    with socket.create_connection((host, port), timeout=10) as sock:
        send_json(sock, payload)
        return recv_json(sock)


def key_to_text(key):
    return b64_encode(key)


def key_from_text(text):
    return b64_decode(text)


if __name__ == "__main__":
    test_key = derive_client_key("alice", "alice123")
    encrypted = encrypt_json(test_key, {"mensagem": "teste"})
    decrypted = decrypt_json(test_key, encrypted)

    print("crypto_utils OK")
    print(decrypted)
