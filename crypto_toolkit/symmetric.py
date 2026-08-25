"""
Symmetric encryption: AES-256-GCM via the `cryptography` library.

This module deliberately does NOT implement AES itself — rolling your
own AES is a well-known way to end up with a broken cipher. The point
here is correct *usage*: key derivation, nonce handling, and why GCM
(authenticated encryption) is preferred over unauthenticated modes
like plain CBC.

File format written by encrypt_file():
    [16 bytes salt][12 bytes nonce][ciphertext + 16-byte GCM tag]
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

SALT_SIZE = 16
NONCE_SIZE = 12  # 96 bits — the recommended nonce size for AES-GCM
KEY_SIZE = 32  # AES-256
PBKDF2_ITERATIONS = 600_000  # OWASP-recommended floor as of 2023+ guidance


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from a password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    """
    Encrypt bytes with AES-256-GCM. A fresh random salt and nonce are
    generated per call — reusing a nonce with the same key breaks GCM's
    security guarantees, so we never let the caller supply one.
    """
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    return salt + nonce + ciphertext


def decrypt_bytes(blob: bytes, password: str) -> bytes:
    """
    Decrypt bytes produced by encrypt_bytes(). Raises
    cryptography.exceptions.InvalidTag if the password is wrong or the
    data was tampered with — GCM's built-in authentication catches both.
    """
    if len(blob) < SALT_SIZE + NONCE_SIZE:
        raise ValueError("Data too short to contain salt + nonce + ciphertext")

    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = blob[SALT_SIZE + NONCE_SIZE:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)


def encrypt_file(input_path: str, output_path: str, password: str) -> None:
    with open(input_path, "rb") as f:
        plaintext = f.read()
    blob = encrypt_bytes(plaintext, password)
    with open(output_path, "wb") as f:
        f.write(blob)


def decrypt_file(input_path: str, output_path: str, password: str) -> None:
    with open(input_path, "rb") as f:
        blob = f.read()
    plaintext = decrypt_bytes(blob, password)
    with open(output_path, "wb") as f:
        f.write(plaintext)