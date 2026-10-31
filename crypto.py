"""
crypto.py  --  Security layer for "Image Steganography with Encrypted Messages"
Owner: Member 1

Public interface (the only things other modules should use):
    encrypt_message(message: str, password: str) -> bytes
    decrypt_message(payload: bytes, password: str) -> str
    DecryptionError            (raised on ANY decryption failure)
    OVERHEAD_BYTES             (payload size = len(message in UTF-8) + OVERHEAD_BYTES)
    payload_size(message)      (exact payload length for a given message, for capacity checks)

Payload layout (opaque bytes as far as steganography.py is concerned):

    +---------+-----------+-----------+--------------------------------+
    | version |   salt    |   nonce   |  ciphertext  ||  GCM tag       |
    | 1 byte  |  16 bytes | 12 bytes  |  len(msg)    ||  16 bytes      |
    +---------+-----------+-----------+--------------------------------+

Design:
  * AES-256-GCM  : authenticated encryption (confidentiality + integrity).
  * PBKDF2-HMAC-SHA256 with a random per-message salt derives the key from the password.
  * Random 96-bit nonce per message (never reused with the same key).
  * The version byte is passed to GCM as Associated Data, so it is authenticated too.
"""

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ---------------------------------------------------------------- constants
VERSION = b"\x01"          # format version / magic byte
VERSION_LEN = 1
SALT_LEN = 16              # 128-bit salt
NONCE_LEN = 12             # 96-bit nonce (recommended size for GCM)
TAG_LEN = 16               # 128-bit GCM authentication tag
KEY_LEN = 32               # 256-bit AES key
ITERATIONS = 200_000       # PBKDF2 work factor

# Bytes added on top of the UTF-8 message: 1 + 16 + 12 + 16 = 45
OVERHEAD_BYTES = VERSION_LEN + SALT_LEN + NONCE_LEN + TAG_LEN


class DecryptionError(Exception):
    """Raised on wrong password, tampered data, or malformed payload.

    A single exception type is used on purpose: callers need only one
    `except DecryptionError`, and the message never reveals *why* it failed
    (wrong password and tampering look identical to an attacker).
    """


# ------------------------------------------------------------------ helpers
def _derive_key(password: str, salt: bytes) -> bytes:
    """Stretch a password into a 256-bit AES key using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def payload_size(message: str) -> int:
    """Exact size in bytes of the payload `encrypt_message` will return.

    Member 2 / Member 3 can call this to check image capacity BEFORE encrypting.
    """
    return len(message.encode("utf-8")) + OVERHEAD_BYTES


# --------------------------------------------------------------- public API
def encrypt_message(message: str, password: str) -> bytes:
    """Encrypt `message` with a key derived from `password`.

    Returns:
        bytes: version | salt | nonce | ciphertext+tag  (ready to be embedded)

    Raises:
        TypeError:  if message or password is not a str
        ValueError: if password is empty
    """
    if not isinstance(message, str):
        raise TypeError("message must be a str")
    if not isinstance(password, str):
        raise TypeError("password must be a str")
    if not password:
        raise ValueError("Password must not be empty")

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(password, salt)

    # AAD = version byte -> authenticated but not encrypted
    ciphertext = AESGCM(key).encrypt(nonce, message.encode("utf-8"), VERSION)
    return VERSION + salt + nonce + ciphertext


def decrypt_message(payload: bytes, password: str) -> str:
    """Decrypt a payload produced by `encrypt_message`.

    Returns:
        str: the original message

    Raises:
        DecryptionError: wrong password, tampered/corrupted payload, wrong
                         format, or payload that is not a stego payload at all.
    """
    if not isinstance(payload, (bytes, bytearray)):
        raise DecryptionError("Payload must be bytes")
    if not isinstance(password, str) or not password:
        raise DecryptionError("A password is required")

    payload = bytes(payload)

    if len(payload) < OVERHEAD_BYTES:
        raise DecryptionError("Payload too short or corrupted")

    version = payload[:VERSION_LEN]
    if version != VERSION:
        raise DecryptionError("Unrecognised payload format")

    offset = VERSION_LEN
    salt = payload[offset:offset + SALT_LEN]
    offset += SALT_LEN
    nonce = payload[offset:offset + NONCE_LEN]
    offset += NONCE_LEN
    ciphertext = payload[offset:]          # includes the 16-byte GCM tag

    key = _derive_key(password, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, version)
        return plaintext.decode("utf-8")
    except (InvalidTag, UnicodeDecodeError):
        raise DecryptionError("Wrong password or data was tampered with") from None


if __name__ == "__main__":
    # Quick demo:  python crypto.py
    secret = "Meet at the library at 5pm"
    blob = encrypt_message(secret, "correct horse battery staple")
    print(f"Payload ({len(blob)} bytes): {blob.hex()[:64]}...")
    print("Decrypted:", decrypt_message(blob, "correct horse battery staple"))
    try:
        decrypt_message(blob, "wrong password")
    except DecryptionError as e:
        print("Wrong password ->", e)
