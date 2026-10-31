"""Unit tests for crypto.py  (run from project root:  pytest tests/test_crypto.py -v)"""

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from crypto import (  # noqa: E402
    OVERHEAD_BYTES,
    DecryptionError,
    decrypt_message,
    encrypt_message,
    payload_size,
)

PASSWORD = "s3cret-Pa$$word"
MESSAGE = "Hello, this is a secret message."


# ------------------------------------------------------ 1. round trip
def test_round_trip():
    payload = encrypt_message(MESSAGE, PASSWORD)
    assert decrypt_message(payload, PASSWORD) == MESSAGE


@pytest.mark.parametrize(
    "msg",
    [
        "",                                   # empty string
        "a",                                  # single character
        "नमस्ते, दुनिया",                      # Devanagari
        "héllo wörld ñ ü",                    # accented Latin
        "Secret 🔐🕵️‍♂️ message 🎉",             # emoji
        "line1\nline2\ttabbed\r\n",           # whitespace / control chars
        "A" * 100_000,                        # long message
    ],
)
def test_round_trip_varied_messages(msg):
    assert decrypt_message(encrypt_message(msg, PASSWORD), PASSWORD) == msg


def test_unicode_password():
    pw = "पासवर्ड🔑"
    assert decrypt_message(encrypt_message(MESSAGE, pw), pw) == MESSAGE


# ------------------------------------------------------ 2. wrong password
def test_wrong_password_raises():
    payload = encrypt_message(MESSAGE, PASSWORD)
    with pytest.raises(DecryptionError):
        decrypt_message(payload, "not-the-password")


def test_password_is_case_sensitive():
    payload = encrypt_message(MESSAGE, "Password")
    with pytest.raises(DecryptionError):
        decrypt_message(payload, "password")


# ------------------------------------------------------ 3. tampering
@pytest.mark.parametrize("index", [0, 1, 16, 17, 28, 29, 35, -1])
def test_single_byte_flip_detected(index):
    """Flipping one byte anywhere (version, salt, nonce, ciphertext, tag) is detected."""
    payload = bytearray(encrypt_message(MESSAGE, PASSWORD))
    payload[index] ^= 0x01
    with pytest.raises(DecryptionError):
        decrypt_message(bytes(payload), PASSWORD)


def test_every_byte_position_detected():
    payload = encrypt_message("short", PASSWORD)
    for i in range(len(payload)):
        tampered = bytearray(payload)
        tampered[i] ^= 0xFF
        with pytest.raises(DecryptionError):
            decrypt_message(bytes(tampered), PASSWORD)


def test_appended_bytes_detected():
    payload = encrypt_message(MESSAGE, PASSWORD) + b"\x00"
    with pytest.raises(DecryptionError):
        decrypt_message(payload, PASSWORD)


# ------------------------------------------------------ 4. malformed input
def test_empty_payload():
    with pytest.raises(DecryptionError):
        decrypt_message(b"", PASSWORD)


def test_truncated_payload():
    payload = encrypt_message(MESSAGE, PASSWORD)
    for cut in (1, 10, OVERHEAD_BYTES - 1, len(payload) - 1):
        with pytest.raises(DecryptionError):
            decrypt_message(payload[:cut], PASSWORD)


def test_random_garbage_payload():
    with pytest.raises(DecryptionError):
        decrypt_message(os.urandom(200), PASSWORD)


def test_wrong_version_byte():
    payload = bytearray(encrypt_message(MESSAGE, PASSWORD))
    payload[0] = 0x99
    with pytest.raises(DecryptionError):
        decrypt_message(bytes(payload), PASSWORD)


def test_non_bytes_payload():
    with pytest.raises(DecryptionError):
        decrypt_message("not bytes", PASSWORD)  # type: ignore[arg-type]


def test_empty_password_on_decrypt():
    payload = encrypt_message(MESSAGE, PASSWORD)
    with pytest.raises(DecryptionError):
        decrypt_message(payload, "")


# ------------------------------------------------------ 5. randomness
def test_same_input_gives_different_output():
    a = encrypt_message(MESSAGE, PASSWORD)
    b = encrypt_message(MESSAGE, PASSWORD)
    assert a != b
    assert a[1:17] != b[1:17]      # salts differ
    assert a[17:29] != b[17:29]    # nonces differ
    assert decrypt_message(a, PASSWORD) == decrypt_message(b, PASSWORD) == MESSAGE


# ------------------------------------------------------ 6. interface contract
def test_output_is_bytes():
    assert isinstance(encrypt_message(MESSAGE, PASSWORD), bytes)


def test_returns_str_on_decrypt():
    assert isinstance(decrypt_message(encrypt_message(MESSAGE, PASSWORD), PASSWORD), str)


def test_overhead_matches_constant():
    for msg in ["", "x", MESSAGE, "🔐" * 50]:
        payload = encrypt_message(msg, PASSWORD)
        assert len(payload) == len(msg.encode("utf-8")) + OVERHEAD_BYTES
        assert len(payload) == payload_size(msg)
    assert OVERHEAD_BYTES == 45


def test_empty_password_on_encrypt():
    with pytest.raises(ValueError):
        encrypt_message(MESSAGE, "")


def test_non_str_inputs_on_encrypt():
    with pytest.raises(TypeError):
        encrypt_message(b"bytes", PASSWORD)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        encrypt_message(MESSAGE, 1234)  # type: ignore[arg-type]


def test_plaintext_not_visible_in_payload():
    payload = encrypt_message("VERY-DISTINCTIVE-PLAINTEXT", PASSWORD)
    assert b"VERY-DISTINCTIVE-PLAINTEXT" not in payload
