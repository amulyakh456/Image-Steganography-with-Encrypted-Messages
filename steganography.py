
"""
steganography.py
LSB Image Steganography Module

Project: Image Steganography with Encrypted Messages
Owner: Member 2

Features:
- Embed encrypted bytes inside images using LSB encoding.
- Extract hidden encrypted bytes.
- Calculate image embedding capacity.
- Calculate MSE and PSNR.
- Detect invalid images and corrupted headers.

Compatible with Member 1's crypto.py.
"""

from PIL import Image
from pathlib import Path
import math
import struct
from typing import Union


# -------------------------------------------------
# CONSTANTS
# -------------------------------------------------

MAGIC = b"STEG"
HEADER_SIZE = 8  # 4 bytes magic + 4 bytes payload length

ImageInput = Union[Image.Image, str, Path]


# -------------------------------------------------
# CUSTOM EXCEPTIONS
# -------------------------------------------------

class SteganographyError(Exception):
    """Base exception for steganography operations."""


class InsufficientCapacityError(SteganographyError):
    """Raised when image capacity is insufficient."""


class InvalidStegoImageError(SteganographyError):
    """Raised when image does not contain valid hidden data."""


# -------------------------------------------------
# IMAGE HANDLING
# -------------------------------------------------

def _load_image(image: ImageInput) -> Image.Image:
    """
    Accept either a PIL Image object or an image path.
    Return an independent RGB image.
    """
    try:
        if isinstance(image, Image.Image):
            return image.convert("RGB")

        if isinstance(image, (str, Path)):
            with Image.open(image) as img:
                return img.convert("RGB")

        raise TypeError("Input must be a PIL Image or image path.")

    except (OSError, ValueError) as exc:
        raise SteganographyError(
            f"Unable to open image: {exc}"
        ) from exc


# -------------------------------------------------
# CAPACITY CALCULATION
# -------------------------------------------------

def calculate_capacity(image: ImageInput) -> int:
    """
    Calculate maximum encrypted payload capacity in bytes.

    Uses:
    3 RGB channels per pixel
    1 LSB per channel
    8 bits per byte
    8 bytes reserved for header
    """
    img = _load_image(image)

    width, height = img.size

    total_bits = width * height * 3
    total_bytes = total_bits // 8

    return max(0, total_bytes - HEADER_SIZE)


# -------------------------------------------------
# BIT CONVERSION HELPERS
# -------------------------------------------------

def _bytes_to_bits(data: bytes):
    """Convert bytes into bits, most significant bit first."""
    for byte in data:
        for shift in range(7, -1, -1):
            yield (byte >> shift) & 1


def _bits_to_bytes(bits) -> bytes:
    """Convert a sequence of bits into bytes."""
    result = bytearray()

    for i in range(0, len(bits), 8):
        byte = 0

        for bit in bits[i:i + 8]:
            byte = (byte << 1) | bit

        result.append(byte)

    return bytes(result)


# -------------------------------------------------
# LSB ENCODING
# -------------------------------------------------

def encode_data(image: ImageInput, data: bytes) -> Image.Image:
    """
    Embed encrypted bytes inside an image using LSB encoding.

    Parameters:
        image: PIL Image object or image path.
        data: Encrypted bytes from crypto.encrypt_message().

    Returns:
        PIL Image: Stego image.

    Header format:
        4 bytes: Magic identifier (STEG)
        4 bytes: Payload length (big-endian)
        Remaining bytes: Encrypted payload.
    """

    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Data must be bytes or bytearray.")

    data = bytes(data)

    img = _load_image(image)

    # Check capacity before encoding
    capacity = calculate_capacity(img)

    if len(data) > capacity:
        raise InsufficientCapacityError(
            f"Payload too large. Maximum capacity: {capacity} bytes. "
            f"Payload size: {len(data)} bytes."
        )

    # Construct header
    header = MAGIC + struct.pack(">I", len(data))

    # Combine header and encrypted payload
    complete_payload = header + data

    # Convert payload into bits
    bits = list(_bytes_to_bits(complete_payload))

    # Get RGB pixel data
    pixels = bytearray(img.tobytes())

    # Embed one bit into each channel's LSB
    for i, bit in enumerate(bits):
        pixels[i] = (pixels[i] & 0xFE) | bit

    # Reconstruct the image
    stego_image = Image.frombytes(
        "RGB",
        img.size,
        bytes(pixels)
    )

    return stego_image


# -------------------------------------------------
# LSB DECODING
# -------------------------------------------------

def decode_data(image: ImageInput) -> bytes:
    """
    Extract encrypted bytes from an image.

    Returns:
        bytes: Original encrypted payload.

    Raises:
        InvalidStegoImageError: If header or payload is invalid.
    """

    img = _load_image(image)

    pixels = img.tobytes()

    # Minimum bits required for the 8-byte header
    header_bits_required = HEADER_SIZE * 8

    if len(pixels) < header_bits_required:
        raise InvalidStegoImageError(
            "Image is too small to contain a valid header."
        )

    # Extract header bits
    header_bits = [
        pixels[i] & 1
        for i in range(header_bits_required)
    ]

    header = _bits_to_bytes(header_bits)

    # Validate magic identifier
    magic = header[:4]

    if magic != MAGIC:
        raise InvalidStegoImageError(
            "No valid hidden message found in this image."
        )

    # Extract payload length
    payload_length = struct.unpack(">I", header[4:8])[0]

    # Calculate required bits
    payload_bits_required = payload_length * 8

    total_required_bits = (
        header_bits_required + payload_bits_required
    )

    # Validate image capacity
    if total_required_bits > len(pixels):
        raise InvalidStegoImageError(
            "Embedded payload is incomplete or corrupted."
        )

    # Extract payload bits
    payload_bits = [
        pixels[i] & 1
        for i in range(
            header_bits_required,
            total_required_bits
        )
    ]

    # Convert bits back to encrypted bytes
    encrypted_payload = _bits_to_bytes(payload_bits)

    return encrypted_payload


# -------------------------------------------------
# IMAGE QUALITY ANALYSIS
# -------------------------------------------------

def calculate_mse(
    original_image: ImageInput,
    stego_image: ImageInput
) -> float:
    """
    Calculate Mean Squared Error between two images.

    Lower MSE indicates less distortion.
    """

    original = _load_image(original_image)
    stego = _load_image(stego_image)

    if original.size != stego.size:
        raise ValueError(
            "Both images must have identical dimensions."
        )

    original_pixels = original.tobytes()
    stego_pixels = stego.tobytes()

    total_error = sum(
        (a - b) ** 2
        for a, b in zip(original_pixels, stego_pixels)
    )

    return total_error / len(original_pixels)


def calculate_psnr(
    original_image: ImageInput,
    stego_image: ImageInput
) -> float:
    """
    Calculate Peak Signal-to-Noise Ratio.

    Higher PSNR indicates better image quality.
    """

    mse = calculate_mse(original_image, stego_image)

    if mse == 0:
        return float("inf")

    return 10 * math.log10((255 ** 2) / mse)


# -------------------------------------------------
# QUICK DEMONSTRATION
# -------------------------------------------------

if __name__ == "__main__":

    message = b"Hello! This is a secret message."

    original = Image.new(
        "RGB",
        (100, 100),
        color="white"
    )

    print("Original image capacity:",
          calculate_capacity(original), "bytes")

    stego = encode_data(original, message)

    stego.save("stego.png", format="PNG")

    extracted = decode_data("stego.png")

    print("Original payload:", message)
    print("Extracted payload:", extracted)

    print("Payload recovered successfully:",
          message == extracted)

    print("MSE:", calculate_mse(original, stego))
    print("PSNR:", calculate_psnr(original, stego))
