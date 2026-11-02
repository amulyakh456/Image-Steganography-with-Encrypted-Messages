
import pytest
from PIL import Image

from steganography import (
    encode_data,
    decode_data,
    calculate_capacity,
    calculate_mse,
    calculate_psnr,
    InsufficientCapacityError,
    InvalidStegoImageError
)


@pytest.fixture
def sample_image():
    return Image.new("RGB", (100, 100), color="white")


def test_encode_decode(sample_image):
    message = b"Hello, this is a secret message"

    stego = encode_data(sample_image, message)
    extracted = decode_data(stego)

    assert extracted == message


def test_long_message(sample_image):
    message = b"A" * 1000

    stego = encode_data(sample_image, message)
    extracted = decode_data(stego)

    assert extracted == message


def test_capacity(sample_image):
    capacity = calculate_capacity(sample_image)

    assert capacity == (100 * 100 * 3) // 8 - 8


def test_insufficient_capacity():
    small_image = Image.new("RGB", (5, 5))

    with pytest.raises(InsufficientCapacityError):
        encode_data(small_image, b"A" * 100)


def test_image_without_hidden_data(sample_image):
    with pytest.raises(InvalidStegoImageError):
        decode_data(sample_image)


def test_corrupted_magic(sample_image):
    stego = encode_data(sample_image, b"Secret")

    pixels = bytearray(stego.tobytes())

    # Corrupt the first magic-header bit
    pixels[0] ^= 1

    corrupted = Image.frombytes(
        "RGB", stego.size, bytes(pixels)
    )

    with pytest.raises(InvalidStegoImageError):
        decode_data(corrupted)


def test_mse(sample_image):
    stego = encode_data(sample_image, b"Test")

    mse = calculate_mse(sample_image, stego)

    assert mse >= 0


def test_psnr(sample_image):
    stego = encode_data(sample_image, b"Test")

    psnr = calculate_psnr(sample_image, stego)

    assert psnr > 0


def test_identical_images(sample_image):
    assert calculate_mse(sample_image, sample_image) == 0

    assert calculate_psnr(
        sample_image, sample_image
    ) == float("inf")


def test_invalid_image_size():
    tiny_image = Image.new("RGB", (2, 2))

    with pytest.raises(InvalidStegoImageError):
        decode_data(tiny_image)
