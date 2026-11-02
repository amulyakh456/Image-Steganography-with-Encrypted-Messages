import io
from PIL import Image
import pytest

from app import allowed_file, open_uploaded_image


def test_allowed_extensions():
    assert allowed_file("photo.png")
    assert allowed_file("photo.JPG")
    assert not allowed_file("photo.gif")
    assert not allowed_file("photo")


def test_open_uploaded_image_returns_rgb():
    from werkzeug.datastructures import FileStorage
    image = Image.new("RGBA", (12, 10), (255, 0, 0, 128))
    stream = io.BytesIO()
    image.save(stream, format="PNG")
    stream.seek(0)

    uploaded = FileStorage(stream=stream, filename="test.png")
    result = open_uploaded_image(uploaded)

    assert result.mode == "RGB"
    assert result.size == (12, 10)


def test_reject_invalid_image():
    from werkzeug.datastructures import FileStorage
    uploaded = FileStorage(stream=io.BytesIO(b"not an image"), filename="bad.png")
    with pytest.raises(ValueError):
        open_uploaded_image(uploaded)
