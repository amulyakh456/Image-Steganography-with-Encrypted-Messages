"""Member 3: Flask interface and integration for the DSP steganography project."""

from __future__ import annotations

import io
import os
import time
import uuid
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, send_file, url_for
from PIL import Image, UnidentifiedImageError

from crypto import (
    DecryptionError,
    decrypt_message,
    encrypt_message,
    payload_size,
)
from steganography import (
    InsufficientCapacityError,
    InvalidStegoImageError,
    SteganographyError,
    calculate_capacity,
    calculate_mse,
    calculate_psnr,
    decode_data,
    encode_data,
)

BASE_DIR = Path(__file__).resolve().parent
GENERATED_DIR = BASE_DIR / "generated"
GENERATED_DIR.mkdir(exist_ok=True)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "bmp"}
MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_IMAGE_PIXELS = 20_000_000

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "development-only-change-this")
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def open_uploaded_image(file_storage) -> Image.Image:
    """Validate an uploaded image and return a detached RGB PIL image."""
    if not file_storage or not file_storage.filename:
        raise ValueError("Please choose an image file.")

    if not allowed_file(file_storage.filename):
        raise ValueError("Unsupported file type. Upload PNG, JPG, JPEG or BMP.")

    try:
        with Image.open(file_storage.stream) as source:
            source.load()
            if source.width * source.height > MAX_IMAGE_PIXELS:
                raise ValueError("Image is too large. Maximum allowed size is 20 megapixels.")
            return source.convert("RGB")
    except (UnidentifiedImageError, OSError) as exc:
        raise ValueError("The uploaded file is not a valid image.") from exc


def remove_old_generated_files(max_age_seconds: int = 24 * 60 * 60) -> None:
    """Best-effort cleanup of generated downloads older than 24 hours."""
    cutoff = time.time() - max_age_seconds
    for path in GENERATED_DIR.glob("*.png"):
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink(missing_ok=True)
        except OSError:
            # Cleanup must not prevent the main request from completing.
            pass


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/hide")
def hide_message():
    message = request.form.get("message", "")
    password = request.form.get("password", "")
    upload = request.files.get("image")

    if not message:
        flash("Enter a message before hiding it.", "error")
        return redirect(url_for("index"))
    if not password:
        flash("Enter an encryption password.", "error")
        return redirect(url_for("index"))

    try:
        original = open_uploaded_image(upload)
        required_bytes = payload_size(message)
        available_bytes = calculate_capacity(original)

        if required_bytes > available_bytes:
            raise InsufficientCapacityError(
                f"Image capacity is {available_bytes} bytes, but this message "
                f"needs {required_bytes} bytes after encryption."
            )

        encrypted_payload = encrypt_message(message, password)
        stego = encode_data(original, encrypted_payload)

        # Save as PNG because JPEG compression would damage LSB data.
        token = uuid.uuid4().hex
        output_path = GENERATED_DIR / f"{token}.png"
        stego.save(output_path, format="PNG")

        mse = calculate_mse(original, stego)
        psnr = calculate_psnr(original, stego)
        remove_old_generated_files()

        return render_template(
            "result.html",
            mode="hide",
            download_url=url_for("download_stego", token=token),
            original_data=png_data_uri(original),
            image_data=png_data_uri(stego),
            mse=f"{mse:.6f}",
            psnr="Infinity" if psnr == float("inf") else f"{psnr:.2f} dB",
            capacity=available_bytes,
            payload_size=len(encrypted_payload),
        )

    except (ValueError, SteganographyError) as exc:
        flash(str(exc), "error")
        return redirect(url_for("index"))


@app.post("/extract")
def extract_message():
    password = request.form.get("extract_password", "")
    upload = request.files.get("stego_image")

    if not password:
        flash("Enter the password used to encrypt the message.", "error")
        return redirect(url_for("index"))

    try:
        stego = open_uploaded_image(upload)
        encrypted_payload = decode_data(stego)
        message = decrypt_message(encrypted_payload, password)

        return render_template(
            "result.html",
            mode="extract",
            message=message,
            payload_size=len(encrypted_payload),
        )

    except (ValueError, SteganographyError, DecryptionError) as exc:
        # Do not reveal whether failure was caused by a wrong password
        # or authenticated-payload tampering.
        flash(str(exc), "error")
        return redirect(url_for("index"))


def png_data_uri(image: Image.Image) -> str:
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    import base64
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


@app.get("/download/<token>")
def download_stego(token: str):
    # UUID hex is exactly 32 hexadecimal characters; reject all other input.
    if len(token) != 32 or any(ch not in "0123456789abcdef" for ch in token):
        return "Invalid download identifier.", 404

    path = GENERATED_DIR / f"{token}.png"
    if not path.is_file():
        return "This download has expired or does not exist.", 404

    return send_file(
        path,
        mimetype="image/png",
        as_attachment=True,
        download_name="stego_image.png",
    )


@app.errorhandler(413)
def upload_too_large(_error):
    flash("Upload too large. Maximum upload size is 10 MB.", "error")
    return redirect(url_for("index"))


if __name__ == "__main__":
    # Local development only. For deployment, use a production WSGI server.
    app.run(debug=True)
