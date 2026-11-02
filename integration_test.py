
from PIL import Image

from crypto import encrypt_message, decrypt_message
from steganography import encode_data, decode_data

message = "This is our DSP project secret message!"
password = "team_secret_123"

# Step 1: Encrypt
encrypted = encrypt_message(message, password)
print("Encrypted payload size:", len(encrypted))

# Step 2: Create original image
original = Image.new("RGB", (100, 100), color="white")
original.save("original.png")

# Step 3: Embed encrypted data
stego = encode_data(original, encrypted)
stego.save("stego.png", format="PNG")

# Step 4: Extract encrypted data
extracted = decode_data("stego.png")

assert extracted == encrypted
print("Extraction successful!")

# Step 5: Decrypt
recovered = decrypt_message(extracted, password)

assert recovered == message
print("Recovered message:", recovered)

# Step 6: Image quality
from steganography import calculate_mse, calculate_psnr

print("MSE:", calculate_mse(original, stego))
print("PSNR:", calculate_psnr(original, stego))

print("\nEND-TO-END TEST PASSED!")
