"""Підписування зображення та додавання підпису в кінець JPEG файлу."""

import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def sign_image(image_path: str, private_key_path: str, output_path: str) -> None:
    """Створює цифровий підпис і додає його в кінець файлу."""
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    with open(image_path, "rb") as img_file:
        image_data = img_file.read()

    signature = private_key.sign(
        image_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    with open(output_path, "wb") as signed_file:
        signed_file.write(image_data + b"SIGNATURE:" + signature)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 sign_image.py <image_path> <private_key_path> <output_path>")
        sys.exit(1)

    sign_image(sys.argv[1], sys.argv[2], sys.argv[3])
    print("Image signed and saved successfully!")
