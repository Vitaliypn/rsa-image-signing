"""Перевірка цифрового підпису у базовій версії JPEG."""

import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def verify_signature_basic(signed_image_path: str, public_key_path: str) -> bool:
    """Перевіряє підпис, доданий у кінець файлу JPEG."""
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    with open(signed_image_path, "rb") as img_file:
        full_data = img_file.read()

    separator = b"SIGNATURE:"
    if separator not in full_data:
        print("No signature found.")
        return False

    image_data, signature = full_data.split(separator)

    try:
        public_key.verify(
            signature,
            image_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature is valid.")
        return True
    except Exception as verification_error:
        print(f"Signature is invalid: {verification_error}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 verify_signature.py <signed_image_path> <public_key_path>")
        sys.exit(1)

    verify_signature_basic(sys.argv[1], sys.argv[2])
