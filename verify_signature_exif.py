"""Перевірка цифрового підпису в метаданих PNG."""

import base64
import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from PIL import Image

def verify_signature_png(signed_image_path: str, public_key_path: str) -> bool:
    """Перевіряє підпис у PNG-файлі."""
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    img = Image.open(signed_image_path).convert("RGB")

    signature_encoded = img.info.get("Signature", None)
    if not signature_encoded:
        print("No signature found in PNG metadata.")
        return False

    signature = base64.b64decode(signature_encoded)

    image_hash = hashes.Hash(hashes.SHA256())
    image_hash.update(img.tobytes())
    digest = image_hash.finalize()

    try:
        public_key.verify(
            signature,
            digest,
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
        print("Usage: python3 verify_signature_exif.py <signed_image_path> <public_key_path>")
        sys.exit(1)

    verify_signature_png(sys.argv[1], sys.argv[2])
