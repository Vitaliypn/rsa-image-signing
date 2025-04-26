"""Підписування зображення і збереження підпису у метаданих PNG."""

import base64
import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from PIL import Image, PngImagePlugin

def sign_and_embed_png(image_path: str, private_key_path: str, output_path: str) -> None:
    """Створює цифровий підпис для зображення і вшиває його в метадані PNG."""
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    img = Image.open(image_path).convert("RGB")
    image_hash = hashes.Hash(hashes.SHA256())
    image_hash.update(img.tobytes())
    digest = image_hash.finalize()

    signature = private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    encoded_signature = base64.b64encode(signature).decode()

    meta = PngImagePlugin.PngInfo()
    meta.add_text("Signature", encoded_signature)

    img.save(output_path, "PNG", pnginfo=meta)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 sign_image_exif.py <image_path> <private_key_path> <output_path>")
        sys.exit(1)

    sign_and_embed_png(sys.argv[1], sys.argv[2], sys.argv[3])
    print("Image signed and signature embedded into PNG metadata successfully!")
