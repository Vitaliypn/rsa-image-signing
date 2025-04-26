"""Конвертація зображення JPEG у PNG."""

from PIL import Image

def convert_to_png(input_path: str, output_path: str) -> None:
    """Конвертує зображення у формат PNG."""
    img = Image.open(input_path)
    img.save(output_path, format="PNG")

if __name__ == "__main__":
    convert_to_png("test.jpg", "test.png")
    print("Converted test.jpg -> test.png")
