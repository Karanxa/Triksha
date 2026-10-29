"""
Image utilities for visual prompt injection attacks.
Requires Pillow (pip install Pillow).
"""

import base64
import os
import textwrap
from typing import Optional


def create_text_overlay_image(prompt_text: str, output_path: str, style: str = "default") -> str:
    """Create image with text overlay containing adversarial prompt.

    Falls back to a plain-text stub if Pillow is unavailable.
    Returns the output_path on success.
    """
    try:
        from PIL import Image, ImageDraw, ImageFont

        width, height = 800, 600
        bg_color = "white"
        text_color = "black"

        # Styles supported by the visual_attack_runner (ATTACK_STYLES):
        #   - "default": high-contrast black-on-white (baseline readability)
        #   - "subtle":  reduced contrast — still readable to vision models,
        #                tests robustness to lower-quality OCR-style input
        #   - "large":   bigger font, same contrast as default
        # "dark" is also supported for ad-hoc tests but is not in ATTACK_STYLES.
        if style == "dark":
            bg_color = "#1a1a1a"
            text_color = "#f0f0f0"
        elif style == "subtle":
            bg_color = "#fafafa"
            text_color = "#909090"  # readable to vision models, lower contrast than default

        img = Image.new("RGB", (width, height), color=bg_color)
        draw = ImageDraw.Draw(img)

        font_size = 40 if style == "large" else 20
        font: Optional[object] = None
        for font_path in [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/Library/Fonts/Arial.ttf",
            "/System/Library/Fonts/Helvetica.ttc",
        ]:
            if os.path.exists(font_path):
                try:
                    font = ImageFont.truetype(font_path, font_size)
                    break
                except Exception:
                    pass
        if font is None:
            font = ImageFont.load_default()

        # Wrap text to fit image width
        max_chars = max(20, width // (font_size // 2 + 2))
        lines = textwrap.wrap(prompt_text, width=max_chars)
        if not lines:
            lines = [prompt_text]

        # Calculate total text height
        line_height = font_size + 6
        total_height = line_height * len(lines)
        y = (height - total_height) // 2

        for line in lines:
            bbox = draw.textbbox((0, 0), line, font=font)
            text_width = bbox[2] - bbox[0]
            x = (width - text_width) // 2
            draw.text((x, y), line, fill=text_color, font=font)
            y += line_height

        img.save(output_path, format="PNG")
        return output_path

    except ImportError:
        # Pillow not installed — write a placeholder PNG (1x1 white pixel)
        _write_placeholder_png(output_path)
        return output_path


def _write_placeholder_png(path: str) -> None:
    """Write a minimal valid 1×1 white PNG without Pillow."""
    # Minimal PNG bytes for a 1×1 white pixel
    PNG_BYTES = (
        b"\x89PNG\r\n\x1a\n"
        b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02"
        b"\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00"
        b"\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(PNG_BYTES)


def encode_image_base64(image_path: str) -> str:
    """Read an image file and return its base64-encoded content."""
    with open(image_path, "rb") as fh:
        return base64.b64encode(fh.read()).decode("utf-8")


def is_pillow_available() -> bool:
    """Return True if Pillow is installed."""
    try:
        from PIL import Image  # noqa: F401
        return True
    except ImportError:
        return False
