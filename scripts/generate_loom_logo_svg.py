#!/usr/bin/env python3
"""Generate the Loom knot SVG from the approved PNG reference.

Path analysis
-------------
The mark is not eighteen independent stroked curves. It is one connected white
silhouette with an outer boundary and 25 negative spaces. The six petals meet
in a pinwheel weave, and treating them as repeated strokes changes both the
center and the shoulder crossings. This generator therefore preserves the
compound-path topology and fits its boundaries directly with optimized cubic
Bezier curves.

The preprocessing is intentionally conservative:
  * project source pixels from the teal background toward the ivory foreground;
  * apply a small 1 px low-pass filter to remove raster stair-steps only;
  * keep the original geometry and crossing order;
  * use Potrace curve optimization to replace pixel edges with cubic Beziers.

Dependencies: Python 3 standard library and Potrace (including mkbitmap).
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import zlib


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
BACKGROUND = (0x5B, 0x61, 0x66)
FOREGROUND = (0xFA, 0xFA, 0xF7)


def _paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


def read_rgb_png(path: Path) -> tuple[int, int, bytes]:
    """Read an 8-bit, non-interlaced RGB/RGBA PNG using stdlib only."""
    data = path.read_bytes()
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError(f"{path} is not a PNG file")

    offset = len(PNG_SIGNATURE)
    compressed = bytearray()
    width = height = color_type = bit_depth = interlace = None
    while offset < len(data):
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        chunk_type = data[offset + 4 : offset + 8]
        payload = data[offset + 8 : offset + 8 + length]
        offset += 12 + length
        if chunk_type == b"IHDR":
            width, height, bit_depth, color_type, _, _, interlace = struct.unpack(
                ">IIBBBBB", payload
            )
        elif chunk_type == b"IDAT":
            compressed.extend(payload)
        elif chunk_type == b"IEND":
            break

    if bit_depth != 8 or color_type not in (2, 6) or interlace != 0:
        raise ValueError("expected an 8-bit, non-interlaced RGB or RGBA PNG")
    assert width is not None and height is not None
    channels = 3 if color_type == 2 else 4
    stride = width * channels
    raw = zlib.decompress(bytes(compressed))
    previous = bytearray(stride)
    rgb = bytearray(width * height * 3)
    source_offset = target_offset = 0

    for _ in range(height):
        filter_type = raw[source_offset]
        source_offset += 1
        scanline = bytearray(raw[source_offset : source_offset + stride])
        source_offset += stride
        for i, value in enumerate(scanline):
            left = scanline[i - channels] if i >= channels else 0
            above = previous[i]
            upper_left = previous[i - channels] if i >= channels else 0
            if filter_type == 1:
                scanline[i] = (value + left) & 0xFF
            elif filter_type == 2:
                scanline[i] = (value + above) & 0xFF
            elif filter_type == 3:
                scanline[i] = (value + ((left + above) >> 1)) & 0xFF
            elif filter_type == 4:
                scanline[i] = (value + _paeth(left, above, upper_left)) & 0xFF
            elif filter_type != 0:
                raise ValueError(f"unsupported PNG filter {filter_type}")
        for x in range(width):
            src = x * channels
            rgb[target_offset : target_offset + 3] = scanline[src : src + 3]
            target_offset += 3
        previous = scanline
    return width, height, bytes(rgb)


def write_reference_pgm(path: Path, width: int, height: int, rgb: bytes) -> None:
    """Map teal-to-ivory source color onto white-background/black-mark PGM."""
    source_background = (80.0, 157.0, 154.0)
    source_foreground = (250.0, 250.0, 248.0)
    axis = tuple(f - b for b, f in zip(source_background, source_foreground))
    denominator = sum(value * value for value in axis)
    pixels = bytearray(width * height)
    for index in range(width * height):
        color = rgb[index * 3 : index * 3 + 3]
        alpha = sum(
            (float(channel) - background) * direction
            for channel, background, direction in zip(color, source_background, axis)
        ) / denominator
        alpha = min(1.0, max(0.0, alpha))
        pixels[index] = round(255.0 * (1.0 - alpha))
    path.write_bytes(f"P5\n{width} {height}\n255\n".encode() + pixels)


def read_pgm(path: Path) -> tuple[int, int, bytes]:
    data = path.read_bytes()
    offset = 0

    def token() -> bytes:
        nonlocal offset
        while offset < len(data):
            if data[offset : offset + 1] == b"#":
                offset = data.index(b"\n", offset) + 1
            elif data[offset] in b" \t\r\n":
                offset += 1
            else:
                break
        end = offset
        while end < len(data) and data[end] not in b" \t\r\n":
            end += 1
        result = data[offset:end]
        offset = end
        return result

    if token() != b"P5":
        raise ValueError("expected a binary PGM preview")
    width, height, maximum = int(token()), int(token()), int(token())
    if maximum != 255:
        raise ValueError("expected an 8-bit PGM preview")
    while offset < len(data) and data[offset] in b" \t\r\n":
        offset += 1
    pixels = data[offset : offset + width * height]
    if len(pixels) != width * height:
        raise ValueError("truncated PGM preview")
    return width, height, pixels


def write_colorized_png(path: Path, width: int, height: int, gray: bytes) -> None:
    rows = bytearray()
    for y in range(height):
        rows.append(0)
        for value in gray[y * width : (y + 1) * width]:
            alpha = 1.0 - value / 255.0
            rows.extend(
                round(background * (1.0 - alpha) + foreground * alpha)
                for background, foreground in zip(BACKGROUND, FOREGROUND)
            )

    def chunk(kind: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + kind
            + payload
            + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    path.write_bytes(
        PNG_SIGNATURE
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(bytes(rows), 9))
        + chunk(b"IEND", b"")
    )


def _tool(explicit: str | None, name: str) -> str:
    result = explicit or shutil.which(name)
    if not result:
        raise SystemExit(
            f"{name} was not found. Install the 'potrace' package or pass --{name}."
        )
    return result


def run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def normalize_svg(path: Path, width: int, height: int) -> None:
    """Give Potrace output stable metadata and pixel-oriented dimensions."""
    svg = path.read_text(encoding="utf-8")
    svg = svg.replace(
        "<!-- Created by potrace 1.16, written by Peter Selinger 2001-2019 -->",
        "<!-- Generated from loom-logo-final.png by generate_loom_logo_svg.py -->",
    )
    title = (
        "<title>Loom logo</title>\n"
        "<desc>A smooth six-petal woven knot in ivory white on titanium gray.</desc>"
    )
    svg = svg.replace(">\n<metadata>", f">\n{title}\n<metadata>", 1)
    svg = svg.replace(f'width="{width}.000000pt"', f'width="{width}"')
    svg = svg.replace(f'height="{height}.000000pt"', f'height="{height}"')
    svg = svg.replace(
        "</metadata>\n<g ",
        f'</metadata>\n<rect width="{width}" height="{height}" fill="#5B6166"/>\n<g ',
        1,
    )
    path.write_text(svg, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--potrace", help="path to the potrace executable")
    parser.add_argument("--mkbitmap", help="path to the mkbitmap executable")
    parser.add_argument("--preview", type=Path, help="render the fitted curves to PNG")
    parser.add_argument(
        "--blur", type=float, default=1.0, help="low-pass radius in source pixels"
    )
    parser.add_argument(
        "--curve-tolerance",
        type=float,
        default=0.65,
        help="Potrace cubic-curve optimization tolerance",
    )
    args = parser.parse_args()

    potrace = _tool(args.potrace, "potrace")
    mkbitmap = _tool(args.mkbitmap, "mkbitmap")
    width, height, rgb = read_rgb_png(args.source)
    args.output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="loom-logo-") as temporary:
        temporary_path = Path(temporary)
        reference = temporary_path / "reference.pgm"
        bitmap = temporary_path / "smoothed.pbm"
        write_reference_pgm(reference, width, height, rgb)

        run(
            [
                mkbitmap,
                "-x",
                "-b",
                str(args.blur),
                "-s",
                "1",
                "-3",
                "-t",
                "0.5",
                "-o",
                str(bitmap),
                str(reference),
            ]
        )
        run(
            [
                potrace,
                "--svg",
                "--flat",
                "--opaque",
                "--color",
                "#FAFAF7",
                "--fillcolor",
                "#5B6166",
                "--turdsize",
                "12",
                "--alphamax",
                "1.0",
                "--opttolerance",
                str(args.curve_tolerance),
                "--unit",
                "1",
                "--width",
                f"{width}pt",
                "--height",
                f"{height}pt",
                "--output",
                str(args.output),
                str(bitmap),
            ]
        )
        if args.preview:
            gray_preview = temporary_path / "traced.pgm"
            run(
                [
                    potrace,
                    "--backend",
                    "pgm",
                    "--gamma",
                    "2.2",
                    "--scale",
                    "1",
                    "--turdsize",
                    "12",
                    "--alphamax",
                    "1.0",
                    "--opttolerance",
                    str(args.curve_tolerance),
                    "--output",
                    str(gray_preview),
                    str(bitmap),
                ]
            )
            preview_width, preview_height, gray = read_pgm(gray_preview)
            args.preview.parent.mkdir(parents=True, exist_ok=True)
            write_colorized_png(args.preview, preview_width, preview_height, gray)
    normalize_svg(args.output, width, height)
    print(f"wrote {args.output} ({width}x{height})")


if __name__ == "__main__":
    main()
