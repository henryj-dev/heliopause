#!/usr/bin/env python3
"""Generate placeholder app icons (PNG/ICO/ICNS) with no external deps.

Draws a simple "heliopause" ring mark on a dark background. Run from anywhere:
    python3 generate_icons.py
Writes files next to this script. Replace with `npx tauri icon <logo.png>`
if you want a real, multi-resolution icon set.
"""
import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))

BG = (13, 17, 23, 255)       # #0d1117
ACCENT = (77, 163, 255, 255)  # #4da3ff


def render_rgba(size: int) -> bytes:
    """Return raw RGBA bytes (size*size*4) for the mark at the given size."""
    cx = cy = (size - 1) / 2.0
    r_out = size * 0.42
    r_in = size * 0.30
    r_dot = size * 0.12
    px = bytearray()
    for y in range(size):
        for x in range(size):
            dx = x - cx
            dy = y - cy
            d = (dx * dx + dy * dy) ** 0.5
            if d <= r_dot or (r_in <= d <= r_out):
                px += bytes(ACCENT)
            else:
                px += bytes(BG)
    return bytes(px)


def encode_png(size: int, rgba: bytes) -> bytes:
    """Encode raw RGBA into a PNG byte string."""
    # Add filter byte (0) at the start of each scanline.
    stride = size * 4
    raw = bytearray()
    for y in range(size):
        raw.append(0)
        raw += rgba[y * stride:(y + 1) * stride]

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + tag + data +
                struct.pack(">I", zlib.crc32(tag + data) & 0xffffffff))

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)  # 8-bit RGBA
    idat = zlib.compress(bytes(raw), 9)
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def encode_ico(png_by_size: dict) -> bytes:
    """Build a PNG-compressed .ico from {size: png_bytes}."""
    entries = sorted(png_by_size.items())
    out = struct.pack("<HHH", 0, 1, len(entries))  # reserved, type=icon, count
    offset = 6 + 16 * len(entries)
    dir_entries = bytearray()
    image_data = bytearray()
    for size, png in entries:
        w = 0 if size >= 256 else size
        h = 0 if size >= 256 else size
        dir_entries += struct.pack(
            "<BBBBHHII", w, h, 0, 0, 1, 32, len(png), offset)
        image_data += png
        offset += len(png)
    return out + bytes(dir_entries) + bytes(image_data)


def encode_icns(png_by_type: dict) -> bytes:
    """Build an .icns from {ostype(bytes4): png_bytes}."""
    body = bytearray()
    for ostype, png in png_by_type.items():
        body += ostype + struct.pack(">I", len(png) + 8) + png
    return b"icns" + struct.pack(">I", len(body) + 8) + bytes(body)


def main() -> None:
    sizes = {}
    for s in (16, 32, 64, 128, 256, 512):
        sizes[s] = encode_png(s, render_rgba(s))

    def write(name: str, data: bytes) -> None:
        with open(os.path.join(HERE, name), "wb") as fh:
            fh.write(data)

    # PNGs referenced by tauri.conf.json / codegen default window icon.
    write("32x32.png", sizes[32])
    write("128x128.png", sizes[128])
    write("128x128@2x.png", sizes[256])
    write("icon.png", sizes[512])

    # Windows .ico (PNG-compressed entries).
    write("icon.ico", encode_ico({16: sizes[16], 32: sizes[32],
                                   64: sizes[64], 256: sizes[256]}))

    # macOS .icns (PNG entries).
    write("icon.icns", encode_icns({
        b"ic07": sizes[128],   # 128x128
        b"ic08": sizes[256],   # 256x256
        b"ic09": sizes[512],   # 512x512
    }))

    print("wrote icons to", HERE)


if __name__ == "__main__":
    main()
