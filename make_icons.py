#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generate the 拾词 app icons (home-screen / PWA).

Requires Pillow (a dev-time tool only; the runtime server stays pure-stdlib).
    python make_icons.py

Produces, next to this file:
    apple-touch-icon.png  (180)   icon-192.png   icon-512.png   icon-1024.png
A full-bleed pine-green squircle background with a cream "拾" glyph; iOS applies
its own rounded mask, so the source is a plain square (no alpha / pre-rounding).
"""
import os
from PIL import Image, ImageDraw, ImageFont, ImageFilter

BASE = os.path.dirname(os.path.abspath(__file__))
FONT_PATH = r"C:\Windows\Fonts\msyhbd.ttc"        # Microsoft YaHei Bold
S = 1024
CREAM = (0xF6, 0xF1, 0xE6)
TOP = (0x30, 0x74, 0x60)
BOT = (0x14, 0x3F, 0x33)


def lerp(a, b, t):
    return tuple(round(a[i] + (b[i] - a[i]) * t) for i in range(3))


def base_img():
    img = Image.new("RGB", (S, S))
    px = img.load()
    for y in range(S):
        c = lerp(TOP, BOT, y / (S - 1))
        for x in range(S):
            px[x, y] = c
    # soft diagonal glow from the top-left, echoing the in-app brand seal
    glow = Image.new("L", (S, S), 0)
    ImageDraw.Draw(glow).ellipse(
        [-int(S * 0.25), -int(S * 0.30), int(S * 0.75), int(S * 0.70)], fill=95)
    glow = glow.filter(ImageFilter.GaussianBlur(S * 0.12))
    light = Image.new("RGB", (S, S), (0x3C, 0x88, 0x72))
    return Image.composite(light, img, glow)


def draw_glyph(img):
    img = img.convert("RGBA")
    font = ImageFont.truetype(FONT_PATH, int(S * 0.58))
    text = "拾"
    measure = ImageDraw.Draw(img)
    bbox = measure.textbbox((0, 0), text, font=font)
    w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
    x = (S - w) // 2 - bbox[0]
    y = (S - h) // 2 - bbox[1] - int(S * 0.01)
    # subtle drop shadow for depth
    shadow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ImageDraw.Draw(shadow).text((x, y + int(S * 0.012)), text, font=font, fill=(0, 0, 0, 90))
    shadow = shadow.filter(ImageFilter.GaussianBlur(S * 0.012))
    img = Image.alpha_composite(img, shadow)
    # the glyph itself
    layer = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ImageDraw.Draw(layer).text((x, y), text, font=font, fill=CREAM + (255,))
    img = Image.alpha_composite(img, layer)
    return img.convert("RGB")


def main():
    master = draw_glyph(base_img())
    for name, size in [("apple-touch-icon.png", 180), ("icon-192.png", 192),
                       ("icon-512.png", 512), ("icon-1024.png", 1024)]:
        master.resize((size, size), Image.LANCZOS).save(os.path.join(BASE, name), "PNG")
        print("wrote", name)


if __name__ == "__main__":
    main()
