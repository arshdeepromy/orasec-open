#!/usr/bin/env python3
"""Generate every launch (splash) screen from the app icon.

Source: store-assets/app-icon-1024.png (the OraSec icon: teal shield and magnifier on the dark console tile). Output: the icon centred on the brand navy with a
faint teal glow (top left) and gold glow (top right) — the "OraFlows Navy" look.

  Android  res/drawable*/splash.png (legacy splash, every density/orientation)
           res/drawable/splash_icon.png (Android 12+ system splash icon)
  iOS      Assets.xcassets/Splash.imageset/splash-2732x2732*.png

    python3 scripts/make-splash.py
"""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

REPO = Path(__file__).resolve().parent.parent
ICON = REPO / "store-assets/app-icon-1024.png"
RES = REPO / "android/app/src/main/res"
IOS = REPO / "ios/App/App/Assets.xcassets/Splash.imageset"

NAVY = (13, 21, 20)        # #0D1514 — OraSec console background
NAVY_DEEP = (7, 15, 14)    # #070F0E
TEAL = (0, 168, 144)       # #00A890
GOLD = (25, 211, 181)      # #19D3B5 (second teal glow)

# Share of the shorter side the icon tile takes.
ICON_SHARE = 0.30


def background(w: int, h: int) -> Image.Image:
    """Vertical navy gradient with soft teal / gold glows."""
    small_w, small_h = max(8, w // 8), max(8, h // 8)
    bg = Image.new("RGB", (small_w, small_h), NAVY)
    px = bg.load()
    for y in range(small_h):
        t = y / max(1, small_h - 1)
        c = tuple(round(NAVY[i] + (NAVY_DEEP[i] - NAVY[i]) * t) for i in range(3))
        for x in range(small_w):
            px[x, y] = c
    glow = Image.new("RGBA", (small_w, small_h), (0, 0, 0, 0))
    d = ImageDraw.Draw(glow)
    r = int(max(small_w, small_h) * 0.45)
    d.ellipse((-r // 2, -r // 2, r, r), fill=TEAL + (60,))
    d.ellipse((small_w - r, -r // 2, small_w + r // 2, r), fill=GOLD + (45,))
    glow = glow.filter(ImageFilter.GaussianBlur(radius=max(4, r // 2)))
    bg = Image.alpha_composite(bg.convert("RGBA"), glow)
    return bg.resize((w, h), Image.BICUBIC).convert("RGB")


def rounded_tile(size: int) -> Image.Image:
    icon = Image.open(ICON).convert("RGB").resize((size, size), Image.LANCZOS).convert("RGBA")
    big = size * 4
    mask = Image.new("L", (big, big), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, big - 1, big - 1), radius=int(big * 0.225), fill=255)
    icon.putalpha(mask.resize((size, size), Image.LANCZOS))
    return icon


def splash(w: int, h: int) -> Image.Image:
    img = background(w, h).convert("RGBA")
    side = max(48, int(min(w, h) * ICON_SHARE))
    tile = rounded_tile(side)
    # Soft shadow under the tile.
    blur = max(4, side // 12)
    pad = blur * 4
    off = max(2, side // 40)
    shadow = Image.new("RGBA", (side + 2 * pad, side + 2 * pad), (0, 0, 0, 0))
    ImageDraw.Draw(shadow).rounded_rectangle((pad, pad + off, side + pad, side + pad + off), radius=int(side * 0.225), fill=(0, 6, 24, 140))
    shadow = shadow.filter(ImageFilter.GaussianBlur(radius=blur))
    x, y = (w - side) // 2, (h - side) // 2
    img.alpha_composite(shadow, (x - pad, y - pad))
    img.alpha_composite(tile, (x, y))
    return img.convert("RGB")


def main() -> None:
    if not ICON.exists():
        raise SystemExit(f"icon missing: {ICON}")

    count = 0
    for path in sorted(RES.glob("drawable*/splash.png")):
        w, h = Image.open(path).size
        splash(w, h).save(path, "PNG", optimize=True)
        count += 1
        print(f"android {path.parent.name:24s} {w}x{h}")

    # Android 12+: the system draws this icon inside a circle (inner 2/3 of a
    # 432px canvas is visible) on windowSplashScreenBackground. Fill the circle
    # with the tile so only its navy interior and the artwork show.
    canvas = 432
    tile = Image.open(ICON).convert("RGB").resize((300, 300), Image.LANCZOS).convert("RGBA")
    icon_layer = Image.new("RGBA", (canvas, canvas), (0, 0, 0, 0))
    icon_layer.alpha_composite(tile, ((canvas - 300) // 2, (canvas - 300) // 2))
    icon_layer.save(RES / "drawable/splash_icon.png", "PNG", optimize=True)
    print("android drawable/splash_icon.png 432x432")

    for path in sorted(IOS.glob("splash-2732x2732*.png")):
        splash(2732, 2732).save(path, "PNG", optimize=True)
        count += 1
        print(f"ios     {path.name}")

    print(f"{count} splash images written")


if __name__ == "__main__":
    main()

