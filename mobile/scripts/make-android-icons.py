#!/usr/bin/env python3
"""Generate the Android launcher icons from the same artwork as the iOS icon.

Source of truth is the iOS 1024 icon that already lives in the repo, so both
platforms cannot drift.

Android needs three separate things, which is why this is not just a resize:

  ic_launcher.png          legacy square icon (API < 26), rounded corners baked in
  ic_launcher_round.png    legacy round icon, circular crop
  ic_launcher_foreground.png
                           the adaptive-icon foreground layer (API 26+)

The adaptive layer is the fiddly one. Its canvas is 108dp but the launcher only
ever shows the inner ~72dp — the outer ring is reserved for mask shape and
parallax. Dropping the artwork in at full canvas size would crop a third of it.
So the artwork is drawn at ART_DP inside the 108dp canvas: slightly larger than
the 72dp viewport so no background shows at the mask edge, but not so large that
the wave gets cut. The background layer is a flat brand colour sampled from the
artwork itself, so any bleed matches seamlessly.

    python3 scripts/make-android-icons.py
"""
from pathlib import Path

from PIL import Image, ImageDraw

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "ios/App/App/Assets.xcassets/AppIcon.appiconset/AppIcon-512@2x.png"
RES = REPO / "android/app/src/main/res"

# Android density buckets: (directory suffix, legacy px, adaptive-layer px)
# Legacy is 48dp, the adaptive layer 108dp, at 1x/1.5x/2x/3x/4x.
DENSITIES = [
    ("mdpi", 48, 108),
    ("hdpi", 72, 162),
    ("xhdpi", 96, 216),
    ("xxhdpi", 144, 324),
    ("xxxhdpi", 192, 432),
]

# Artwork size inside the 108dp adaptive canvas. 72dp is the guaranteed-visible
# viewport; 80 gives a little bleed so no flat colour peeks in at the mask edge.
ART_DP = 80.0
CANVAS_DP = 108.0

# iOS uses a ~22.37% continuous corner radius; match it for the legacy icon.
CORNER_RATIO = 0.2237
SUPERSAMPLE = 4


def rounded_mask(size: int, radius_ratio: float) -> Image.Image:
    big = size * SUPERSAMPLE
    mask = Image.new("L", (big, big), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        (0, 0, big - 1, big - 1), radius=int(big * radius_ratio), fill=255
    )
    return mask.resize((size, size), Image.LANCZOS)


def circle_mask(size: int) -> Image.Image:
    big = size * SUPERSAMPLE
    mask = Image.new("L", (big, big), 0)
    ImageDraw.Draw(mask).ellipse((0, 0, big - 1, big - 1), fill=255)
    return mask.resize((size, size), Image.LANCZOS)


def main() -> None:
    if not SRC.exists():
        raise SystemExit(f"source artwork missing: {SRC}")

    art = Image.open(SRC).convert("RGB")

    # Brand colour for the adaptive background layer: the median colour of the
    # artwork's outer border, so the two never disagree. (A single top-centre
    # sample would hit artwork that touches the top edge.)
    small = art.resize((64, 64), Image.LANCZOS)
    edge = [small.getpixel((x, y)) for x in range(64) for y in range(64)
            if x < 3 or y < 3 or x > 60 or y > 60]
    bg = tuple(sorted(c[i] for c in edge)[len(edge) // 2] for i in range(3))

    for suffix, legacy_px, layer_px in DENSITIES:
        out_dir = RES / f"mipmap-{suffix}"
        out_dir.mkdir(parents=True, exist_ok=True)

        # --- legacy square (rounded) ---
        square = art.resize((legacy_px, legacy_px), Image.LANCZOS).convert("RGBA")
        square.putalpha(rounded_mask(legacy_px, CORNER_RATIO))
        square.save(out_dir / "ic_launcher.png", "PNG", optimize=True)

        # --- legacy round ---
        round_icon = art.resize((legacy_px, legacy_px), Image.LANCZOS).convert("RGBA")
        round_icon.putalpha(circle_mask(legacy_px))
        round_icon.save(out_dir / "ic_launcher_round.png", "PNG", optimize=True)

        # --- adaptive foreground layer ---
        art_px = max(1, round(layer_px * ART_DP / CANVAS_DP))
        layer = Image.new("RGBA", (layer_px, layer_px), (0, 0, 0, 0))
        scaled = art.resize((art_px, art_px), Image.LANCZOS).convert("RGBA")
        offset = (layer_px - art_px) // 2
        layer.paste(scaled, (offset, offset))
        layer.save(out_dir / "ic_launcher_foreground.png", "PNG", optimize=True)

        print(f"mipmap-{suffix:8s} legacy {legacy_px}px  layer {layer_px}px "
              f"(art {art_px}px)")

    colour = "#%02X%02X%02X" % bg
    (RES / "values/ic_launcher_background.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        "<resources>\n"
        f'    <color name="ic_launcher_background">{colour}</color>\n'
        "</resources>\n"
    )
    print(f"background colour -> {colour} (sampled from the artwork)")
    print(f"source            -> {SRC.relative_to(REPO)}")


if __name__ == "__main__":
    main()

