/**
 * Small colour helpers for the appearance tokens: hex parsing, alpha blending, mixing,
 * HSL channel output (the format the shadcn tokens use: `H S% L%`) and WCAG 2.x contrast.
 * Pure functions, no DOM — shared by the CSS generator and the unit tests.
 */

export type Rgb = { r: number; g: number; b: number; a: number };

export const parseHex = (hex: string): Rgb => {
  const value = hex.replace('#', '').trim();

  if (!/^([0-9a-f]{3}|[0-9a-f]{6}|[0-9a-f]{8})$/i.test(value)) {
    throw new Error(`Invalid hex colour: ${hex}`);
  }

  const full =
    value.length === 3
      ? value
          .split('')
          .map((c) => c + c)
          .join('')
      : value;

  return {
    r: Number.parseInt(full.slice(0, 2), 16),
    g: Number.parseInt(full.slice(2, 4), 16),
    b: Number.parseInt(full.slice(4, 6), 16),
    a: full.length === 8 ? Number.parseInt(full.slice(6, 8), 16) / 255 : 1,
  };
};

const toHexByte = (value: number) =>
  Math.round(Math.min(255, Math.max(0, value)))
    .toString(16)
    .padStart(2, '0')
    .toUpperCase();

export const toHex = ({ r, g, b }: Rgb) => `#${toHexByte(r)}${toHexByte(g)}${toHexByte(b)}`;

/** Composite a (possibly translucent) colour over an opaque background. */
export const blend = (foreground: string, background: string): string => {
  const fg = parseHex(foreground);
  const bg = parseHex(background);

  return toHex({
    r: fg.r * fg.a + bg.r * (1 - fg.a),
    g: fg.g * fg.a + bg.g * (1 - fg.a),
    b: fg.b * fg.a + bg.b * (1 - fg.a),
    a: 1,
  });
};

/** Mix two opaque colours: `amount` = share of `b` (0…1). */
export const mix = (a: string, b: string, amount: number): string => {
  const x = parseHex(a);
  const y = parseHex(b);

  return toHex({
    r: x.r + (y.r - x.r) * amount,
    g: x.g + (y.g - x.g) * amount,
    b: x.b + (y.b - x.b) * amount,
    a: 1,
  });
};

/** Hex with an alpha channel, e.g. `withAlpha('#112420', 0.4)` → `#11242066`. */
export const withAlpha = (hex: string, alpha: number) => `${toHex(parseHex(hex))}${toHexByte(alpha * 255)}`;

const round = (value: number, digits = 1) => {
  const factor = 10 ** digits;

  return Math.round(value * factor) / factor;
};

/** `#0B1220` → `220 49% 8.4%` (the channel format consumed as `hsl(var(--token))`). */
export const hexToHslChannels = (hex: string): string => {
  const { r, g, b } = parseHex(hex);
  const rn = r / 255;
  const gn = g / 255;
  const bn = b / 255;

  const max = Math.max(rn, gn, bn);
  const min = Math.min(rn, gn, bn);
  const lightness = (max + min) / 2;

  let hue = 0;
  let saturation = 0;

  if (max !== min) {
    const delta = max - min;

    saturation = lightness > 0.5 ? delta / (2 - max - min) : delta / (max + min);

    if (max === rn) {
      hue = (gn - bn) / delta + (gn < bn ? 6 : 0);
    } else if (max === gn) {
      hue = (bn - rn) / delta + 2;
    } else {
      hue = (rn - gn) / delta + 4;
    }

    hue *= 60;
  }

  return `${round(hue)} ${round(saturation * 100)}% ${round(lightness * 100)}%`;
};

const channelToLinear = (channel: number) => {
  const value = channel / 255;

  return value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
};

export const relativeLuminance = (hex: string) => {
  const { r, g, b } = parseHex(hex);

  return 0.2126 * channelToLinear(r) + 0.7152 * channelToLinear(g) + 0.0722 * channelToLinear(b);
};

/** WCAG 2.x contrast ratio of two opaque colours (1…21). */
export const contrastRatio = (a: string, b: string) => {
  const la = relativeLuminance(a);
  const lb = relativeLuminance(b);

  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
};
