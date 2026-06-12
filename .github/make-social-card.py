#!/usr/bin/env python3
"""Regenerate the GitHub social card in the synthwave style of the reference
artwork ("Dom image.png"): the retrowave scene is the background, the baked-in
"SYNTH Wave" text is suppressed with a soft center glow, a chrome "Dom"
wordmark replaces it, and a color-coded capability mindmap is overlaid BEHIND
the wordmark (branch lines run behind the letters).
"""
import os
import sys
from PIL import Image, ImageDraw, ImageFont, ImageFilter

# Reference artwork + output path are configurable — no hardcoded local path.
#   make-social-card.py <reference-image.png> [out.png]
# or set DOM_SOCIAL_REF / DOM_SOCIAL_OUT.
REF = os.environ.get("DOM_SOCIAL_REF") or (sys.argv[1] if len(sys.argv) > 1 else "")
OUT = os.environ.get("DOM_SOCIAL_OUT") or (sys.argv[2] if len(sys.argv) > 2 else ".github/social-card.png")
if not REF:
    sys.exit("usage: make-social-card.py <reference-image.png> [out.png]  (or set DOM_SOCIAL_REF)")

W, H = 1280, 640
S = 2  # supersample factor

CAT = {
    "security": (34, 211, 238),   # cyan
    "sandbox":  (251, 191, 36),   # amber
    "review":   (192, 132, 252),  # violet
    "ops":      (236, 240, 245),  # near-white
}
HUB = (640, 248)
NODES = [
    ("Docker Sandbox",     250, 110, "sandbox"),
    ("Guardrail Hooks",    540, 78,  "security"),
    ("5 Reviewers",        858, 90,  "review"),
    ("Audit Log",         1062, 162, "security"),
    ("Leak Detection",    1110, 330, "security"),
    ("Session Encryption", 980, 470, "security"),
    ("Shared Brain",       176, 330, "ops"),
    ("Cost Budget",        236, 470, "ops"),
]

FONT = "/System/Library/Fonts/HelveticaNeue.ttc"
FONT_BOLD = "/System/Library/Fonts/Supplemental/Arial Bold.ttf"


def font(path, size):
    try:
        return ImageFont.truetype(path, size)
    except Exception:
        return ImageFont.load_default()


# ---------------------------------------------------------------------------
# 1. synthwave background + center spotlight (suppress old "SYNTH Wave")
# ---------------------------------------------------------------------------
ref = Image.open(REF).convert("RGB")
rw, rh = ref.size
scale = max(W / rw, H / rh)
ref = ref.resize((int(round(rw * scale)), int(round(rh * scale))), Image.LANCZOS)
nw, nh = ref.size
left, top = (nw - W) // 2, (nh - H) // 2
base = ref.crop((left, top, left + W, top + H))

spot = Image.new("L", (W, H), 0)
sd = ImageDraw.Draw(spot)
sd.ellipse([640 - 600, 272 - 258, 640 + 600, 272 + 258], fill=255)
sd.ellipse([650 - 370, 352 - 165, 650 + 370, 352 + 165], fill=255)  # over the "Wave" script
spot = spot.filter(ImageFilter.GaussianBlur(65))
base = Image.composite(Image.new("RGB", (W, H), (6, 5, 18)), base, spot.point(lambda v: int(v * 1.0)))
base = base.convert("RGBA")


# ---------------------------------------------------------------------------
# 2. color-coded mindmap (drawn BEFORE the wordmark so "Dom" covers the lines)
# ---------------------------------------------------------------------------
layer = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
ld = ImageDraw.Draw(layer)
flab = font(FONT, 15 * S)
hx, hy = HUB[0] * S, HUB[1] * S

chips = []
for label, x, y, cat in NODES:
    color = CAT[cat]
    bbox = ld.textbbox((0, 0), label, font=flab)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    dot_d, px, py, gap = 10 * S, 15 * S, 9 * S, 9 * S
    cw = px + dot_d + gap + tw + px
    ch = py + max(th, dot_d) + py
    cx, cy = x * S, y * S
    x0, y0 = cx - cw // 2, cy - ch // 2
    m = 16 * S
    x0 = max(m, min(x0, W * S - m - cw))
    y0 = max(m, min(y0, H * S - m - ch))
    chips.append((label, color, x0, y0, cw, ch, dot_d, px, py, gap, bbox, th))

for label, color, x0, y0, cw, ch, *_ in chips:
    ld.line([(hx, hy), (x0 + cw // 2, y0 + ch // 2)], fill=color + (140,), width=2 * S)

hr = 20 * S
ld.ellipse([hx - hr, hy - hr, hx + hr, hy + hr], outline=(236, 240, 245, 70), width=2 * S)

for label, color, x0, y0, cw, ch, dot_d, px, py, gap, bbox, th in chips:
    try:
        ld.rounded_rectangle([x0, y0, x0 + cw, y0 + ch], radius=ch // 2,
                             fill=(8, 10, 22, 225), outline=color + (255,), width=2 * S)
    except AttributeError:
        ld.rectangle([x0, y0, x0 + cw, y0 + ch], fill=(8, 10, 22, 225), outline=color + (255,), width=2 * S)
    dcx, dcy = x0 + px + dot_d // 2, y0 + ch // 2
    ld.ellipse([dcx - dot_d // 2, dcy - dot_d // 2, dcx + dot_d // 2, dcy + dot_d // 2], fill=color + (255,))
    tx = x0 + px + dot_d + gap - bbox[0]
    ty = y0 + (ch - th) // 2 - bbox[1]
    ld.text((tx, ty), label, font=flab, fill=(234, 240, 246, 255))

base = Image.alpha_composite(base, layer.resize((W, H), Image.LANCZOS))


# ---------------------------------------------------------------------------
# 3. chrome "Dom" wordmark (80s metallic: cyan-blue top, warm-pink bottom)
# ---------------------------------------------------------------------------
def chrome_text(text, fnt, cy_center):
    cw_, ch_ = W * S, H * S
    tmp = ImageDraw.Draw(Image.new("RGBA", (1, 1)))
    bbox = tmp.textbbox((0, 0), text, font=fnt)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    tx = (cw_ - tw) // 2 - bbox[0]
    ty = int(cy_center * S - th / 2) - bbox[1]
    text_top, text_h = ty + bbox[1], th

    # vertical chrome gradient (classic split with a hard horizon)
    stops = [(0.00, (215, 243, 255)), (0.32, (120, 182, 240)), (0.50, (38, 86, 168)),
             (0.52, (255, 150, 70)), (0.74, (255, 108, 152)), (1.00, (255, 216, 188))]
    grad = Image.new("RGB", (cw_, ch_), (0, 0, 0))
    gd = ImageDraw.Draw(grad)
    for y in range(ch_):
        t = min(1.0, max(0.0, (y - text_top) / max(1, text_h)))
        col = stops[-1][1]
        for i in range(len(stops) - 1):
            t0, c0 = stops[i]
            t1, c1 = stops[i + 1]
            if t0 <= t <= t1:
                f = (t - t0) / max(1e-6, t1 - t0)
                col = tuple(int(c0[k] + (c1[k] - c0[k]) * f) for k in range(3))
                break
        gd.line([(0, y), (cw_, y)], fill=col)

    mask = Image.new("L", (cw_, ch_), 0)
    ImageDraw.Draw(mask).text((tx, ty), text, font=fnt, fill=255)
    chrome = Image.new("RGBA", (cw_, ch_), (0, 0, 0, 0))
    chrome.paste(grad, (0, 0), mask)

    out = Image.new("RGBA", (cw_, ch_), (0, 0, 0, 0))
    # outer neon glow
    for col, blur in [((255, 40, 160, 215), 28 * S), ((90, 210, 255, 150), 13 * S)]:
        g = Image.new("RGBA", (cw_, ch_), (0, 0, 0, 0))
        ImageDraw.Draw(g).text((tx, ty), text, font=fnt, fill=col, stroke_width=3 * S, stroke_fill=col)
        out = Image.alpha_composite(out, g.filter(ImageFilter.GaussianBlur(blur)))
    # dark rim for definition
    rim = Image.new("RGBA", (cw_, ch_), (0, 0, 0, 0))
    ImageDraw.Draw(rim).text((tx, ty), text, font=fnt, fill=(16, 12, 36, 255),
                             stroke_width=5 * S, stroke_fill=(16, 12, 36, 255))
    out = Image.alpha_composite(out, rim)
    # chrome fill
    out = Image.alpha_composite(out, chrome)
    return out.resize((W, H), Image.LANCZOS)


base = Image.alpha_composite(base, chrome_text("Dom", font(FONT_BOLD, 196 * S), HUB[1]))


# ---------------------------------------------------------------------------
# 4. tagline + url
# ---------------------------------------------------------------------------
tl = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
td = ImageDraw.Draw(tl)
ftag = font(FONT, 30 * S)
furl = font(FONT, 19 * S)
tag = "Autonomous coding agent — sandboxed, audited, self-reviewing."
b = td.textbbox((0, 0), tag, font=ftag)
td.text(((W * S - (b[2] - b[0])) // 2 - b[0], 545 * S), tag, font=ftag, fill=(232, 238, 248, 255))
url = "github.com/T11g1/dom"
b2 = td.textbbox((0, 0), url, font=furl)
td.text(((W * S - (b2[2] - b2[0])) // 2 - b2[0], 597 * S), url, font=furl, fill=(125, 205, 235, 255))
base = Image.alpha_composite(base, tl.resize((W, H), Image.LANCZOS))

base.convert("RGB").save(OUT)
print("wrote", OUT)
