"""Image parser: OCR via pytesseract (needs the tesseract binary) -> one event per OCR line.

Real evidence is rarely a clean 300-DPI scan: analysts paste JPEG-compressed screenshots, photograph a
screen with a phone, and drop dark-mode terminal captures into the case. Tesseract does badly on all three
un-helped, so the bytes go through a preprocessing search before they reach it:

  * rescale        - to a MEASURED text line height (~18 px), not a fixed DPI: a 400 px crop is enlarged,
                     a 4000 px phone photo of the same eight lines is shrunk
  * deskew         - the dominant text angle is estimated from a projection profile and rotated out
  * contrast       - autocontrast and background flattening for the uneven light of a photo of a screen
  * binarize       - Otsu (global) or an adaptive local-mean threshold
  * denoise        - a 3x3 median kills JPEG mosquito noise and screen moire

Light-on-dark (dark-mode UI, terminals) is normalised to dark-on-light. Which engine you have decides how
much that matters: tesseract 5 (the CPU image, Debian) reads inverted text about as well either way, while
tesseract 4.1 (the GPU image, Ubuntu 22.04 universe) does NOT - inverting took a dark-mode photo of a screen
from 26% to 60% character accuracy there. The ink mask behind the skew and line-height estimates needs a
light background regardless, so the step is not optional.

Several recipes are tried and the winner is chosen by TESSERACT'S OWN per-word confidence rather than by
guessing which one should have worked. The work is bounded: recipes stop early once a pass is clearly good
(`GOOD_CONF`), at most `MAX_RUNS` OCR passes happen per image, and later frames of a multi-frame TIFF/GIF
replay the recipe the first frame settled on. In practice a decent screenshot costs ONE pass.

Every threshold here was measured against rendered log text degraded seven ways (downscale, JPEG q20,
noise, 3.5 deg rotation, dark mode, photo-of-screen, dark photo) rather than assumed - several plausible
ideas (unsharp masking, a second pass at 1.5x, trying other page-segmentation modes on merely-low-confidence
pages) measured WORSE than doing nothing and are deliberately absent.

The winning recipe and the mean confidence are written onto every event (`ocr_variant`, `ocr_confidence`,
`ocr_quality`), so a shaky extraction is visibly shaky instead of silently wrong.

Everything heavy is imported inside the functions: the app must still start (and report the format as
unavailable) with no tesseract, and preprocessing degrades to plain grayscale if numpy/Pillow ops fail.
"""
from __future__ import annotations

import io
import shutil
import time
from typing import Iterable, Iterator, Optional

from .base import BaseParser, ParsedEvent
from .tabular import line_event

IMAGE_MAGIC = (
    (b"\x89PNG\r\n\x1a\n", "png"), (b"\xff\xd8\xff", "jpeg"), (b"GIF87a", "gif"), (b"GIF89a", "gif"),
    (b"BM", "bmp"), (b"II*\x00", "tiff"), (b"MM\x00*", "tiff"),
)
EXTENSIONS = (".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".webp", ".gif")
OCR_UNAVAILABLE = "OCR unavailable: install tesseract-ocr"

# --- preprocessing / search budget -------------------------------------------------------------------
TARGET_LINE_H = 18.0         # px of text line height tesseract reads best (measured, see _prepare)
DOWNSCALE_LINE_H = 45.0      # bigger than this is wasted work: shrink instead
MIN_WORKING_EDGE = 1600      # fallback when the text size cannot be measured at all
MAX_UPSCALE = 2.0
MIN_DOWNSCALE = 0.5
MAX_WORKING_PIXELS = 40_000_000
GOOD_CONF = 82.0             # a pass this confident ends the search
MIN_GOOD_CHARS = 20          # ...but only if it actually read something
TRUSTED_CONF = 45.0          # per-line confidence below which the text is treated as noise when scoring
SPARSE_CHARS = 60            # under this, the "one uniform block" assumption clearly failed
# A later recipe has to WIN, not tie: the list runs least-destructive first, and thresholding an image
# that did not need it consistently measured worse than leaving it alone.
IMPROVE_MARGIN = 0.08
MAX_RUNS = 6                 # hard cap on tesseract passes for one frame
SEARCH_BUDGET_S = 45.0       # wall clock for the recipe search of one frame
MAX_FRAMES = 50
DESKEW_MIN_ANGLE = 0.4       # degrees; below this a rotation costs more than it fixes
TESS_TIMEOUT_S = 120

# --oem 3 = default engine, psm 6 = one uniform block (a screenshot of a log, not a magazine page).
# preserve_interword_spaces keeps column alignment readable in the raw line.
_TESS_BASE = "--oem 3 -c preserve_interword_spaces=1"
PRIMARY_PSM = 6
FALLBACK_PSMS = (3, 11)      # 3 = auto page segmentation, 11 = sparse text (photos, scattered UI labels)

# Ordered cheapest-first. Each is a list of op names understood by _apply().
RECIPES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("plain", ()),
    ("contrast", ("autocontrast",)),
    ("otsu", ("autocontrast", "otsu")),
    ("denoise-otsu", ("median", "flatten", "otsu")),
    ("adaptive", ("median", "adaptive")),
)


def image_magic(head: bytes) -> Optional[str]:
    for magic, kind in IMAGE_MAGIC:
        if head.startswith(magic):
            return kind
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    return None


def ocr_status() -> tuple[bool, str]:
    """(available, note): pytesseract + Pillow importable and a tesseract binary reachable.

    The binary check is what a local (non-Docker) install trips on: the wrapper installs from PyPI but
    tesseract itself does not, so the note has to name the system package, not the Python one.
    """
    try:
        import pytesseract
    except Exception:
        return False, "pytesseract not installed"
    try:
        from PIL import Image  # noqa: F401
    except Exception:
        return False, "Pillow not installed"
    cmd = getattr(pytesseract.pytesseract, "tesseract_cmd", "tesseract")
    if shutil.which(cmd) is None:
        return False, OCR_UNAVAILABLE
    return True, ""


# --------------------------------------------------------------------------- preprocessing
def _np():
    import numpy as np
    return np


def _img(a):
    from PIL import Image
    return Image.fromarray(a.astype(_np().uint8), mode="L")


def _otsu_threshold(a) -> int:
    """Otsu's global threshold from the 256-bin histogram."""
    np = _np()
    hist = np.bincount(a.ravel(), minlength=256).astype(np.float64)
    p = hist / max(float(a.size), 1.0)
    omega = np.cumsum(p)
    mu = np.cumsum(p * np.arange(256))
    mu_t = mu[-1]
    denom = omega * (1.0 - omega)
    with np.errstate(divide="ignore", invalid="ignore"):
        sigma_b = (mu_t * omega - mu) ** 2 / denom
    sigma_b[~np.isfinite(sigma_b)] = 0.0
    # A bilevel image (a pure black-on-white screenshot, a fax scan) has a FLAT maximum spanning every
    # level between its two peaks. argmax would return the bottom of that plateau, i.e. the ink value
    # itself, and `pixel < threshold` then selects nothing at all - an empty ink mask, no measurements,
    # and a blank frame out of the otsu recipe. Take the middle of the plateau instead.
    peak = float(sigma_b.max())
    if peak <= 0:
        return 128
    plateau = np.flatnonzero(sigma_b >= peak - 1e-12)
    return int(round(float(plateau.mean())))


def _needs_invert(a) -> bool:
    """True for light-on-dark images. The MEDIAN tracks the background, which the mean does not when a
    screenshot is mostly text."""
    np = _np()
    return float(np.median(a)) < 118.0


def _ink_mask(a):
    """A small binary ink mask that survives uneven lighting.

    Otsu straight off a phone photo thresholds the LIGHTING gradient, not the text - half the frame comes
    back as ink and every measurement taken from it (text size, skew) is nonsense. Dividing out a heavily
    blurred copy first flattens the gradient, which is what makes the estimates below trustworthy.
    """
    np = _np()
    from PIL import Image, ImageFilter

    img = _img(a)
    if img.width > 900:
        img = img.resize((900, max(1, int(img.height * 900.0 / img.width))), Image.BILINEAR)
    radius = max(5, min(img.width, img.height) // 20)
    bg = np.asarray(img.filter(ImageFilter.GaussianBlur(radius)), dtype=np.float32)
    cur = np.asarray(img, dtype=np.float32)
    flat = np.clip(cur / np.maximum(bg, 1.0) * 190.0, 0, 255).astype(np.uint8)
    return flat < _otsu_threshold(flat)


def _text_metrics(a) -> tuple[float, float]:
    """(median text line height in px at full scale, ink fraction) - or (0, frac) when unmeasurable."""
    np = _np()
    mask = _ink_mask(a)
    frac = float(mask.mean())
    if not (0.01 <= frac <= 0.45):
        return 0.0, frac
    profile = mask.sum(axis=1).astype(np.float32)
    if profile.max() <= 0:
        return 0.0, frac
    runs: list[int] = []
    current = 0
    for value in profile:
        if value > profile.max() * 0.15:
            current += 1
        elif current:
            runs.append(current)
            current = 0
    if current:
        runs.append(current)
    # A "line" as tall as the image means the rows merged (skewed text, or a photo whose ink mask is
    # mostly noise). That is a failed measurement, not a 155 px font - trusting it downscaled real
    # evidence to half size and destroyed the read, so it is rejected instead.
    if len(runs) < 2 or float(np.median(runs)) > mask.shape[0] / 4.0:
        return 0.0, frac
    scale_back = a.shape[1] / float(mask.shape[1] or 1)
    return float(np.median(runs)) * scale_back, frac


def _estimate_skew(a) -> float:
    """Dominant text angle in degrees, from the variance of the horizontal ink profile.

    Text lines pile ink into a few rows only when they are level, so the profile variance peaks at the
    true angle. Measured on the flattened binary mask and heavily guarded: an estimate that lands on the
    edge of the search range, or that barely beats "no rotation at all", is a measurement failure rather
    than a skewed page, and rotating on it made a photo-of-a-screen materially WORSE (measured).
    """
    np = _np()
    from PIL import Image

    mask = _ink_mask(a)
    if not (0.01 <= float(mask.mean()) <= 0.45):
        return 0.0
    base = Image.fromarray((mask.astype(np.uint8) * 255), mode="L")
    limit = 6

    def score(angle: float) -> float:
        rot = base if angle == 0 else base.rotate(angle, resample=Image.BILINEAR, fillcolor=0)
        prof = np.asarray(rot, dtype=np.float32).sum(axis=1)
        return float(prof.var())

    flat_score = score(0.0)
    coarse = max(range(-limit, limit + 1), key=lambda d: score(float(d)))
    if abs(coarse) >= limit:
        return 0.0  # the peak is outside the range we searched: do not trust it
    best, best_score = float(coarse), score(float(coarse))
    for d in range(-3, 4):
        angle = coarse + d * 0.25
        if angle == coarse:
            continue
        s = score(angle)
        if s > best_score:
            best, best_score = angle, s
    if abs(best) < DESKEW_MIN_ANGLE or best_score < flat_score * 1.05:
        return 0.0
    return best


def _apply(a, ops: tuple[str, ...]):
    """Run a recipe's ops over a uint8 grayscale array (already upscaled/inverted/deskewed)."""
    np = _np()
    from PIL import Image, ImageFilter, ImageOps

    img = _img(a)
    for op in ops:
        if op == "median":
            img = img.filter(ImageFilter.MedianFilter(3))
        elif op == "autocontrast":
            img = ImageOps.autocontrast(img, cutoff=1)
        elif op == "unsharp":
            img = img.filter(ImageFilter.UnsharpMask(radius=2, percent=140, threshold=3))
        elif op == "flatten":
            # divide out a heavily blurred copy: kills the lighting gradient of a photo of a screen
            radius = max(5, min(img.width, img.height) // 20)
            bg = np.asarray(img.filter(ImageFilter.GaussianBlur(radius)), dtype=np.float32)
            cur = np.asarray(img, dtype=np.float32)
            flat = np.clip(cur / np.maximum(bg, 1.0) * 190.0, 0, 255)
            img = _img(flat)
        elif op == "otsu":
            cur = np.asarray(img, dtype=np.uint8)
            img = _img((cur > _otsu_threshold(cur)).astype(np.uint8) * 255)
        elif op == "adaptive":
            radius = max(6, min(img.width, img.height) // 60)
            local = np.asarray(img.filter(ImageFilter.GaussianBlur(radius)), dtype=np.float32)
            cur = np.asarray(img, dtype=np.float32)
            img = _img(((cur > local - 10.0).astype(np.uint8)) * 255)
    return np.asarray(img.convert("L"), dtype=np.uint8)


def _prepare(pil_image) -> tuple[object, dict[str, str]]:
    """Grayscale, normalise polarity, deskew and rescale - everything every recipe wants. (array, notes)."""
    np = _np()
    from PIL import Image

    notes: dict[str, str] = {}
    g = pil_image.convert("RGB").convert("L")
    a = np.asarray(g, dtype=np.uint8)
    if _needs_invert(a):
        a = 255 - a
        notes["ocr_inverted"] = "yes"

    # Deskew BEFORE measuring: rotated text lines overlap in the horizontal profile, so the line-height
    # measurement below reads the whole block as one line and asks for a ruinous downscale.
    angle = _estimate_skew(a)
    if angle:
        rotated = _img(a).rotate(angle, resample=Image.BICUBIC, fillcolor=255, expand=False)
        a = np.asarray(rotated, dtype=np.uint8)
        notes["ocr_deskew"] = f"{angle:.2f}deg"

    # Scale by TEXT SIZE, not image size: a 4000 px phone photo of eight log lines needs no upscale, and a
    # 400 px crop of the same lines needs a big one. Measured sweet spot is a line height around 18 px; past
    # 2x the resampler's ringing costs more accuracy than the extra pixels buy (measured on downscaled text).
    line_h, _frac = _text_metrics(a)
    scale = 1.0
    if line_h > 0:
        if line_h < TARGET_LINE_H:
            scale = min(MAX_UPSCALE, TARGET_LINE_H / line_h)
        elif line_h > DOWNSCALE_LINE_H:
            scale = max(MIN_DOWNSCALE, DOWNSCALE_LINE_H / line_h)
        notes["ocr_line_h"] = f"{line_h:.0f}px"
    elif max(g.width, g.height) < MIN_WORKING_EDGE:
        scale = min(MAX_UPSCALE, MIN_WORKING_EDGE / max(max(g.width, g.height), 1))
    if a.shape[0] * a.shape[1] * scale * scale > MAX_WORKING_PIXELS:
        scale = min(scale, (MAX_WORKING_PIXELS / max(a.shape[0] * a.shape[1], 1)) ** 0.5)
    scale = round(scale * 4) / 4.0
    if abs(scale - 1.0) > 0.05:
        resized = _img(a).resize((max(1, int(a.shape[1] * scale)), max(1, int(a.shape[0] * scale))),
                                 Image.LANCZOS)
        a = np.asarray(resized, dtype=np.uint8)
        notes["ocr_rescale"] = f"{scale:.2f}x"
    return a, notes


# --------------------------------------------------------------------------- one OCR pass
class _Pass:
    """The result of one tesseract run: its lines plus the numbers used to compare recipes."""

    def __init__(self, recipe: str, psm: int, lines: list[tuple[str, float]]) -> None:
        self.recipe = recipe
        self.psm = psm
        self.lines = lines
        chars = 0.0
        weighted = 0.0
        trusted = 0.0
        for text, conf in lines:
            n = len(text.strip())
            if n and conf >= 0:
                chars += n
                weighted += conf * n
                if conf >= TRUSTED_CONF:
                    trusted += n
        self.chars = int(chars)
        self.mean_conf = (weighted / chars) if chars else 0.0
        # Mean confidence times the characters that came from lines worth believing. Scoring on raw
        # character count instead let a binarisation that hallucinated 536 characters of noise at 31%
        # confidence beat a pass that read the page (measured); scoring on confidence alone lets a
        # two-word fragment win. The 0.01*chars term only breaks ties when NOTHING was trusted.
        self.score = self.mean_conf * (trusted + 0.01 * chars)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<_Pass {self.recipe}/psm{self.psm} chars={self.chars} conf={self.mean_conf:.1f}>"


def _ocr_pass(pyt, pil_image, recipe: str, psm: int) -> _Pass:
    """One tesseract run, grouping words into lines by (block, paragraph, line) with a mean confidence."""
    config = f"{_TESS_BASE} --psm {psm}"
    try:
        d = pyt.image_to_data(pil_image, output_type=pyt.Output.DICT, config=config, timeout=TESS_TIMEOUT_S)
    except pyt.TesseractNotFoundError:
        raise RuntimeError(OCR_UNAVAILABLE)
    except Exception:
        d = None
    if d is None:  # image_to_data unavailable (old tesseract) - fall back to plain text, unscored
        try:
            text = pyt.image_to_string(pil_image, config=config, timeout=TESS_TIMEOUT_S)
        except pyt.TesseractNotFoundError:
            raise RuntimeError(OCR_UNAVAILABLE)
        except Exception:
            text = ""
        return _Pass(recipe, psm, [(l.strip(), 60.0) for l in text.splitlines() if l.strip()])

    groups: dict[tuple[int, int, int], tuple[list[str], list[float]]] = {}
    order: list[tuple[int, int, int]] = []
    for i, word in enumerate(d.get("text", [])):
        if not str(word).strip():
            continue
        try:
            key = (int(d["block_num"][i]), int(d["par_num"][i]), int(d["line_num"][i]))
        except (KeyError, IndexError, TypeError, ValueError):
            key = (0, 0, i)
        if key not in groups:
            groups[key] = ([], [])
            order.append(key)
        groups[key][0].append(str(word))
        try:
            conf = float(d["conf"][i])
        except (KeyError, IndexError, TypeError, ValueError):
            conf = -1.0
        if conf >= 0:
            groups[key][1].append(conf)
    lines: list[tuple[str, float]] = []
    for key in order:
        words, confs = groups[key]
        text = " ".join(words).strip()
        if text:
            lines.append((text, (sum(confs) / len(confs)) if confs else -1.0))
    return _Pass(recipe, psm, lines)


def _best_pass(pyt, base_array, plan: Optional[tuple[str, int]]) -> _Pass:
    """Search the recipes for the best OCR of one prepared frame (or replay a known-good `plan`)."""
    started = time.monotonic()
    runs = 0

    def run(recipe: str, ops: tuple[str, ...], psm: int) -> _Pass:
        nonlocal runs
        runs += 1
        return _ocr_pass(pyt, _img(_apply(base_array, ops)), recipe, psm)

    def spent() -> bool:
        return runs >= MAX_RUNS or time.monotonic() - started > SEARCH_BUDGET_S

    by_name = dict(RECIPES)
    if plan is not None and plan[0] in by_name:
        return run(plan[0], by_name[plan[0]], plan[1])

    best: Optional[_Pass] = None
    for name, ops in RECIPES:
        if best is not None and spent():
            break
        current = run(name, ops, PRIMARY_PSM)
        if best is None or current.score > best.score * (1.0 + IMPROVE_MARGIN):
            best = current
        if best.mean_conf >= GOOD_CONF and best.chars >= MIN_GOOD_CHARS:
            return best  # already good; spending four more passes on it would be waste

    if best is None:
        return _Pass("plain", PRIMARY_PSM, [])
    # The page may simply not be one uniform block (sparse UI labels scattered over a screenshot).
    # Re-segmenting is only tried when almost NOTHING came back: on merely-low-confidence pages the
    # other segmentation modes measured worse than psm 6 across every degradation, so they are not
    # a general-purpose second opinion.
    if best.chars < SPARSE_CHARS:
        for psm in FALLBACK_PSMS:
            if spent():
                break
            current = run(best.recipe, by_name.get(best.recipe, ()), psm)
            if current.score > best.score * (1.0 + IMPROVE_MARGIN):
                best = current
    return best


def _quality(mean_conf: float) -> str:
    if mean_conf >= 80:
        return "high"
    if mean_conf >= 60:
        return "medium"
    return "low"


class ImageParser(BaseParser):
    name = "Image (OCR)"
    family = "document.image"
    binary = True
    extensions = EXTENSIONS

    def sniff(self, sample: list[str], filename: str = "", head: bytes = b"") -> float:
        if image_magic(head):
            return 1.0
        if filename.lower().endswith(EXTENSIONS):
            return 0.8
        return 0.0

    def parse(self, lines: Iterable[str]) -> Iterator[ParsedEvent]:
        return iter(())

    def parse_bytes(self, data: bytes) -> Iterator[ParsedEvent]:
        ok, _note = ocr_status()
        if not ok:
            raise RuntimeError(OCR_UNAVAILABLE)
        import pytesseract
        from PIL import Image

        img = Image.open(io.BytesIO(data))
        frames = getattr(img, "n_frames", 1) or 1
        image_name = f"{img.format or 'image'} {img.width}x{img.height}"
        line_no = 0
        plan: Optional[tuple[str, int]] = None
        for frame in range(min(frames, MAX_FRAMES)):
            if frames > 1:
                img.seek(frame)
            base = {"image": image_name}
            if frames > 1:
                base["frame"] = str(frame + 1)
            try:
                prepared, notes = _prepare(img)
            except Exception:
                # never let preprocessing be the reason an image yields nothing
                from PIL import ImageOps
                import numpy as np
                prepared = np.asarray(ImageOps.grayscale(img.convert("RGB")), dtype=np.uint8)
                notes = {"ocr_preprocess": "unavailable"}
            base.update(notes)
            result = _best_pass(pytesseract, prepared, plan)
            plan = (result.recipe, result.psm)  # later frames of this file replay the winner
            base["ocr_variant"] = f"{result.recipe}/psm{result.psm}"
            if result.chars:
                base["ocr_confidence"] = f"{result.mean_conf:.0f}"
                base["ocr_quality"] = _quality(result.mean_conf)
            for text, conf in result.lines:
                line_no += 1
                extra = {**base, "line_no": str(line_no)}
                if conf >= 0:
                    extra["confidence"] = f"{conf:.0f}"
                yield line_event(text, extra)
