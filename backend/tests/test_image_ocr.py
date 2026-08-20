"""OCR preprocessing: the parts that can be checked without the tesseract binary, plus a real end-to-end
read when tesseract IS present (the Docker image ships it; a bare `pip install` does not).

The preprocessing decisions are what make a bad screenshot readable, and each of them has already been
wrong once in a way that silently destroyed a read, so they are pinned here:
  * a skew estimate taken off an unevenly lit photo used to come back as 6.75 degrees for a 2 degree tilt
  * the line-height measurement used to read a whole skewed block as one 155 px "line" and downscale to 0.5x
  * the recipe scorer used to prefer 536 characters of 31%-confidence noise over a real read
"""
from __future__ import annotations

import io

import pytest

from app.parsers import image as im
from app.parsers.image import ImageParser, OCR_UNAVAILABLE, ocr_status

np = pytest.importorskip("numpy")
PIL = pytest.importorskip("PIL")
from PIL import Image, ImageDraw  # noqa: E402


def _bars(width=800, height=400, dark_on_light=True, rows=8) -> Image.Image:
    """A stand-in for text: evenly spaced horizontal ink bars. Font-free, so it works anywhere."""
    bg, fg = (255, 0) if dark_on_light else (0, 255)
    img = Image.new("L", (width, height), bg)
    d = ImageDraw.Draw(img)
    step = height // (rows + 1)
    for i in range(rows):
        y = step * (i + 1)
        d.rectangle([40, y, width - 40, y + 6], fill=fg)
    return img


def _arr(img) -> "np.ndarray":
    return np.asarray(img.convert("L"), dtype=np.uint8)


# --------------------------------------------------------------------------- primitives
def test_otsu_splits_a_bimodal_image():
    a = np.concatenate([np.full(5000, 30, np.uint8), np.full(5000, 220, np.uint8)])
    t = im._otsu_threshold(a)
    assert 30 < t < 220


def test_dark_mode_is_detected_and_normalised():
    dark = _arr(_bars(dark_on_light=False))
    assert im._needs_invert(dark) is True
    assert im._needs_invert(_arr(_bars())) is False
    prepared, notes = im._prepare(_bars(dark_on_light=False))
    assert notes.get("ocr_inverted") == "yes"
    assert float(np.median(prepared)) > 118  # light background after the fix


@pytest.mark.parametrize("angle", [0.0, 2.0, 3.5, -3.0])
def test_skew_is_estimated_within_half_a_degree(angle):
    img = _bars()
    if angle:
        img = img.rotate(-angle, resample=Image.BICUBIC, fillcolor=255, expand=True)
    estimate = im._estimate_skew(_arr(img))
    assert abs(estimate - angle) < 0.6, f"estimated {estimate} for a {angle} degree tilt"


def test_skew_is_not_guessed_from_an_unreadable_image():
    """A flat / near-empty frame has no dominant text angle; rotating on a noise peak makes it worse."""
    assert im._estimate_skew(np.full((300, 300), 255, np.uint8)) == 0.0
    rng = np.random.default_rng(3)
    assert im._estimate_skew(rng.integers(0, 255, (300, 300), dtype=np.uint8)) == 0.0


def test_line_height_is_measured_and_drives_the_rescale():
    small = _bars(width=400, height=200)
    line_h, _frac = im._text_metrics(_arr(small))
    assert 1 < line_h < 20
    _prepared, notes = im._prepare(small)
    assert notes.get("ocr_rescale", "").endswith("x")
    assert float(notes["ocr_rescale"][:-1]) > 1.0, "small text must be enlarged"


def test_unmeasurable_text_height_never_downscales():
    """The bug: one merged 'line' as tall as the frame asked for a 0.5x downscale and wrecked the read."""
    solid = np.zeros((200, 200), np.uint8)
    line_h, _frac = im._text_metrics(solid)
    assert line_h == 0.0
    _prepared, notes = im._prepare(Image.fromarray(solid, mode="L"))
    assert float(notes.get("ocr_rescale", "1.0x")[:-1]) >= 1.0


def test_every_recipe_produces_a_usable_grayscale_frame():
    a = _arr(_bars())
    for name, ops in im.RECIPES:
        out = im._apply(a, ops)
        assert out.shape == a.shape and out.dtype == np.uint8, name


# --------------------------------------------------------------------------- scoring
def _pass(lines):
    return im._Pass("r", 6, lines)


def test_confident_text_outscores_a_pile_of_low_confidence_noise():
    real = _pass([("2024-03-11 sshd Failed password for root", 86.0)] * 4)
    noise = _pass([("l1I" * 30, 31.0)] * 12)
    assert noise.chars > real.chars, "the noisy pass really is longer"
    assert real.score > noise.score, "scoring must not reward hallucinated characters"


def test_a_confident_fragment_does_not_beat_a_whole_page():
    fragment = _pass([("root", 99.0)])
    page = _pass([("2024-03-11 sshd Failed password for root from 10.0.0.9", 78.0)] * 6)
    assert page.score > fragment.score


def test_quality_labels_track_confidence():
    assert im._quality(91) == "high"
    assert im._quality(64) == "medium"
    assert im._quality(30) == "low"


# --------------------------------------------------------------------------- end to end
def test_missing_tesseract_reports_the_system_package():
    ok, note = ocr_status()
    if ok:
        pytest.skip("tesseract is installed here; the unavailable path is not exercised")
    assert note in (OCR_UNAVAILABLE, "pytesseract not installed", "Pillow not installed")
    if note == OCR_UNAVAILABLE:
        assert "tesseract-ocr" in note  # the apt package, not the pip one
        png = io.BytesIO()
        _bars().save(png, "PNG")
        with pytest.raises(RuntimeError) as exc:
            list(ImageParser().parse_bytes(png.getvalue()))
        assert OCR_UNAVAILABLE in str(exc.value)


def _render_text(lines, width=900, size=15):
    from PIL import ImageFont
    for path in ("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
                 "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"):
        try:
            font = ImageFont.truetype(path, size)
            break
        except Exception:
            continue
    else:
        pytest.skip("no scalable font available to render OCR test text")
    img = Image.new("RGB", (width, 22 * len(lines) + 20), "white")
    d = ImageDraw.Draw(img)
    for i, line in enumerate(lines):
        d.text((10, 10 + i * 22), line, font=font, fill=(20, 20, 20))
    return img


@pytest.mark.parametrize("degrade", ["none", "jpeg", "rotate", "dark"])
def test_degraded_images_still_read_back(degrade):
    if not ocr_status()[0]:
        pytest.skip("tesseract not installed")
    lines = ["2024-03-11 04:12:07 sshd Failed password for root from 203.0.113.42",
             "2024-03-11 04:13:44 sudo admin COMMAND=/bin/bash"]
    img = _render_text(lines)
    fmt = "PNG"
    if degrade == "jpeg":
        fmt = "JPEG"
    elif degrade == "rotate":
        img = img.rotate(-3.0, resample=Image.BICUBIC, fillcolor=(255, 255, 255), expand=True)
    elif degrade == "dark":
        img = Image.fromarray(255 - np.asarray(img.convert("RGB"), dtype=np.uint8))
    buf = io.BytesIO()
    img.save(buf, fmt, **({"quality": 25} if fmt == "JPEG" else {}))

    events = list(ImageParser().parse_bytes(buf.getvalue()))
    assert events, f"{degrade}: OCR returned nothing"
    text = " ".join(e.raw for e in events)
    for token in ("sshd", "root", "203.0.113.42", "sudo"):
        assert token in text, f"{degrade}: lost {token!r} - got {text!r}"
    fields = events[0].fields
    assert fields["ocr_variant"].startswith(("plain", "contrast", "otsu", "denoise-otsu", "adaptive"))
    assert 0 < float(fields["ocr_confidence"]) <= 100
    assert fields["ocr_quality"] in ("high", "medium", "low")
