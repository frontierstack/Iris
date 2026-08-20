"""A note that references an attached image must RENDER as an <img>, on the surface the app uses.

The analyst's report: pasting a screenshot into a case note showed
`![testdata.png](/api/cases/CASE-0017/attachments/att-<hex>.png)` as literal text. The upload and the
markdown were fine, so the failure could only be in rendering — either the note body never reaching the
markdown renderer (a plain `{note.text}`), or the renderer's URL allow-list rejecting the attachment
path and falling back to emitting the literal source, which is exactly what an unsafe URL does.

So this file pins both halves:
  * the REAL renderer (frontend/src/utils/markdown.tsx, bundled and executed through React's server
    renderer) turns the attachment markdown into an <img> pointing at the attachment URL;
  * `NoteRow` — the one component in the app that displays a posted note — passes `note.text` through
    `renderMarkdown` and never renders it as text.

The first half needs node + the frontend's node_modules; it skips when they are not installed.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FRONTEND = ROOT / "frontend"
MARKDOWN_TSX = FRONTEND / "src" / "utils" / "markdown.tsx"
CASE_NOTES_TSX = FRONTEND / "src" / "components" / "CaseNotes.tsx"

# the analyst's note, verbatim in shape
NOTE = "![testdata.png](/api/cases/CASE-0017/attachments/att-566437ef0b30fb16d93136d74bda6cd4.png)"

ENTRY = """
import { renderMarkdown } from './src/utils/markdown';
import { renderToStaticMarkup } from 'react-dom/server';
const note = %(note)s;
process.stdout.write(renderToStaticMarkup(renderMarkdown(note)));
"""


def _esbuild() -> Path | None:
    for name in ("esbuild.cmd", "esbuild"):
        p = FRONTEND / "node_modules" / ".bin" / name
        if p.is_file():
            return p
    return None


@pytest.mark.skipif(not MARKDOWN_TSX.is_file(), reason="frontend sources not present")
def test_note_image_markdown_renders_an_img(tmp_path):
    """Run the app's own renderer over the analyst's note and read the HTML it produces."""
    node = shutil.which("node")
    bundler = _esbuild()
    if not node or bundler is None or not (FRONTEND / "node_modules" / "react-dom").is_dir():
        pytest.skip("node / frontend node_modules not available")

    # the entry has to live inside frontend/ — esbuild resolves react-dom by walking up from the
    # IMPORTING file, not from the working directory
    entry = FRONTEND / ".iris-note-render-test.tsx"
    out = tmp_path / "bundle.cjs"

    def render(note: str) -> str:
        entry.write_text(ENTRY % {"note": json.dumps(note)}, encoding="utf-8")
        build = subprocess.run([str(bundler), str(entry), "--bundle", "--platform=node", "--format=cjs",
                                "--jsx=automatic", f"--outfile={out}"],
                               cwd=str(FRONTEND), capture_output=True, text=True)
        assert build.returncode == 0, build.stderr
        run = subprocess.run([node, str(out)], cwd=str(FRONTEND), capture_output=True, text=True)
        assert run.returncode == 0, run.stderr
        return run.stdout

    try:
        html = render(NOTE)
        unsafe = render("![x](javascript:alert(1))")
    finally:
        entry.unlink(missing_ok=True)

    # an <img> whose src is the attachment URL — not a literal "![testdata.png](...)"
    assert "<img" in html, html
    assert 'src="/api/cases/CASE-0017/attachments/att-566437ef0b30fb16d93136d74bda6cd4.png"' in html, html
    assert 'alt="testdata.png"' in html, html
    assert "![" not in html, html

    # a javascript: URL still degrades to inert literal text — the allow-list is intact
    assert "<img" not in unsafe and "javascript:" in unsafe


@pytest.mark.skipif(not CASE_NOTES_TSX.is_file(), reason="frontend sources not present")
def test_the_note_surface_renders_markdown_not_text():
    """The posted-note surface must go through renderMarkdown. `{note.text}` there is the bug itself."""
    src = CASE_NOTES_TSX.read_text(encoding="utf-8")
    assert "renderMarkdown(note.text)" in src, "NoteRow must render the note body as markdown"
    # the raw body must never be dropped into JSX directly (the draft state in the editor is separate)
    assert not re.search(r">\s*\{note\.text\}\s*<", src), "a note body is rendered as plain text somewhere"
    # …and the WRITE-mode editor, where the markdown token legitimately appears as text, has to show the
    # picture too: attaching a screenshot and seeing only `![shot.png](…)` is the analyst's whole report.
    assert "md-shots" in src and "draftImages(value)" in src, "the composer must preview attached images"
