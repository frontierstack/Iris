"""A deployed UI fix must not be invisible because the browser kept the old index.html.

Three fixes in a row — the note renderer, the timeline layout, the graph highlight — were verified in
the served bundle, deployed, and reported back as "it still looks the same". They were: the browser was
holding `index.html`, which is the one file whose NAME does not change between builds and which names
every content-hashed asset. Nothing set `Cache-Control` on it, so browsers applied HEURISTIC freshness
(a fraction of the file's age) and kept serving an old app against a new server.

So: index.html is `no-store`, and the hashed assets are `immutable` for a year — which is safe by
construction, because a changed asset has a different name.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import FRONTEND_DIST, app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


built = pytest.mark.skipif(not (FRONTEND_DIST / "index.html").exists(),
                           reason="frontend/dist is not built in this environment")


@built
def test_index_html_is_never_cached(client):
    for path in ("/", "/cases", "/graph"):
        r = client.get(path)
        assert r.status_code == 200
        cc = r.headers.get("cache-control", "")
        assert "no-store" in cc, f"{path} served index.html as {cc!r} — a stale SPA is the result"


@built
def test_hashed_assets_are_cached_hard(client):
    assets = sorted((FRONTEND_DIST / "assets").glob("index-*.js"))
    if not assets:
        pytest.skip("no built assets")
    r = client.get(f"/assets/{assets[0].name}")
    assert r.status_code == 200
    cc = r.headers.get("cache-control", "")
    assert "immutable" in cc and "max-age=31536000" in cc, (
        f"{cc!r}: a content-hashed file may be cached for ever — the NAME changes when it does")
