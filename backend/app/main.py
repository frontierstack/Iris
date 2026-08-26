"""Iris backend - FastAPI application."""
from __future__ import annotations

import faulthandler
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from typing import Any

from fastapi.staticfiles import StaticFiles

from . import compute, metrics

# A native crash (cupy, sqlite3, a parser C extension) kills the process with SIGSEGV and, without this,
# leaves no trace of where. Three exit-139s during library loads were invisible until it was on.
faulthandler.enable(all_threads=True)
from . import security
from .config import VERSION, load_settings
from .routers import (admin, ai, anomalies, attachments, auth as auth_router, case, case_set, cases, compute as compute_router, events, exclusions as exclusions_router, graph, iocs, jobs, library, mcp, parsers,
                      report, rules, settings, sources, timeline)

FRONTEND_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"


@asynccontextmanager
async def lifespan(_: FastAPI):
    load_settings()
    compute.start_background()
    metrics.start_background()
    try:
        from . import resources
        print(resources.describe(), flush=True)
    except Exception as exc:  # noqa: BLE001 — a banner must never stop the app
        print(f"[iris] resource probe failed: {exc}", flush=True)
    try:
        from . import cases as _cases
        from .store import STORE
        # Before the pool loads: the first warm can then read the packed index off disk instead of
        # re-packing 11 M events (165 s, during which every query takes the 35-45 s scan path).
        STORE.install_index_signature_provider()
        _cases.startup()
        # Upload/parse jobs outlive the request that started them, so a restart can leave one claiming to
        # be running forever. Reconcile AFTER the case is restored: jobs whose sources came back complete
        # resolve normally, the rest are marked interrupted. See app/jobs.py.
        try:
            from .jobs import REGISTRY as _JOBS
            buried = _JOBS.reconcile()
            if buried:
                print(f"[iris] {buried} upload job(s) were interrupted by the last shutdown")
        except Exception as exc:
            print(f"[iris] job reconcile failed: {exc}")
        # Same problem, same fix, for AI conversations: an investigation that was mid-flight when the
        # process died must not display as still running forever. See app/ai/history.py.
        try:
            from .ai.history import HISTORY as _AI_HISTORY
            buried = _AI_HISTORY.reconcile()
            if buried:
                print(f"[iris] {buried} AI investigation(s) were interrupted by the last shutdown")
        except Exception as exc:
            print(f"[iris] AI history reconcile failed: {exc}")
        # The enrichment worker (two-phase ingest, app/enrich.py). Started here rather than lazily on
        # the first upload so a source left in 'raw'/'queued' by a shutdown is picked back up: the raw
        # lines are already in the pool, and nothing else would ever come along to interpret them.
        try:
            from . import enrich as _enrich
            _enrich.QUEUE.start(STORE)
            resumed = STORE.requeue_unenriched()
            if resumed:
                print(f"[iris] {resumed} source(s) queued for enrichment")
        except Exception as exc:
            print(f"[iris] enrichment worker failed to start: {exc}")
        # The entity graph builds ITSELF once the workspace settles, instead of waiting for someone to
        # open the Graph screen (see app/autobuild.py). It asks ONCE, after a quiet window, and never
        # while a load or an enrichment run is in flight — that restraint is the whole design, because
        # asking often is what turned a library load into a SIGSEGV storm.
        try:
            from .autobuild import AUTOBUILD
            AUTOBUILD.start(STORE)
        except Exception as exc:
            print(f"[iris] graph autobuild failed to start: {exc}")
        if STORE.events:
            print(f"[iris] restored case {STORE.case_id}: {len(STORE.events)} events from {len(STORE.sources)} sources")
    except Exception as exc:  # never block startup on a corrupt case file
        print(f"[iris] case restore failed: {exc}")
    # What is actually protecting this instance, printed every boot. A hardening measure nobody can see
    # is one nobody maintains — and "no authentication" is a property the operator has to know, not
    # something to discover from a red-team report.
    try:
        for line in security.startup_banner():
            print(line)
    except Exception as exc:
        print(f"[iris] security banner failed: {exc}")
    yield
    try:
        from . import enrich as _enrich
        _enrich.QUEUE.stop()
    except Exception:
        pass
    try:
        from .autobuild import AUTOBUILD
        AUTOBUILD.stop()
    except Exception:
        pass
    compute.stop_background()
    metrics.stop_background()


app = FastAPI(title="Iris", version=VERSION, lifespan=lifespan)


# Formats that are ALREADY compressed, so gzip is pure loss. Measured on this bundle's own
# frontend/dist/assets: 263 font files, 3,235 KB of .woff/.woff2, come out of gzip level 6 at
# 3,230 KB — i.e. the .woff2 half gets BIGGER (1,481 KB -> 1,484 KB) — for ~100 ms of event-loop
# time in which no other request in the process is served. That is the same arithmetic that took
# compresslevel from 9 to 6; here it says do not compress these at all. The two files under
# /assets that are worth it are the bundle and the stylesheet (below).
INCOMPRESSIBLE_SUFFIXES = (".woff", ".woff2", ".ttf", ".otf", ".eot", ".png", ".jpg", ".jpeg",
                           ".gif", ".webp", ".avif", ".ico", ".mp4", ".webm", ".mp3", ".ogg",
                           ".zip", ".gz", ".br", ".zst", ".pdf")


class SelectiveGZip:
    """GZipMiddleware for a fixed set of GET paths (prefix match), plain pass-through for the rest."""

    def __init__(self, app, paths: tuple[str, ...], minimum_size: int = 1024) -> None:
        from starlette.middleware.gzip import GZipMiddleware
        self.app = app
        # Level 6, not Starlette's default of 9. Measured on a real 2.25 MB graph payload:
        # level 9 takes 56.8 ms and produces 0.14 MB, level 6 takes 21.1 ms and produces 0.14 MB —
        # the SAME size, 2.7x faster. This compresses in the ASGI send path, which is the event
        # loop, so those 36 ms are 36 ms in which no other request in the process is served.
        self.gz = GZipMiddleware(app, minimum_size=minimum_size, compresslevel=6)
        self.paths = paths

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http" and scope.get("method") == "GET":
            path = scope.get("path", "")
            if any(path == p or path.startswith(p + "/") or path.startswith(p + "?") for p in self.paths) \
                    and not path.lower().endswith(INCOMPRESSIBLE_SUFFIXES) and not self._ranged(scope):
                await self.gz(scope, receive, send)
                return
        await self.app(scope, receive, send)

    @staticmethod
    def _ranged(scope) -> bool:
        """A Range request must never be gzipped.

        StaticFiles honours Range and answers 206 with a Content-Range describing offsets into the
        IDENTITY bytes. Starlette's GZipMiddleware (0.41.3) does not look at the status or at
        Content-Range: it would compress that slice and stamp `Content-Encoding: gzip` beside a
        Content-Range that no longer describes it — a corrupt response, not a slow one. No /api path
        serves ranges, so this costs nothing there; it exists because /assets does.
        """
        return any(k == b"range" for k, _ in scope.get("headers") or ())


# NEVER `allow_origins=["*"]`. Iris is unauthenticated, so the wildcard is not a convenience — it is a
# standing grant to every page the analyst has open to read the whole evidence pool, and (through the
# preflight) to be told that DELETE is allowed on cases and sources. The SPA is served from this same
# origin and needs no entry here at all; the list exists for `npm run dev` on :5173. See app/security.py.
app.add_middleware(CORSMiddleware, allow_origins=security.cors_origins(), allow_credentials=False,
                   allow_methods=["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"],
                   allow_headers=["*"], max_age=600)

# Compression for the BIG JSON answers only. A 2,000-node graph is 5-8 MB of repetitive JSON even
# after the edge cap (37 MB before it) and every Search page is a few hundred KB; gzip takes them down
# 5-8x, which matters through Docker Desktop's port proxy and over any link that is not loopback.
# Starlette's GZipMiddleware would also wrap the SSE streams (the AI investigator, the graph review),
# buffering tokens inside zlib — so it is applied only to GET requests on an explicit list of paths.
#
# `/assets` is on the list too, and it is the app's OWN first paint: every JSON endpoint was gzipped
# while the bundle that renders them was not. Measured on this build, ASGI bytes actually sent —
# index-*.js 634,279 -> 190,868 B and index-*.css 271,244 -> 66,853 B, so first paint goes from
# 905,523 B to 257,721 B, a 3.5x cut on the one request every session starts with. It is safe
# to compress precisely because those files are CONTENT-HASHED and served `immutable`: the name changes
# when the bytes do, so a cached compressed copy can never be the wrong copy. The fonts that share the
# directory are excluded by INCOMPRESSIBLE_SUFFIXES and Range requests by `_ranged` — see both above.
#
# `/api/compute` is here for ONE endpoint under it: `/api/compute/metrics` hands back the WHOLE sample
# ring on every 2 s poll of the Settings -> Compute panel, to redraw a chart that gained one ~380-byte
# sample. Measured on this instance: 41,580 B at the panel's default 5-minute window with the ring
# part-full, 345,465 B (337 KiB, i.e. 10.4 MB/min) once the 30-minute ring is. It is one repeated
# object shape full of small integers, which is the best case gzip has — 8.4x with every field
# jittering, 13.3x on the real idle ring — so this line is worth more than the incremental `?since=`
# protocol it replaces the need for. `/api/compute` itself (the status object, ~750 B) is under
# minimum_size and stays uncompressed, so the prefix costs nothing on the sibling that is polled
# alongside it. `/api/compute/recheck` is a POST and is excluded by the method guard, like every SSE
# route here — see tests/test_metrics_payload_gzip.py.
app.add_middleware(SelectiveGZip, paths=("/api/graph", "/api/events", "/api/timeline", "/api/anomalies",
                                         "/api/library", "/api/case", "/api/jobs", "/api/ai/runs",
                                         "/api/compute", "/assets"),
                   minimum_size=2048)

# Added last, so it is the OUTERMOST layer: it must refuse a cross-site write before CORSMiddleware can
# decorate the response, and it must not be inside anything that buffers a body (the AI investigator and
# the graph review stream SSE through here).
app.add_middleware(security.SecurityMiddleware)

api = APIRouter(prefix="/api")


@api.get("/health")
def health() -> dict:
    return {"ok": True, "version": VERSION}


for r in (case, cases, attachments, sources, events, timeline, graph, case_set, iocs, jobs, library, report, settings, compute_router, ai, admin, parsers, rules, exclusions_router, anomalies, mcp, auth_router):
    api.include_router(r.router)
app.include_router(api)

class _HashedAssets(StaticFiles):
    """Vite writes content-hashed filenames, so an asset is immutable by construction: cache it for a
    year. The FILE NAME changes when the content does, which is the whole point of the hash."""

    def file_response(self, *args: Any, **kwargs: Any):  # type: ignore[override]
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        return response


if FRONTEND_DIST.exists() and (FRONTEND_DIST / "index.html").exists():
    assets = FRONTEND_DIST / "assets"
    if assets.exists():
        app.mount("/assets", _HashedAssets(directory=str(assets)), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str, request: Request) -> FileResponse:
        # An /api path that NO router claimed is a mistyped or removed endpoint, and it must say so.
        # This catch-all is registered after the API router, so it used to answer `GET /api/nope` with
        # 200 text/html and the whole 754-byte index.html — measured. Every caller that checks
        # `response.ok` then hands a page of HTML to a JSON parser, and the one fact that would have
        # explained it ("that endpoint does not exist") never reaches anybody: the SPA reports a parse
        # error, the MCP bridge reports a protocol error, an AI tool reports a tool failure, and curl
        # prints a web page. Nothing here can affect a REAL client-side route (/cases, /search, /graph)
        # — those do not begin with `api/`. Non-GET methods on an unknown /api path already answer 405
        # (this route is GET-only, so Starlette partial-matches it); that is at least a JSON error the
        # caller cannot mistake for a page, and widening this route to every method to turn it into a
        # 404 would ALSO turn the legitimate 405 on `POST /api/health` into one.
        if full_path == "api" or full_path.startswith("api/"):
            raise HTTPException(404, f"no such endpoint: /{full_path[:200]}")
        candidate = FRONTEND_DIST / full_path
        try:
            inside = candidate.resolve().is_relative_to(FRONTEND_DIST.resolve())
        except (OSError, ValueError):
            inside = False
        if full_path and inside and candidate.is_file():
            # not hashed, so not immutable — but not index.html either. Revalidate hourly.
            return FileResponse(str(candidate), headers={"Cache-Control": "public, max-age=3600"})
        response = FileResponse(str(FRONTEND_DIST / "index.html"))
        # NEVER cache index.html. It is the one file whose NAME does not change between builds, and it
        # is what names every hashed asset — so a browser holding an old copy runs an old app against a
        # new server and every deployed fix is invisible. With no Cache-Control header at all (what this
        # served before) browsers apply HEURISTIC freshness and keep it for a fraction of its age, which
        # is exactly how three separate UI fixes were verified in the served bundle, deployed, and still
        # reported as "it looks the same". It is ~1 kB; revalidating it every time costs nothing.
        response.headers["Cache-Control"] = "no-store, max-age=0"
        # The whole of "logging in" when IRIS_AUTH_TOKEN is set: open the app once at
        # http://host:port/?token=<token> and the session cookie is planted. The SPA needs no code for
        # this — same-origin fetch/XHR send the cookie on their own. HttpOnly so a script cannot read
        # it back out; SameSite=strict so it is never attached to a cross-site request, which is what
        # keeps the cookie from re-opening the CSRF hole the Origin check just closed.
        token = security.auth_token()
        if security.constant_eq(request.query_params.get("token", ""), token):
            response.set_cookie(security.COOKIE_NAME, token, httponly=True, samesite="strict",
                                path="/", max_age=30 * 24 * 3600)
        return response
