"""Iris backend - FastAPI application."""
from __future__ import annotations

import faulthandler
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import APIRouter, FastAPI, Request
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
from .routers import (admin, ai, anomalies, attachments, auth as auth_router, case, case_set, cases, compute as compute_router, events, graph, iocs, jobs, library, mcp, parsers,
                      report, rules, settings, sources, timeline)

FRONTEND_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"


@asynccontextmanager
async def lifespan(_: FastAPI):
    load_settings()
    compute.start_background()
    metrics.start_background()
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

# NEVER `allow_origins=["*"]`. Iris is unauthenticated, so the wildcard is not a convenience — it is a
# standing grant to every page the analyst has open to read the whole evidence pool, and (through the
# preflight) to be told that DELETE is allowed on cases and sources. The SPA is served from this same
# origin and needs no entry here at all; the list exists for `npm run dev` on :5173. See app/security.py.
app.add_middleware(CORSMiddleware, allow_origins=security.cors_origins(), allow_credentials=False,
                   allow_methods=["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"],
                   allow_headers=["*"], max_age=600)

# Added last, so it is the OUTERMOST layer: it must refuse a cross-site write before CORSMiddleware can
# decorate the response, and it must not be inside anything that buffers a body (the AI investigator and
# the graph review stream SSE through here).
app.add_middleware(security.SecurityMiddleware)

api = APIRouter(prefix="/api")


@api.get("/health")
def health() -> dict:
    return {"ok": True, "version": VERSION}


for r in (case, cases, attachments, sources, events, timeline, graph, case_set, iocs, jobs, library, report, settings, compute_router, ai, admin, parsers, rules, anomalies, mcp, auth_router):
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
