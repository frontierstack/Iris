# Global build args (must precede the first FROM). setup.sh/setup.ps1 or docker-compose.gpu.yml override them.
#   CPU : python:3.12-slim
#   GPU : nvidia/cuda:12.4.1-runtime-ubuntu22.04
ARG BASE_IMAGE=python:3.12-slim

# ---------- Stage 1: build the frontend ----------
FROM node:22-alpine AS web
WORKDIR /web
COPY frontend/package*.json frontend/.npmrc ./
# --ignore-scripts: no dependency install/postinstall hooks run during the image build (see frontend/.npmrc).
RUN npm ci --ignore-scripts
# WEB_REBUILD busts the cache for everything below it. The dependency install above stays cached (it
# keys on package*.json), so this costs the ~3 s of `npm run build` and nothing else.
#
# It exists because the alternative failed silently and cost hours: BuildKit reported
# `COPY frontend/ ./  CACHED` for a context whose sources had genuinely changed, so the image shipped
# a WEEKS-old SPA while the build said "Built". A UI fix that is not in the bundle looks exactly like
# a UI fix that does not work — the analyst reported the same bug three times and each report was
# correct. A stale frontend must never be something a build can decide to do.
ARG WEB_REBUILD=dev
RUN echo "web build $WEB_REBUILD" > /web/.rebuild
COPY frontend/ ./
RUN npm run build

# ---------- Stage 2: runtime (CPU or CUDA) ----------
FROM ${BASE_IMAGE} AS runtime
ARG WITH_GPU=0
# Which GPU wheel set to install — setup.sh/setup.ps1 pick this from the host driver's CUDA version
# (requirements-gpu.txt = CUDA 12/13 hosts, requirements-gpu-cuda11.txt = CUDA 11-only hosts).
ARG GPU_REQUIREMENTS=requirements-gpu.txt
# torch must come from its own index (exclusive, not --extra-index-url) so it resolves to a build whose
# nvidia-* CUDA deps match cupy's major. Mixing cu12 cupy with a PyPI torch that pulls cu13 breaks
# cupy's JIT (missing cuda_fp16.h) and silently drops compute back to numpy.
ARG GPU_TORCH_INDEX=https://download.pytorch.org/whl/cu124
# PYTHONFAULTHANDLER: a segfault (exit 139) prints the Python stack of every thread to stderr before
# the process dies, so `docker logs` says WHERE. Three silent 139s during library loads is why.
ENV PYTHONFAULTHANDLER=1 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    IRIS_DATA_DIR=/data

# On the CUDA base image python isn't installed; on python:slim it already is.
# tesseract-ocr is the OCR engine behind the image parser (pytesseract from requirements.txt is only the wrapper).
RUN apt-get update && \
    if ! command -v python3 >/dev/null 2>&1; then \
      apt-get install -y --no-install-recommends python3 python3-pip python3-venv; fi && \
    apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-eng && \
    rm -rf /var/lib/apt/lists/* && \
    ln -sf "$(command -v python3)" /usr/local/bin/python || true

WORKDIR /app
COPY backend/requirements.txt backend/requirements-gpu.txt backend/requirements-gpu-cuda11.txt ./backend/
RUN python3 -m pip install --break-system-packages --upgrade pip 2>/dev/null || python3 -m pip install --upgrade pip; \
    python3 -m pip install --break-system-packages -r backend/requirements.txt 2>/dev/null || python3 -m pip install -r backend/requirements.txt; \
    if [ "$WITH_GPU" = "1" ]; then \
      echo "installing GPU wheels from backend/${GPU_REQUIREMENTS}"; \
      python3 -m pip install --break-system-packages -r "backend/${GPU_REQUIREMENTS}" 2>/dev/null || python3 -m pip install -r "backend/${GPU_REQUIREMENTS}"; \
    fi

COPY backend/ ./backend/
COPY --from=web /web/dist ./frontend/dist

VOLUME ["/data"]
EXPOSE 8000
WORKDIR /app/backend
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health').status==200 else 1)"
# --no-access-log: uvicorn prints a line per request and this app POLLS - /api/case, /api/jobs,
# /api/compute/metrics, the transfer panel - so `docker logs` fills with thousands of 200 OK
# lines that say nothing, Docker writes every one of them to disk, and they bury the [iris]
# startup diagnostics that `start.* -Mode logs` exists to show. Errors, warnings and the
# banner still print. Same flag and same reason as `start.* local`.
CMD ["python3", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
