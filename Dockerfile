# syntax=docker/dockerfile:1.7
# ---------- 1. Build the React dashboard ----------
FROM node:22-alpine AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---------- 2. Python runtime ----------
FROM python:3.13-slim AS runtime
ARG NV_VERSION=""
ENV NV_VERSION=${NV_VERSION} \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    NV_DATA_DIR=/data \
    NV_STATIC_DIR=/app/static \
    NV_PORT=8080
WORKDIR /app

COPY backend/requirements.txt ./
RUN pip install -r requirements.txt

COPY backend/app ./app
COPY --from=web /web/dist ./static

# Unprivileged user; data lives in a volume.
RUN useradd --system --uid 10001 --home /app nv \
    && mkdir -p /data && chown -R nv:nv /data
USER nv
VOLUME ["/data"]

EXPOSE 8080/tcp 5514/udp 5514/tcp
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,os;urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"NV_PORT\",\"8080\")}/api/health',timeout=4)" || exit 1

CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${NV_PORT} --proxy-headers --forwarded-allow-ips='*' --no-server-header"]
