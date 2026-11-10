# ══ Kelan Community Security Scanner — Dockerfile ═════════════════════════════
# Multi-stage build producing a secure, lightweight, non-root Community image.

# ── Stage 1: Build & Dependencies ─────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt pyproject.toml README.md LICENSE ./
COPY kelan/ ./kelan/
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt \
    && pip install --no-cache-dir --prefix=/install .

# ── Stage 2: Production Runtime ───────────────────────────────────────────────
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="Kelan Community Security Scanner" \
      org.opencontainers.image.description="Audit-only open-source AST, DAST, SCA & offline vulnerability intelligence scanner" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    git \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -u 1000 -m -s /bin/bash kelan \
    && mkdir -p /app/data /app/log /app/reports \
    && chown -R kelan:kelan /app

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Copy application source & dashboard UI
COPY --chown=kelan:kelan pyproject.toml README.md LICENSE ./
COPY --chown=kelan:kelan kelan/ ./kelan/
COPY --chown=kelan:kelan static/ ./static/

USER kelan

ENV PYTHONUNBUFFERED=1 \
    KELAN_DATA_DIR=/app/data \
    KELAN_LOG_DIR=/app/log

EXPOSE 7681 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD kelan --help > /dev/null 2>&1 || exit 1

ENTRYPOINT ["kelan"]
CMD ["--help"]

# Compatibility stage aliases
FROM runtime AS community
FROM runtime AS full
FROM runtime AS dast
