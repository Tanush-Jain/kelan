# ---- dast-only stage (smallest runtime) ----
FROM python:3.12-slim AS dast
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml .
COPY kelan/ kelan/
RUN pip install --no-cache-dir .
ENTRYPOINT ["kelan"]

# ---- full stage: + SAST chunker libs + SCA tools ----
FROM python:3.12-slim AS full
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates git build-essential \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml .
COPY kelan/ kelan/
RUN pip install --no-cache-dir ".[all]" \
    && pip install --no-cache-dir osv-scanner pip-audit
ENTRYPOINT ["kelan"]
