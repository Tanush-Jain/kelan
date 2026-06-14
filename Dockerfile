# =============================================
# Kelan Security — Production Dockerfile
# Fixed for netifaces + cryptography build
# =============================================

FROM python:3.12-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    libssl-dev \
    libffi-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Final runtime image
FROM python:3.12-slim

WORKDIR /app

# Install runtime dependencies (including curl for HEALTHCHECK and libpq5)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 libpq5 curl \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY kelan/ ./kelan/
COPY scripts/ ./scripts/
COPY .env.example .env

# Create required directories
RUN mkdir -p data logs && chmod 777 data logs

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

CMD ["python", "scripts/start_server.py"]
