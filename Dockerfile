# ── Stage 1: Rust builder ────────────────────────────────────────────────────
FROM rust:slim AS rust-builder

WORKDIR /build

# Cache dependencies
COPY Cargo.toml Cargo.lock* ./
COPY kelan-ebpf/Cargo.toml ./kelan-ebpf/
COPY kelan-ebpf/kelan-ebpf-loader/Cargo.toml ./kelan-ebpf/kelan-ebpf-loader/

# Build deps only (cache layer)
RUN mkdir -p kelan-ebpf/kelan-ebpf-loader/src && \
    echo "fn main() {}" > kelan-ebpf/kelan-ebpf-loader/src/main.rs && \
    touch kelan-ebpf/kelan-ebpf-loader/src/lib.rs && \
    cargo build --release 2>/dev/null || true

# Copy full source and build
COPY . .
RUN cargo build --release

# ── Stage 2: Python builder ───────────────────────────────────────────────────
FROM python:3.12-slim AS python-builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt --target=/build/deps

# ── Stage 3: Runtime ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Install runtime dependencies (including curl for HEALTHCHECK)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Security: non-root user
RUN groupadd -r kelan && useradd -r -g kelan kelan

WORKDIR /app

# Copy Python deps
COPY --from=python-builder /build/deps /app/deps
ENV PYTHONPATH=/app/deps

# Copy Rust binary
COPY --from=rust-builder /build/target/release/kelan-ebpf-loader /usr/local/bin/
RUN chmod +x /usr/local/bin/kelan-ebpf-loader

# Copy application code (exclude secrets)
COPY --chown=kelan:kelan . .

# Remove any accidentally included secrets
RUN rm -f .env .env.* *.log

USER kelan

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

CMD ["python", "scripts/start_server.py"]
