# ── Stage 1: Rust builder ────────────────────────────────────────────────────
FROM rust:slim AS rust-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY Cargo.toml Cargo.lock* ./
COPY kelan-ebpf/Cargo.toml ./kelan-ebpf/
COPY kelan-ebpf/kelan-ebpf-loader/Cargo.toml ./kelan-ebpf/kelan-ebpf-loader/

RUN mkdir -p kelan-ebpf/kelan-ebpf-loader/src && \
    echo "fn main() {}" > kelan-ebpf/kelan-ebpf-loader/src/main.rs && \
    touch kelan-ebpf/kelan-ebpf-loader/src/lib.rs && \
    cargo build --release --workspace 2>/dev/null || true

COPY . .
RUN cargo build --release --workspace

# ── Stage 2: Python builder ───────────────────────────────────────────────────
FROM python:3.14-slim AS python-builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --upgrade pip wheel && \
    pip install --no-cache-dir -r requirements.txt

# ── Stage 3: Runtime ──────────────────────────────────────────────────────────
FROM python:3.14-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r kelan && useradd -r -g kelan kelan

WORKDIR /app

COPY --from=python-builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY --from=rust-builder /build/target/release/kelan-ebpf-loader /usr/local/bin/
RUN chmod +x /usr/local/bin/kelan-ebpf-loader

COPY --chown=kelan:kelan . .

RUN rm -f .env .env.* *.log

USER kelan

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

CMD ["python", "scripts/start_server.py"]
