# =============================================================================
# PanicMode — Multi-stage Dockerfile
# =============================================================================
#
# Stage 1 (builder): compiles both binaries with Rust
# Stage 2 (runtime): minimal Debian image, ~50MB final size
#
# Usage:
#   docker build -t panicmode .
#   docker compose up -d          # recommended — see docker-compose.yml
# =============================================================================

# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM rust:1.88-slim-bookworm AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Cache dependencies separately from source code.
# Copy only Cargo manifests first and build a dummy binary — this layer is
# cached as long as Cargo.toml/Cargo.lock don't change, even if src/ changes.
COPY Cargo.toml Cargo.lock* ./
RUN mkdir -p src/bin \
    && echo "fn main() {}" > src/main.rs \
    && echo "fn main() {}" > src/bin/panicmode-ctl.rs \
    && cargo build --release \
    && rm -rf src

# Now copy the real source and rebuild (only recompiles panicmode itself,
# not all dependencies — much faster on iterative builds).
COPY src/ ./src/
RUN touch src/main.rs src/bin/panicmode-ctl.rs \
    && cargo build --release

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim

# ca-certificates: required for HTTPS alerts (Telegram, Discord, ntfy, Twilio)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled binaries from builder
COPY --from=builder /build/target/release/panicmode     /usr/local/bin/panicmode
COPY --from=builder /build/target/release/panicmode-ctl /usr/local/bin/panicmode-ctl

# Pre-create directories that PanicMode writes to.
# These are overridden by volume mounts at runtime.
RUN mkdir -p \
    /etc/panicmode \
    /var/lib/panicmode \
    /var/log/panicmode \
    /run/panicmode

# Default log level — override with -e RUST_LOG=debug
ENV RUST_LOG=panicmode=info

# Config path is the first CLI argument.
# docker-compose.yml mounts ./config → /etc/panicmode
ENTRYPOINT ["/usr/local/bin/panicmode"]
CMD ["/etc/panicmode/config.yaml"]
