# Multi-stage build for minimal image (~15 MB)
FROM rust:1.86-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
COPY src/ src/
COPY benches/ benches/

RUN cargo build --release --locked --features full 2>/dev/null || cargo build --release --features full

# Runtime: distroless for minimal attack surface
FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=builder /build/target/release/agentshield /usr/local/bin/agentshield

WORKDIR /scan
ENTRYPOINT ["agentshield"]
CMD ["--help"]
