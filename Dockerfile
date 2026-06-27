# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Stage 1: dependency cache (cargo-chef pattern avoids re-downloading crates)
# ---------------------------------------------------------------------------
FROM rust:1-bookworm AS chef
RUN cargo install cargo-chef --locked
WORKDIR /build

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ---------------------------------------------------------------------------
# Stage 2: build
# ---------------------------------------------------------------------------
FROM chef AS builder
COPY --from=planner /build/recipe.json recipe.json

# Build dependencies only (cached layer).
RUN cargo chef cook --release --recipe-path recipe.json

# Build the operator binary.
COPY . .
RUN cargo build --release --bin vaultwarden-operator

# ---------------------------------------------------------------------------
# Stage 3: minimal runtime image
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Non-root user matching the deployment securityContext.
RUN groupadd -g 65532 nonroot && useradd -u 65532 -g nonroot -s /sbin/nologin nonroot

COPY --from=builder /build/target/release/vaultwarden-operator /usr/local/bin/vaultwarden-operator

USER nonroot
EXPOSE 8081

ENTRYPOINT ["/usr/local/bin/vaultwarden-operator"]
