# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Stage 1: dependency cache (cargo-chef pattern avoids re-downloading crates)
# ---------------------------------------------------------------------------
FROM rust:1-alpine AS chef
# musl-dev + gcc + make + perl are required to compile ring and link musl targets
RUN apk add --no-cache musl-dev gcc make perl
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
FROM alpine:3 AS runtime

RUN apk add --no-cache ca-certificates

# Non-root user matching the deployment securityContext (busybox addgroup/adduser).
RUN addgroup -g 65532 -S nonroot \
 && adduser -u 65532 -S -G nonroot -s /sbin/nologin nonroot

COPY --from=builder /build/target/release/vaultwarden-operator /usr/local/bin/vaultwarden-operator

USER nonroot
EXPOSE 8081

ENTRYPOINT ["/usr/local/bin/vaultwarden-operator"]
