# Stage 1: Build
FROM rust:1-slim AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY benches/ benches/
COPY src/ src/

RUN cargo build --release && strip target/release/pqguard

# Stage 2: Runtime (distroless)
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

COPY --from=builder /app/target/release/pqguard /usr/local/bin/pqguard

USER nonroot:nonroot

ENTRYPOINT ["pqguard"]
