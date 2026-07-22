# ---- build ----
FROM rust:1.92-slim AS builder
WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
      pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Build WITH the sniper feature: the full command set (/balance, /positions,
# /new_wallet, tuning, gen-wallet) needs it, and a config with sniper.enabled =
# true refuses to start on a default build.
ARG FEATURES=sniper

# Cache dependency compilation separately from source changes.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs \
    && cargo build --release --locked --features "${FEATURES}" \
    && rm -rf src

COPY src ./src
# Touch so cargo rebuilds the real binary over the dummy.
RUN touch src/main.rs && cargo build --release --locked --features "${FEATURES}"

# ---- runtime ----
FROM debian:bookworm-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -m volens

COPY --from=builder /build/target/release/volens /usr/local/bin/volens
COPY config.toml ./config.toml

# data  — detected pools + audit log
# wallets — generated keypairs (mount a NAMED volume so keys persist and are
#           never in the host filesystem; generate them here, never copy in)
RUN mkdir -p /app/data /app/wallets && chown -R volens:volens /app
USER volens

ENV LOG_LEVEL=info
ENTRYPOINT ["/usr/local/bin/volens", "/app/config.toml"]
