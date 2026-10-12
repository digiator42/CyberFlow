# CyberFlow (logs-soc) backend image: GritShield (crates.io) + SQLite.
# Build context is this repo (logs-soc/backend).
FROM rust:1-bookworm AS builder
RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libssl3 curl \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/logs-soc-backend /usr/local/bin/logs-soc-backend
ENV SOC_BIND=0.0.0.0 \
    SOC_PORT=8010 \
    SOC_DATABASE_URL="sqlite:///data/logs_soc.db?mode=rwc"
EXPOSE 8010
VOLUME /data
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8010/health || exit 1
CMD ["logs-soc-backend"]
