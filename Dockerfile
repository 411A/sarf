# syntax=docker/dockerfile:1
#
# SARF multi-stage build.
#
#   docker build -t sarf .                 # runtime image
#   docker build --target test -t sarf-test .   # release test suite
#
# The builder needs a C compiler because rusqlite is built with the bundled
# SQLite amalgamation. The runtime stage contains only the stripped binary and
# a private, non-root data directory; it needs no network access.

FROM rust:1.88-bookworm AS builder

ENV CARGO_TERM_COLOR=always \
    CARGO_INCREMENTAL=0

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the manifests and every compile-time input. Cargo.lock is committed,
# hence --locked for reproducible builds. No BuildKit cache mounts are used, so
# this file also builds with classic builders; add
# --mount=type=cache,target=/usr/local/cargo/registry if desired.
COPY Cargo.toml Cargo.lock ./

# `src` and `config` are both required at compile time: config/defaults.toml and
# config/integrations/*.toml are embedded with include_str!.
COPY src ./src
COPY config ./config

RUN cargo build --release --locked

# Test stage. It is not part of the default image build.
FROM builder AS test

COPY tests ./tests

RUN cargo test --release --all-targets --locked

# Runtime stage.
FROM debian:bookworm-slim AS runtime

ARG SARF_VERSION=0.1.15

LABEL org.opencontainers.image.title="SARF" \
      org.opencontainers.image.description="Lightweight Linux process, service and activity forensics" \
      org.opencontainers.image.source="https://github.com/411A/sarf" \
      org.opencontainers.image.version="${SARF_VERSION}" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.base.name="docker.io/library/debian:bookworm-slim"

# Run unprivileged. The home directory doubles as the default data directory;
# seed it once with `sarf init` (the config is not baked into the image).
RUN groupadd --gid 10001 sarf \
    && useradd --uid 10001 --gid sarf \
        --home-dir /var/lib/sarf \
        --no-create-home \
        --shell /usr/sbin/nologin \
        sarf \
    && install -d -m 0750 -o sarf -g sarf /var/lib/sarf

COPY --from=builder --chmod=0755 /build/target/release/sarf /usr/local/bin/sarf

# The binary prefers --data-dir, then SARF_DATA_DIR, then <exe dir>/sarf-data.
ENV SARF_DATA_DIR=/var/lib/sarf

WORKDIR /var/lib/sarf
USER sarf

STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/sarf"]
CMD ["run"]
