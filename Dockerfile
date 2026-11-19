# syntax=docker/dockerfile:1
# SuperBot server image: botd + botctl, with the harness CLIs baked in.
# Compose setup and docs: deploy/README.md ("Docker Compose (supported)").

ARG DEBIAN_RELEASE=trixie
ARG RUST_IMAGE=rust:1-${DEBIAN_RELEASE}
ARG NODE_IMAGE=node:22-${DEBIAN_RELEASE}-slim

FROM ${RUST_IMAGE} AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY server server
COPY web web
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
    && install -D -m 0755 -t /out target/release/botd target/release/botctl

# Harness CLIs are Node packages, so the runtime is Node's slim Debian image.
FROM ${NODE_IMAGE} AS runtime

# Space-separated subset of: claude codex pi. Empty = none (install later into the home volume).
ARG HARNESSES="claude codex pi"
ARG CLAUDE_CODE_VERSION=latest
ARG CODEX_VERSION=latest
ARG PI_VERSION=latest
ARG SUPERBOT_UID=10001

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl git procps sqlite3 tini tzdata \
    && rm -rf /var/lib/apt/lists/*

RUN set -eu; pkgs=""; \
    for h in $HARNESSES; do \
        case "$h" in \
            claude) pkgs="$pkgs @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" ;; \
            codex) pkgs="$pkgs @openai/codex@${CODEX_VERSION}" ;; \
            pi) pkgs="$pkgs @earendil-works/pi-coding-agent@${PI_VERSION}" ;; \
            *) echo "Unknown harness in HARNESSES: $h (use claude, codex, pi)" >&2; exit 1 ;; \
        esac; \
    done; \
    if [ -n "$pkgs" ]; then \
        npm install -g --omit=dev --no-fund --no-audit $pkgs; \
        npm cache clean --force; \
    fi

RUN groupadd --system --gid "$SUPERBOT_UID" superbot \
    && useradd --system --uid "$SUPERBOT_UID" --gid superbot \
        --home-dir /home/superbot --create-home --shell /bin/bash superbot \
    && install -d -o superbot -g superbot -m 0700 /data /workspace /backups

COPY --from=build /out/botd /out/botctl /usr/local/bin/
COPY --chmod=0755 deploy/docker/superbot-backup.sh /usr/local/bin/superbot-backup
COPY --chmod=0755 deploy/docker/superbot-restore.sh /usr/local/bin/superbot-restore

# HOST=0.0.0.0 makes botd refuse to start without AUTH_PASSWORD.
# Harness CLIs installed at runtime (npm i -g) land in the persistent home volume and win on PATH.
ENV HOME=/home/superbot \
    HOST=0.0.0.0 \
    PORT=3000 \
    DATA_DIR=/data \
    WORKSPACE_DIR=/workspace \
    BACKUP_DIR=/backups \
    NPM_CONFIG_PREFIX=/home/superbot/.local \
    PATH=/home/superbot/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    DISABLE_AUTOUPDATER=1

USER superbot
WORKDIR /workspace
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null || exit 1

LABEL org.opencontainers.image.title="SuperBot" \
      org.opencontainers.image.description="SuperBot server (botd) with harness CLIs" \
      org.opencontainers.image.source="https://github.com/CG-Labs/superbot" \
      org.opencontainers.image.licenses="MIT"

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["botd"]
