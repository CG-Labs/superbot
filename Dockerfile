# syntax=docker/dockerfile:1
# SuperBot server image: botd + botctl, with the harness CLIs baked in.
# Compose setup and docs: deploy/README.md ("Docker Compose (supported)").

ARG DEBIAN_RELEASE=trixie
ARG RUST_IMAGE=rust:1-${DEBIAN_RELEASE}
ARG NODE_IMAGE=node:22-${DEBIAN_RELEASE}-slim
ARG CADDY_IMAGE=caddy:2

# The web client (apps/client), exported for the /app/ path.
FROM ${NODE_IMAGE} AS client
WORKDIR /src/apps/client
ENV CI=1 EXPO_NO_TELEMETRY=1 ELECTRON_SKIP_BINARY_DOWNLOAD=1
COPY apps/client/package.json apps/client/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund
COPY apps/client ./
RUN SUPERBOT_WEB_BASE_URL=/app npx expo export --platform web --output-dir /out/app

# Compose's Caddy (`target: caddy`): stock Caddy plus the client and the landing page, so
# each rebuild ships them from this checkout. The Caddyfile is mounted from deploy/docker/.
FROM ${CADDY_IMAGE} AS caddy
COPY --from=client /out/app /srv/superbot-app
COPY site /srv/superbot-site

FROM ${RUST_IMAGE} AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY server server
COPY web web
COPY site site
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
    && install -D -m 0755 -t /out target/release/botd target/release/botctl

# Harness CLIs are Node packages, so the runtime is Node's slim Debian image.
FROM ${NODE_IMAGE} AS runtime

# Space-separated subset of: claude codex pi hermes. Empty = none (install later into the home volume).
# hermes (Hermes Agent) is opt-in: it adds about 2.5 GB, plus about 0.5 GB per Bot in /data.
ARG HARNESSES="claude codex pi"
ARG CLAUDE_CODE_VERSION=latest
ARG CODEX_VERSION=latest
ARG PI_VERSION=latest
# Hermes Agent release the image installs: the commit of tag v0.23.2 (NousResearch/hermes-agent).
ARG HERMES_COMMIT=ae2a81ccc00e9b7c06301523e5bb09608397149c
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
            hermes) ;; \
            *) echo "Unknown harness in HARNESSES: $h (use claude, codex, pi, hermes)" >&2; exit 1 ;; \
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

# Hermes's own installer, outside the home volume. It runs as superbot because Hermes
# refuses to use a checkout another user owns. Each Bot gets its own Hermes data root,
# which shares the installed tools only while the checkout sits in the installer's
# data root (.hermes/hermes-agent, the default layout).
RUN set -eu; case " $HARNESSES " in *" hermes "*) ;; *) exit 0 ;; esac; \
    apt-get update; apt-get install -y --no-install-recommends libatomic1 xz-utils; rm -rf /var/lib/apt/lists/*; \
    install -d -o superbot -g superbot /opt/hermes; \
    curl -fsSL "https://raw.githubusercontent.com/NousResearch/hermes-agent/${HERMES_COMMIT}/scripts/install.sh" -o /tmp/hermes-install.sh; \
    runuser -u superbot -- env HOME=/opt/hermes bash /tmp/hermes-install.sh --non-interactive --skip-browser \
        --skip-computer-use --commit "$HERMES_COMMIT"; \
    rm -f /tmp/hermes-install.sh; \
    ln -s /opt/hermes/.hermes/hermes-agent/.hermes/bin/hermes /usr/local/bin/hermes; \
    runuser -u superbot -- env HOME=/opt/hermes hermes --version; \
    if find /opt/hermes \! -user superbot | grep -q .; then echo "root-owned files in /opt/hermes" >&2; exit 1; fi

# botd prepends its own folder to each Bot's PATH, so it lives apart from the npm CLIs in /usr/local/bin.
COPY --from=build /out/botd /out/botctl /opt/superbot/bin/
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
    PATH=/opt/superbot/bin:/home/superbot/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
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
