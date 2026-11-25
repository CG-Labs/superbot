# syntax=docker/dockerfile:1
# SuperBot server image: botd + botctl (and superbot-machine, the agent botd serves to managed machines),
# with the harness CLIs and the Bots' computer (screens, browser, live view) baked in.
# Published to ghcr.io/cg-labs/superbot by .github/workflows/docker.yml.
# Compose setup and docs: deploy/README.md ("Docker Compose (supported)").

ARG DEBIAN_RELEASE=trixie
ARG RUST_IMAGE=rust:1-${DEBIAN_RELEASE}
ARG NODE_IMAGE=node:22-${DEBIAN_RELEASE}-slim
ARG CADDY_IMAGE=caddy:2
# on: the Bots' computer (screens, browser, live view) is in the image. off: about 1.2 GB smaller, no screens.
ARG COMPUTER=on

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
# The upgrade brings Alpine's security fixes in before caddy:2 itself is rebuilt (ADR 0101).
FROM ${CADDY_IMAGE} AS caddy
RUN apk upgrade --no-cache
COPY --from=client /out/app /srv/superbot-app
COPY site /srv/superbot-site
LABEL org.opencontainers.image.title="SuperBot Caddy" \
      org.opencontainers.image.description="Caddy with the SuperBot web client and landing page" \
      org.opencontainers.image.source="https://github.com/CG-Labs/superbot" \
      org.opencontainers.image.licenses="MIT"

FROM ${RUST_IMAGE} AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock .env.example ./
COPY server server
COPY web web
COPY site site
COPY deploy/hermes-share.sh deploy/hermes-share.sh
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
    && install -D -m 0755 -t /out target/release/botd target/release/botctl target/release/superbot-machine \
        target/release/superbot-run

# voxl streams each Bot's screen to the app (docs/computer.md), built from source as
# deploy/install-computer.sh does. It links only x264, libyuv, opus and libjpeg.
FROM ${RUST_IMAGE} AS voxl-on
ARG VOXL_VERSION=0.3.5
RUN apt-get update \
    && apt-get install -y --no-install-recommends clang esbuild libopus-dev libx264-dev libyuv-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo install --locked --version "$VOXL_VERSION" voxl-server --no-default-features --root /out \
    && strip /out/bin/voxl

FROM ${NODE_IMAGE} AS voxl-off
RUN mkdir -p /out/bin

FROM voxl-${COMPUTER} AS voxl

# Harness CLIs are Node packages, so the runtime is Node's slim Debian image.
FROM ${NODE_IMAGE} AS runtime

# Space-separated subset of: claude codex pi hermes. Empty = none (install later into the home volume).
# hermes (Hermes Agent) is opt-in: it adds about 2.5 GB; its Bots share its one environment.
ARG HARNESSES="claude codex pi"
ARG CLAUDE_CODE_VERSION=latest
ARG CODEX_VERSION=latest
ARG PI_VERSION=latest
# Hermes Agent release the image installs: the commit of tag v0.23.3 (NousResearch/hermes-agent),
# as server/src/adapters/install.rs pins it. Change it with deploy/hermes-pin.sh bump.
ARG HERMES_COMMIT=caafe5389ae585ef77387a962aee05b1bcf17029
ARG SUPERBOT_UID=10001

# The upgrade brings Debian's security fixes in before the Node image itself is rebuilt (ADR 0101).
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends \
        acl age ca-certificates curl git libatomic1 procps sqlite3 sudo tini tzdata \
    && rm -rf /var/lib/apt/lists/*

# The Bots' computer (docs/computer.md, docs/adr/0084-published-image-with-computer-use.md): the
# same screen stack as deploy/install-computer.sh, with Debian's Chromium in place of Chrome for
# Testing, which has no arm64 build. botd turns screens on when Xvfb and openbox are on PATH.
ARG COMPUTER
ARG TARGETARCH
ARG AGENT_BROWSER_VERSION=v0.43.0
ARG AGENT_BROWSER_SHA256_AMD64=8e69c9fb662514c9cf36e4911e94e913742ba066e55102486350e049dd847612
ARG AGENT_BROWSER_SHA256_ARM64=34be55c2b92d8d199fb9d1d62a905ee5b6ac5b1f3e8c24e5b20597f370d905e5
ARG AGENT_DESKTOP_VERSION=v1.3.1
ARG AGENT_DESKTOP_SHA256_AMD64=ca77b6b75034eeb12e537dd8c0a4f2a3424119253f38b7e6bd79ba0d2fef1264
ARG AGENT_DESKTOP_SHA256_ARM64=438990a703fbeb19775596c341c3701435e80adbfa1b2f64b82ff17567d5573b
RUN set -eu; \
    case "$COMPUTER" in on) ;; off) exit 0 ;; *) echo "COMPUTER must be on or off, not $COMPUTER" >&2; exit 1 ;; esac; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        xvfb openbox x11-utils dbus-x11 at-spi2-core fonts-noto-core fonts-noto-color-emoji chromium \
        libjpeg62-turbo libopus0 libx264-164 libyuv0; \
    rm -rf /var/lib/apt/lists/*; \
    case "$TARGETARCH" in \
        amd64) ab=x64; ad=x86_64; ab_sum=$AGENT_BROWSER_SHA256_AMD64; ad_sum=$AGENT_DESKTOP_SHA256_AMD64 ;; \
        arm64) ab=arm64; ad=aarch64; ab_sum=$AGENT_BROWSER_SHA256_ARM64; ad_sum=$AGENT_DESKTOP_SHA256_ARM64 ;; \
        *) echo "No computer-use build for $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /usr/local/bin/agent-browser \
        "https://github.com/vercel-labs/agent-browser/releases/download/$AGENT_BROWSER_VERSION/agent-browser-linux-$ab"; \
    echo "$ab_sum  /usr/local/bin/agent-browser" | sha256sum -c -; \
    chmod 0755 /usr/local/bin/agent-browser; \
    curl -fsSL -o /tmp/agent-desktop.tar.gz \
        "https://github.com/vercel-labs/agent-desktop/releases/download/$AGENT_DESKTOP_VERSION/agent-desktop-$AGENT_DESKTOP_VERSION-$ad-unknown-linux-gnu.tar.gz"; \
    echo "$ad_sum  /tmp/agent-desktop.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/agent-desktop.tar.gz -C /usr/local/bin agent-desktop agent-desktop-linux-clipboard-owner; \
    rm -f /tmp/agent-desktop.tar.gz; \
    git -c advice.detachedHead=false clone -q --depth 1 --branch "$AGENT_BROWSER_VERSION" --filter=blob:none --sparse \
        https://github.com/vercel-labs/agent-browser.git /tmp/ab-src; \
    git -C /tmp/ab-src sparse-checkout set skill-data; \
    install -d /opt/computer/share; \
    cp -r /tmp/ab-src/skill-data /opt/computer/share/agent-browser-skills; \
    rm -rf /tmp/ab-src; \
    install -d -m 1777 /tmp/.X11-unix
COPY --from=voxl /out/bin/ /usr/local/bin/
# Chromium with its sandbox on, whatever agent-browser asks (ADR 0107). Ahead of /usr/bin on PATH.
COPY --chmod=0755 deploy/docker/chromium.sh /usr/local/bin/chromium
RUN if [ "$COMPUTER" = off ]; then rm /usr/local/bin/chromium; fi

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
# refuses to use a checkout another user owns. Each Bot gets its own Hermes data root;
# deploy/hermes-share.sh makes the install's environment every Bot's, read-only, and
# leaves the hermes they run (docs/adr/0072-one-hermes-environment-per-computer.md).
COPY deploy/hermes-share.sh /tmp/hermes-share.sh
RUN set -eu; case " $HARNESSES " in *" hermes "*) ;; *) rm -f /tmp/hermes-share.sh; exit 0 ;; esac; \
    apt-get update; apt-get install -y --no-install-recommends xz-utils; rm -rf /var/lib/apt/lists/*; \
    install -d -o superbot -g superbot /opt/hermes; \
    curl -fsSL "https://raw.githubusercontent.com/NousResearch/hermes-agent/${HERMES_COMMIT}/scripts/install.sh" -o /tmp/hermes-install.sh; \
    runuser -u superbot -- env HOME=/opt/hermes bash /tmp/hermes-install.sh --non-interactive --skip-browser \
        --skip-computer-use --commit "$HERMES_COMMIT"; \
    rm -f /tmp/hermes-install.sh; \
    runuser -u superbot -- env HOME=/opt/hermes sh /tmp/hermes-share.sh; \
    rm -f /tmp/hermes-share.sh; \
    ln -s /opt/hermes/.hermes/superbot/hermes /usr/local/bin/hermes; \
    probe=$(mktemp -d); chmod 0777 "$probe"; \
    runuser -u nobody -- env HOME="$probe" HERMES_HOME="$probe/hermes" hermes --version; \
    rm -rf "$probe"; \
    if find /opt/hermes \! -user superbot | grep -q .; then echo "root-owned files in /opt/hermes" >&2; exit 1; fi
# Hermes Agent from a Hermes bundle, which deploy/offline-bundle.sh load-hermes puts in a volume that
# docker-compose.hermes.yml mounts at /opt/hermes (docs/adr/0275-hermes-agent-bundle-for-docker-compose.md).
# Without it the link leads nowhere, so botd doesn't count Hermes as installed.
RUN ln -sfn /opt/hermes/.hermes/superbot/hermes /usr/local/bin/hermes

# botd prepends its own folder to each Bot's PATH, so it lives apart from the npm CLIs in /usr/local/bin.
COPY --from=build /out/botd /out/botctl /out/superbot-machine /out/superbot-run /opt/superbot/bin/
COPY --chmod=0755 deploy/superbot-backup.sh /usr/local/bin/superbot-backup
COPY --chmod=0755 deploy/superbot-restore.sh /usr/local/bin/superbot-restore

# Per-user accounts (ISOLATION=users; docs/adr/0037-per-user-unix-accounts.md and
# docs/adr/0058-harness-os-user-by-default.md): the root helper, its config, and the two
# sudo rules, written by the installer's own function. Each user's folders live in the
# users volume at /srv/superbot/users (root, 0711). sudo is the only setuid program left.
COPY --chmod=0755 deploy/superbot-userctl.sh /usr/local/sbin/superbot-userctl
COPY deploy/install.sh /tmp/superbot-install.sh
RUN set -eu; \
    groupadd --system superbot-users; \
    install -d -m 0711 -o root -g root /srv/superbot /srv/superbot/users; \
    install -d -m 0755 -o root -g root /etc/superbot; \
    printf '%s\n' "# Read by /usr/local/sbin/superbot-userctl. Written by the Dockerfile." \
        "ISOLATION_DIR=/srv/superbot/users" "SERVICE_GROUP=superbot" >/etc/superbot/isolation.conf; \
    chmod 0644 /etc/superbot/isolation.conf; \
    SUPERBOT_INSTALL_NO_MAIN=1 bash -c 'source /tmp/superbot-install.sh; \
        SUPERBOT_USER=superbot BIN_DIR=/opt/superbot/bin isolation_sudoers' >/tmp/superbot-sudoers; \
    visudo -cqf /tmp/superbot-sudoers; \
    install -m 0440 -o root -g root /tmp/superbot-sudoers /etc/sudoers.d/superbot-isolation; \
    rm -f /tmp/superbot-sudoers /tmp/superbot-install.sh; \
    find / -xdev -type f -perm /6000 ! -path /usr/bin/sudo -exec chmod ug-s {} +; \
    chmod 0750 /home/superbot

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
    DISABLE_AUTOUPDATER=1 \
    AGENT_BROWSER_EXECUTABLE_PATH=/usr/local/bin/chromium \
    AGENT_BROWSER_SKILLS_DIR=/opt/computer/share/agent-browser-skills

USER superbot
WORKDIR /workspace
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null || exit 1

LABEL org.opencontainers.image.title="SuperBot" \
      org.opencontainers.image.description="SuperBot server (botd) with harness CLIs and the Bots' computer (screens, browser)" \
      org.opencontainers.image.source="https://github.com/CG-Labs/superbot" \
      org.opencontainers.image.licenses="MIT"

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["botd"]
