#!/usr/bin/env bash
# SuperBot VPS installer — idempotent; safe to re-run for upgrades.
# Curl example:
#   curl -fsSL https://raw.githubusercontent.com/CG-Labs/superbot/main/deploy/install.sh | sudo bash -s -- --domain bots.example.com --tz Europe/Jersey
set -euo pipefail

SUPERBOT_USER=${SUPERBOT_USER:-superbot}
REPO_URL=${REPO_URL:-https://github.com/CG-Labs/superbot.git}
REPO_BRANCH=${REPO_BRANCH:-main}
BIN_DIR=${BIN_DIR:-/usr/local/bin}
INSTALL_DIR=""
DOMAIN=""
TZ_VALUE=""
USER_NAME_VALUE=""
ENABLE_UFW=false
ENABLE_BACKUP=true
UPGRADE=false
DRY_RUN=false
INTERACTIVE=true

log() { printf '==> %s\n' "$*"; }
warn() { printf '!! %s\n' "$*" >&2; }
die() { warn "$*"; exit 1; }

usage() {
  cat <<'EOF'
Usage: install.sh [options]

  --domain NAME       Public HTTPS name for Caddy (required for TLS)
  --tz ZONE           TZ for botd and routines (e.g. Europe/Jersey)
  --user-name NAME    USER_NAME shown in the app
  --user NAME         Linux system user (default: superbot)
  --repo-url URL      Git remote (default: CG-Labs/superbot)
  --branch NAME       Git branch (default: main)
  --source-dir PATH   Use a local checkout instead of cloning
  --upgrade           git pull + rebuild + restart
  --ufw               Enable UFW (allow 22, 80, 443)
  --no-backup         Skip daily DATA_DIR backup timer
  --dry-run           Print actions without changing the system
  --non-interactive   Fail instead of prompting for missing flags
  -h, --help          Show this help

Run as root on Ubuntu 22.04 or 24.04.
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --domain) DOMAIN=$2; shift 2 ;;
      --tz) TZ_VALUE=$2; shift 2 ;;
      --user-name) USER_NAME_VALUE=$2; shift 2 ;;
      --user) SUPERBOT_USER=$2; shift 2 ;;
      --repo-url) REPO_URL=$2; shift 2 ;;
      --branch) REPO_BRANCH=$2; shift 2 ;;
      --source-dir) INSTALL_DIR=$2; shift 2 ;;
      --upgrade) UPGRADE=true; shift ;;
      --ufw) ENABLE_UFW=true; shift ;;
      --no-backup) ENABLE_BACKUP=false; shift ;;
      --dry-run) DRY_RUN=true; shift ;;
      --non-interactive) INTERACTIVE=false; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown option: $1" ;;
    esac
  done
}

prompt_missing() {
  if [[ "$INTERACTIVE" != true ]] || [[ ! -t 0 ]]; then
    return
  fi
  if [[ -z "$DOMAIN" ]]; then
    read -r -p "Public domain for HTTPS (empty = skip Caddy): " DOMAIN || true
  fi
  if [[ -z "$TZ_VALUE" ]]; then
    read -r -p "Time zone [UTC]: " TZ_VALUE || true
    TZ_VALUE=${TZ_VALUE:-UTC}
  fi
  if [[ -z "$USER_NAME_VALUE" ]]; then
    read -r -p "Your name (USER_NAME) [Owner]: " USER_NAME_VALUE || true
    USER_NAME_VALUE=${USER_NAME_VALUE:-Owner}
  fi
}

run() {
  if [[ "$DRY_RUN" == true ]]; then
    log "[dry-run] $*"
  else
    "$@"
  fi
}

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "Run as root: sudo $0 ..."
  fi
}

detect_source_dir() {
  if [[ -n "$INSTALL_DIR" ]]; then
    return
  fi
  local script_dir
  script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  if [[ -f "$script_dir/../Cargo.toml" ]] && [[ -f "$script_dir/../server/src/main.rs" ]]; then
    INSTALL_DIR=$(cd "$script_dir/.." && pwd)
    log "Using local checkout: $INSTALL_DIR"
  fi
}

user_home() {
  if getent passwd "$SUPERBOT_USER" &>/dev/null; then
    getent passwd "$SUPERBOT_USER" | cut -d: -f6
  elif [[ "$DRY_RUN" == true ]]; then
    echo "/home/$SUPERBOT_USER"
  else
    die "User $SUPERBOT_USER does not exist"
  fi
}

ensure_user() {
  if id "$SUPERBOT_USER" &>/dev/null; then
    log "User $SUPERBOT_USER already exists"
    return
  fi
  log "Creating user $SUPERBOT_USER"
  run useradd -m -s /bin/bash "$SUPERBOT_USER"
}

install_packages() {
  log "Installing system packages"
  run apt-get update -qq
  run apt-get install -y -qq \
    build-essential pkg-config libssl-dev git curl sqlite3 ca-certificates \
    debian-keyring debian-archive-keyring apt-transport-https rsync gnupg openssl
}

install_node() {
  if command -v node >/dev/null 2>&1; then
    log "Node.js already installed: $(node -v)"
    return
  fi
  log "Installing Node.js LTS"
  if [[ "$DRY_RUN" == true ]]; then
    return
  fi
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
  apt-get install -y -qq nodejs
}

# shellcheck disable=SC2016
install_rustup_user() {
  local home
  home=$(user_home)
  if [[ "$DRY_RUN" == true ]]; then
    log "[dry-run] install rustup for $SUPERBOT_USER"
    return
  fi
  if sudo -u "$SUPERBOT_USER" -H bash -lc 'command -v cargo' 2>/dev/null | grep -q cargo; then
    log "Rust toolchain present for $SUPERBOT_USER"
    return
  fi
  log "Installing rustup for $SUPERBOT_USER"
  sudo -u "$SUPERBOT_USER" -H bash -lc 'curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal'
  grep -qF '. "$HOME/.cargo/env"' "$home/.bashrc" 2>/dev/null || \
    printf '%s\n' '. "$HOME/.cargo/env"' >>"$home/.bashrc"
}

sync_repo() {
  local home repo_path
  home=$(user_home)
  repo_path="$home/superbot"
  if [[ -n "$INSTALL_DIR" ]]; then
    log "Syncing $INSTALL_DIR -> $repo_path"
    if [[ "$DRY_RUN" == true ]]; then
      return
    fi
    mkdir -p "$(dirname "$repo_path")"
    if [[ -d "$repo_path/.git" ]]; then
      rsync -a --delete --exclude target --exclude .git "$INSTALL_DIR/" "$repo_path/"
    else
      rsync -a --exclude target "$INSTALL_DIR/" "$repo_path/"
    fi
    return
  fi
  if [[ -d "$repo_path/.git" ]]; then
    log "Updating git checkout"
    if [[ "$DRY_RUN" == true ]]; then
      return
    fi
    sudo -u "$SUPERBOT_USER" -H git -C "$repo_path" fetch origin "$REPO_BRANCH"
    sudo -u "$SUPERBOT_USER" -H git -C "$repo_path" checkout "$REPO_BRANCH"
    sudo -u "$SUPERBOT_USER" -H git -C "$repo_path" pull --ff-only origin "$REPO_BRANCH"
  else
    log "Cloning $REPO_URL"
    if [[ "$DRY_RUN" == true ]]; then
      return
    fi
    sudo -u "$SUPERBOT_USER" -H git clone --branch "$REPO_BRANCH" --depth 1 "$REPO_URL" "$repo_path"
  fi
}

build_botd() {
  local home repo_path
  home=$(user_home)
  repo_path="$home/superbot"
  log "Building release binaries"
  if [[ "$DRY_RUN" == true ]]; then
    return
  fi
  sudo -u "$SUPERBOT_USER" -H bash -lc "cd '$repo_path' && . \"\$HOME/.cargo/env\" && cargo build --release"
  run install -m 0755 "$repo_path/target/release/botd" "$BIN_DIR/botd"
  run install -m 0755 "$repo_path/target/release/botctl" "$BIN_DIR/botctl"
}

set_env_var() {
  local file=$1 key=$2 value=$3
  if grep -q "^${key}=" "$file"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$file"
  else
    echo "${key}=${value}" >>"$file"
  fi
}

configure_env() {
  local home repo_path env_file pass_file
  home=$(user_home)
  repo_path="$home/superbot"
  env_file="$repo_path/.env"
  pass_file="$home/.superbot-admin-password"
  TZ_VALUE=${TZ_VALUE:-UTC}
  USER_NAME_VALUE=${USER_NAME_VALUE:-Owner}

  if [[ "$DRY_RUN" == true ]]; then
    log "[dry-run] configure $env_file"
    return
  fi

  if [[ ! -f "$env_file" ]]; then
    cp "$repo_path/.env.example" "$env_file"
    chown "$SUPERBOT_USER:$SUPERBOT_USER" "$env_file"
    chmod 0600 "$env_file"
  fi

  set_env_var "$env_file" HOST 127.0.0.1
  set_env_var "$env_file" PORT 3000
  set_env_var "$env_file" TZ "$TZ_VALUE"
  set_env_var "$env_file" USER_NAME "$USER_NAME_VALUE"
  set_env_var "$env_file" DATA_DIR "$repo_path/data"
  set_env_var "$env_file" WORKSPACE_DIR "$repo_path/workspace"

  if [[ -n "$DOMAIN" ]]; then
    set_env_var "$env_file" ALLOWED_HOSTS "$DOMAIN"
    set_env_var "$env_file" CORS_ORIGINS "https://${DOMAIN}"
  fi

  if ! grep -q '^AUTH_PASSWORD=.' "$env_file"; then
    local pass
    pass=$(openssl rand -base64 32 | tr -d '/+=' | head -c 32)
    set_env_var "$env_file" AUTH_PASSWORD "$pass"
    printf '%s\n' "$pass" >"$pass_file"
    chown "$SUPERBOT_USER:$SUPERBOT_USER" "$pass_file"
    chmod 0600 "$pass_file"
    export NEW_PASSWORD_FILE=$pass_file
  fi

  chown "$SUPERBOT_USER:$SUPERBOT_USER" "$env_file"
  chmod 0600 "$env_file"
}

install_systemd() {
  local home script_dir
  home=$(user_home)
  script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  local unit=/etc/systemd/system/superbot.service
  log "Installing systemd unit"
  if [[ "$DRY_RUN" == true ]]; then
    return
  fi
  sed -e "s|/home/superbot|$home|g" -e "s|User=superbot|User=$SUPERBOT_USER|g" \
    -e "s|Group=superbot|Group=$SUPERBOT_USER|g" \
    "$script_dir/superbot.service" >"$unit"
  systemctl daemon-reload
  systemctl enable superbot.service
  systemctl restart superbot.service
}

install_backup() {
  local home script_dir
  home=$(user_home)
  script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  run install -m 0755 "$script_dir/superbot-backup.sh" "$BIN_DIR/superbot-backup"
  if [[ "$ENABLE_BACKUP" != true ]]; then
    return
  fi
  log "Enabling daily backup timer"
  if [[ "$DRY_RUN" == true ]]; then
    return
  fi
  sed -e "s|/home/superbot|$home|g" -e "s|User=superbot|User=$SUPERBOT_USER|g" \
    "$script_dir/superbot-backup.service" >/etc/systemd/system/superbot-backup.service
  cp "$script_dir/superbot-backup.timer" /etc/systemd/system/superbot-backup.timer
  systemctl daemon-reload
  systemctl enable --now superbot-backup.timer
}

install_caddy() {
  if [[ -z "$DOMAIN" ]]; then
    warn "No --domain: skipping Caddy (botd listens on 127.0.0.1:3000 only)"
    return
  fi
  log "Installing Caddy"
  if [[ "$DRY_RUN" == true ]]; then
    return
  fi
  if ! command -v caddy >/dev/null 2>&1; then
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -qq
    apt-get install -y -qq caddy
  fi
  local caddyfile=/etc/caddy/Caddyfile
  cat >"$caddyfile" <<EOF
${DOMAIN} {
	encode gzip
	reverse_proxy 127.0.0.1:3000 {
		flush_interval -1
	}
}
EOF
  systemctl enable caddy
  systemctl reload caddy || systemctl restart caddy
}

configure_ufw() {
  if [[ "$ENABLE_UFW" != true ]]; then
    return
  fi
  log "Configuring UFW"
  if [[ "$DRY_RUN" == true ]]; then
    return
  fi
  apt-get install -y -qq ufw
  ufw allow 22/tcp
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw --force enable
}

summary() {
  local home repo_path pass_file url
  home=$(user_home)
  repo_path="$home/superbot"
  pass_file="$home/.superbot-admin-password"
  if [[ -n "$DOMAIN" ]]; then
    url="https://${DOMAIN}"
  else
    url="http://127.0.0.1:3000 (on this host)"
  fi
  cat <<EOF

SuperBot is installed.

  URL:      $url
  Password: stored in $pass_file (also in $repo_path/.env as AUTH_PASSWORD)
  Logs:     journalctl -u superbot -f
  Upgrade:  re-run this script with --upgrade (or curl | sudo bash -s -- --upgrade)

Next steps (as the service user):
  sudo -iu $SUPERBOT_USER
  # Install harness CLIs if needed, then log in, e.g.:
  npm install -g @anthropic-ai/claude-code  # if you use Claude Code
  claude login
  # or: codex login

EOF
  if [[ -f "$pass_file" ]] && [[ "${NEW_PASSWORD_FILE:-}" == "$pass_file" ]]; then
    warn "New login password (saved to $pass_file): $(cat "$pass_file")"
  fi
}

main() {
  parse_args "$@"
  need_root
  prompt_missing
  detect_source_dir
  TZ_VALUE=${TZ_VALUE:-UTC}
  USER_NAME_VALUE=${USER_NAME_VALUE:-Owner}

  ensure_user
  install_packages
  install_node
  install_rustup_user
  if [[ "$UPGRADE" == true ]]; then
    log "Upgrade mode: updating source and rebuilding"
  fi
  sync_repo
  build_botd
  configure_env
  install_systemd
  install_backup
  install_caddy
  configure_ufw
  summary
}

main "$@"