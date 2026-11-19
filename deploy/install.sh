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
SHARE_DIR=${SHARE_DIR:-/usr/local/share/superbot}
SYSTEMD_DIR=${SYSTEMD_DIR:-/etc/systemd/system}
CLIENT_DIR=${CLIENT_DIR:-/var/www/superbot-app}
CLIENT_BASE_URL=/app
BUILD_CLIENT=true
DEPLOY_FILES=(superbot.service superbot-backup.sh superbot-backup.service superbot-backup.timer)

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
  --no-client         Skip building the web client (served at /app/)
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
      --no-client) BUILD_CLIENT=false; shift ;;
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
  local script_path script_dir
  script_path=${BASH_SOURCE[0]:-}
  if [[ -z "$script_path" ]] || [[ ! -f "$script_path" ]]; then
    return
  fi
  script_dir=$(cd "$(dirname "$script_path")" && pwd)
  if [[ -f "$script_dir/../Cargo.toml" ]] && [[ -f "$script_dir/../server/src/main.rs" ]]; then
    INSTALL_DIR=$(cd "$script_dir/.." && pwd)
    log "Using local checkout: $INSTALL_DIR"
  fi
}

# Root installs units only from this root-owned copy, never from the service
# user's checkout (that user could edit templates to gain root).
trusted_deploy_dir() { printf '%s/deploy\n' "$SHARE_DIR"; }

assert_not_service_owned() {
  local path=$1 home owner
  home=$(user_home)
  case "$path/" in
    "$home"/*) die "Refusing $path: it is under $home, writable by $SUPERBOT_USER. Use a root-owned checkout or curl | bash." ;;
  esac
  [[ -e "$path" ]] || return 0
  owner=$(stat -c %U "$path")
  [[ "$owner" != "$SUPERBOT_USER" ]] || die "Refusing $path: owned by $SUPERBOT_USER"
}

install_trusted_files() {
  local src=$1 dest=$2 f
  install -d -m 0755 -o root -g root "$SHARE_DIR" "$dest"
  for f in "${DEPLOY_FILES[@]}"; do
    [[ -f "$src/$f" ]] || die "Missing deploy template: $src/$f"
    install -m 0644 -o root -g root "$src/$f" "$dest/$f"
  done
}

# Local checkout: copy its deploy/ (same trust as this script).
# curl | bash: root fetches REPO_URL into a root-owned bare repo and reads
# deploy/ from the fetched commit with git show.
stage_trusted_deploy() {
  local dest git_dir rev tmp f src
  dest=$(trusted_deploy_dir)
  if [[ -n "$INSTALL_DIR" ]]; then
    src=$(realpath -m "$INSTALL_DIR")
    assert_not_service_owned "$src"
    assert_not_service_owned "$src/deploy"
    for f in "${DEPLOY_FILES[@]}"; do
      assert_not_service_owned "$src/deploy/$f"
    done
    if [[ "$DRY_RUN" == true ]]; then
      log "[dry-run] would copy deploy templates from $src/deploy to $dest"
      return
    fi
    install_trusted_files "$src/deploy" "$dest"
    log "Staged deploy templates from $src/deploy to $dest"
    return
  fi
  git_dir="$SHARE_DIR/src.git"
  if [[ "$DRY_RUN" == true ]]; then
    log "[dry-run] would fetch $REPO_URL ($REPO_BRANCH) into root-owned $git_dir and stage deploy templates in $dest"
    return
  fi
  install -d -m 0755 -o root -g root "$SHARE_DIR"
  [[ -d "$git_dir" ]] || git init -q --bare "$git_dir"
  git --git-dir="$git_dir" fetch -q --depth 1 "$REPO_URL" "$REPO_BRANCH"
  rev=$(git --git-dir="$git_dir" rev-parse FETCH_HEAD)
  tmp=$(mktemp -d)
  for f in "${DEPLOY_FILES[@]}"; do
    git --git-dir="$git_dir" show "$rev:deploy/$f" >"$tmp/$f" || die "Missing deploy/$f at $REPO_URL@$rev"
  done
  install_trusted_files "$tmp" "$dest"
  rm -rf "$tmp"
  log "Staged deploy templates from $REPO_URL@$rev to $dest"
}

# Drop identity/exec lines from a template and inject fixed ones after
# [Service]. Fail closed on any other directive that could change what runs
# or as whom.
render_unit() {
  local template=$1 out=$2 fixed=$3 tmp
  if grep -Ev '^[[:space:]]*ExecStart[[:space:]]*=' "$template" |
    grep -Eq '^[[:space:]]*(Exec[A-Za-z]*|DynamicUser|SupplementaryGroups|AmbientCapabilities|PermissionsStartOnly|RootDirectory|RootImage|Alias)[[:space:]]*='; then
    die "Refusing $template: unexpected privileged directive"
  fi
  tmp=$(mktemp)
  awk -v fixed="$fixed" '
    /^[[:space:]]*(User|Group|ExecStart|WorkingDirectory|EnvironmentFile|Unit)[[:space:]]*=/ { next }
    { print }
    /^[[:space:]]*\[Service\][[:space:]]*$/ && fixed != "" { print fixed }
  ' "$template" >"$tmp"
  if [[ -n "$fixed" ]] && ! grep -qxF "$(printf '%s\n' "$fixed" | grep '^ExecStart=')" "$tmp"; then
    rm -f "$tmp"
    die "Refusing $template: no [Service] section"
  fi
  install -m 0644 -o root -g root "$tmp" "$out"
  rm -f "$tmp"
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
      rsync -a --delete --exclude target --exclude node_modules --exclude dist-app --exclude .git "$INSTALL_DIR/" "$repo_path/"
    else
      rsync -a --exclude target --exclude node_modules --exclude dist-app "$INSTALL_DIR/" "$repo_path/"
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

client_releases_dir() { printf '%s.releases\n' "$CLIENT_DIR"; }

client_node_ok() {
  sudo -u "$SUPERBOT_USER" -H bash -lc 'command -v npm >/dev/null && node -e "process.exit(+process.versions.node.split(\".\")[0] < 20 ? 1 : 0)"' 2>/dev/null
}

# The web client (apps/client) is built by the service user from its checkout. Root then
# unpacks only plain files and folders into a root-owned folder that Caddy serves, so a
# tampered checkout can change what browsers load but never what root runs or reads.
build_client() {
  local home client
  home=$(user_home)
  client="$home/superbot/apps/client"
  if [[ "$BUILD_CLIENT" != true ]]; then
    log "Skipping the web client (--no-client)"
    return
  fi
  if [[ "$DRY_RUN" == true ]]; then
    log "[dry-run] would build the web client in $client as $SUPERBOT_USER (base URL $CLIENT_BASE_URL) and install it into root-owned $CLIENT_DIR"
    return
  fi
  if ! client_node_ok; then
    warn "Node.js 20+ and npm not found for $SUPERBOT_USER: skipping the web client. botd still serves its built-in page."
    return
  fi
  log "Building the web client"
  if ! sudo -u "$SUPERBOT_USER" -H env CI=1 EXPO_NO_TELEMETRY=1 ELECTRON_SKIP_BINARY_DOWNLOAD=1 SUPERBOT_WEB_BASE_URL="$CLIENT_BASE_URL" \
    bash -lc "cd '$client' && npm ci --no-audit --no-fund && npx expo export --platform web --output-dir dist-app"; then
    warn "Web client build failed: keeping the previous one, if any"
    return
  fi
  install_client "$client/dist-app" || warn "Web client not installed: keeping the previous one, if any"
}

# Plain files and folders only (no links, devices, or ".."), with an index.html.
client_archive_ok() {
  local archive=$1
  tar -tvf "$archive" | awk '{ t = substr($0, 1, 1) } t != "-" && t != "d" { bad = 1 } END { exit bad }' || return 1
  if tar -tf "$archive" | grep -Eq '^/|(^|/)\.\.(/|$)'; then
    return 1
  fi
  tar -tf "$archive" | grep -qx './index.html'
}

# Unpacks a fresh release beside the live one, then swaps the CLIENT_DIR symlink with one
# rename, so Caddy never serves a half-copied client. Keeps the previous release.
install_client() {
  local src=$1 releases tmp release rev old
  [[ "$CLIENT_DIR" == /* && "$CLIENT_DIR/" != */../* ]] || { warn "CLIENT_DIR must be an absolute path: $CLIENT_DIR"; return 1; }
  releases=$(client_releases_dir)
  assert_not_service_owned "$(dirname "$CLIENT_DIR")"
  assert_not_service_owned "$CLIENT_DIR"
  assert_not_service_owned "$releases"
  tmp=$(mktemp -d)
  # The service user reads its own build; root only ever opens the resulting archive.
  # shellcheck disable=SC2024
  if ! sudo -u "$SUPERBOT_USER" tar -C "$src" -cf - . >"$tmp/client.tar"; then
    rm -rf "$tmp"
    warn "Could not read the web client build in $src"
    return 1
  fi
  if ! client_archive_ok "$tmp/client.tar"; then
    rm -rf "$tmp"
    warn "Refusing the web client build in $src: it must hold only plain files and folders, with index.html"
    return 1
  fi
  rev=$(sudo -u "$SUPERBOT_USER" git -C "$src" rev-parse --short=12 HEAD 2>/dev/null | tr -cd '0-9a-f' || true)
  # Callers use `||`, which turns off set -e here, so every step is checked by hand.
  if ! install -d -m 0755 -o root -g root "$(dirname "$CLIENT_DIR")" "$releases" ||
    ! release=$(mktemp -d "$releases/$(date -u +%Y%m%dT%H%M%SZ)-${rev:-local}-XXXX"); then
    rm -rf "$tmp"
    warn "Could not create a release folder in $releases"
    return 1
  fi
  if ! { tar -xf "$tmp/client.tar" -C "$release" --no-same-owner --no-same-permissions &&
    chown -R root:root "$release" &&
    find "$release" -type d -exec chmod 0755 {} + &&
    find "$release" -type f -exec chmod 0644 {} + &&
    [[ -f "$release/index.html" ]] &&
    touch "$release"; }; then
    rm -rf "$tmp" "$release"
    warn "Could not unpack the web client into $release"
    return 1
  fi
  rm -rf "$tmp"
  old=""
  if [[ -d "$CLIENT_DIR" && ! -L "$CLIENT_DIR" ]]; then
    # A folder from before releases (e.g. a manual build) is kept as the previous release.
    old="$releases/previous-$(date -u +%Y%m%dT%H%M%SZ)-$$"
    if ! mv -T "$CLIENT_DIR" "$old"; then
      rm -rf "$release"
      warn "Could not move $CLIENT_DIR aside"
      return 1
    fi
  fi
  if ! { ln -sfn "$release" "$CLIENT_DIR.new" && mv -Tf "$CLIENT_DIR.new" "$CLIENT_DIR"; }; then
    rm -f "$CLIENT_DIR.new"
    [[ -z "$old" ]] || mv -T "$old" "$CLIENT_DIR" || true
    rm -rf "$release"
    warn "Could not switch $CLIENT_DIR to the new release"
    return 1
  fi
  find "$releases" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -rn | tail -n +3 | cut -d' ' -f2- |
    while IFS= read -r old; do
      [[ "$old" == "$release" ]] || rm -rf -- "$old"
    done
  log "Installed the web client into $CLIENT_DIR -> $release"
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

  [[ ! -L "$env_file" ]] || die "Refusing symlinked $env_file"
  [[ ! -L "$pass_file" ]] || die "Refusing symlinked $pass_file"
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

  if ! grep -q '^AUTH_PASSWORD=.' "$env_file" && ! grep -q '^AUTH_PASSWORD_FILE=.' "$env_file"; then
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

master_key_default() { printf '%s/.config/superbot/master.key\n' "$1"; }

# True if botd already sealed values in this database (so only the old key opens them).
db_has_sealed_values() {
  local db=$1
  [[ -f "$db" ]] || return 1
  [[ -n $(sudo -u "$SUPERBOT_USER" sqlite3 -readonly "$db" "SELECT 1 FROM settings WHERE key = 'secrets_key_check'" 2>/dev/null) ]]
}

# The key that encrypts secrets in SQLite (docs/adr/0010-secrets.md). Made once,
# before botd (re)starts, as the service user: 0600 in a 0700 folder, outside
# DATA_DIR so database backups don't carry it. Never replaced.
# shellcheck disable=SC2016
ensure_master_key() {
  local home repo_path env_file key_file owner mode
  home=$(user_home)
  repo_path="$home/superbot"
  env_file="$repo_path/.env"
  key_file=$(master_key_default "$home")
  if [[ "$DRY_RUN" == true ]]; then
    log "[dry-run] would keep or create master key $key_file (0600, $SUPERBOT_USER) and set SUPERBOT_MASTER_KEY_FILE"
    return
  fi
  if grep -q '^SUPERBOT_MASTER_KEY=.' "$env_file"; then
    log "Master key: set in $env_file as SUPERBOT_MASTER_KEY"
    return
  fi
  if grep -q '^SUPERBOT_MASTER_KEY_FILE=.' "$env_file"; then
    key_file=$(sed -n 's/^SUPERBOT_MASTER_KEY_FILE=//p' "$env_file" | tail -n 1)
    case $key_file in
      \"*\" | \'*\') key_file=${key_file:1:-1} ;;
    esac
  fi
  [[ "$key_file" == /* ]] || die "SUPERBOT_MASTER_KEY_FILE must be an absolute path, not $key_file"
  [[ "$key_file/" != */../* ]] || die "SUPERBOT_MASTER_KEY_FILE must not contain '..': $key_file"
  [[ "$key_file/" != "$repo_path/data/"* ]] || die "$key_file is inside DATA_DIR, which backups copy. Keep the master key elsewhere."
  [[ ! -L "$key_file" ]] || die "Refusing symlinked $key_file"
  if [[ -e "$key_file" ]]; then
    [[ -s "$key_file" ]] || die "$key_file is empty. Restore the master key from your backup (deploy/README.md)."
    owner=$(stat -c %U "$key_file")
    [[ "$owner" == "$SUPERBOT_USER" ]] || die "$key_file must be owned by $SUPERBOT_USER, not $owner"
    mode=$(stat -c %a "$key_file")
    if [[ "${mode: -2}" != 00 ]]; then
      warn "$key_file was mode $mode; tightening to 0600"
      chmod 0600 "$key_file"
    fi
    log "Master key: keeping $key_file"
  else
    if db_has_sealed_values "$repo_path/data/app.sqlite" && ! grep -q '^SUPERBOT_FORGET_SEALED=1$' "$env_file"; then
      die "No master key at $key_file, but the database holds values sealed with one. Restore the key (deploy/README.md) and re-run."
    fi
    log "Creating master key $key_file"
    sudo -u "$SUPERBOT_USER" -H env KEY_FILE="$key_file" sh -c '
      set -eu
      umask 077
      dir=$(dirname "$KEY_FILE")
      [ -d "$dir" ] || mkdir -p -m 700 "$dir"
      tmp=$(mktemp "$KEY_FILE.XXXXXX")
      head -c 32 /dev/urandom | base64 >"$tmp"
      mv -n "$tmp" "$KEY_FILE"
      rm -f "$tmp"'
    [[ -s "$key_file" ]] || die "Could not create $key_file"
    export NEW_MASTER_KEY_FILE=$key_file
  fi
  set_env_var "$env_file" SUPERBOT_MASTER_KEY_FILE "$key_file"
}

service_unit_fixed() {
  local home=$1
  printf '%s\n' "User=$SUPERBOT_USER" "Group=$SUPERBOT_USER" \
    "WorkingDirectory=$home/superbot" "EnvironmentFile=-$home/superbot/.env" \
    "ExecStart=$BIN_DIR/botd"
}

backup_unit_fixed() {
  local home=$1
  printf '%s\n' "User=$SUPERBOT_USER" "Group=$SUPERBOT_USER" \
    "EnvironmentFile=-$home/superbot/.env" \
    "ExecStart=$BIN_DIR/superbot-backup $home"
}

install_systemd() {
  local home deploy unit
  home=$(user_home)
  deploy=$(trusted_deploy_dir)
  unit="$SYSTEMD_DIR/superbot.service"
  if [[ "$DRY_RUN" == true ]]; then
    log "[dry-run] would render $unit from $deploy/superbot.service (User=$SUPERBOT_USER, ExecStart=$BIN_DIR/botd)"
    return
  fi
  log "Installing $unit from $deploy"
  render_unit "$deploy/superbot.service" "$unit" "$(service_unit_fixed "$home")"
  systemctl daemon-reload
  systemctl enable superbot.service
  systemctl restart superbot.service
}

install_backup() {
  local home deploy
  home=$(user_home)
  deploy=$(trusted_deploy_dir)
  run install -m 0755 -o root -g root "$deploy/superbot-backup.sh" "$BIN_DIR/superbot-backup"
  if [[ "$ENABLE_BACKUP" != true ]]; then
    return
  fi
  if [[ "$DRY_RUN" == true ]]; then
    log "[dry-run] would render $SYSTEMD_DIR/superbot-backup.{service,timer} from $deploy (User=$SUPERBOT_USER, ExecStart=$BIN_DIR/superbot-backup $home)"
    return
  fi
  log "Enabling daily backup timer from $deploy"
  render_unit "$deploy/superbot-backup.service" "$SYSTEMD_DIR/superbot-backup.service" "$(backup_unit_fixed "$home")"
  render_unit "$deploy/superbot-backup.timer" "$SYSTEMD_DIR/superbot-backup.timer" ""
  systemctl daemon-reload
  systemctl enable --now superbot-backup.timer
}

# Caddyfile for SITE: the web client at /app/ when CLIENT_ROOT is set; everything else (the
# built-in page at /, /login, /api, the /api/events SSE stream, /healthz) goes to botd.
render_caddyfile() {
  local site=$1 upstream=$2 client_root=${3:-}
  printf '%s {\n\tencode gzip\n' "$site"
  if [[ -n "$client_root" ]]; then
    cat <<CADDY
	redir /app /app/
	handle_path /app/* {
		root * ${client_root}
		# Hashed bundles never change; everything else is re-checked so upgrades show at once.
		@immutable {
			path /_expo/static/*
			file
		}
		@mutable not {
			path /_expo/static/*
			file
		}
		header @immutable Cache-Control "public, max-age=31536000, immutable"
		header @mutable Cache-Control "no-cache"
		try_files {path} /index.html
		file_server
	}
CADDY
  fi
  cat <<CADDY
	handle {
		reverse_proxy ${upstream} {
			flush_interval -1
		}
	}
}
CADDY
}

client_installed() {
  [[ -f "$CLIENT_DIR/index.html" ]] || [[ "$DRY_RUN" == true && "$BUILD_CLIENT" == true ]]
}

install_caddy() {
  local client_root=""
  if [[ -z "$DOMAIN" ]]; then
    warn "No --domain: skipping Caddy (botd listens on 127.0.0.1:3000 only; the web client is not served)"
    return
  fi
  if client_installed; then
    client_root=$CLIENT_DIR
  fi
  log "Installing Caddy"
  if [[ "$DRY_RUN" == true ]]; then
    log "[dry-run] would write /etc/caddy/Caddyfile for $DOMAIN: ${client_root:+web client at /app/ from $client_root, }everything else to botd on 127.0.0.1:3000"
    return
  fi
  if ! command -v caddy >/dev/null 2>&1; then
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -qq
    apt-get install -y -qq caddy
  fi
  render_caddyfile "$DOMAIN" 127.0.0.1:3000 "$client_root" >/etc/caddy/Caddyfile
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
  local home repo_path pass_file url app
  home=$(user_home)
  repo_path="$home/superbot"
  pass_file="$home/.superbot-admin-password"
  if [[ -n "$DOMAIN" ]]; then
    url="https://${DOMAIN}"
  else
    url="http://127.0.0.1:3000 (on this host)"
  fi
  app="not served (needs --domain and the web client)"
  if [[ -n "$DOMAIN" ]] && client_installed; then
    app="https://${DOMAIN}/app/"
  fi
  cat <<EOF

SuperBot is installed.

  URL:      $url (built-in admin page)
  App:      $app
  Password: stored in $pass_file (also in $repo_path/.env as AUTH_PASSWORD)
  Key:      $(master_key_default "$home") encrypts saved secrets. Back it up apart from
            the database: without it they can't be read (deploy/README.md).
  Logs:     journalctl -u superbot -f
  Upgrade:  sudo bash -s -- --upgrade < <(curl -fsSL https://raw.githubusercontent.com/CG-Labs/superbot/main/deploy/install.sh)

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
  if [[ -n "${NEW_MASTER_KEY_FILE:-}" ]]; then
    warn "New master key at $NEW_MASTER_KEY_FILE. Copy it somewhere safe, away from your database backups."
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
  stage_trusted_deploy
  build_botd
  build_client
  configure_env
  ensure_master_key
  install_systemd
  install_backup
  install_caddy
  configure_ufw
  summary
}

# CI sources the functions without running the install.
if [[ "${SUPERBOT_INSTALL_NO_MAIN:-}" != 1 ]]; then
  main "$@"
fi