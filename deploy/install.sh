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
WITH_HERMES=false
LICENSE_FILE=""
# --testing-mode: run unlicensed with billing off (TESTING_MODE=on; docs/adr/0068-no-free-tier.md).
TESTING_MODE_ON=false
# Hermes Agent release --with-hermes installs: the commit of tag v0.23.3 (NousResearch/hermes-agent),
# as server/src/adapters/install.rs pins it. Change it with deploy/hermes-pin.sh bump.
HERMES_COMMIT=${HERMES_COMMIT:-caafe5389ae585ef77387a962aee05b1bcf17029}
SHARE_DIR=${SHARE_DIR:-/usr/local/share/superbot}
SYSTEMD_DIR=${SYSTEMD_DIR:-/etc/systemd/system}
CLIENT_DIR=${CLIENT_DIR:-/var/www/superbot-app}
SITE_DIR=${SITE_DIR:-/var/www/superbot-site}
CLIENT_BASE_URL=/app
BUILD_CLIENT=true
# Exit status when everything else installed but this run's web client did not.
CLIENT_NOT_INSTALLED_EXIT=3
CLIENT_NOT_INSTALLED=""
DEPLOY_FILES=(superbot.service superbot-backup.sh superbot-restore.sh superbot-backup.service superbot-backup.timer superbot-userctl.sh hermes-share.sh)
# Per-user accounts (docs/adr/0037-per-user-unix-accounts.md): "" keeps what root set up last.
ISOLATION_MODE=""
# Unset: the one in root's isolation.conf, else /srv/superbot/users (isolation_dir).
ISOLATION_DIR=${ISOLATION_DIR:-}
ISOLATION_GROUP=superbot-users
HERMES_SHARED_DIR=/opt/hermes
ISOLATION_CONF=/etc/superbot/isolation.conf
USERCTL_BIN=/usr/local/sbin/superbot-userctl
SUDOERS_FILE=/etc/sudoers.d/superbot-isolation

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
  --with-hermes       Also install the Hermes Agent CLI (about 2.5 GB; HERMES_COMMIT pins it)
  --license-file PATH Install the license key CG-Labs sent. SuperBot has no free tier: without a
                      license, Bots don't run unless testing mode is on
  --testing-mode      Set TESTING_MODE=on: no license, billing off, for test servers only
  --isolation         Run each user's Bots as their own Unix account (ISOLATION=users; ADR 0037),
                      which can't read .env, the database or the master key. On by default for
                      new installs (ADR 0058); an upgrade keeps what it had. ISOLATION_DIR sets
                      where their folders go (default /srv/superbot/users)
  --no-isolation      Turn that off (accounts and their folders are kept)
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
      --with-hermes) WITH_HERMES=true; shift ;;
      --license-file) LICENSE_FILE=$2; shift 2 ;;
      --testing-mode) TESTING_MODE_ON=true; shift ;;
      --isolation) ISOLATION_MODE=users; shift ;;
      --no-isolation) ISOLATION_MODE=off; shift ;;
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
  if grep -Eq '^[[:space:]]*(Exec[A-Za-z]*|DynamicUser|SupplementaryGroups|AmbientCapabilities|PermissionsStartOnly|RootDirectory|RootImage|Alias)[[:space:]]*=' \
    <<<"$(grep -Ev '^[[:space:]]*ExecStart[[:space:]]*=' "$template")"; then
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
  # Optional: encrypts backups when SUPERBOT_BACKUP_AGE_RECIPIENTS is set (Ubuntu universe).
  run apt-get install -y -qq age || warn "Could not install age: encrypted backups are unavailable"
  # Harness sandboxes (ADR 0055): Codex and Claude Code build theirs with bubblewrap;
  # Claude Code also needs socat.
  run apt-get install -y -qq bubblewrap socat || warn "Could not install bubblewrap and socat: harness sandboxes are unavailable"
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
  if sudo -u "$SUPERBOT_USER" -H bash -lc 'command -v cargo' >/dev/null 2>&1; then
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
  run install -m 0755 "$repo_path/target/release/superbot-machine" "$BIN_DIR/superbot-machine"
  run install -m 0755 "$repo_path/target/release/superbot-run" "$BIN_DIR/superbot-run"
}

releases_dir() { printf '%s.releases\n' "$1"; }
client_releases_dir() { releases_dir "$CLIENT_DIR"; }

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
    client_not_installed "Web client build failed"
    return
  fi
  install_client "$client/dist-app" || client_not_installed "Web client not installed"
}

# main exits non-zero at the end, so an upgrade can't quietly leave /app/ on the old client.
client_not_installed() {
  CLIENT_NOT_INSTALLED=$1
  warn "$1: keeping the previous one, if any"
}

# Plain files and folders only (no links, devices, or ".."), with an index.html.
# Never pipe tar into `grep -q`: grep exits at the first match, tar dies of SIGPIPE, and
# pipefail turns a good archive into a refused one (#93).
client_archive_ok() {
  local archive=$1 entries names
  entries=$(tar -tvf "$archive") && names=$(tar -tf "$archive") || return 1
  awk '{ t = substr($0, 1, 1) } t != "-" && t != "d" { bad = 1 } END { exit bad }' <<<"$entries" || return 1
  ! grep -Eq '^/|(^|/)\.\.(/|$)' <<<"$names" && grep -qx './index.html' <<<"$names"
}

install_client() { install_release "$CLIENT_DIR" "$1" "web client"; }

# Unpacks a fresh release of SRC beside the live one, then swaps the DIR symlink with one
# rename, so Caddy never serves a half-copied folder. Keeps the previous release.
install_release() {
  local dir=$1 src=$2 what=$3 releases tmp release rev old
  [[ "$dir" == /* && "$dir/" != */../* ]] || { warn "The $what folder must be an absolute path: $dir"; return 1; }
  releases=$(releases_dir "$dir")
  assert_not_service_owned "$(dirname "$dir")"
  assert_not_service_owned "$dir"
  assert_not_service_owned "$releases"
  tmp=$(mktemp -d)
  # The service user reads its own build; root only ever opens the resulting archive.
  # shellcheck disable=SC2024
  if ! sudo -u "$SUPERBOT_USER" tar -C "$src" -cf - . >"$tmp/release.tar"; then
    rm -rf "$tmp"
    warn "Could not read the $what build in $src"
    return 1
  fi
  if ! client_archive_ok "$tmp/release.tar"; then
    rm -rf "$tmp"
    warn "Refusing the $what build in $src: it must hold only plain files and folders, with index.html"
    return 1
  fi
  rev=$(sudo -u "$SUPERBOT_USER" git -C "$src" rev-parse --short=12 HEAD 2>/dev/null | tr -cd '0-9a-f' || true)
  # Callers use `||`, which turns off set -e here, so every step is checked by hand.
  if ! install -d -m 0755 -o root -g root "$(dirname "$dir")" "$releases" ||
    ! release=$(mktemp -d "$releases/$(date -u +%Y%m%dT%H%M%SZ)-${rev:-local}-XXXX"); then
    rm -rf "$tmp"
    warn "Could not create a release folder in $releases"
    return 1
  fi
  if ! { tar -xf "$tmp/release.tar" -C "$release" --no-same-owner --no-same-permissions &&
    chown -R root:root "$release" &&
    find "$release" -type d -exec chmod 0755 {} + &&
    find "$release" -type f -exec chmod 0644 {} + &&
    [[ -f "$release/index.html" ]] &&
    touch "$release"; }; then
    rm -rf "$tmp" "$release"
    warn "Could not unpack the $what into $release"
    return 1
  fi
  rm -rf "$tmp"
  old=""
  if [[ -d "$dir" && ! -L "$dir" ]]; then
    # A folder from before releases (e.g. a manual build) is kept as the previous release.
    old="$releases/previous-$(date -u +%Y%m%dT%H%M%SZ)-$$"
    if ! mv -T "$dir" "$old"; then
      rm -rf "$release"
      warn "Could not move $dir aside"
      return 1
    fi
  fi
  if ! { ln -sfn "$release" "$dir.new" && mv -Tf "$dir.new" "$dir"; }; then
    rm -f "$dir.new"
    [[ -z "$old" ]] || mv -T "$old" "$dir" || true
    rm -rf "$release"
    warn "Could not switch $dir to the new release"
    return 1
  fi
  find "$releases" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -rn | tail -n +3 | cut -d' ' -f2- |
    while IFS= read -r old; do
      [[ "$old" == "$release" ]] || rm -rf -- "$old"
    done
  log "Installed the $what into $dir -> $release"
}

# The landing page and get-started form (site/, ADR 0022): plain files from the checkout,
# installed root-owned like the client, so no build and no Node are needed.
install_site() {
  local src
  src="$(user_home)/superbot/site"
  if [[ "$DRY_RUN" == true ]]; then
    log "[dry-run] would install the landing page from $src into root-owned $SITE_DIR"
    return
  fi
  install_release "$SITE_DIR" "$src" "landing page" || warn "Landing page not installed: botd serves its built-in copy"
}

# Values are written as given: `&`, `|` and `\` are not sed syntax here.
set_env_var() {
  local file=$1 key=$2 value=$3 tmp
  [[ "$value" != *$'\n'* ]] || die "Refusing a multi-line value for $key"
  if grep -q "^${key}=" "$file"; then
    tmp=$(mktemp)
    K=$key V=$value awk 'index($0, ENVIRON["K"] "=") == 1 { print ENVIRON["K"] "=" ENVIRON["V"]; next } { print }' "$file" >"$tmp" \
      && cat "$tmp" >"$file"
    local rc=$?
    rm -f "$tmp"
    return "$rc"
  else
    printf '%s=%s\n' "$key" "$value" >>"$file"
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
    local testing=""
    [[ "$TESTING_MODE_ON" != true ]] || testing=" (TESTING_MODE=on: no license, billing off)"
    log "[dry-run] configure $env_file$testing"
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

  if [[ "$TESTING_MODE_ON" == true ]]; then
    set_env_var "$env_file" TESTING_MODE on
  fi

  if [[ -n "$DOMAIN" ]]; then
    set_env_var "$env_file" ALLOWED_HOSTS "$DOMAIN"
    set_env_var "$env_file" CORS_ORIGINS "https://${DOMAIN}"
  fi

  if ! grep -q '^AUTH_PASSWORD=.' "$env_file" && ! grep -q '^AUTH_PASSWORD_FILE=.' "$env_file"; then
    local pass
    pass=$(openssl rand -base64 48 | tr -d '/+=\n')
    pass=${pass:0:32}
    [[ ${#pass} == 32 ]] || die "Could not generate a password"
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

# The license key (docs/adr/0038-self-host-license-key.md). Its shape is checked early,
# before the long build; botd checks its signature when it starts and logs what it found.
check_license_file() {
  [[ -n "$LICENSE_FILE" ]] || return 0
  [[ -f "$LICENSE_FILE" && -r "$LICENSE_FILE" ]] || die "--license-file: can't read $LICENSE_FILE"
  (( $(stat -c %s "$LICENSE_FILE") <= 8192 )) || die "--license-file: $LICENSE_FILE is too big to be a license key"
  local key
  key=$(tr -d '[:space:]' <"$LICENSE_FILE")
  [[ "$key" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]] \
    || die "--license-file: $LICENSE_FILE isn't a SuperBot license key (three parts separated by dots)"
}

# Saved where PUT /api/license saves it, DATA_DIR/license.key, written by the service
# user (DATA_DIR is theirs) so root never writes through a path they control.
# shellcheck disable=SC2016
install_license() {
  [[ -n "$LICENSE_FILE" ]] || return 0
  local home repo_path env_file dest
  home=$(user_home)
  repo_path="$home/superbot"
  env_file="$repo_path/.env"
  dest="$repo_path/data/license.key"
  if [[ "$DRY_RUN" == true ]]; then
    log "[dry-run] would install the license key from $LICENSE_FILE as $dest (0600, $SUPERBOT_USER)"
    return
  fi
  tr -d '[:space:]' <"$LICENSE_FILE" | sudo -u "$SUPERBOT_USER" -H env DEST="$dest" sh -c '
    set -eu
    umask 077
    mkdir -p "$(dirname "$DEST")"
    tmp=$(mktemp "$DEST.XXXXXX")
    cat >"$tmp"
    printf "\n" >>"$tmp"
    mv -f "$tmp" "$DEST"'
  log "License key installed as $dest. botd checks it when it starts: journalctl -u superbot | grep License"
  if grep -Eq '^LICENSE_KEY(_FILE)?=.' "$env_file" 2>/dev/null; then
    warn "$env_file sets LICENSE_KEY or LICENSE_KEY_FILE, which wins over $dest. Remove it to use this key."
  fi
}

# The Hermes commit installed for the HOME $1 Hermes's installer ran with, if any.
hermes_installed() { head -n 1 "$1/.hermes/hermes-agent/.git/HEAD" 2>/dev/null || true; }

# A new Hermes replaces the one environment every running Bot uses, so botd stops
# while Hermes's installer runs; install_systemd starts it again
# (docs/adr/0072-one-hermes-environment-per-computer.md). Everything that can fail
# beforehand (packages, the installer's download) happens first, and a failure once
# botd is stopped starts it again before the install gives up.
HERMES_STOPPED=false

stop_for_hermes() {
  if systemctl is-active --quiet superbot.service 2>/dev/null; then
    log "Stopping superbot while Hermes Agent changes"
    systemctl stop superbot.service
    HERMES_STOPPED=true
  fi
}

hermes_failed() {
  if [[ "$HERMES_STOPPED" == true ]]; then
    warn "Starting superbot again with the Hermes Agent it had"
    systemctl start superbot.service || true
  fi
  die "$1"
}

# Hermes's installer from $1, into a file every account may read.
fetch_hermes_installer() {
  local tmp
  tmp=$(mktemp)
  curl -fsSL "$1" -o "$tmp" || { rm -f "$tmp"; die "Couldn't download Hermes Agent's installer from $1"; }
  chmod 0644 "$tmp"
  printf '%s\n' "$tmp"
}

# Hermes's own installer, as the service user (Hermes refuses a checkout another user
# owns), then deploy/hermes-share.sh, which makes its environment every Bot's and leaves
# the hermes Bots run in ~/.hermes/superbot, which botd gets on PATH through .env. With
# per-user accounts, which can't read botd's home, it goes system-wide instead.
install_hermes() {
  [[ "$WITH_HERMES" == true ]] || return 0
  [[ "$HERMES_COMMIT" =~ ^[0-9a-f]{40}$ ]] || die "HERMES_COMMIT must be a full commit SHA"
  local home env_file bin_path url share wrapper cur installer ok
  home=$(user_home)
  env_file="$home/superbot/.env"
  bin_path="$home/.hermes/superbot:$home/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  url="https://raw.githubusercontent.com/NousResearch/hermes-agent/$HERMES_COMMIT/scripts/install.sh"
  share="$(trusted_deploy_dir)/hermes-share.sh"
  wrapper="$home/.hermes/superbot/hermes"
  if [[ "$(isolation_mode)" == users ]]; then
    install_hermes_shared "$url" "$share"
    return
  fi
  if [[ "$DRY_RUN" == true ]]; then
    log "[dry-run] would install Hermes Agent $HERMES_COMMIT for $SUPERBOT_USER from $url"
    log "[dry-run] would share its environment across Bots with $share"
    log "[dry-run] would set PATH=$bin_path in $env_file"
    return
  fi
  if [[ "$(hermes_installed "$home")" == "$HERMES_COMMIT" ]] && sudo -u "$SUPERBOT_USER" -H sh "$share" >/dev/null 2>&1; then
    log "Hermes Agent ${HERMES_COMMIT:0:12} is already installed for $SUPERBOT_USER"
  else
    apt-get install -y -qq libatomic1 xz-utils
    installer=$(fetch_hermes_installer "$url")
    stop_for_hermes
    log "Installing Hermes Agent ${HERMES_COMMIT:0:12} for $SUPERBOT_USER"
    ok=true
    sudo -u "$SUPERBOT_USER" -H bash "$installer" --non-interactive --skip-browser --skip-computer-use \
      --commit "$HERMES_COMMIT" || ok=false
    rm -f "$installer"
    [[ "$ok" == true ]] || hermes_failed "Hermes Agent did not install"
  fi
  sudo -u "$SUPERBOT_USER" -H sh "$share" >/dev/null || hermes_failed "Couldn't share Hermes Agent's environment"
  sudo -u "$SUPERBOT_USER" -H "$wrapper" --version >/dev/null || hermes_failed "Hermes Agent did not install"
  cur=$(sed -n 's/^PATH=//p' "$env_file" | tail -n 1)
  if [[ -z "$cur" ]]; then
    set_env_var "$env_file" PATH "$bin_path"
  elif [[ ":$cur:" != *":$home/.hermes/superbot:"* ]]; then
    set_env_var "$env_file" PATH "$home/.hermes/superbot:$cur"
  fi
}

# Root's checkout in $HERMES_SHARED_DIR, which every account may run but none may change.
# Each run has its own HERMES_HOME (the Bot's folder), holding the Bot's own record of the
# install; the environment is the install's one, read-only to them.
install_hermes_shared() {
  local url=$1 share=$2 probe installer ok wrapper="$HERMES_SHARED_DIR/.hermes/superbot/hermes"
  if [[ "$DRY_RUN" == true ]]; then
    log "[dry-run] would share its environment across Bots with $share"
    log "[dry-run] would install Hermes Agent $HERMES_COMMIT system-wide in $HERMES_SHARED_DIR from $url, linked from /usr/local/bin/hermes"
    return
  fi
  if [[ "$(hermes_installed "$HERMES_SHARED_DIR")" == "$HERMES_COMMIT" ]] && env HOME="$HERMES_SHARED_DIR" sh "$share" >/dev/null 2>&1; then
    log "Hermes Agent ${HERMES_COMMIT:0:12} is already installed in $HERMES_SHARED_DIR"
  else
    apt-get install -y -qq libatomic1 xz-utils
    installer=$(fetch_hermes_installer "$url")
    stop_for_hermes
    log "Installing Hermes Agent ${HERMES_COMMIT:0:12} system-wide in $HERMES_SHARED_DIR (per-user accounts run it)"
    install -d -m 0755 -o root -g root "$HERMES_SHARED_DIR"
    ok=true
    env HOME="$HERMES_SHARED_DIR" SHELL=/bin/bash bash "$installer" --non-interactive --skip-browser --skip-computer-use \
      --commit "$HERMES_COMMIT" || ok=false
    rm -f "$installer"
    [[ "$ok" == true ]] || hermes_failed "Hermes Agent did not install"
  fi
  env HOME="$HERMES_SHARED_DIR" sh "$share" >/dev/null || hermes_failed "Couldn't share Hermes Agent's environment"
  chmod -R go-w "$HERMES_SHARED_DIR"
  chmod go+rx "$HERMES_SHARED_DIR/.hermes" "$HERMES_SHARED_DIR/.hermes/superbot"
  ln -sfn "$wrapper" /usr/local/bin/hermes
  probe=$(mktemp -d)
  chmod 0777 "$probe"
  sudo -u nobody env HOME="$probe" HERMES_HOME="$probe/hermes" /usr/local/bin/hermes --version >/dev/null \
    || { rm -rf "$probe"; hermes_failed "Hermes Agent did not install for other accounts"; }
  rm -rf "$probe"
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
    "ExecStart=$BIN_DIR/superbot-backup --home $home"
}

# --isolation or --no-isolation, else what .env already says, so an upgrade keeps it.
# Root-owned and writable by root alone, so botd's account can't steer root through it.
root_only() {
  [[ -f "$1" && ! -L "$1" && "$(stat -c '%u' "$1")" == 0 && $(( 0$(stat -c '%a' "$1") & 022 )) == 0 ]]
}

# On or off: the flag, else whether root's sudoers rule is there. Never .env, which
# botd's account can write.
isolation_mode() {
  if [[ -n "$ISOLATION_MODE" ]]; then
    printf '%s\n' "$ISOLATION_MODE"
  elif root_only "$SUDOERS_FILE"; then
    echo users
  else
    echo off
  fi
}

isolation_sudoers() {
  cat <<EOF
# SuperBot per-user accounts (docs/adr/0037-per-user-unix-accounts.md). Written by
# deploy/install.sh --isolation; --no-isolation removes it. botd's account may start
# superbot-run (which runs a harness) as a per-user account, keeping the run's env, make a
# user's account with the root helper, and remove a leaving teammate's account
# (docs/adr/0066-removing-teammate-accounts-on-one-server.md). Nothing else, and no one else.
Defaults!$BIN_DIR/superbot-run !syslog
$SUPERBOT_USER ALL=(%$ISOLATION_GROUP) NOPASSWD:SETENV: $BIN_DIR/superbot-run
$SUPERBOT_USER ALL=(root) NOPASSWD: $USERCTL_BIN ensure *, $USERCTL_BIN remove *, $USERCTL_BIN purge *
EOF
}

isolation_dropin() {
  cat <<'EOF'
# SuperBot per-user accounts (docs/adr/0037-per-user-unix-accounts.md), from deploy/install.sh.
[Service]
# sudo is setuid: botd needs it to start runs as each user's account.
NoNewPrivileges=false
# Runs see only their own account's processes, not other users' command lines.
ProtectProc=invisible
EOF
}

# ISOLATION_DIR as given, else root's saved one, so an upgrade keeps a custom folder.
isolation_dir() {
  local saved=""
  if root_only "$ISOLATION_CONF"; then
    saved=$(sed -n 's/^ISOLATION_DIR=//p' "$ISOLATION_CONF" | tail -n 1)
  fi
  if [[ -n "$ISOLATION_DIR" ]]; then
    if [[ -n "$saved" && "$saved" != "$ISOLATION_DIR" ]]; then
      warn "ISOLATION_DIR changes from $saved to $ISOLATION_DIR: existing accounts keep their homes in $saved, and botd refuses their runs until they're moved by hand"
    fi
    printf '%s\n' "$ISOLATION_DIR"
  else
    printf '%s\n' "${saved:-/srv/superbot/users}"
  fi
}

# Per-user accounts on or off. On: the root helper, the sudoers rule, the unit drop-in,
# the users' folder, and ISOLATION=users in .env. Off: the rule and drop-in go; accounts
# and their folders stay, as data.
configure_isolation() {
  local mode home env_file group dropin tmp
  mode=$(isolation_mode)
  home=$(user_home)
  env_file="$home/superbot/.env"
  ISOLATION_DIR=$(isolation_dir)
  dropin="$SYSTEMD_DIR/superbot.service.d/isolation.conf"
  if [[ "$mode" != users ]]; then
    [[ "$ISOLATION_MODE" == off ]] || return 0
    if [[ "$DRY_RUN" == true ]]; then
      log "[dry-run] would set ISOLATION=off in $env_file and remove $SUDOERS_FILE and $dropin"
      return
    fi
    log "Per-user accounts: off (accounts and $ISOLATION_DIR are kept)"
    rm -f "$SUDOERS_FILE" "$dropin"
    set_env_var "$env_file" ISOLATION off
    return
  fi
  [[ "$ISOLATION_DIR" =~ ^(/[A-Za-z0-9._-]+)+$ && "$ISOLATION_DIR/" != */../* ]] || die "ISOLATION_DIR must be a plain absolute path: $ISOLATION_DIR"
  case "$ISOLATION_DIR/" in
    "$home"/*) die "ISOLATION_DIR must not be under $home" ;;
  esac
  if [[ "$DRY_RUN" == true ]]; then
    log "[dry-run] would install $USERCTL_BIN, $SUDOERS_FILE, and $dropin, make $ISOLATION_DIR (root, 0711) and group $ISOLATION_GROUP, chmod 0750 $home, and set ISOLATION=users in $env_file"
    return
  fi
  log "Per-user accounts: on, in $ISOLATION_DIR"
  apt-get install -y -qq acl sudo
  group=$(id -gn "$SUPERBOT_USER")
  groupadd -r -f "$ISOLATION_GROUP"
  install -d -m 0755 -o root -g root /etc/superbot
  # The folders above it are checked (root's, only root's to write) by the helper, not changed.
  [[ -d "$(dirname "$ISOLATION_DIR")" ]] || install -d -m 0755 -o root -g root "$(dirname "$ISOLATION_DIR")"
  install -d -m 0711 -o root -g root "$ISOLATION_DIR"
  chown root:root "$ISOLATION_DIR"
  chmod 0711 "$ISOLATION_DIR"
  tmp=$(mktemp)
  printf '%s\n' "# Read by $USERCTL_BIN. Written by deploy/install.sh." "ISOLATION_DIR=$ISOLATION_DIR" "SERVICE_GROUP=$group" >"$tmp"
  install -m 0644 -o root -g root "$tmp" "$ISOLATION_CONF"
  install -m 0755 -o root -g root "$(trusted_deploy_dir)/superbot-userctl.sh" "$USERCTL_BIN"
  isolation_sudoers >"$tmp"
  visudo -cqf "$tmp" || { rm -f "$tmp"; die "The sudoers rule for per-user accounts didn't check out"; }
  install -m 0440 -o root -g root "$tmp" "$SUDOERS_FILE"
  install -d -m 0755 -o root -g root "$(dirname "$dropin")"
  isolation_dropin >"$tmp"
  install -m 0644 -o root -g root "$tmp" "$dropin"
  rm -f "$tmp"
  # Per-user accounts must not read botd's database, .env, or master key.
  chmod 0750 "$home"
  set_env_var "$env_file" ISOLATION users
  set_env_var "$env_file" ISOLATION_DIR "$ISOLATION_DIR"
}

# New installs get per-user accounts (ADR 0058). An existing one (it has .env) keeps what
# it had, so an upgrade doesn't change how its Bots run; botd's startup log says how to opt in.
default_isolation() {
  [[ -z "$ISOLATION_MODE" && "$UPGRADE" != true ]] || return 0
  local home
  home=$(getent passwd "$SUPERBOT_USER" | cut -d: -f6 || true)
  [[ -n "$home" && -e "$home/superbot/.env" ]] && return 0
  ISOLATION_MODE=users
  log "New install: each user's Bots run as their own Unix account (--no-isolation turns this off)"
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
  run install -m 0755 -o root -g root "$deploy/superbot-restore.sh" "$BIN_DIR/superbot-restore"
  if [[ "$ENABLE_BACKUP" != true ]]; then
    return
  fi
  if [[ "$DRY_RUN" == true ]]; then
    log "[dry-run] would render $SYSTEMD_DIR/superbot-backup.{service,timer} from $deploy (User=$SUPERBOT_USER, ExecStart=$BIN_DIR/superbot-backup --home $home)"
    return
  fi
  log "Enabling daily backup timer from $deploy"
  render_unit "$deploy/superbot-backup.service" "$SYSTEMD_DIR/superbot-backup.service" "$(backup_unit_fixed "$home")"
  render_unit "$deploy/superbot-backup.timer" "$SYSTEMD_DIR/superbot-backup.timer" ""
  systemctl daemon-reload
  systemctl enable --now superbot-backup.timer
}

# Caddyfile for SITE: the landing page at / and /get-started when SITE_ROOT is set, the web
# client at /app/ when CLIENT_ROOT is set; everything else (/console/, /login, /api, the
# /api/events SSE stream, /healthz, the /status page) goes to botd, which also has the landing built in.
render_caddyfile() {
  local site=$1 upstream=$2 client_root=${3:-} site_root=${4:-}
  printf '%s {\n\tencode gzip\n' "$site"
  if [[ -n "$site_root" ]]; then
    cat <<CADDY
	@site path / /index.html /get-started /get-started/ /site/*
	handle @site {
		root * ${site_root}
		# Keep in step with SITE_CSP in server/src/main.rs.
		header Content-Security-Policy "default-src 'self'; script-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
		header X-Content-Type-Options nosniff
		header Referrer-Policy strict-origin-when-cross-origin
		header Cache-Control no-cache
		rewrite /get-started /get-started.html
		rewrite /get-started/ /get-started.html
		uri /site/* replace /site/ /assets/ 1
		file_server
	}
CADDY
  fi
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

site_installed() {
  [[ -f "$SITE_DIR/index.html" ]] || [[ "$DRY_RUN" == true ]]
}

install_caddy() {
  local client_root="" site_root=""
  if [[ -z "$DOMAIN" ]]; then
    warn "No --domain: skipping Caddy (botd listens on 127.0.0.1:3000 only; the web client is not served)"
    return
  fi
  if client_installed; then
    client_root=$CLIENT_DIR
  fi
  if site_installed; then
    site_root=$SITE_DIR
  fi
  log "Installing Caddy"
  if [[ "$DRY_RUN" == true ]]; then
    log "[dry-run] would write /etc/caddy/Caddyfile for $DOMAIN: ${site_root:+landing page at / from $site_root, }${client_root:+web client at /app/ from $client_root, }everything else to botd on 127.0.0.1:3000"
    return
  fi
  if ! command -v caddy >/dev/null 2>&1; then
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -qq
    apt-get install -y -qq caddy
  fi
  render_caddyfile "$DOMAIN" 127.0.0.1:3000 "$client_root" "$site_root" >/etc/caddy/Caddyfile
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
  local home repo_path pass_file url where app
  home=$(user_home)
  repo_path="$home/superbot"
  pass_file="$home/.superbot-admin-password"
  if [[ -n "$DOMAIN" ]]; then
    url="https://${DOMAIN}" where=""
  else
    url="http://127.0.0.1:3000" where=" (on this host)"
  fi
  app="not served (needs --domain and the web client)"
  if [[ -n "$DOMAIN" ]] && client_installed; then
    app="https://${DOMAIN}/app/"
  fi
  if [[ -n "$CLIENT_NOT_INSTALLED" ]] && ! client_installed; then
    app="not served (this run's web client was not installed)"
  elif [[ -n "$CLIENT_NOT_INSTALLED" && -n "$DOMAIN" ]]; then
    app="$app (still the previous web client: this run's was not installed)"
  fi
  cat <<EOF

SuperBot is installed.

  URL:      $url/$where (landing page and get-started form)
  App:      $app
  Console:  $url/console/$where (built-in admin page)
  Sign-ups: botctl signup list (approve with botctl signup approve <id>)
  Password: stored in $pass_file (also in $repo_path/.env as AUTH_PASSWORD)
  Key:      $(master_key_default "$home") encrypts saved secrets. Back it up apart from
            the database: without it they can't be read (deploy/README.md).
  License:  botctl license (no free tier: without a license, Bots run only with TESTING_MODE=on)
  Logs:     journalctl -u superbot -f
  Upgrade:  sudo bash -s -- --upgrade < <(curl -fsSL https://raw.githubusercontent.com/CG-Labs/superbot/main/deploy/install.sh)

Next steps (as the service user):
  sudo -iu $SUPERBOT_USER
  # Install harness CLIs if needed, then log in, e.g.:
  npm install -g @anthropic-ai/claude-code  # if you use Claude Code
  claude login
  # or: codex login
  # Hermes Agent (--with-hermes): save its provider key with botctl secret set (docs/backend.md)

EOF
  if [[ "$(isolation_mode)" == users ]]; then
    cat <<EOF
Per-user accounts are on (ISOLATION=users, docs/adr/0058-harness-os-user-by-default.md):
  each user's Bots run as sb-u-<user id>, in $ISOLATION_DIR/<user id>, and can't read
  botd's .env, database or master key. Install harness CLIs system-wide
  (sudo npm install -g ...), not in ~/.local, so every account finds them. Then log
  Claude Code or Codex in for each user, as $SUPERBOT_USER, at a terminal:
    botctl user harness-login <user> claude    # or codex
  Pi and Hermes Agent use provider keys saved with botctl secret set.

EOF
  fi
  if [[ -f "$pass_file" ]] && [[ "${NEW_PASSWORD_FILE:-}" == "$pass_file" ]]; then
    warn "New login password (saved to $pass_file): $(cat "$pass_file")"
  fi
  if [[ -n "${NEW_MASTER_KEY_FILE:-}" ]]; then
    warn "New master key at $NEW_MASTER_KEY_FILE. Copy it somewhere safe, away from your database backups."
  fi
}

finish() {
  [[ -n "$CLIENT_NOT_INSTALLED" ]] || return 0
  warn "$CLIENT_NOT_INSTALLED. Everything else is installed, but /app/ still serves the previous web client, if any."
  warn "Fix the cause above and re-run the installer. Exiting with status $CLIENT_NOT_INSTALLED_EXIT."
  exit "$CLIENT_NOT_INSTALLED_EXIT"
}

main() {
  parse_args "$@"
  need_root
  check_license_file
  prompt_missing
  detect_source_dir
  TZ_VALUE=${TZ_VALUE:-UTC}
  USER_NAME_VALUE=${USER_NAME_VALUE:-Owner}

  default_isolation
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
  install_site
  configure_env
  ensure_master_key
  install_license
  install_hermes
  configure_isolation
  install_systemd
  install_backup
  install_caddy
  configure_ufw
  summary
  finish
}

# CI sources the functions without running the install.
if [[ "${SUPERBOT_INSTALL_NO_MAIN:-}" != 1 ]]; then
  main "$@"
fi