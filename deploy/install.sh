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
# Off-host copies of server backups (docs/adr/0109-server-backups-off-the-host.md). Empty:
# .env keeps what it has. The keys come from the installer's environment, never flags:
# SERVER_BACKUP_S3_ACCESS_KEY_ID and SERVER_BACKUP_S3_SECRET_ACCESS_KEY.
BACKUP_S3_ENDPOINT=""
BACKUP_S3_BUCKET=""
BACKUP_S3_REGION=""
BACKUP_S3_PREFIX=""
BACKUP_AGE_RECIPIENTS=""
BACKUP_OFF_HOST=""
# Backup encryption (docs/adr/0114-backups-encrypted-by-default.md). A new install makes an
# age key for its backups unless given recipients or --backup-encryption off; an upgrade
# makes one only with --backup-age-generate. The private half stays root-only on this host
# until the operator copies it off.
BACKUP_ENCRYPTION=""
BACKUP_AGE_GENERATE=false
BACKUP_IDENTITY_FILE=${BACKUP_IDENTITY_FILE:-/root/superbot-backup-identity.txt}
# Database encryption at rest (docs/adr/0116-database-encrypted-at-rest.md). A new install
# writes required; an upgrade keeps what .env has unless given --database-encryption.
DATABASE_ENCRYPTION=""
# --testing-mode: run unlicensed with billing off (TESTING_MODE=on; docs/adr/0068-no-free-tier.md).
TESTING_MODE_ON=false
# Air-gapped installs (docs/adr/0128-air-gapped-self-host.md, docs/ops/air-gapped.md): --offline
# installs or upgrades from a bundle deploy/offline-bundle.sh made, with no network at all.
OFFLINE_BUNDLE=""
OFFLINE_BUNDLE_SHA256=""
# Set by offline_check_origin: whether the bundle's signature was verified.
OFFLINE_SIGNED=false
OFFLINE_DIR=""
OFFLINE_RELEASE_FILE=${OFFLINE_RELEASE_FILE:-}
OFFLINE_BINARIES=(botd botctl superbot-machine superbot-run)
# Who may sign a bundle's SHA256SUMS (cosign keyless), checked when the bundle carries a signature.
OFFLINE_SIGNER_IDENTITY_REGEXP=${OFFLINE_SIGNER_IDENTITY_REGEXP:-'^https://github\.com/CG-Labs/superbot/\.github/workflows/offline\.yml@refs/(heads/main|tags/v[0-9A-Za-z.+-]+)$'}
OFFLINE_SIGNER_ISSUER=${OFFLINE_SIGNER_ISSUER:-https://token.actions.githubusercontent.com}
# --tls-cert/--tls-key: the operator's certificate for --domain; Caddy then never asks a CA for one.
TLS_CERT=""
TLS_KEY=""
TLS_DIR=${TLS_DIR:-/etc/caddy/superbot-tls}
# Hermes Agent release --with-hermes installs: the commit of tag v0.23.3 (NousResearch/hermes-agent),
# as server/src/adapters/install.rs pins it. Change it with deploy/hermes-pin.sh bump.
HERMES_COMMIT=${HERMES_COMMIT:-caafe5389ae585ef77387a962aee05b1bcf17029}
# --hermes-bundle: Hermes Agent for --offline --with-hermes, already installed for /opt/hermes
# on a connected machine by deploy/offline-bundle.sh hermes
# (docs/adr/0200-hermes-agent-bundle-for-air-gapped-installs.md).
HERMES_BUNDLE=""
HERMES_BUNDLE_SHA256=""
# Set by prepare_hermes_bundle: the checked bundle's root, inside HERMES_STAGE (beside
# HERMES_SHARED_DIR, so the new tree moves into place in one rename).
HERMES_STAGE=""
HERMES_BUNDLE_DIR=""
# The tree install_hermes_shared moved aside, put back if the new one fails.
HERMES_PREVIOUS=""
# --harness-bundle: Claude Code, Codex and Pi with their own Node.js, at the release's pins, for
# --offline, already installed for HARNESSES_DIR on a connected machine by
# deploy/offline-bundle.sh harnesses (docs/adr/0232-harness-cli-bundle-for-air-gapped-servers.md).
HARNESS_BUNDLE=""
HARNESS_BUNDLE_SHA256=""
HARNESSES_DIR=/opt/superbot-harnesses
# Set by prepare_harness_bundle, as for Hermes: the checked bundle's root inside HARNESS_STAGE,
# and the MANIFEST lines this release's botd pins (harness_manifest_lines).
HARNESS_STAGE=""
HARNESS_BUNDLE_DIR=""
HARNESS_WANTED=""
# The tree install_harnesses moved aside, whether the new one is in HARNESSES_DIR, and the links
# it made where there were none: all undone if the new tree fails.
HARNESS_PREVIOUS=""
HARNESS_MOVED_IN=false
HARNESS_LINKED=()
# --machine-hermes-bundle/--machine-harness-bundle: MACHINE_HERMES_BUNDLE and
# MACHINE_HARNESS_BUNDLE for .env on an --offline --upgrade, checked with the rest of machines'
# settings by the bundle's botd before anything changes
# (docs/adr/0294-offline-upgrades-checked-against-machines-settings.md).
MACHINE_HERMES_BUNDLE_VALUE=""
MACHINE_HARNESS_BUNDLE_VALUE=""
# An offline upgrade to a newer release first backs up DATA_DIR and .env with the release that
# is running, into ROLLBACK_DIR (root only); --rollback puts that release back from them
# (docs/adr/0300-offline-upgrades-keep-a-way-back.md). --no-upgrade-backup skips the backup.
ROLLBACK=false
NO_UPGRADE_BACKUP=false
ROLLBACK_DIR=${ROLLBACK_DIR:-}
# Set by prepare_offline: the release this host runs, and whether this run restores ROLLBACK_DIR.
OFFLINE_INSTALLED=""
ROLLBACK_RESTORE=false
# Set by offline_license_check (docs/adr/0305-the-license-through-offline-upgrades.md): the key
# the bundle's botd judged and what it is, and on a rollback the license installed now, kept.
LICENSE_JUDGED=""
LICENSE_WHAT=""
LICENSE_ENV=""
ROLLBACK_LICENSE=""
ROLLBACK_LICENSE_DEST=""
ROLLBACK_LICENSE_WHAT=""
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
# Hermes writes some files every run reads as 0600 (its install's facts.json, its checkout's
# stamps), so other accounts must be given them. Only the parts runs use: not the install's
# own data root (its .env, sessions and memories).
HERMES_SHARED_READABLE=(.hermes/hermes-agent .hermes/installs .hermes/tools .local/share/uv)
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
  --backup-s3-endpoint URL, --backup-s3-bucket NAME
                      Copy server backups off this host to S3-compatible storage (ADR 0109).
                      Give the keys in the environment, not as flags:
                      SERVER_BACKUP_S3_ACCESS_KEY_ID=... SERVER_BACKUP_S3_SECRET_ACCESS_KEY=...
                      Without a store, backups stay on this host and the installer says so
  --backup-s3-region NAME, --backup-s3-prefix PREFIX
                      The store's region (default us-east-1; auto for R2) and key prefix
                      (default superbot/)
  --backup-age-recipients KEYS
                      Encrypt backup archives to these age public keys (comma-separated), on
                      this host and off it (SUPERBOT_BACKUP_AGE_RECIPIENTS). Without them a
                      new install makes an age key at BACKUP_IDENTITY_FILE (default
                      /root/superbot-backup-identity.txt, root only): copy it off the host
  --backup-age-generate
                      Make that key on an upgrade too, if .env has no recipients
  --backup-encryption auto|required|off
                      SUPERBOT_BACKUP_ENCRYPTION: warn about plain backups (auto, the default),
                      refuse to write or start with them (required), or keep them plain by
                      choice (off)
  --database-encryption auto|required|off
                      SUPERBOT_DATABASE_ENCRYPTION (ADR 0116): new databases encrypted, an
                      existing plain one kept plain with a warning (auto); encrypt a plain one
                      on the next start, keeping a plain copy (required, the default for new
                      installs); or keep the database plain by choice (off)
  --backup-off-host auto|on|off
                      SERVER_BACKUP_OFF_HOST: copy when a store is set (auto, the default),
                      refuse to start without one (on), or never copy (off)
  --with-hermes       Also install the Hermes Agent CLI (about 2.5 GB; HERMES_COMMIT pins it).
                      With --offline, from --hermes-bundle
  --license-file PATH Install the license key CG-Labs sent. SuperBot has no free tier: without a
                      license, Bots don't run unless testing mode is on
  --testing-mode      Set TESTING_MODE=on: no license, billing off, for test servers only
  --isolation         Run each user's Bots as their own Unix account (ISOLATION=users; ADR 0037),
                      which can't read .env, the database or the master key. On by default for
                      new installs (ADR 0058); an upgrade keeps what it had. ISOLATION_DIR sets
                      where their folders go (default /srv/superbot/users)
  --no-isolation      Turn that off (accounts and their folders are kept)
  --no-client         Skip building the web client (served at /app/)
  --offline BUNDLE    Install or upgrade (with --upgrade) from an offline bundle made by
                      deploy/offline-bundle.sh, with no network: no apt, git, curl, cargo, npm
                      or certificate authority. Needs the system packages already installed
                      (docs/ops/air-gapped.md), and --tls-cert/--tls-key with --domain
  --bundle-sha256 HEX The bundle's SHA-256, from where it was published (else BUNDLE.sha256)
  --hermes-bundle FILE
                      With --offline --with-hermes: install Hermes Agent from this Hermes bundle
                      (deploy/offline-bundle.sh hermes), checked like the bundle
  --hermes-bundle-sha256 HEX
                      The Hermes bundle's SHA-256, from where it was published (else FILE.sha256)
  --harness-bundle FILE
                      With --offline: install Claude Code, Codex and Pi, with their own Node.js,
                      from this harness bundle (deploy/offline-bundle.sh harnesses) into
                      /opt/superbot-harnesses, checked like the bundle and against its pins
  --harness-bundle-sha256 HEX
                      The harness bundle's SHA-256, from where it was published (else FILE.sha256)
  --machine-hermes-bundle LIST, --machine-harness-bundle LIST
                      With --offline --upgrade: set MACHINE_HERMES_BUNDLE and MACHINE_HARNESS_BUNDLE
                      in .env (as there: FILE or FILE=SHA-256, comma-separated, one per arch), the
                      bundles users' machines take from botd. Before anything changes, the bundle's
                      botd checks its settings with them (botd settings check)
  --rollback          With --offline <older bundle> --upgrade: go back to the release this host
                      ran before its last offline upgrade, putting back the database and .env
                      that upgrade backed up. Everything since that upgrade is lost
  --no-upgrade-backup With --offline --upgrade: don't back up DATA_DIR and .env first, so
                      --rollback can't go back to the release running now
  --tls-cert PATH, --tls-key PATH
                      Serve --domain with this certificate (PEM, full chain) and key instead of
                      getting one from Let's Encrypt
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
      --backup-s3-endpoint) BACKUP_S3_ENDPOINT=$2; shift 2 ;;
      --backup-s3-bucket) BACKUP_S3_BUCKET=$2; shift 2 ;;
      --backup-s3-region) BACKUP_S3_REGION=$2; shift 2 ;;
      --backup-s3-prefix) BACKUP_S3_PREFIX=$2; shift 2 ;;
      --backup-age-recipients) BACKUP_AGE_RECIPIENTS=$2; shift 2 ;;
      --backup-off-host) BACKUP_OFF_HOST=$2; shift 2 ;;
      --backup-age-generate) BACKUP_AGE_GENERATE=true; shift ;;
      --backup-encryption) BACKUP_ENCRYPTION=$2; shift 2 ;;
      --database-encryption) DATABASE_ENCRYPTION=$2; shift 2 ;;
      --with-hermes) WITH_HERMES=true; shift ;;
      --license-file) LICENSE_FILE=$2; shift 2 ;;
      --testing-mode) TESTING_MODE_ON=true; shift ;;
      --isolation) ISOLATION_MODE=users; shift ;;
      --no-isolation) ISOLATION_MODE=off; shift ;;
      --no-client) BUILD_CLIENT=false; shift ;;
      --offline) OFFLINE_BUNDLE=$2; shift 2 ;;
      --bundle-sha256) OFFLINE_BUNDLE_SHA256=$2; shift 2 ;;
      --hermes-bundle) HERMES_BUNDLE=$2; shift 2 ;;
      --hermes-bundle-sha256) HERMES_BUNDLE_SHA256=$2; shift 2 ;;
      --harness-bundle) HARNESS_BUNDLE=$2; shift 2 ;;
      --machine-hermes-bundle) MACHINE_HERMES_BUNDLE_VALUE=$2; shift 2 ;;
      --machine-harness-bundle) MACHINE_HARNESS_BUNDLE_VALUE=$2; shift 2 ;;
      --harness-bundle-sha256) HARNESS_BUNDLE_SHA256=$2; shift 2 ;;
      --rollback) ROLLBACK=true; shift ;;
      --no-upgrade-backup) NO_UPGRADE_BACKUP=true; shift ;;
      --tls-cert) TLS_CERT=$2; shift 2 ;;
      --tls-key) TLS_KEY=$2; shift 2 ;;
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
  if [[ -n "$OFFLINE_BUNDLE" ]]; then
    if [[ "$DRY_RUN" == true ]]; then
      log "[dry-run] would copy deploy templates from the bundle to $dest"
      return
    fi
    install_trusted_files "$OFFLINE_DIR/deploy" "$dest"
    log "Staged deploy templates from the bundle to $dest"
    return
  fi
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

# rsync arguments that keep the install's runtime state out of a --source-dir sync, so it's
# neither overwritten from the checkout nor removed by --delete: .env, data, the workspace,
# backups, and every *_DIR or *_FILE that .env (read as botd reads it, from the install
# folder) points inside the install folder, with botd's default BACKUP_DIR beside DATA_DIR.
# A path is kept as configured (and through any link on the way to it) and as resolved.
state_excludes() {
  local root env_file=$1/.env line key value abs rel part prefix data_dir="" backup_dir="" lexical resolved
  local -a fixed=(.env '.env.*' data workspace backups logs secrets backup-identity.txt license.key \
    metrics-token tiers.json '*.sqlite' '*.sqlite-*') named=()
  root=$(realpath -m -s -- "$1")
  resolved=$(realpath -m -- "$1")
  printf '%s\n' --include=/.env.example
  for rel in "${fixed[@]}"; do printf -- '--exclude=/%s\n' "$rel"; done
  [[ -f "$env_file" ]] || return 0
  while IFS= read -r line; do
    key=${line%%=*}
    value=$(sed 's/^[[:space:]]*//; s/[[:space:]]*$//' <<<"${line#*=}")
    [[ "$value" =~ ^\"(.*)\"$ || "$value" =~ ^\'(.*)\'$ ]] && value=${BASH_REMATCH[1]}
    [[ -n "$value" ]] || continue
    case $key in
      DATA_DIR) data_dir=$value ;;
      BACKUP_DIR) backup_dir=$value ;;
    esac
    named+=("$value")
  done < <(grep -E '^[A-Z0-9_]+_(DIR|FILE)=' "$env_file" || true)
  [[ -n "$backup_dir" ]] || named+=("$(dirname -- "${data_dir:-./data}")/backups")
  for value in "${named[@]}"; do
    [[ "$value" == /* ]] && abs=$value || abs=$root/$value
    lexical=$(realpath -m -s -- "$abs")
    abs=$(realpath -m -- "$abs")
    if [[ "$lexical" == "$root" || "$abs" == "$resolved" ]]; then
      die "$env_file points a setting at $root itself, which --source-dir syncs over. Keep runtime state in a folder of its own."
    fi
    case $lexical in
      "$root"/*)
        rel=${lexical#"$root"/} prefix=""
        while IFS= read -r -d / part; do
          prefix+=$part
          [[ ! -L "$root/$prefix" ]] || rsync_exclude "$prefix"
          prefix+=/
        done <<<"$rel/"
        rsync_exclude "$rel"
        ;;
    esac
    case $abs in
      "$resolved"/*) rsync_exclude "${abs#"$resolved"/}" ;;
    esac
  done
}

# An anchored rsync exclude for one literal path under the synced folder.
rsync_exclude() {
  local rel=$1
  rel=${rel//\\/\\\\} rel=${rel//\*/\\*} rel=${rel//\?/\\?} rel=${rel//\[/\\[}
  printf -- '--exclude=/%s\n' "$rel"
}

# shellcheck disable=SC2016
sync_repo() {
  local home repo_path
  home=$(user_home)
  repo_path="$home/superbot"
  if [[ -n "$OFFLINE_BUNDLE" ]]; then
    # No source on the host: the service user's folder holds .env, data and the workspace.
    log "Preparing $repo_path from the bundle"
    if [[ "$DRY_RUN" == true ]]; then
      return
    fi
    sudo -u "$SUPERBOT_USER" -H sh -c 'mkdir -p "$1" && cp "$2" "$1/.env.example"' _ "$repo_path" "$OFFLINE_DIR/env.example"
    return
  fi
  if [[ -n "$INSTALL_DIR" ]]; then
    local keep_list
    local -a keep
    keep_list=$(state_excludes "$repo_path") || exit 1
    mapfile -t keep <<<"$keep_list"
    log "Syncing $INSTALL_DIR -> $repo_path, keeping its .env, data, workspace, backups and other runtime state"
    if [[ "$DRY_RUN" == true ]]; then
      return
    fi
    mkdir -p "$(dirname "$repo_path")"
    if [[ -d "$repo_path/.git" ]]; then
      rsync -a --delete --exclude target --exclude node_modules --exclude dist-app --exclude .git "${keep[@]}" "$INSTALL_DIR/" "$repo_path/"
    else
      rsync -a --exclude target --exclude node_modules --exclude dist-app "${keep[@]}" "$INSTALL_DIR/" "$repo_path/"
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
  if [[ -n "$OFFLINE_BUNDLE" ]]; then
    local b
    log "Installing the bundle's binaries into $BIN_DIR"
    for b in "${OFFLINE_BINARIES[@]}"; do
      run install -m 0755 -o root -g root "$OFFLINE_DIR/bin/$b" "$BIN_DIR/$b"
    done
    return
  fi
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
  if [[ -n "$OFFLINE_BUNDLE" ]]; then
    if [[ "$DRY_RUN" == true ]]; then
      log "[dry-run] would install the bundle's web client into root-owned $CLIENT_DIR"
      return
    fi
    install_client "$OFFLINE_DIR/client" || client_not_installed "Web client not installed"
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
  [[ -z "$OFFLINE_BUNDLE" ]] || src="$OFFLINE_DIR/site"
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

unset_env_var() {
  local file=$1 key=$2 tmp
  grep -q "^${key}=" "$file" || return 0
  tmp=$(mktemp)
  K=$key awk 'index($0, ENVIRON["K"] "=") != 1' "$file" >"$tmp" && cat "$tmp" >"$file"
  local rc=$?
  rm -f "$tmp"
  return "$rc"
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
    if [[ -n "$DATABASE_ENCRYPTION" ]] || [[ ! -f "$env_file" ]]; then
      log "[dry-run] would set SUPERBOT_DATABASE_ENCRYPTION=${DATABASE_ENCRYPTION:-required}"
    fi
    if [[ -z "$BACKUP_AGE_RECIPIENTS" && "$BACKUP_ENCRYPTION" != off ]] && { [[ ! -f "$env_file" ]] || [[ "$BACKUP_AGE_GENERATE" == true ]]; }; then
      log "[dry-run] would make a backup age key at $BACKUP_IDENTITY_FILE (root, 0600) and set SUPERBOT_BACKUP_AGE_RECIPIENTS, unless $env_file has recipients"
    fi
    configure_machine_bundles "$env_file"
    return
  fi

  [[ ! -L "$env_file" ]] || die "Refusing symlinked $env_file"
  [[ ! -L "$pass_file" ]] || die "Refusing symlinked $pass_file"
  local fresh=false
  if [[ ! -f "$env_file" ]]; then
    fresh=true
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

  configure_backup_target "$env_file"
  configure_backup_encryption "$env_file" "$fresh"
  configure_database_encryption "$env_file" "$fresh"
  configure_machine_bundles "$env_file"

  chown "$SUPERBOT_USER:$SUPERBOT_USER" "$env_file"
  chmod 0600 "$env_file"
}

# The off-host backup flags' shapes, checked before the long build. botd checks the rest
# when it starts and refuses to start on settings that can't work.
check_backup_target() {
  if [[ -n "$BACKUP_S3_ENDPOINT$BACKUP_S3_REGION$BACKUP_S3_PREFIX" && -z "$BACKUP_S3_BUCKET" ]]; then
    die "--backup-s3-endpoint, --backup-s3-region and --backup-s3-prefix need --backup-s3-bucket"
  fi
  if [[ -n "$BACKUP_S3_BUCKET" ]]; then
    [[ -n "$BACKUP_S3_ENDPOINT" ]] || die "--backup-s3-bucket needs --backup-s3-endpoint (https://...)"
    [[ "$BACKUP_S3_BUCKET" =~ ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$ ]] || die "--backup-s3-bucket: \"$BACKUP_S3_BUCKET\" isn't a bucket name"
  fi
  case $BACKUP_S3_ENDPOINT in
    "" | https://* | http://127.0.0.1* | http://localhost*) ;;
    *) die "--backup-s3-endpoint must be https://host[:port]" ;;
  esac
  [[ -z "$BACKUP_S3_REGION" || "$BACKUP_S3_REGION" =~ ^[A-Za-z0-9_-]+$ ]] || die "--backup-s3-region must be a region name, e.g. us-east-1"
  [[ -z "$BACKUP_S3_PREFIX" || "$BACKUP_S3_PREFIX" =~ ^[A-Za-z0-9._/-]+$ ]] || die "--backup-s3-prefix: letters, digits, dots, dashes, underscores and slashes"
  case $BACKUP_OFF_HOST in
    "" | auto | on | off) ;;
    *) die "--backup-off-host must be auto, on or off" ;;
  esac
  local r
  for r in ${BACKUP_AGE_RECIPIENTS//,/ }; do
    [[ "$r" == age1* ]] || die "--backup-age-recipients: \"$r\" isn't an age public key (age1...)"
  done
  case $BACKUP_ENCRYPTION in
    "" | auto | required | off) ;;
    *) die "--backup-encryption must be auto, required or off" ;;
  esac
  if [[ "$BACKUP_AGE_GENERATE" == true ]]; then
    [[ -z "$BACKUP_AGE_RECIPIENTS" ]] || die "give --backup-age-recipients or --backup-age-generate, not both"
    [[ "$BACKUP_ENCRYPTION" != off ]] || die "--backup-age-generate makes a key that --backup-encryption off would not use"
  fi
  [[ "$BACKUP_IDENTITY_FILE" == /* ]] || die "BACKUP_IDENTITY_FILE must be an absolute path, not $BACKUP_IDENTITY_FILE"
  case $DATABASE_ENCRYPTION in
    "" | auto | required | off) ;;
    *) die "--database-encryption must be auto, required or off" ;;
  esac
}

# Writes the off-host backup settings given into .env; nothing given, nothing changes, so
# an upgrade keeps what the server had (docs/adr/0109-server-backups-off-the-host.md).
configure_backup_target() {
  local env_file=$1 key
  if [[ -n "$BACKUP_S3_BUCKET" ]]; then
    for key in SERVER_BACKUP_S3_ACCESS_KEY_ID SERVER_BACKUP_S3_SECRET_ACCESS_KEY; do
      if [[ -z "${!key:-}" ]] && ! grep -q "^${key}=." "$env_file" && ! grep -q "^${key}_FILE=." "$env_file"; then
        die "--backup-s3-bucket needs $key: run the installer with $key=... in its environment"
      fi
    done
    set_env_var "$env_file" SERVER_BACKUP_S3_ENDPOINT "$BACKUP_S3_ENDPOINT"
    set_env_var "$env_file" SERVER_BACKUP_S3_BUCKET "$BACKUP_S3_BUCKET"
    [[ -z "$BACKUP_S3_REGION" ]] || set_env_var "$env_file" SERVER_BACKUP_S3_REGION "$BACKUP_S3_REGION"
    [[ -z "$BACKUP_S3_PREFIX" ]] || set_env_var "$env_file" SERVER_BACKUP_S3_PREFIX "$BACKUP_S3_PREFIX"
  fi
  # botd refuses a key set both ways, so a key given now replaces its _FILE too.
  for key in SERVER_BACKUP_S3_ACCESS_KEY_ID SERVER_BACKUP_S3_SECRET_ACCESS_KEY; do
    [[ -z "${!key:-}" ]] || { set_env_var "$env_file" "$key" "${!key}" && unset_env_var "$env_file" "${key}_FILE"; }
  done
  [[ -z "$BACKUP_AGE_RECIPIENTS" ]] || set_env_var "$env_file" SUPERBOT_BACKUP_AGE_RECIPIENTS "$BACKUP_AGE_RECIPIENTS"
  [[ -z "$BACKUP_OFF_HOST" ]] || set_env_var "$env_file" SERVER_BACKUP_OFF_HOST "$BACKUP_OFF_HOST"
}

# KEY's last value in .env, without quotes.
env_value() {
  sed -n "s/^$2=//p" "$1" | tail -n 1 | tr -d "\"'"
}

backup_recipients_set() {
  [[ -n "$(env_value "$1" SUPERBOT_BACKUP_AGE_RECIPIENTS | tr -d '[:space:]')$(env_value "$1" SUPERBOT_BACKUP_AGE_RECIPIENTS_FILE | tr -d '[:space:]')" ]]
}

# Makes (or, if one is already there, reuses) the backup age identity at BACKUP_IDENTITY_FILE,
# private to whoever runs the installer (root), and sets BACKUP_PUBLIC to its public key.
# Returns 1 if age-keygen is missing or fails.
make_backup_identity() {
  local file=$BACKUP_IDENTITY_FILE
  BACKUP_PUBLIC=""
  [[ ! -L "$file" ]] || die "Refusing symlinked $file"
  command -v age-keygen >/dev/null 2>&1 || return 1
  if [[ ! -e "$file" ]]; then
    mkdir -p "$(dirname "$file")"
    (umask 077 && age-keygen -o "$file" 2>/dev/null) || { rm -f "$file"; return 1; }
    NEW_BACKUP_IDENTITY_FILE=$file
  fi
  chmod 0600 "$file"
  BACKUP_PUBLIC=$(age-keygen -y "$file" 2>/dev/null) || return 1
  [[ "$BACKUP_PUBLIC" == age1* ]]
}

# Backup encryption (docs/adr/0114-backups-encrypted-by-default.md): --backup-encryption is
# written as given; a new .env (or --backup-age-generate) with no recipients gets an age key
# made here, unless backups are plain by choice. An upgrade with no flags changes nothing.
configure_backup_encryption() {
  local env_file=$1 fresh=$2 policy
  [[ -z "$BACKUP_ENCRYPTION" ]] || set_env_var "$env_file" SUPERBOT_BACKUP_ENCRYPTION "$BACKUP_ENCRYPTION"
  policy=$(env_value "$env_file" SUPERBOT_BACKUP_ENCRYPTION | tr '[:upper:]' '[:lower:]')
  backup_recipients_set "$env_file" && return 0
  [[ "$policy" != off ]] || return 0
  if [[ "$fresh" == true || "$BACKUP_AGE_GENERATE" == true ]]; then
    if make_backup_identity; then
      set_env_var "$env_file" SUPERBOT_BACKUP_AGE_RECIPIENTS "$BACKUP_PUBLIC"
      log "Backups: encrypted to the age key in $BACKUP_IDENTITY_FILE"
      return 0
    fi
    warn "Could not make a backup age key (is age installed?): backups stay plain until SUPERBOT_BACKUP_AGE_RECIPIENTS is set"
  fi
  [[ "$policy" != required ]] ||
    die "SUPERBOT_BACKUP_ENCRYPTION=required, but $env_file has no SUPERBOT_BACKUP_AGE_RECIPIENTS: re-run with --backup-age-generate or --backup-age-recipients age1..."
}

# Database encryption (docs/adr/0116-database-encrypted-at-rest.md): --database-encryption is
# written as given, and a new .env gets required. An upgrade with no flag changes nothing.
# botd does the encrypting when it starts, keeping a plain copy of a database it encrypts.
configure_database_encryption() {
  local env_file=$1 fresh=$2 policy=$DATABASE_ENCRYPTION
  [[ -n "$policy" || "$fresh" != true ]] || policy=required
  [[ -n "$policy" ]] || return 0
  set_env_var "$env_file" SUPERBOT_DATABASE_ENCRYPTION "$policy"
  if [[ "$policy" == required ]] && plain_database "$(env_value "$env_file" DATA_DIR)/app.sqlite"; then
    log "Database: botd encrypts it when it starts, keeping a plain copy beside it until you delete it (docs/ops/database-encryption.md)"
  fi
}

# --machine-hermes-bundle and --machine-harness-bundle, as offline_settings_start_check checked them.
configure_machine_bundles() {
  local env_file=$1 key value
  for key in MACHINE_HERMES_BUNDLE MACHINE_HARNESS_BUNDLE; do
    value=${key}_VALUE
    value=${!value}
    [[ -n "$value" ]] || continue
    if [[ "$DRY_RUN" == true ]]; then
      log "[dry-run] would set $key=$value in $env_file"
    else
      set_env_var "$env_file" "$key" "$value"
      log "Machines: $key=$value in $env_file"
    fi
  done
}

# True if DB is an ordinary SQLite file: not encrypted (ADR 0116).
plain_database() {
  [[ -s "$1" && "$(head -c 15 "$1" | tr -d '\0')" == "SQLite format 3" ]]
}

# Whether the database is encrypted at rest, from .env and the file itself.
database_encryption_state() {
  local env_file=$1 db policy
  [[ -r "$env_file" ]] || { echo "unknown"; return; }
  db="$(env_value "$env_file" DATA_DIR)/app.sqlite"
  policy=$(env_value "$env_file" SUPERBOT_DATABASE_ENCRYPTION | tr '[:upper:]' '[:lower:]')
  if [[ -s "$db" ]] && ! plain_database "$db"; then
    echo "encrypted (SQLCipher, key derived from the master key)"
  elif [[ "$policy" == off ]]; then
    echo "plain by choice (SUPERBOT_DATABASE_ENCRYPTION=off)"
  elif [[ "$policy" == required ]]; then
    echo "encrypted when botd starts (SUPERBOT_DATABASE_ENCRYPTION=required)"
  elif [[ -s "$db" ]]; then
    echo "plain (SUPERBOT_DATABASE_ENCRYPTION=${policy:-auto})"
  else
    echo "encrypted when botd creates it"
  fi
}

# Whether server backups are encrypted, from .env.
backup_encryption_state() {
  local env_file=$1
  [[ -r "$env_file" ]] || { echo "unknown"; return; }
  if backup_recipients_set "$env_file"; then
    echo "age (SUPERBOT_BACKUP_AGE_RECIPIENTS)"
  elif [[ "$(env_value "$env_file" SUPERBOT_BACKUP_ENCRYPTION | tr '[:upper:]' '[:lower:]')" == off ]]; then
    echo "plain by choice (SUPERBOT_BACKUP_ENCRYPTION=off)"
  else
    echo "plain (no SUPERBOT_BACKUP_AGE_RECIPIENTS)"
  fi
}

# Where server backups go, from .env: "off-host", or why they stay on this host.
backup_destination() {
  local env_file=$1 mode
  [[ -r "$env_file" ]] || { echo "unknown"; return; }
  mode=$(sed -n 's/^SERVER_BACKUP_OFF_HOST=//p' "$env_file" | tail -n 1 | tr -d '"'"'"' ' | tr '[:upper:]' '[:lower:]')
  if [[ "$mode" == off ]]; then
    echo "on this host only (SERVER_BACKUP_OFF_HOST=off)"
  elif grep -q '^SERVER_BACKUP_S3_BUCKET=.' "$env_file"; then
    echo "off-host"
  elif grep -q '^MACHINE_BACKUP_S3_BUCKET=.' "$env_file"; then
    echo "off-host (machine backups' store)"
  else
    echo "on this host only (no store is set)"
  fi
}

master_key_default() { printf '%s/.config/superbot/master.key\n' "$1"; }

# True if botd already sealed values in this database (so only the old key opens them).
db_has_sealed_values() {
  local db=$1
  [[ -f "$db" ]] || return 1
  # An encrypted database opens only with its master key (ADR 0116).
  [[ ! -s "$db" ]] || plain_database "$db" || return 0
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

# The key in SRC, whitespace dropped, as DEST, written whole by the service user (DATA_DIR is
# theirs) so root never writes through a path they control.
# shellcheck disable=SC2016
write_license_key() {
  tr -d '[:space:]' <"$1" | sudo -u "$SUPERBOT_USER" env DEST="$2" sh -c '
    set -eu
    umask 077
    mkdir -p "$(dirname "$DEST")"
    tmp=$(mktemp "$DEST.XXXXXX")
    cat >"$tmp"
    printf "\n" >>"$tmp"
    mv -f "$tmp" "$DEST"'
}

# Saved where PUT /api/license saves it, DATA_DIR/license.key.
install_license() {
  [[ -n "$LICENSE_FILE" && -z "$ROLLBACK_LICENSE_DEST" ]] || return 0
  local home repo_path env_file dest
  home=$(user_home)
  repo_path="$home/superbot"
  env_file="$repo_path/.env"
  dest="$repo_path/data/license.key"
  if [[ "$DRY_RUN" == true ]]; then
    log "[dry-run] would install the license key from $LICENSE_FILE as $dest (0600, $SUPERBOT_USER)"
    return
  fi
  write_license_key "$LICENSE_FILE" "$dest"
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
# botd is stopped starts it again before the install gives up. The harness bundle's
# tree is swapped the same way.
BOTD_STOPPED=false

# What is about to change under botd's running Bots, as "Hermes Agent changes" (the default).
stop_botd_for_swap() {
  if systemctl is-active --quiet superbot.service 2>/dev/null; then
    log "Stopping superbot while ${1:-Hermes Agent changes}"
    systemctl stop superbot.service
    BOTD_STOPPED=true
  fi
}

hermes_failed() {
  hermes_put_back || true
  if [[ "$BOTD_STOPPED" == true ]]; then
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
  if [[ "$WITH_HERMES" != true ]]; then
    hermes_pin_notice
    return 0
  fi
  [[ "$HERMES_COMMIT" =~ ^[0-9a-f]{40}$ ]] || die "HERMES_COMMIT must be a full commit SHA"
  local home env_file bin_path url share wrapper cur installer ok
  home=$(user_home)
  env_file="$home/superbot/.env"
  bin_path="$home/.hermes/superbot:$home/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  url="https://raw.githubusercontent.com/NousResearch/hermes-agent/$HERMES_COMMIT/scripts/install.sh"
  share="$(trusted_deploy_dir)/hermes-share.sh"
  wrapper="$home/.hermes/superbot/hermes"
  # A Hermes bundle was installed for $HERMES_SHARED_DIR, so it goes there with or without
  # per-user accounts; botd finds it on PATH as /usr/local/bin/hermes.
  if [[ "$(isolation_mode)" == users || -n "$HERMES_BUNDLE" ]]; then
    install_hermes_shared "$url" "$share"
    if [[ -n "$HERMES_BUNDLE" && "$(isolation_mode)" != users ]]; then
      cur=$(env_value "$env_file" PATH 2>/dev/null || true)
      [[ ":$cur:" != *":$home/.hermes/superbot:"* ]] \
        || warn "$env_file puts $home/.hermes/superbot on PATH, so botd runs the Hermes Agent there, not the one in $HERMES_SHARED_DIR: remove it from PATH"
    fi
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
    stop_botd_for_swap
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
  local url=$1 share=$2 probe installer ok d wrapper="$HERMES_SHARED_DIR/.hermes/superbot/hermes" from=$1
  [[ -z "$HERMES_BUNDLE" ]] || from="the Hermes bundle $HERMES_BUNDLE"
  if [[ "$DRY_RUN" == true ]]; then
    log "[dry-run] would share its environment across Bots with $share"
    log "[dry-run] would install Hermes Agent $HERMES_COMMIT system-wide in $HERMES_SHARED_DIR from $from, linked from /usr/local/bin/hermes"
    return
  fi
  if [[ "$(hermes_installed "$HERMES_SHARED_DIR")" == "$HERMES_COMMIT" ]] && env HOME="$HERMES_SHARED_DIR" sh "$share" >/dev/null 2>&1; then
    log "Hermes Agent ${HERMES_COMMIT:0:12} is already installed in $HERMES_SHARED_DIR"
  elif [[ -n "$HERMES_BUNDLE" ]]; then
    install_hermes_from_bundle
  else
    apt-get install -y -qq libatomic1 xz-utils
    installer=$(fetch_hermes_installer "$url")
    stop_botd_for_swap
    log "Installing Hermes Agent ${HERMES_COMMIT:0:12} system-wide in $HERMES_SHARED_DIR (per-user accounts run it)"
    install -d -m 0755 -o root -g root "$HERMES_SHARED_DIR"
    ok=true
    env HOME="$HERMES_SHARED_DIR" SHELL=/bin/bash bash "$installer" --non-interactive --skip-browser --skip-computer-use \
      --commit "$HERMES_COMMIT" || ok=false
    rm -f "$installer"
    [[ "$ok" == true ]] || hermes_failed "Hermes Agent did not install"
  fi
  env HOME="$HERMES_SHARED_DIR" sh "$share" >/dev/null || hermes_failed "Couldn't share Hermes Agent's environment"
  chmod -R go-w "$HERMES_SHARED_DIR" || hermes_failed "Couldn't make Hermes Agent writable by root only"
  for d in "${HERMES_SHARED_READABLE[@]}"; do
    [[ ! -d "$HERMES_SHARED_DIR/$d" ]] || chmod -R a+rX "$HERMES_SHARED_DIR/$d" || hermes_failed "Couldn't make Hermes Agent readable by other accounts"
  done
  chmod go+rx "$HERMES_SHARED_DIR/.hermes" "$HERMES_SHARED_DIR/.hermes/superbot" || hermes_failed "Couldn't make Hermes Agent readable by other accounts"
  ln -sfn "$wrapper" /usr/local/bin/hermes || hermes_failed "Couldn't link /usr/local/bin/hermes"
  probe=$(mktemp -d)
  chmod 0777 "$probe"
  sudo -u nobody env HOME="$probe" HERMES_HOME="$probe/hermes" /usr/local/bin/hermes --version >/dev/null \
    || { rm -rf "$probe"; hermes_failed "Hermes Agent did not install for other accounts"; }
  rm -rf "$probe"
  if [[ -n "$HERMES_PREVIOUS" ]]; then
    rm -rf -- "$HERMES_PREVIOUS"
    HERMES_PREVIOUS=""
  fi
}

# The checked Hermes bundle's tree, unpacked beside $HERMES_SHARED_DIR, checked again as files,
# and moved into its place; the tree it replaces is kept until the new one runs for other
# accounts (hermes_put_back). Bots' own Hermes data is in their folders, never in it.
install_hermes_from_bundle() {
  local tree="$HERMES_STAGE/tree"
  log "Unpacking Hermes Agent ${HERMES_COMMIT:0:12} from $HERMES_BUNDLE"
  mkdir -m 0700 "$tree"
  tar -xf "$HERMES_BUNDLE_DIR/hermes.tar" -C "$tree" --no-same-owner || die "Couldn't unpack Hermes Agent from $HERMES_BUNDLE"
  rm -f -- "$HERMES_BUNDLE_DIR/hermes.tar"
  bundle_tree_ok "$tree/hermes" "$HERMES_SHARED_DIR" || die "Refusing $HERMES_BUNDLE: $BUNDLE_TREE_PROBLEM"
  [[ "$(hermes_installed "$tree/hermes")" == "$HERMES_COMMIT" ]] || die "Refusing $HERMES_BUNDLE: its checkout isn't Hermes Agent $HERMES_COMMIT"
  stop_botd_for_swap
  log "Installing Hermes Agent ${HERMES_COMMIT:0:12} system-wide in $HERMES_SHARED_DIR from the Hermes bundle"
  if [[ -e "$HERMES_SHARED_DIR" || -L "$HERMES_SHARED_DIR" ]]; then
    mv -- "$HERMES_SHARED_DIR" "$HERMES_STAGE/previous" || hermes_failed "Couldn't move the Hermes Agent in $HERMES_SHARED_DIR aside"
    HERMES_PREVIOUS="$HERMES_STAGE/previous"
  fi
  chown root:root "$tree/hermes" || hermes_failed "Couldn't make root own Hermes Agent's tree"
  chmod 0755 "$tree/hermes" || hermes_failed "Couldn't set the permissions of Hermes Agent's tree"
  mv -- "$tree/hermes" "$HERMES_SHARED_DIR" || hermes_failed "Couldn't move Hermes Agent into $HERMES_SHARED_DIR"
}

# The Hermes Agent install_hermes_from_bundle moved aside, back in $HERMES_SHARED_DIR. If that
# fails, HERMES_PREVIOUS stays set, so cleanup_offline keeps it for the operator.
hermes_put_back() {
  [[ -n "$HERMES_PREVIOUS" && -e "$HERMES_PREVIOUS" ]] || return 0
  warn "Putting back the Hermes Agent $HERMES_SHARED_DIR had"
  if rm -rf -- "$HERMES_SHARED_DIR" && mv -- "$HERMES_PREVIOUS" "$HERMES_SHARED_DIR"; then
    HERMES_PREVIOUS=""
  else
    warn "Couldn't put it back: it is in $HERMES_PREVIOUS; move it to $HERMES_SHARED_DIR by hand"
    return 1
  fi
}

# An upgrade without --with-hermes keeps the Hermes Agent it has; say so when this release
# pins another one, since botd's Hermes adapter expects the pinned one.
hermes_pin_notice() {
  local d c
  for d in "$HERMES_SHARED_DIR" "$(user_home 2>/dev/null || true)"; do
    [[ -n "$d" ]] || continue
    c=$(hermes_installed "$d")
    [[ -n "$c" && "$c" != "$HERMES_COMMIT" ]] || continue
    if [[ -n "$OFFLINE_BUNDLE" ]]; then
      warn "Hermes Agent ${c:0:12} is installed in $d, but this release pins ${HERMES_COMMIT:0:12}: re-run with --with-hermes --hermes-bundle <its Hermes bundle> (docs/ops/air-gapped.md#hermes-agent)"
    else
      warn "Hermes Agent ${c:0:12} is installed in $d, but this release pins ${HERMES_COMMIT:0:12}: re-run with --with-hermes"
    fi
  done
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
  [[ -n "$OFFLINE_BUNDLE" ]] || apt-get install -y -qq acl sudo
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

# Since ADR 0145, Bots on users' machines run as their own locked-down user unless .env says
# MACHINE_BOT_USER=off. An upgrade of a control plane that never set it says what will change.
machine_bot_user_notice() {
  local env_file="$1"
  [[ "$UPGRADE" == true && -f "$env_file" ]] || return 0
  [[ -n "$(env_value "$env_file" MACHINE_CONTROL_URL | tr -d '[:space:]')" ]] || return 0
  case "$(env_value "$env_file" MACHINE_BOT_USER | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')" in
    "")
      log "Machines: Bots now run as the unprivileged superbot-bots user by default (ADR 0145)."
      log "  Each idle agent switches after its next heartbeat; agents too old to switch hold runs"
      log "  (agent_outdated) until upgraded: botctl machine upgrade <user>. MACHINE_BOT_USER=off opts out."
      ;;
    off)
      warn "MACHINE_BOT_USER=off: Bots on users' machines run as root and can read the agent's key (ADR 0145)."
      ;;
  esac
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
# With TLS_DIR (an operator's certificate there), Caddy serves it and never asks a CA for one or
# staples OCSP, so it makes no outbound calls (docs/adr/0128-air-gapped-self-host.md).
render_caddyfile() {
  local site=$1 upstream=$2 client_root=${3:-} site_root=${4:-} tls_dir=${5:-}
  if [[ -n "$tls_dir" ]]; then
    printf '{\n\tauto_https disable_certs\n\tocsp_stapling off\n}\n\n'
  fi
  printf '%s {\n\tencode gzip\n' "$site"
  if [[ -n "$tls_dir" ]]; then
    printf '\ttls %s/cert.pem %s/key.pem\n' "$tls_dir" "$tls_dir"
  fi
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
    [[ -z "$TLS_CERT" ]] || log "[dry-run] would serve $DOMAIN with the certificate in $TLS_CERT (copied to $TLS_DIR), never asking a CA"
    return
  fi
  if ! command -v caddy >/dev/null 2>&1; then
    [[ -z "$OFFLINE_BUNDLE" ]] || die "Caddy isn't installed: install the caddy package from your internal mirror (docs/ops/air-gapped.md)"
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -qq
    apt-get install -y -qq caddy
  fi
  local tls_dir=""
  if [[ -n "$TLS_CERT" ]]; then
    install_tls_files
    tls_dir=$TLS_DIR
  fi
  render_caddyfile "$DOMAIN" 127.0.0.1:3000 "$client_root" "$site_root" "$tls_dir" >/etc/caddy/Caddyfile
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
  [[ -n "$OFFLINE_BUNDLE" ]] || apt-get install -y -qq ufw
  ufw allow 22/tcp
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw --force enable
}

summary() {
  local home repo_path pass_file url where app backups encryption database upgrade clis systemwide
  clis="npm install -g @anthropic-ai/claude-code  # if you use Claude Code"
  systemwide="(sudo npm install -g ...)"
  if [[ -f "$HARNESSES_DIR/superbot/MANIFEST" || -n "$HARNESS_BUNDLE" ]]; then
    clis="# Claude Code, Codex and Pi are in $HARNESSES_DIR, from the harness bundle"
    systemwide="(as the harness bundle does)"
  elif [[ -n "$OFFLINE_BUNDLE" ]]; then
    clis="# Offline: re-run with --harness-bundle <this release's harness bundle> (docs/ops/air-gapped.md#harness-clis-on-this-server)"
    systemwide="(with --harness-bundle)"
  fi
  upgrade="sudo bash -s -- --upgrade < <(curl -fsSL https://raw.githubusercontent.com/CG-Labs/superbot/main/deploy/install.sh)"
  [[ -z "$OFFLINE_BUNDLE" ]] || upgrade="sudo bash install.sh --offline <newer bundle> --upgrade${DOMAIN:+ --domain $DOMAIN --tls-cert ... --tls-key ...} (docs/ops/air-gapped.md)"
  home=$(user_home)
  repo_path="$home/superbot"
  pass_file="$home/.superbot-admin-password"
  backups=$(backup_destination "$repo_path/.env")
  encryption=$(backup_encryption_state "$repo_path/.env")
  database=$(database_encryption_state "$repo_path/.env")
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
  Key:      $(master_key_default "$home") encrypts the database and saved secrets. Back it
            up apart from the database: without it they can't be read (deploy/README.md).
  Database: $database (botctl database)
  License:  botctl license (no free tier: without a license, Bots run only with TESTING_MODE=on)
  Backups:  $backups (botctl backups)
  Encrypted: $encryption
  Logs:     journalctl -u superbot -f
  Upgrade:  $upgrade

Next steps (as the service user):
  sudo -iu $SUPERBOT_USER
  # Install harness CLIs if needed, then log in, e.g.:
  $clis
  claude login
  # or: codex login
  # Hermes Agent (--with-hermes): save its provider key with botctl secret set (docs/backend.md)

EOF
  if [[ "$(isolation_mode)" == users ]]; then
    cat <<EOF
Per-user accounts are on (ISOLATION=users, docs/adr/0058-harness-os-user-by-default.md):
  each user's Bots run as sb-u-<user id>, in $ISOLATION_DIR/<user id>, and can't read
  botd's .env, database or master key. Install harness CLIs system-wide
  $systemwide, not in ~/.local, so every account finds them. Then log
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
  if [[ "$backups" == "on this host only"* ]]; then
    warn "Server backups stay on this host, so losing the host loses them. Copy them off: re-run with --backup-s3-endpoint and --backup-s3-bucket (keys in SERVER_BACKUP_S3_ACCESS_KEY_ID and SERVER_BACKUP_S3_SECRET_ACCESS_KEY), or see docs/ops/backup-restore.md."
  fi
  if [[ "$encryption" == "plain (no"* ]]; then
    warn "Server backups aren't encrypted: anyone who gets a copy can read every chat. Re-run with --backup-age-generate (or --backup-age-recipients age1...), or --backup-encryption off to keep them plain by choice (docs/ops/backup-restore.md#encryption)."
  fi
  if [[ "$database" == "plain (SUPERBOT"* ]]; then
    warn "The database isn't encrypted: anyone who copies DATA_DIR can read every chat. Re-run with --database-encryption required (botd encrypts it on its next start and keeps a plain copy until you delete it), or --database-encryption off to keep it plain by choice (docs/ops/database-encryption.md)."
  fi
  local copies=()
  [[ ! -r "$repo_path/.env" ]] || mapfile -t copies < <(compgen -G "$(env_value "$repo_path/.env" DATA_DIR)/app.sqlite-plain-*" || true)
  if [[ ${#copies[@]} -gt 0 ]]; then
    warn "A plain copy of the database is still beside it: ${copies[*]}. Once botd runs well on the encrypted one, delete it (shred -u), as it holds every chat unencrypted (docs/ops/database-encryption.md#the-plain-copy)."
  fi
  if [[ -n "${NEW_BACKUP_IDENTITY_FILE:-}" ]]; then
    warn "New backup key at $NEW_BACKUP_IDENTITY_FILE: the only key that opens your encrypted backups. Copy it off this host now (a password manager or vault), then delete it here (shred -u $NEW_BACKUP_IDENTITY_FILE). Left here, it is lost with the host, and whoever takes the host can read the backups."
  elif [[ -f "$BACKUP_IDENTITY_FILE" ]]; then
    warn "The backup key is still on this host at $BACKUP_IDENTITY_FILE. Once you have a copy off the host, delete it here (shred -u $BACKUP_IDENTITY_FILE)."
  fi
  offline_settings_check "$home"
}

# Offline installs: what botd's settings would reach outside the network
# (docs/adr/0257-checking-settings-for-air-gapped-networks.md). botd reads only its .env, as its
# unit does, and opens no connection. Settings on the internet are warned about, not refused:
# the operator may still be connected, and changes them in .env.
offline_settings_check() {
  local home=$1 out rc=0 doc="docs/ops/air-gapped.md#checking-settings-before-going-offline"
  [[ -n "$OFFLINE_BUNDLE" ]] || return 0
  if [[ "$DRY_RUN" == true ]]; then
    log "[dry-run] would check botd's settings for anything on the internet: botd offline check --home $home"
    return 0
  fi
  [[ -x "$BIN_DIR/botd" ]] || return 0
  out=$(cd / && env -i PATH=/usr/bin:/bin "$BIN_DIR/botd" offline check --home "$home" 2>&1) || rc=$?
  case $rc in
    0)
      log "botd offline check: nothing botd's settings name is on the internet ($doc)"
      if grep -qE '^  check ' <<<"$out"; then
        log "Check these, which botd can't place from their names:"
        grep -E '^  check ' <<<"$out"
      fi
      ;;
    1)
      warn "botd offline check: some of botd's settings reach the internet, which an air-gapped network can't. Change them in $home/superbot/.env and restart botd ($doc):"
      grep -E '^  (internet|check) ' <<<"$out" >&2 || printf '%s\n' "$out" >&2
      warn "Run it again with: sudo -u $SUPERBOT_USER botd offline check --home $home [--internal <your DNS suffix>]"
      ;;
    *) warn "botd offline check didn't run (status $rc): $out" ;;
  esac
}

# What configure_env writes into ENV_FILE on this run, as `--set` for botd settings check, so the
# bundle's botd judges the .env the install leaves (docs/adr/0310-offline-upgrades-checked-against-every-setting.md).
# A password or age key made later, and S3 keys from the installer's environment, are stand-ins:
# botd only checks they're there, and the keys never reach a command line.
next_env_settings() {
  local env_file=$1 home=$2 key policy
  NEXT_ENV_SETTINGS=(--set HOST=127.0.0.1 --set PORT=3000 --set "DATA_DIR=$home/superbot/data" --set "WORKSPACE_DIR=$home/superbot/workspace")
  [[ "$TESTING_MODE_ON" != true ]] || NEXT_ENV_SETTINGS+=(--set TESTING_MODE=on)
  [[ -z "$DOMAIN" ]] || NEXT_ENV_SETTINGS+=(--set "ALLOWED_HOSTS=$DOMAIN" --set "CORS_ORIGINS=https://${DOMAIN}")
  if ! grep -q '^AUTH_PASSWORD=.' "$env_file" && ! grep -q '^AUTH_PASSWORD_FILE=.' "$env_file"; then
    NEXT_ENV_SETTINGS+=(--set AUTH_PASSWORD=made-by-the-installer)
  fi
  if [[ -n "$BACKUP_S3_BUCKET" ]]; then
    NEXT_ENV_SETTINGS+=(--set "SERVER_BACKUP_S3_ENDPOINT=$BACKUP_S3_ENDPOINT" --set "SERVER_BACKUP_S3_BUCKET=$BACKUP_S3_BUCKET")
    [[ -z "$BACKUP_S3_REGION" ]] || NEXT_ENV_SETTINGS+=(--set "SERVER_BACKUP_S3_REGION=$BACKUP_S3_REGION")
    [[ -z "$BACKUP_S3_PREFIX" ]] || NEXT_ENV_SETTINGS+=(--set "SERVER_BACKUP_S3_PREFIX=$BACKUP_S3_PREFIX")
  fi
  for key in SERVER_BACKUP_S3_ACCESS_KEY_ID SERVER_BACKUP_S3_SECRET_ACCESS_KEY; do
    [[ -z "${!key:-}" ]] || NEXT_ENV_SETTINGS+=(--set "$key=given-to-the-installer" --set "${key}_FILE=")
  done
  [[ -z "$BACKUP_AGE_RECIPIENTS" ]] || NEXT_ENV_SETTINGS+=(--set "SUPERBOT_BACKUP_AGE_RECIPIENTS=$BACKUP_AGE_RECIPIENTS")
  [[ -z "$BACKUP_OFF_HOST" ]] || NEXT_ENV_SETTINGS+=(--set "SERVER_BACKUP_OFF_HOST=$BACKUP_OFF_HOST")
  [[ -z "$BACKUP_ENCRYPTION" ]] || NEXT_ENV_SETTINGS+=(--set "SUPERBOT_BACKUP_ENCRYPTION=$BACKUP_ENCRYPTION")
  policy=${BACKUP_ENCRYPTION:-$(env_value "$env_file" SUPERBOT_BACKUP_ENCRYPTION | tr '[:upper:]' '[:lower:]')}
  if [[ "$BACKUP_AGE_GENERATE" == true && -z "$BACKUP_AGE_RECIPIENTS" && "$policy" != off ]] && ! backup_recipients_set "$env_file"; then
    NEXT_ENV_SETTINGS+=(--set SUPERBOT_BACKUP_AGE_RECIPIENTS=made-by-the-installer)
  fi
  [[ -z "$DATABASE_ENCRYPTION" ]] || NEXT_ENV_SETTINGS+=(--set "SUPERBOT_DATABASE_ENCRYPTION=$DATABASE_ENCRYPTION")
  [[ "$ISOLATION_MODE" != off ]] || NEXT_ENV_SETTINGS+=(--set ISOLATION=off)
  [[ -z "$MACHINE_HERMES_BUNDLE_VALUE" ]] || NEXT_ENV_SETTINGS+=(--set "MACHINE_HERMES_BUNDLE=$MACHINE_HERMES_BUNDLE_VALUE")
  [[ -z "$MACHINE_HARNESS_BUNDLE_VALUE" ]] || NEXT_ENV_SETTINGS+=(--set "MACHINE_HARNESS_BUNDLE=$MACHINE_HARNESS_BUNDLE_VALUE")
}

# Offline installs over an existing .env: whether the bundle's botd would start with it, before
# anything changes. A release can tighten a setting it used to take, or move the pins machines
# install, and botd won't start while .env names something it refuses
# (docs/adr/0310-offline-upgrades-checked-against-every-setting.md). `botd settings check` judges
# every setting botd refuses at start before it opens the database, over what this run writes;
# a bundle's botd from before it (a rollback to an older release) judges machines' alone, with
# --machine-*-bundle over them (docs/adr/0294-offline-upgrades-checked-against-machines-settings.md).
# It runs as botd's user, who must read the bundles, with only the .env, as the unit runs botd.
# An older botd would take the subcommand for a start and run as the server, so each check runs
# only with a botd that has it.
offline_settings_start_check() {
  [[ -n "$OFFLINE_BUNDLE" ]] || return 0
  local home env_file out rc=0 doc="docs/ops/air-gapped.md#upgrading" args=() why what=settings said refused
  id "$SUPERBOT_USER" &>/dev/null || return 0
  home=$(user_home)
  env_file="$home/superbot/.env"
  [[ -f "$env_file" ]] || return 0
  [[ "$ROLLBACK_RESTORE" != true ]] || env_file="$(rollback_dir)/$(manifest_value "$(rollback_dir)/record" env)"
  if grep -qaF "Usage: botd settings check" "$OFFLINE_DIR/bin/botd"; then
    next_env_settings "$env_file" "$home"
    args=("${NEXT_ENV_SETTINGS[@]}")
  elif grep -qaF "Usage: botd machines check" "$OFFLINE_DIR/bin/botd"; then
    what=machines
    [[ -z "$MACHINE_HERMES_BUNDLE_VALUE" ]] || args+=(--set "MACHINE_HERMES_BUNDLE=$MACHINE_HERMES_BUNDLE_VALUE")
    [[ -z "$MACHINE_HARNESS_BUNDLE_VALUE" ]] || args+=(--set "MACHINE_HARNESS_BUNDLE=$MACHINE_HARNESS_BUNDLE_VALUE")
    [[ "$ROLLBACK_RESTORE" != true ]] || args=()
  else
    warn "The bundle's botd ($OFFLINE_VERSION) can't check machines' settings (botd machines check), so they weren't checked before the upgrade"
    return 0
  fi
  if [[ "$ROLLBACK_RESTORE" == true ]]; then
    # A rollback puts back the .env from before the upgrade, which root alone reads. botd's user
    # gets a copy of its own, as it owns the live .env: a pipe root made can't be reopened as
    # /dev/stdin by another user. botd runs in the folder the unit runs it in.
    doc="docs/ops/air-gapped.md#going-back"
    local copy
    copy=$(cat -- "$env_file" | (cd / && sudo -u "$SUPERBOT_USER" sh -c 'f=$(mktemp) && cat >"$f" && echo "$f"')) \
      || die "Couldn't hand $SUPERBOT_USER the .env from before the upgrade to check. Nothing has changed."
    out=$(cd "$home/superbot" && sudo -u "$SUPERBOT_USER" env -i PATH=/usr/bin:/bin HOME="$home" "$OFFLINE_DIR/bin/botd" "$what" check --env-file "$copy" "${args[@]}" 2>&1) || rc=$?
    rm -f -- "$copy"
  else
    out=$(cd / && sudo -u "$SUPERBOT_USER" env -i PATH=/usr/bin:/bin HOME="$home" "$OFFLINE_DIR/bin/botd" "$what" check --home "$home" "${args[@]}" 2>&1) || rc=$?
  fi
  said="Machines' settings: the bundle's botd would start with them (botd machines check)"
  [[ "$what" == machines ]] || said="Settings: the bundle's botd would start with them (botd settings check)"
  case $rc in
    0)
      log "$said"
      grep -E '^(Machines:|Machine upkeep:|Machines would|x86_64 |aarch64 )' <<<"$out" | sed 's/^/    /' || true
      ;;
    1)
      refused=$(sed -n "s/^botd wouldn't start with these settings: //p" <<<"$out")
      # Per-user accounts this run turns on are made after the check: their folder and helpers.
      if [[ "$what" == settings && "$(isolation_mode)" == users ]] && ! root_only "$SUDOERS_FILE"; then
        refused=$(grep -v '^Isolation: ' <<<"$refused" || true)
        if [[ -z "$refused" ]]; then
          log "$said, once this run has set up per-user accounts"
          return 0
        fi
      fi
      [[ -n "$refused" ]] || refused=$out
      why="The bundle's botd ($OFFLINE_VERSION) wouldn't start with $env_file: $(head -n 1 <<<"$refused")"
      if [[ "$DRY_RUN" == true ]]; then
        warn "[dry-run] would stop here: $why"
        tail -n +2 <<<"$refused" | sed 's/^/    and: /' >&2
        return 0
      fi
      warn "$why"
      tail -n +2 <<<"$refused" | sed 's/^/    and: /' >&2
      [[ "$ROLLBACK_RESTORE" != true ]] \
        || die "Nothing has changed. The .env from before the upgrade names something $OFFLINE_VERSION's botd can't use now, such as machines' bundles since removed: put back what it names, then run the rollback again ($doc)"
      die "Nothing has changed. If it names MACHINE_HERMES_BUNDLE or MACHINE_HARNESS_BUNDLE, carry in this release's Hermes or harness bundles for your machines' arches, put them on this server where $SUPERBOT_USER can read them, and re-run with --machine-hermes-bundle or --machine-harness-bundle naming them; else change $env_file as it says, checking with the bundle's botd: sudo -u $SUPERBOT_USER <bundle>/bin/botd settings check --home $home ($doc)"
      ;;
    *) warn "botd $what check didn't run (status $rc), so $([[ "$what" == machines ]] && echo "machines' settings weren't" || echo "botd's settings weren't") checked before the upgrade: $(head -n 1 <<<"$out")" ;;
  esac
}

# --- The license through offline upgrades and rollbacks (docs/adr/0305-the-license-through-offline-upgrades.md)

# Whether BOTD has `botd license check`: an older one would take the subcommand for a start.
botd_checks_license() { [[ -x "$1" ]] && grep -qaF "Usage: botd license check" "$1"; }

# BOTD's `botd license check` as botd's user, over the server's .env, or over ENV_FILE (root's,
# handed over as a copy botd's user owns, read in the folder the unit runs botd in). KEY, a file
# root reads, is judged as DATA_DIR/license.key, whitespace dropped as write_license_key installs
# it; an empty one judges none. Prints what it said, and returns its status: 0 Bots would run,
# 1 they wouldn't, else it didn't run.
license_verdict() {
  local botd=$1 key=${2:-} env_file=${3:-} home copy rc=0
  local -a args=(license check)
  home=$(user_home)
  [[ -z "$key" ]] || args+=(--key-file -)
  if [[ -n "$env_file" ]]; then
    copy=$(cat -- "$env_file" | (cd / && sudo -u "$SUPERBOT_USER" sh -c 'f=$(mktemp) && cat >"$f" && echo "$f"')) || return 3
    tr -d '[:space:]' <"${key:-/dev/null}" | (cd "$home/superbot" && sudo -u "$SUPERBOT_USER" env -i PATH=/usr/bin:/bin HOME="$home" "$botd" "${args[@]}" --env-file "$copy") 2>&1 || rc=$?
    rm -f -- "$copy"
  else
    tr -d '[:space:]' <"${key:-/dev/null}" | (cd / && sudo -u "$SUPERBOT_USER" env -i PATH=/usr/bin:/bin HOME="$home" "$botd" "${args[@]}" --home "$home") 2>&1 || rc=$?
  fi
  return "$rc"
}

license_mode() { sed -n 's/^License: \([a-z]*\),.*/\1/p;T;q' <<<"$1"; }
license_detail() { sed -n '/^License: /{n;s/^  //p;q}' <<<"$1"; }
same_license() { [[ "$(tr -d '[:space:]' <"$1")" == "$(tr -d '[:space:]' <"$2")" ]]; }

# A 0700 folder of root's for the keys a rollback's license check reads.
rollback_license_dir() {
  install -d -m 0700 "$OFFLINE_TMP/license"
  echo "$OFFLINE_TMP/license"
}

# MEMBER of the rollback's backup into OUT, as root, decrypted with the backup key; empty if
# it isn't there.
backup_member() {
  local dir archive
  dir=$(rollback_dir)
  archive="$dir/$(manifest_value "$dir/record" archive)"
  if [[ "$archive" == *.age ]]; then
    { age -d -i "$BACKUP_IDENTITY_FILE" -- "$archive" | tar -xzOf - "$1" >"$2"; } 2>/dev/null || : >"$2"
  else
    tar -xzOf "$archive" "$1" >"$2" 2>/dev/null || : >"$2"
  fi
}

# On a rollback whose .env sets LICENSE_KEY_FILE to a file in DATA_DIR, the restore puts back
# that file too, and it wins over DATA_DIR/license.key: the backup's copy, or the key in
# --license-file, written there once the backup is restored, is judged in its place, over a copy
# of ENV_FILE without it. Sets LICENSE_JUDGED, LICENSE_WHAT and LICENSE_ENV.
rollback_license_key_file() {
  local env_file=$1 home data_dir file lic
  home=$(user_home)
  file=$(env_value "$env_file" LICENSE_KEY_FILE)
  # With LICENSE_KEY too, botd refuses both as ambiguous: judged over the .env as it is.
  [[ -n "$file" && -z "$(env_value "$env_file" LICENSE_KEY)" ]] || return 1
  [[ "$file" == /* ]] || file="$home/superbot/$file"
  data_dir=$(realpath -m -- "$(env_data_dir "$env_file" "$home")")
  file=$(realpath -m -- "$file")
  [[ "$file" == "$data_dir"/* ]] || return 1
  lic=$(rollback_license_dir)
  grep -v '^LICENSE_KEY_FILE=' "$env_file" >"$lic/env" || true
  LICENSE_ENV="$lic/env"
  if [[ -n "$LICENSE_FILE" ]]; then
    LICENSE_JUDGED=$LICENSE_FILE LICENSE_WHAT="the key in --license-file, as LICENSE_KEY_FILE ($file)"
    ROLLBACK_LICENSE=$LICENSE_FILE ROLLBACK_LICENSE_DEST=$file ROLLBACK_LICENSE_WHAT="the key in --license-file, which LICENSE_KEY_FILE names,"
    return 0
  fi
  backup_member "./${file#"$data_dir"/}" "$lic/key-file"
  LICENSE_JUDGED="$lic/key-file"
  LICENSE_WHAT="the license in LICENSE_KEY_FILE ($file) from before the upgrade, which the rollback puts back"
}

# On a rollback, the license it leaves, unless --license-file names one: the key installed now,
# if the older release takes it, so a renewal installed since the upgrade outlives it
# (ROLLBACK_LICENSE, written back once the backup is restored); else the backup's. Root reads
# the backup, and botd's user its own DATA_DIR, so a link there can't read root's files. Sets
# LICENSE_JUDGED and LICENSE_WHAT.
rollback_license_choice() {
  local botd=$1 env_file=$2 lic now out
  lic=$(rollback_license_dir)
  backup_member ./license.key "$lic/backup"
  LICENSE_JUDGED="$lic/backup" LICENSE_WHAT="the license from before the upgrade, which the rollback puts back"
  now="$(user_home)/superbot/data/license.key"
  (cd / && sudo -u "$SUPERBOT_USER" sh -c 'if [ -f "$1" ]; then head -c 9000 -- "$1"; fi' _ "$now") >"$lic/now" 2>/dev/null || : >"$lic/now"
  if [[ -z "$(tr -d '[:space:]' <"$lic/now")" ]] || same_license "$lic/now" "$lic/backup"; then
    return 0
  fi
  out=$(license_verdict "$botd" "$lic/now" "$env_file") || true
  case $(license_mode "$out") in
    active | grace)
      ROLLBACK_LICENSE="$lic/now" ROLLBACK_LICENSE_WHAT="the license installed since the upgrade"
      LICENSE_JUDGED="$lic/now" LICENSE_WHAT="the license installed now, which the rollback keeps"
      log "Rollback: keeping the license installed since the upgrade to $OFFLINE_INSTALLED, which $OFFLINE_VERSION takes"
      ;;
    *) warn "The license installed since the upgrade to $OFFLINE_INSTALLED isn't one $OFFLINE_VERSION takes ($(license_detail "$out")), so the rollback puts back the one from before" ;;
  esac
}

# Offline installs: whether Bots will run with the server's license on the release being
# installed, before anything changes (docs/adr/0305-the-license-through-offline-upgrades.md). A
# release can stop trusting the key a license was signed with, --license-file can bring a key it
# doesn't take, and a rollback puts back the license from before the upgrade. The running
# release and the bundle's each judge the license as their start would. The install stops when
# Bots run now but wouldn't after; otherwise it says what it found.
offline_license_check() {
  [[ -n "$OFFLINE_BUNDLE" ]] || return 0
  local botd="$OFFLINE_DIR/bin/botd" home env_file="" out rc=0 now_rc=2 why doc="docs/ops/air-gapped.md#the-license-through-upgrades"
  LICENSE_JUDGED="$LICENSE_FILE" LICENSE_WHAT="the key in --license-file"
  if ! id "$SUPERBOT_USER" &>/dev/null || [[ ! -f "$(user_home)/superbot/.env" ]]; then
    # A new server: Bots don't run yet, so a key the bundle's botd doesn't take is only said.
    [[ -n "$LICENSE_FILE" ]] && botd_checks_license "$botd" || return 0
    out=$(tr -d '[:space:]' <"$LICENSE_FILE" | (cd / && env -i PATH=/usr/bin:/bin "$botd" license check --key-file -) 2>&1) || true
    case $(license_mode "$out") in
      active | grace) log "License: $OFFLINE_VERSION takes the key in --license-file: $(license_detail "$out")" ;;
      *) warn "The key in --license-file isn't a license $OFFLINE_VERSION takes: $(license_detail "$out") Install one it takes before Bots can run (botctl license install, $doc)" ;;
    esac
    return 0
  fi
  home=$(user_home)
  if ! botd_checks_license "$botd"; then
    warn "The bundle's botd ($OFFLINE_VERSION) can't check licenses (botd license check), so the license wasn't checked before the $([[ "$ROLLBACK_RESTORE" == true ]] && echo rollback || echo upgrade)"
    return 0
  fi
  if [[ "$ROLLBACK_RESTORE" == true ]]; then
    env_file="$(rollback_dir)/$(manifest_value "$(rollback_dir)/record" env)"
    if rollback_license_key_file "$env_file"; then
      env_file=$LICENSE_ENV
    elif [[ -z "$LICENSE_FILE" ]]; then
      rollback_license_choice "$botd" "$env_file"
    fi
  elif [[ -z "$LICENSE_FILE" ]]; then
    LICENSE_WHAT="this server's license"
  fi
  if [[ "$TESTING_MODE_ON" == true ]]; then
    log "License: --testing-mode sets TESTING_MODE=on, so $OFFLINE_VERSION runs Bots with or without a license (test servers only)"
    return 0
  fi
  if botd_checks_license "$BIN_DIR/botd"; then
    now_rc=0
    license_verdict "$BIN_DIR/botd" >/dev/null || now_rc=$?
    ((now_rc <= 1)) || now_rc=2
  fi
  out=$(license_verdict "$botd" "$LICENSE_JUDGED" "$env_file") || rc=$?
  case $rc in
    0)
      log "License: $OFFLINE_VERSION would run Bots with $LICENSE_WHAT: $(license_detail "$out")"
      sed -n 's/^Warning: //p' <<<"$out" | while IFS= read -r w; do warn "License with $OFFLINE_VERSION: $w"; done
      ;;
    1)
      why="$OFFLINE_VERSION wouldn't run Bots with $LICENSE_WHAT: $(license_detail "$out")"
      case $now_rc in
        0) ;;
        1) warn "$why Bots don't run on this server now either ($doc)"; return 0 ;;
        *) warn "$why The running release can't say whether Bots run now (botd license check) ($doc)"; return 0 ;;
      esac
      if [[ "$DRY_RUN" == true ]]; then
        warn "[dry-run] would stop here, as Bots run now: $why"
        return 0
      fi
      warn "Bots run now, but $why"
      grep -E '^  ' <<<"$out" | sed -n '2,$p' >&2 || true
      [[ "$ROLLBACK_RESTORE" != true ]] \
        || die "Nothing has changed. Roll back with --license-file naming a license key $OFFLINE_VERSION takes, which the rollback installs; check one first with the bundle's botd: sudo -u $SUPERBOT_USER <bundle>/bin/botd license check --home $home --key-file <file> ($doc)"
      die "Nothing has changed. Ask CG-Labs for a license key $OFFLINE_VERSION takes and re-run with --license-file naming it; check one first with the bundle's botd: sudo -u $SUPERBOT_USER <bundle>/bin/botd license check --home $home --key-file <file> ($doc)"
      ;;
    *) warn "botd license check didn't run (status $rc), so the license wasn't checked: $(head -n 1 <<<"$out")" ;;
  esac
}

# --- Offline installs (docs/adr/0128-air-gapped-self-host.md) ---------------------------------

# The flags --offline can't work with, checked before anything changes.
check_offline_flags() {
  if [[ -z "$OFFLINE_BUNDLE" ]]; then
    [[ -z "$OFFLINE_BUNDLE_SHA256" ]] || die "--bundle-sha256 needs --offline"
    [[ -z "$HERMES_BUNDLE$HERMES_BUNDLE_SHA256" ]] || die "--hermes-bundle is for --offline installs: online, --with-hermes runs Hermes Agent's own installer"
    [[ -z "$HARNESS_BUNDLE$HARNESS_BUNDLE_SHA256" ]] || die "--harness-bundle is for --offline installs: online, install the harness CLIs with npm"
    [[ -z "$MACHINE_HERMES_BUNDLE_VALUE$MACHINE_HARNESS_BUNDLE_VALUE" ]] \
      || die "--machine-hermes-bundle and --machine-harness-bundle are for --offline --upgrade: online, set MACHINE_HERMES_BUNDLE and MACHINE_HARNESS_BUNDLE in .env"
    [[ "$ROLLBACK" != true && "$NO_UPGRADE_BACKUP" != true ]] \
      || die "--rollback and --no-upgrade-backup are for --offline upgrades: online, go back by restoring a backup (docs/ops/backup-restore.md)"
    return 0
  fi
  [[ -z "$MACHINE_HERMES_BUNDLE_VALUE$MACHINE_HARNESS_BUNDLE_VALUE" || "$UPGRADE" == true ]] \
    || die "--machine-hermes-bundle and --machine-harness-bundle change an installed server's .env: use them with --upgrade"
  if [[ "$ROLLBACK" == true ]]; then
    [[ "$UPGRADE" == true ]] || die "--rollback changes an installed server: use it with --upgrade"
    [[ "$NO_UPGRADE_BACKUP" != true ]] || die "--rollback restores the backup an upgrade took: --no-upgrade-backup doesn't go with it"
    [[ -z "$MACHINE_HERMES_BUNDLE_VALUE$MACHINE_HARNESS_BUNDLE_VALUE" ]] \
      || die "--rollback puts back the .env from before the upgrade, with its MACHINE_HERMES_BUNDLE and MACHINE_HARNESS_BUNDLE: change them after the rollback"
  fi
  local flag item path items
  for flag in "--machine-hermes-bundle=$MACHINE_HERMES_BUNDLE_VALUE" "--machine-harness-bundle=$MACHINE_HARNESS_BUNDLE_VALUE"; do
    IFS=, read -ra items <<<"${flag#*=}"
    for item in "${items[@]}"; do
      path=$(sed -E 's/=[0-9a-f]{64}$//; s/^[[:space:]]+//; s/[[:space:]]+$//' <<<"$item")
      # superbot.service has PrivateTmp: botd sees its own empty /tmp and /var/tmp, not these.
      case $path in
        /tmp | /tmp/* | /var/tmp | /var/tmp/*)
          die "${flag%%=*}: $path is under /tmp or /var/tmp, which botd's service can't see (PrivateTmp): put the bundle and its .sha256 where $SUPERBOT_USER can read them, such as /var/lib/superbot" ;;
      esac
    done
  done
  [[ -z "$HARNESS_BUNDLE_SHA256" || -n "$HARNESS_BUNDLE" ]] || die "--harness-bundle-sha256 needs --harness-bundle"
  [[ -z "$HARNESS_BUNDLE" || ( -f "$HARNESS_BUNDLE" && -r "$HARNESS_BUNDLE" ) ]] || die "--harness-bundle: can't read $HARNESS_BUNDLE"
  [[ -z "$HARNESS_BUNDLE_SHA256" || "$HARNESS_BUNDLE_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "--harness-bundle-sha256 must be 64 lowercase hex digits"
  [[ -f "$OFFLINE_BUNDLE" && -r "$OFFLINE_BUNDLE" ]] || die "--offline: can't read $OFFLINE_BUNDLE"
  [[ -z "$INSTALL_DIR" ]] || die "--offline installs from the bundle, not --source-dir"
  [[ "$WITH_HERMES" != true || -n "$HERMES_BUNDLE" ]] \
    || die "--with-hermes --offline needs --hermes-bundle: Hermes Agent's own installer downloads from GitHub and PyPI, so make a Hermes bundle on a connected machine with deploy/offline-bundle.sh hermes, or download the release's (docs/ops/air-gapped.md#hermes-agent)"
  [[ -z "$HERMES_BUNDLE" || "$WITH_HERMES" == true ]] || die "--hermes-bundle needs --with-hermes"
  [[ -z "$HERMES_BUNDLE_SHA256" || -n "$HERMES_BUNDLE" ]] || die "--hermes-bundle-sha256 needs --hermes-bundle"
  [[ -z "$HERMES_BUNDLE" || ( -f "$HERMES_BUNDLE" && -r "$HERMES_BUNDLE" ) ]] || die "--hermes-bundle: can't read $HERMES_BUNDLE"
  [[ -z "$HERMES_BUNDLE_SHA256" || "$HERMES_BUNDLE_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "--hermes-bundle-sha256 must be 64 lowercase hex digits"
  [[ -z "$DOMAIN" || -n "$TLS_CERT" ]] || die "--offline with --domain needs --tls-cert and --tls-key: there is no Let's Encrypt without a network"
  [[ -z "$OFFLINE_BUNDLE_SHA256" || "$OFFLINE_BUNDLE_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "--bundle-sha256 must be 64 lowercase hex digits"
}

# The operator's certificate: both halves, PEM, a pair, valid now, and for --domain.
check_tls_files() {
  [[ -n "$TLS_CERT$TLS_KEY" ]] || return 0
  [[ -n "$TLS_CERT" && -n "$TLS_KEY" ]] || die "Give both --tls-cert and --tls-key"
  [[ -n "$DOMAIN" ]] || die "--tls-cert and --tls-key need --domain"
  local f
  for f in "$TLS_CERT" "$TLS_KEY"; do
    [[ -f "$f" && -r "$f" ]] || die "Can't read $f"
  done
  command -v openssl >/dev/null 2>&1 || die "openssl is needed to check --tls-cert"
  openssl x509 -in "$TLS_CERT" -noout 2>/dev/null || die "--tls-cert: $TLS_CERT isn't a PEM certificate"
  openssl pkey -in "$TLS_KEY" -noout 2>/dev/null || die "--tls-key: $TLS_KEY isn't a PEM private key (or it has a passphrase, which Caddy can't use)"
  [[ "$(openssl x509 -in "$TLS_CERT" -noout -pubkey)" == "$(openssl pkey -in "$TLS_KEY" -pubout)" ]] \
    || die "--tls-key doesn't match --tls-cert"
  local not_before
  not_before=$(openssl x509 -in "$TLS_CERT" -noout -startdate | sed 's/^notBefore=//')
  (($(date -u -d "$not_before" +%s) <= $(date -u +%s) + 300)) \
    || die "--tls-cert isn't valid until $not_before: install it then, keeping the current one until that date"
  openssl x509 -in "$TLS_CERT" -noout -checkend 0 >/dev/null || die "--tls-cert has expired"
  openssl x509 -in "$TLS_CERT" -noout -checkend $((30 * 86400)) >/dev/null || warn "--tls-cert ends within 30 days: renew it and re-run the installer"
  [[ "$(openssl x509 -in "$TLS_CERT" -noout -checkhost "$DOMAIN")" == *"does match"* ]] \
    || die "--tls-cert isn't for $DOMAIN"
}

# Root-owned copies Caddy reads: the key for root and Caddy's group only.
install_tls_files() {
  local group=root
  getent group caddy >/dev/null 2>&1 && group=caddy
  install -d -m 0750 -o root -g "$group" "$TLS_DIR"
  install -m 0644 -o root -g "$group" "$TLS_CERT" "$TLS_DIR/cert.pem"
  install -m 0640 -o root -g "$group" "$TLS_KEY" "$TLS_DIR/key.pem"
  [[ "$group" == caddy ]] || warn "No caddy group: $TLS_DIR/key.pem is root's only, so Caddy must run as root to read it"
  log "Certificate for $DOMAIN installed in $TLS_DIR"
}

manifest_value() { sed -n "s/^$2=//p" "$1" | tail -n 1; }

# The bundle's own SHA-256: SHA256 ($2, else --bundle-sha256), else BUNDLE.sha256 beside it.
offline_expected_sha256() {
  local given=${2-$OFFLINE_BUNDLE_SHA256}
  if [[ -n "$given" ]]; then
    printf '%s\n' "$given"
  elif [[ -f "$1.sha256" ]]; then
    awk 'NR == 1 { print $1 }' "$1.sha256"
  fi
}

# Who made the bundle, before anything in it is read: its signature, if it has one and cosign
# is here, and its SHA-256 (SHA256, else --bundle-sha256, else BUNDLE.sha256). One of them is
# required.
offline_check_origin() {
  local bundle=$1 want got signed=false root=()
  OFFLINE_SIGNED=false
  if [[ -f "$bundle.sigstore.json" ]]; then
    if command -v cosign >/dev/null 2>&1; then
      # The operator's own copy of Sigstore's trusted root (cosign initialize on a connected
      # machine), never one that travelled with the bundle.
      if [[ -n "${SIGSTORE_TRUSTED_ROOT:-}" ]]; then
        [[ -f "$SIGSTORE_TRUSTED_ROOT" ]] || die "SIGSTORE_TRUSTED_ROOT: no file at $SIGSTORE_TRUSTED_ROOT"
        root=(--trusted-root "$SIGSTORE_TRUSTED_ROOT")
      fi
      cosign verify-blob --bundle "$bundle.sigstore.json" "${root[@]}" \
        --certificate-identity-regexp "$OFFLINE_SIGNER_IDENTITY_REGEXP" \
        --certificate-oidc-issuer "$OFFLINE_SIGNER_ISSUER" "$bundle" >/dev/null 2>&1 \
        || die "The bundle's signature ($bundle.sigstore.json) doesn't verify: don't install it (docs/ops/air-gapped.md#verifying-a-bundle)"
      log "Bundle signature verified (signed by $OFFLINE_SIGNER_IDENTITY_REGEXP)"
      # shellcheck disable=SC2034 # offline-bundle.sh push reads it
      signed=true OFFLINE_SIGNED=true
    else
      warn "The bundle is signed, but cosign isn't installed here, so the signature isn't checked"
    fi
  fi
  want=$(offline_expected_sha256 "$bundle" "${@:2}")
  if [[ -z "$want" ]]; then
    [[ "$signed" == true ]] || die "Nothing to check $bundle against: give its SHA-256 (from where it was published) or put $bundle.sha256 beside it"
    return 0
  fi
  [[ "$want" =~ ^[0-9a-f]{64}$ ]] || die "$bundle.sha256 doesn't hold a SHA-256"
  got=$(sha256sum "$bundle" | awk '{ print $1 }')
  [[ "$got" == "$want" ]] || die "The bundle's SHA-256 is $got, not $want: it is damaged or not the one published"
  log "Bundle SHA-256 matches ($got)"
}

# One top folder, PREFIX-* (superbot-offline by default), of plain files and folders: no links,
# devices, absolute names or "..". Prints the top folder.
offline_archive_ok() {
  local archive=$1 prefix=${2:-superbot-offline} entries names top
  entries=$(tar -tvf "$archive" 2>/dev/null) && names=$(tar -tf "$archive" 2>/dev/null) || return 1
  [[ -n "$names" ]] || return 1
  awk '{ t = substr($0, 1, 1) } t != "-" && t != "d" { bad = 1 } END { exit bad }' <<<"$entries" || return 1
  ! grep -Eq '^/|(^|/)\.\.(/|$)' <<<"$names" || return 1
  top=$(awk -F/ 'NR == 1 { print $1 }' <<<"$names")
  [[ "$top" =~ ^$prefix-[0-9A-Za-z._+-]+$ ]] || return 1
  awk -F/ -v top="$top" '$1 != top { bad = 1 } END { exit bad }' <<<"$names" || return 1
  printf '%s\n' "$top"
}

# BUNDLE's unpacked ROOT: format 1, and every file in SHA256SUMS with the right hash, and
# nothing else there.
offline_check_sums() {
  local bundle=$1 dir=$2 listed actual
  [[ -f "$dir/MANIFEST" && -f "$dir/SHA256SUMS" ]] || die "Refusing $bundle: no MANIFEST or SHA256SUMS"
  [[ "$(manifest_value "$dir/MANIFEST" format)" == 1 ]] || die "Refusing $bundle: bundle format $(manifest_value "$dir/MANIFEST" format), this installer reads 1"
  ! grep -Evq '^[0-9a-f]{64}  [^[:space:][:cntrl:]\\]+$' "$dir/SHA256SUMS" || die "Refusing $bundle: SHA256SUMS has a line that isn't a hash and a plain path"
  ! grep -Eq '  (/|(.*/)?\.\.(/|$))' "$dir/SHA256SUMS" || die "Refusing $bundle: SHA256SUMS names a path outside the bundle"
  (cd "$dir" && sha256sum --check --strict --quiet SHA256SUMS) || die "Refusing $bundle: files don't match SHA256SUMS"
  listed=$(sed 's/^[0-9a-f]*  //' "$dir/SHA256SUMS" | LC_ALL=C sort)
  actual=$(cd "$dir" && find . -type f ! -path ./SHA256SUMS -printf '%P\n' | LC_ALL=C sort)
  [[ "$listed" == "$actual" ]] || die "Refusing $bundle: it holds files SHA256SUMS doesn't list, or lists files it doesn't hold"
}

# Checks BUNDLE and unpacks it into DEST (an empty folder), setting OFFLINE_DIR to its root.
# Every file must be in SHA256SUMS with the right hash, and nothing else may be there.
offline_unpack_bundle() {
  local bundle=$1 dest=$2 top root arch
  offline_check_origin "$bundle"
  top=$(offline_archive_ok "$bundle") || die "Refusing $bundle: not an offline bundle (one superbot-offline-* folder of plain files)"
  tar -xf "$bundle" -C "$dest" --no-same-owner --no-same-permissions || die "Couldn't unpack $bundle"
  root="$dest/$top"
  find "$root" -type d -exec chmod 0755 {} +
  find "$root" -type f -exec chmod 0644 {} +
  offline_check_sums "$bundle" "$root"
  OFFLINE_VERSION=$(manifest_value "$root/MANIFEST" version)
  [[ "$OFFLINE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]] || die "Refusing $bundle: version \"$OFFLINE_VERSION\" isn't a version"
  arch=$(manifest_value "$root/MANIFEST" arch)
  [[ "$arch" =~ ^(x86_64|aarch64)$ ]] || die "Refusing $bundle: arch \"$arch\" isn't x86_64 or aarch64"
  [[ "${OFFLINE_ANY_ARCH:-}" == 1 || "$arch" == "$(uname -m)" ]] || die "This bundle is for $arch, but this host is $(uname -m)"
  local f
  for f in "${OFFLINE_BINARIES[@]}"; do
    [[ -f "$root/bin/$f" ]] || die "Refusing $bundle: no bin/$f"
    chmod 0755 "$root/bin/$f"
  done
  for f in "${DEPLOY_FILES[@]}" install.sh; do
    [[ -f "$root/deploy/$f" ]] || die "Refusing $bundle: no deploy/$f"
  done
  [[ -f "$root/env.example" && -f "$root/site/index.html" && -f "$root/client/index.html" ]] \
    || die "Refusing $bundle: it needs env.example, site/ and client/"
  OFFLINE_DIR=$root
  log "Offline bundle $OFFLINE_VERSION ($arch, commit $(manifest_value "$root/MANIFEST" commit)) checked"
}

# --- Hermes bundles (docs/adr/0200-hermes-agent-bundle-for-air-gapped-installs.md) ----------
# superbot-hermes-<tag>-<arch>/ with MANIFEST, SHA256SUMS and hermes.tar: Hermes Agent as its
# own installer left it with HOME=/opt/hermes, made by deploy/offline-bundle.sh hermes.

# A Hermes bundle's hermes.tar (or a harness bundle's harnesses.tar, with TOP
# superbot-harnesses), before it is unpacked: one TOP/ folder (default hermes/) of files,
# folders, symbolic and hard links (Python and Node.js trees are full of links), with no
# absolute names, "..", special files or setuid and setgid bits, and hard links only to its
# own files. The symbolic links' targets are checked once unpacked (bundle_tree_ok). Sets
# BUNDLE_TREE_PROBLEM when it fails.
bundle_tar_ok() {
  local tar=$1 top=${2:-hermes} name entries names targets
  name=$(basename "$tar")
  BUNDLE_TREE_PROBLEM=""
  if ! entries=$(tar -tvf "$tar" 2>/dev/null) || ! names=$(tar -tf "$tar" 2>/dev/null) || [[ -z "$names" ]]; then
    BUNDLE_TREE_PROBLEM="$name can't be read"
  elif ! awk -v top="$top" '$0 != top && index($0, top "/") != 1 { bad = 1 } END { exit bad }' <<<"$names"; then
    BUNDLE_TREE_PROBLEM="$name holds files outside one $top/ folder"
  elif grep -Eq '(^|/)\.\.(/|$)' <<<"$names"; then
    BUNDLE_TREE_PROBLEM="$name names a path with .."
  elif ! awk '{ t = substr($0, 1, 1) } t != "-" && t != "d" && t != "l" && t != "h" { bad = 1 } END { exit bad }' <<<"$entries"; then
    BUNDLE_TREE_PROBLEM="$name holds devices, pipes or other special files"
  elif ! awk 'substr($0, 4, 1) ~ /[sS]/ || substr($0, 7, 1) ~ /[sS]/ { bad = 1 } END { exit bad }' <<<"$entries"; then
    BUNDLE_TREE_PROBLEM="$name holds a setuid or setgid file"
  elif targets=$(sed -n 's/^h.* link to //p' <<<"$entries") && [[ -n "$targets" ]] \
    && ! awk -v top="$top" 'index($0, top "/") != 1 || /(^|\/)\.\.(\/|$)/ { bad = 1 } END { exit bad }' <<<"$targets"; then
    BUNDLE_TREE_PROBLEM="$name holds a hard link to a file outside it"
  fi
  [[ -z "$BUNDLE_TREE_PROBLEM" ]]
}

# Whether the link target $4, in folder $3 of ROOT (a tree to live at DEST), stays inside it,
# following every link on the way as the kernel would once the tree is at DEST: a link that is
# fine read alone (b -> a/../x) can still leave through another (a -> .).
link_stays_inside() {
  local root=$1 dest=$2 dir=$3 target=$4 part next hops=0 kept=() todo=() more=()
  if [[ "$target" == /* ]]; then
    [[ "$target" == "$dest" || "$target" == "$dest"/* ]] || return 1
    target=${target#"$dest"}
  else
    IFS=/ read -ra kept <<<"$dir"
  fi
  IFS=/ read -ra todo <<<"$target"
  while ((${#todo[@]})); do
    part=${todo[0]}
    todo=("${todo[@]:1}")
    case $part in
      '' | .) continue ;;
      ..) ((${#kept[@]})) || return 1; unset 'kept[-1]'; kept=("${kept[@]}"); continue ;;
    esac
    next="$root$(printf '/%s' "${kept[@]}" "$part")"
    if [[ -L "$next" ]]; then
      ((++hops <= 40)) || return 1
      target=$(readlink -- "$next") || return 1
      if [[ "$target" == /* ]]; then
        [[ "$target" == "$dest" || "$target" == "$dest"/* ]] || return 1
        target=${target#"$dest"}
        kept=()
      fi
      IFS=/ read -ra more <<<"$target"
      todo=("${more[@]}" "${todo[@]}")
    else
      kept+=("$part")
    fi
  done
}

# ROOT, a Hermes tree unpacked to live at DEST: files, folders and symbolic links only, none
# setuid or setgid, and every link pointing inside it (absolute ones into DEST), so nothing in
# it reaches the rest of the host or a path from the machine that built it. SKIP... are paths
# in ROOT left unchecked (they aren't bundled).
bundle_tree_ok() {
  local root=$1 dest=$2 odd link target dir skip prune=()
  shift 2
  for skip in "$@"; do prune+=(-path "$root/$skip" -prune -o); done
  BUNDLE_TREE_PROBLEM=""
  odd=$(find "$root" "${prune[@]}" ! -type f ! -type d ! -type l -print -quit)
  [[ -z "$odd" ]] || { BUNDLE_TREE_PROBLEM="it holds a special file: ${odd#"$root"/}"; return 1; }
  odd=$(find "$root" "${prune[@]}" -perm /6000 -print -quit)
  [[ -z "$odd" ]] || { BUNDLE_TREE_PROBLEM="it holds a setuid or setgid file: ${odd#"$root"/}"; return 1; }
  while IFS= read -r -d '' link && IFS= read -r -d '' target; do
    dir=""
    [[ "$link" != */* ]] || dir=${link%/*}
    [[ "$target" != *$'\n'* ]] || { BUNDLE_TREE_PROBLEM="the link $link has a newline in its target"; return 1; }
    link_stays_inside "$root" "$dest" "$dir" "$target" || { BUNDLE_TREE_PROBLEM="the link $link points outside $dest, to $target"; return 1; }
  done < <(find "$root" "${prune[@]}" -type l -printf '%P\0%l\0')
}

# Checks a Hermes bundle and unpacks it into DEST (an empty folder), setting HERMES_BUNDLE_DIR to
# its root: its signature or SHA-256 (SHA256, else BUNDLE.sha256), one superbot-hermes-* folder
# of plain files, SHA256SUMS, its MANIFEST and its hermes.tar. Leaves the tree packed.
hermes_unpack_bundle() {
  local bundle=$1 dest=$2 sha=${3:-} top root arch commit
  offline_check_origin "$bundle" "$sha"
  top=$(offline_archive_ok "$bundle" superbot-hermes) || die "Refusing $bundle: not a Hermes bundle (one superbot-hermes-* folder of plain files)"
  tar -xf "$bundle" -C "$dest" --no-same-owner --no-same-permissions || die "Couldn't unpack $bundle"
  root="$dest/$top"
  find "$root" -type d -exec chmod 0755 {} +
  find "$root" -type f -exec chmod 0644 {} +
  offline_check_sums "$bundle" "$root"
  [[ "$(manifest_value "$root/MANIFEST" kind)" == hermes ]] || die "Refusing $bundle: its MANIFEST isn't a Hermes bundle's (kind=hermes)"
  arch=$(manifest_value "$root/MANIFEST" arch)
  [[ "$arch" =~ ^(x86_64|aarch64)$ ]] || die "Refusing $bundle: arch \"$arch\" isn't x86_64 or aarch64"
  [[ "${OFFLINE_ANY_ARCH:-}" == 1 || "$arch" == "$(uname -m)" ]] || die "This Hermes bundle is for $arch, but this host is $(uname -m)"
  commit=$(manifest_value "$root/MANIFEST" hermes_commit)
  [[ "$commit" =~ ^[0-9a-f]{40}$ ]] || die "Refusing $bundle: hermes_commit \"$commit\" isn't a full commit"
  [[ "$(manifest_value "$root/MANIFEST" prefix)" == "$HERMES_SHARED_DIR" ]] \
    || die "Refusing $bundle: it was installed for $(manifest_value "$root/MANIFEST" prefix), not $HERMES_SHARED_DIR"
  [[ -f "$root/hermes.tar" ]] || die "Refusing $bundle: no hermes.tar"
  bundle_tar_ok "$root/hermes.tar" || die "Refusing $bundle: $BUNDLE_TREE_PROBLEM"
  HERMES_BUNDLE_DIR=$root
  log "Hermes bundle: Hermes Agent $(manifest_value "$root/MANIFEST" hermes_tag) (${commit:0:12}, $arch) checked"
}

# Before anything changes: the Hermes bundle checked, for the Hermes Agent this installer pins,
# in a root-only folder beside HERMES_SHARED_DIR (so its tree moves into place in one rename).
prepare_hermes_bundle() {
  [[ -n "$HERMES_BUNDLE" ]] || return 0
  local commit signed=$OFFLINE_SIGNED
  if [[ "$DRY_RUN" == true ]]; then
    HERMES_STAGE=$(mktemp -d)
  else
    install -d -m 0755 -o root -g root "$(dirname "$HERMES_SHARED_DIR")"
    HERMES_STAGE=$(mktemp -d "$(dirname "$HERMES_SHARED_DIR")/.superbot-hermes.XXXXXX")
  fi
  trap cleanup_offline EXIT
  chmod 0700 "$HERMES_STAGE"
  mkdir "$HERMES_STAGE/bundle"
  hermes_unpack_bundle "$HERMES_BUNDLE" "$HERMES_STAGE/bundle" "$HERMES_BUNDLE_SHA256"
  # shellcheck disable=SC2034 # offline-bundle.sh push reads it, for the main bundle
  OFFLINE_SIGNED=$signed
  commit=$(manifest_value "$HERMES_BUNDLE_DIR/MANIFEST" hermes_commit)
  [[ "$commit" == "$HERMES_COMMIT" ]] \
    || die "The Hermes bundle holds Hermes Agent ${commit:0:12}, but this installer pins ${HERMES_COMMIT:0:12}: use the Hermes bundle made for this release (docs/ops/air-gapped.md#hermes-agent)"
}

# --- Harness bundles (docs/adr/0232-harness-cli-bundle-for-air-gapped-servers.md) -----------
# superbot-harnesses-<version>-<arch>/ with MANIFEST, SHA256SUMS and harnesses.tar: Node.js with
# Claude Code, Codex and Pi installed into it by npm at the release's pins, for HARNESSES_DIR,
# made by deploy/offline-bundle.sh harnesses. The pins come from the release's own botd.

# BOTD's harness pins (botd harness pins), if it prints them as this installer reads them:
# "node <version> <arch> <sha256>", "npm <bin> <version> <package> <integrity>" and
# "hermes <bin> <commit> <tag> <sha256>", with a Node.js and at least one npm harness.
harness_pins() {
  local out
  out=$("$1" harness pins 2>/dev/null) || return 1
  awk '
    $1 == "node" && NF == 4 && $2 ~ /^[0-9]+\.[0-9]+\.[0-9]+$/ && $3 ~ /^(x86_64|aarch64)$/ && length($4) == 64 && $4 ~ /^[0-9a-f]+$/ { n++; next }
    $1 == "npm" && NF == 5 && $2 ~ /^[a-z][a-z0-9-]*$/ && $3 ~ /^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$/ \
      && $4 ~ /^(@[a-z0-9._-]+\/)?[a-z0-9._-]+$/ && $5 ~ /^sha512-[A-Za-z0-9+\/]+=*$/ { m++; next }
    $1 == "hermes" && NF == 5 { next }
    { bad = 1 }
    END { exit bad || !n || !m }
  ' <<<"$out" || return 1
  printf '%s\n' "$out"
}

# The npm harnesses PINS names, space-separated, in its order.
harness_names() { awk '$1 == "npm" { printf "%s%s", sep, $2; sep = " " } END { print "" }' <<<"$1"; }

# What a harness bundle for ARCH at PINS says it holds, as MANIFEST lines: which harnesses,
# Node.js's version and the SHA-256 of its tarball, and each harness's version, package and the
# integrity of its npm tarball.
harness_manifest_lines() {
  printf 'harnesses=%s\n' "$(harness_names "$1")"
  awk -v arch="$2" '
    $1 == "node" && $3 == arch { print "node=" $2 " " $4 }
    $1 == "npm" { print "harness_" $2 "=" $3 " " $4 " " $5 }
  ' <<<"$1"
}

# The first of WANTED's lines that MANIFEST lacks, as "KEY is <its value there>, not <wanted>";
# nothing when it has them all (a missing MANIFEST has none).
harness_mismatch() {
  local manifest=$1 wanted=$2 line key have=""
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    grep -qxF -- "$line" "$manifest" 2>/dev/null && continue
    key=${line%%=*}
    [[ ! -f "$manifest" ]] || have=$(manifest_value "$manifest" "$key")
    printf '%s is %s, not %s\n' "${key#harness_}" "${have:-missing}" "${line#*=}"
    return 0
  done <<<"$wanted"
}

# The wrapper BIN_DIR/<bin> links to: the CLI with the tree's own Node.js first on PATH, so it
# runs whatever Node.js the host has, or none. The installer writes it, never the bundle.
harness_wrapper() {
  printf '%s\n' '#!/bin/sh' \
    "# $1 from SuperBot's harness bundle (docs/adr/0232-harness-cli-bundle-for-air-gapped-servers.md)," \
    "# on its own Node.js. Claude Code's updater can't change this root-owned tree, and has no network." \
    "PATH=$HARNESSES_DIR/bin:\$PATH" \
    'DISABLE_AUTOUPDATER=1' \
    'export PATH DISABLE_AUTOUPDATER' \
    "exec $HARNESSES_DIR/bin/$1 \"\$@\""
}

# Checks a harness bundle and unpacks it into DEST (an empty folder), setting HARNESS_BUNDLE_DIR
# to its root: its signature or SHA-256 (SHA256, else BUNDLE.sha256), one superbot-harnesses-*
# folder of plain files, SHA256SUMS, its MANIFEST and its harnesses.tar. Leaves the tree packed.
harness_unpack_bundle() {
  local bundle=$1 dest=$2 sha=${3:-} top root arch
  offline_check_origin "$bundle" "$sha"
  top=$(offline_archive_ok "$bundle" superbot-harnesses) || die "Refusing $bundle: not a harness bundle (one superbot-harnesses-* folder of plain files)"
  tar -xf "$bundle" -C "$dest" --no-same-owner --no-same-permissions || die "Couldn't unpack $bundle"
  root="$dest/$top"
  find "$root" -type d -exec chmod 0755 {} +
  find "$root" -type f -exec chmod 0644 {} +
  offline_check_sums "$bundle" "$root"
  [[ "$(manifest_value "$root/MANIFEST" kind)" == harnesses ]] || die "Refusing $bundle: its MANIFEST isn't a harness bundle's (kind=harnesses)"
  arch=$(manifest_value "$root/MANIFEST" arch)
  [[ "$arch" =~ ^(x86_64|aarch64)$ ]] || die "Refusing $bundle: arch \"$arch\" isn't x86_64 or aarch64"
  [[ "${OFFLINE_ANY_ARCH:-}" == 1 || "$arch" == "$(uname -m)" ]] || die "This harness bundle is for $arch, but this host is $(uname -m)"
  [[ "$(manifest_value "$root/MANIFEST" prefix)" == "$HARNESSES_DIR" ]] \
    || die "Refusing $bundle: it was installed for $(manifest_value "$root/MANIFEST" prefix), not $HARNESSES_DIR"
  [[ -f "$root/harnesses.tar" ]] || die "Refusing $bundle: no harnesses.tar"
  bundle_tar_ok "$root/harnesses.tar" "$(basename "$HARNESSES_DIR")" || die "Refusing $bundle: $BUNDLE_TREE_PROBLEM"
  HARNESS_BUNDLE_DIR=$root
  log "Harness bundle: $(manifest_value "$root/MANIFEST" harnesses) on Node.js $(manifest_value "$root/MANIFEST" node | cut -d' ' -f1) ($arch, SuperBot $(manifest_value "$root/MANIFEST" version)) checked"
}

# Before anything changes: the harness bundle checked, and holding exactly what the bundle's botd
# pins, in a root-only folder beside HARNESSES_DIR (so its tree moves into place in one rename).
prepare_harness_bundle() {
  [[ -n "$HARNESS_BUNDLE" ]] || return 0
  local pins problem signed=$OFFLINE_SIGNED
  pins=$(harness_pins "$OFFLINE_DIR/bin/botd") \
    || die "The bundle's botd doesn't say which harness CLIs it pins (botd harness pins), so the harness bundle can't be checked against it: use a release that has harness bundles (docs/ops/air-gapped.md#harness-clis-on-this-server)"
  if [[ "$DRY_RUN" == true ]]; then
    HARNESS_STAGE=$(mktemp -d)
  else
    install -d -m 0755 -o root -g root "$(dirname "$HARNESSES_DIR")"
    HARNESS_STAGE=$(mktemp -d "$(dirname "$HARNESSES_DIR")/.superbot-harnesses.XXXXXX")
  fi
  trap cleanup_offline EXIT
  chmod 0700 "$HARNESS_STAGE"
  mkdir "$HARNESS_STAGE/bundle"
  harness_unpack_bundle "$HARNESS_BUNDLE" "$HARNESS_STAGE/bundle" "$HARNESS_BUNDLE_SHA256"
  # shellcheck disable=SC2034 # offline-bundle.sh push reads it, for the main bundle
  OFFLINE_SIGNED=$signed
  HARNESS_WANTED=$(harness_manifest_lines "$pins" "$(uname -m)")
  problem=$(harness_mismatch "$HARNESS_BUNDLE_DIR/MANIFEST" "$HARNESS_WANTED")
  [[ -z "$problem" ]] \
    || die "The harness bundle doesn't hold what this release pins ($problem): use the harness bundle made for this release (docs/ops/air-gapped.md#harness-clis-on-this-server)"
}

# The version HARNESS_WANTED pins for harness BIN, or "node" for Node.js.
harness_wanted_version() {
  local key=harness_$1
  [[ "$1" != node ]] || key=node
  sed -n "s/^$key=\([^ ]*\) .*/\1/p;T;q" <<<"$HARNESS_WANTED"
}

# Whether Node.js and each of NAMES run from HARNESSES_DIR as an account with no access to
# anything else, at the versions pinned.
harness_works() {
  local probe b out want ok=true
  want=$(harness_wanted_version node)
  out=$(timeout 60 "$HARNESSES_DIR/bin/node" --version 2>&1) || true
  [[ "$out" == "v$want" ]] || { warn "$HARNESSES_DIR/bin/node --version says \"$out\", not v$want"; return 1; }
  probe=$(mktemp -d)
  chmod 0777 "$probe"
  for b in $1; do
    want=$(harness_wanted_version "$b")
    out=$(sudo -u nobody env -i HOME="$probe" PATH=/usr/bin:/bin timeout 120 "$BIN_DIR/$b" --version 2>&1) || true
    [[ -n "$want" && "$out" == *"$want"* ]] || { warn "$BIN_DIR/$b --version, as another account, says \"$(head -c 300 <<<"$out")\", not $want"; ok=false; }
  done
  rm -rf -- "$probe"
  [[ "$ok" == true ]]
}

# BIN_DIR/<bin> for each of NAMES, linked to its wrapper. Whatever was there is kept in the
# staging folder until the new tree works (harness_put_back).
harness_link() {
  local b link target
  for b in $1; do
    link="$BIN_DIR/$b" target="$HARNESSES_DIR/superbot/$b"
    [[ "$(readlink -- "$link" 2>/dev/null)" != "$target" ]] || continue
    if [[ -e "$link" || -L "$link" ]]; then
      warn "Replacing $link ($( [[ -L "$link" ]] && readlink -- "$link" || echo a file)) with the harness bundle's $b"
      mkdir -p "$HARNESS_STAGE/replaced"
      mv -- "$link" "$HARNESS_STAGE/replaced/$b" || return 1
    fi
    HARNESS_LINKED+=("$link")
    ln -s -- "$target" "$link" || return 1
  done
}

# Undoes install_harnesses: its links (and what they replaced), its tree, and the tree it moved
# aside, back in HARNESSES_DIR. If that last fails, HARNESS_PREVIOUS stays set, so
# cleanup_offline keeps it for the operator; so does anything left in replaced/.
harness_put_back() {
  local link f stuck=false
  for link in "${HARNESS_LINKED[@]}"; do rm -f -- "$link"; done
  HARNESS_LINKED=()
  for f in "$HARNESS_STAGE"/replaced/*; do
    [[ -e "$f" || -L "$f" ]] || continue
    mv -- "$f" "$BIN_DIR/$(basename "$f")" || { warn "Couldn't put $BIN_DIR/$(basename "$f") back: it is in $f"; stuck=true; }
  done
  if [[ "$HARNESS_MOVED_IN" == true ]]; then
    rm -rf -- "$HARNESSES_DIR" || { warn "Couldn't remove the new harness CLIs from $HARNESSES_DIR"; return 1; }
    HARNESS_MOVED_IN=false
  fi
  if [[ -n "$HARNESS_PREVIOUS" && -e "$HARNESS_PREVIOUS" ]]; then
    warn "Putting back the harness CLIs $HARNESSES_DIR had"
    if mv -- "$HARNESS_PREVIOUS" "$HARNESSES_DIR"; then
      HARNESS_PREVIOUS=""
    else
      warn "Couldn't put them back: they are in $HARNESS_PREVIOUS; move them to $HARNESSES_DIR by hand"
      return 1
    fi
  fi
  [[ "$stuck" == false ]]
}

harness_failed() {
  harness_put_back || true
  if [[ "$BOTD_STOPPED" == true ]]; then
    warn "Starting superbot again with the harness CLIs it had"
    systemctl start superbot.service || true
  fi
  die "$1"
}

# The checked harness bundle's tree in HARNESSES_DIR, root's, which every account may run but
# none may change, each CLI linked from BIN_DIR through the installer's own wrapper. As with
# Hermes, the tree it replaces is kept until the new one runs for other accounts, and Bots keep
# nothing in it.
install_harnesses() {
  if [[ -z "$HARNESS_BUNDLE" ]]; then
    harness_pin_notice
    return 0
  fi
  local names name tree="$HARNESS_STAGE/tree" b
  names=$(manifest_value "$HARNESS_BUNDLE_DIR/MANIFEST" harnesses)
  name=$(basename "$HARNESSES_DIR")
  if [[ "$DRY_RUN" == true ]]; then
    log "[dry-run] would install $names system-wide in $HARNESSES_DIR from the harness bundle $HARNESS_BUNDLE, linked from $BIN_DIR"
    return
  fi
  if [[ -z "$(harness_mismatch "$HARNESSES_DIR/superbot/MANIFEST" "$HARNESS_WANTED")" ]] \
    && harness_link "$names" && harness_works "$names"; then
    HARNESS_LINKED=()
    rm -rf -- "$HARNESS_STAGE/replaced"
    log "The harness CLIs this release pins are already installed in $HARNESSES_DIR ($names)"
    return
  fi
  log "Unpacking $names from $HARNESS_BUNDLE"
  mkdir -m 0700 "$tree"
  tar -xf "$HARNESS_BUNDLE_DIR/harnesses.tar" -C "$tree" --no-same-owner || harness_failed "Couldn't unpack the harness CLIs from $HARNESS_BUNDLE"
  rm -f -- "$HARNESS_BUNDLE_DIR/harnesses.tar"
  bundle_tree_ok "$tree/$name" "$HARNESSES_DIR" || harness_failed "Refusing $HARNESS_BUNDLE: $BUNDLE_TREE_PROBLEM"
  [[ -x "$tree/$name/bin/node" ]] || harness_failed "Refusing $HARNESS_BUNDLE: its tree has no bin/node"
  [[ ! -e "$tree/$name/superbot" && ! -L "$tree/$name/superbot" ]] || harness_failed "Refusing $HARNESS_BUNDLE: its tree has a superbot folder, which is the installer's"
  install -d -m 0755 "$tree/$name/superbot"
  for b in $names; do
    [[ -e "$tree/$name/bin/$b" ]] || harness_failed "Refusing $HARNESS_BUNDLE: its tree has no bin/$b"
    harness_wrapper "$b" >"$tree/$name/superbot/$b"
    chmod 0755 "$tree/$name/superbot/$b"
  done
  install -m 0644 "$HARNESS_BUNDLE_DIR/MANIFEST" "$tree/$name/superbot/MANIFEST"
  if ! { chown root:root "$tree/$name" && chmod -R go-w,a+rX "$tree/$name"; }; then
    harness_failed "Couldn't make the harness CLIs root's, and readable by other accounts"
  fi
  stop_botd_for_swap "the harness CLIs change"
  log "Installing $names system-wide in $HARNESSES_DIR from the harness bundle"
  if [[ -e "$HARNESSES_DIR" || -L "$HARNESSES_DIR" ]]; then
    mv -- "$HARNESSES_DIR" "$HARNESS_STAGE/previous" || harness_failed "Couldn't move the harness CLIs in $HARNESSES_DIR aside"
    HARNESS_PREVIOUS="$HARNESS_STAGE/previous"
  fi
  mv -- "$tree/$name" "$HARNESSES_DIR" || harness_failed "Couldn't move the harness CLIs into $HARNESSES_DIR"
  HARNESS_MOVED_IN=true
  harness_link "$names" || harness_failed "Couldn't link the harness CLIs from $BIN_DIR"
  harness_works "$names" || harness_failed "The harness CLIs from $HARNESS_BUNDLE don't run here"
  HARNESS_MOVED_IN=false HARNESS_LINKED=()
  if [[ -n "$HARNESS_PREVIOUS" ]]; then
    rm -rf -- "$HARNESS_PREVIOUS"
    HARNESS_PREVIOUS=""
  fi
  rm -rf -- "$HARNESS_STAGE/replaced"
}

# An offline upgrade without --harness-bundle keeps the harness CLIs it has; say so when this
# release pins others.
harness_pin_notice() {
  [[ -n "$OFFLINE_DIR" && -f "$HARNESSES_DIR/superbot/MANIFEST" ]] || return 0
  local pins problem
  pins=$(harness_pins "$OFFLINE_DIR/bin/botd") || return 0
  problem=$(harness_mismatch "$HARNESSES_DIR/superbot/MANIFEST" "$(harness_manifest_lines "$pins" "$(uname -m)")")
  [[ -z "$problem" ]] \
    || warn "The harness CLIs in $HARNESSES_DIR aren't the ones this release pins ($problem): re-run with --harness-bundle <this release's harness bundle> (docs/ops/air-gapped.md#harness-clis-on-this-server)"
}

cleanup_offline() {
  [[ -z "${OFFLINE_TMP:-}" ]] || rm -rf -- "$OFFLINE_TMP"
  if [[ -n "${HERMES_STAGE:-}" ]]; then
    # An exit with the old Hermes Agent aside is a failure hermes_failed didn't see: put it
    # back, and start botd again if it was stopped for the swap. One that can't be put back
    # stays in the staging folder.
    local stuck=false
    if [[ -n "${HERMES_PREVIOUS:-}" ]]; then
      hermes_put_back || stuck=true
      [[ "$BOTD_STOPPED" != true ]] || systemctl start superbot.service || true
    fi
    if [[ "$stuck" == true ]]; then
      rm -rf -- "$HERMES_STAGE/bundle" "$HERMES_STAGE/tree"
    else
      rm -rf -- "$HERMES_STAGE"
    fi
  fi
  if [[ -n "${HARNESS_STAGE:-}" ]]; then
    # The same for the harness CLIs: an exit mid-swap puts back what install_harnesses changed.
    local hstuck=false
    if [[ -n "${HARNESS_PREVIOUS:-}" || "${HARNESS_MOVED_IN:-}" == true || ${#HARNESS_LINKED[@]} -gt 0 ]]; then
      harness_put_back || hstuck=true
      [[ "$BOTD_STOPPED" != true ]] || systemctl start superbot.service || true
    fi
    # harness_failed has already tried to put these back; what it couldn't is the operator's.
    [[ -z "$(ls -A -- "$HARNESS_STAGE/replaced" 2>/dev/null)" ]] || hstuck=true
    if [[ "$hstuck" == true ]]; then
      rm -rf -- "$HARNESS_STAGE/bundle" "$HARNESS_STAGE/tree"
    else
      rm -rf -- "$HARNESS_STAGE"
    fi
  fi
}

offline_release_file() { printf '%s\n' "${OFFLINE_RELEASE_FILE:-$SHARE_DIR/offline-release}"; }

# SemVer 2.0.0 precedence, build metadata ignored: 0.1.0-rc.1 < 0.1.0 < 0.1.1, and
# 0.1.0-ci.2 < 0.1.0-ci.10. `sort -V` gets the first one backwards.
semver_gt() {
  local a=${1%%+*} b=${2%%+*} i x y
  local -a ca cb pa=() pb=()
  IFS=. read -ra ca <<<"${a%%-*}"
  IFS=. read -ra cb <<<"${b%%-*}"
  for i in 0 1 2; do
    x=$((10#${ca[i]:-0})) y=$((10#${cb[i]:-0}))
    ((x == y)) || { ((x > y)); return; }
  done
  [[ "$a" == *-* ]] && IFS=. read -ra pa <<<"${a#*-}"
  [[ "$b" == *-* ]] && IFS=. read -ra pb <<<"${b#*-}"
  ((${#pa[@]} || ${#pb[@]})) || return 1
  ((${#pa[@]})) || return 0
  ((${#pb[@]})) || return 1
  for ((i = 0; i < ${#pa[@]} && i < ${#pb[@]}; i++)); do
    x=${pa[i]} y=${pb[i]}
    [[ "$x" == "$y" ]] && continue
    if [[ "$x" =~ ^[0-9]+$ && "$y" =~ ^[0-9]+$ ]]; then
      ((10#$x > 10#$y)); return
    elif [[ "$x" =~ ^[0-9]+$ ]]; then
      return 1
    elif [[ "$y" =~ ^[0-9]+$ ]]; then
      return 0
    fi
    [[ "$x" > "$y" ]]; return
  done
  ((${#pa[@]} > ${#pb[@]}))
}

# Unpacks into a root-owned folder (Caddy's files are copied from it as the service user, who
# can read but not change it) and refuses an older version than the one installed: a newer
# database may not open with older binaries. --rollback goes back with the backup the last
# upgrade took, when that backup is of the bundle's release (rollback_problem).
prepare_offline() {
  [[ -n "$OFFLINE_BUNDLE" ]] || return 0
  local installed release why
  if [[ "$DRY_RUN" == true ]]; then
    OFFLINE_TMP=$(mktemp -d)
  else
    install -d -m 0755 -o root -g root "$SHARE_DIR"
    OFFLINE_TMP=$(mktemp -d "$SHARE_DIR/offline.XXXXXX")
  fi
  chmod 0755 "$OFFLINE_TMP"
  trap cleanup_offline EXIT
  offline_unpack_bundle "$OFFLINE_BUNDLE" "$OFFLINE_TMP"
  release=$(offline_release_file)
  if [[ -f "$release" ]]; then
    installed=$(manifest_value "$release" version)
    OFFLINE_INSTALLED=$installed
    if [[ -n "$installed" ]] && semver_gt "$installed" "$OFFLINE_VERSION"; then
      if [[ "$ROLLBACK" == true ]]; then
        why=$(rollback_problem "$installed")
        [[ -z "$why" ]] || die "Can't roll back to $OFFLINE_VERSION: $why. Nothing has changed. To go back, restore a backup made on $OFFLINE_VERSION (docs/ops/air-gapped.md#going-back)."
        ROLLBACK_RESTORE=true
        log "Offline rollback: $installed -> $OFFLINE_VERSION, with the backup taken before the upgrade to $installed ($(manifest_value "$(rollback_dir)/record" created))"
        return 0
      fi
      if [[ -z "$(rollback_problem "$installed")" ]]; then
        die "This host runs $installed, newer than the bundle's $OFFLINE_VERSION. To go back to the backup taken before the upgrade to $installed, losing everything since, add --rollback (docs/ops/air-gapped.md#going-back)."
      fi
      die "This host runs $installed, newer than the bundle's $OFFLINE_VERSION. To go back, restore a backup made on $OFFLINE_VERSION (docs/ops/air-gapped.md#going-back)."
    fi
    if [[ "$ROLLBACK" == true ]]; then
      [[ "$installed" == "$OFFLINE_VERSION" ]] \
        || die "--rollback goes back to an older release, but this host runs ${installed:-an unknown release} and the bundle is $OFFLINE_VERSION"
      log "This host already runs $OFFLINE_VERSION: nothing to roll back, so the bundle is installed again as is"
    fi
    log "Offline upgrade: ${installed:-unknown} -> $OFFLINE_VERSION"
  else
    [[ "$ROLLBACK" != true ]] || die "--rollback: this host has no offline release recorded in $release, so there's nothing to go back from"
  fi
}

# What the online installer would apt-get: here it must already be installed, from the
# operator's own mirror.
check_offline_tools() {
  local missing=() c
  for c in useradd sudo systemctl tar sha256sum openssl sqlite3 awk sed find install; do
    command -v "$c" >/dev/null 2>&1 || missing+=("$c")
  done
  if [[ "$(isolation_mode)" == users ]]; then
    for c in setfacl visudo; do command -v "$c" >/dev/null 2>&1 || missing+=("$c"); done
  fi
  [[ -z "$DOMAIN" ]] || command -v caddy >/dev/null 2>&1 || missing+=(caddy)
  [[ "$ENABLE_UFW" != true ]] || command -v ufw >/dev/null 2>&1 || missing+=(ufw)
  # The Node.js in Hermes Agent's tools needs it; the online installer apt-gets it.
  [[ "$WITH_HERMES" != true ]] || [[ "$(ldconfig -p 2>/dev/null)" == *libatomic.so.1* ]] || missing+=(libatomic1)
  if [[ ${#missing[@]} -gt 0 ]]; then
    if [[ "$DRY_RUN" == true ]]; then
      warn "[dry-run] missing, to install from your mirror first: ${missing[*]}"
    else
      die "Install these from your package mirror first (docs/ops/air-gapped.md#before-you-start): ${missing[*]}"
    fi
  fi
  command -v age >/dev/null 2>&1 || warn "age isn't installed: encrypted backups are unavailable"
  if ! command -v bwrap >/dev/null 2>&1 || ! command -v socat >/dev/null 2>&1; then
    warn "bubblewrap and socat aren't installed: harness sandboxes are unavailable"
  fi
  log "Offline: no packages, git, curl, cargo or npm; everything comes from the bundle"
}

# Which bundle this host runs, for the next upgrade's version check.
record_offline_release() {
  [[ -n "$OFFLINE_BUNDLE" ]] || return 0
  local release
  release=$(offline_release_file)
  if [[ "$DRY_RUN" == true ]]; then
    log "[dry-run] would record bundle $OFFLINE_VERSION in $release"
    return
  fi
  install -m 0644 -o root -g root "$OFFLINE_DIR/MANIFEST" "$release"
}

# --- Going back after an offline upgrade (docs/adr/0300-offline-upgrades-keep-a-way-back.md) ---

rollback_dir() { printf '%s\n' "${ROLLBACK_DIR:-$SHARE_DIR/rollback}"; }

# DATA_DIR as superbot-restore reads it from an .env: the last value, unquoted, or the default.
env_data_dir() {
  local value
  value=$(sed -n 's/^DATA_DIR=//p' "$1" | tail -n 1)
  case $value in
    \"*\" | \'*\') value=${value:1:-1} ;;
  esac
  printf '%s\n' "${value:-$2/superbot/data}"
}

# The .pre-restore-* folders in a DATA_DIR: superbot-restore makes one as it starts swapping.
pre_restore_dirs() {
  (cd / && find "$1" -mindepth 1 -maxdepth 1 -name '.pre-restore-*' 2>/dev/null | sort) || true
}

# Why the backup in rollback_dir can't take this host, running INSTALLED, back to the bundle's
# release; nothing when it can. It must be that release's, from just before the upgrade to the
# one running now, so no later release has opened the database since.
rollback_problem() {
  local installed=$1 dir record from commit want to archive env
  dir=$(rollback_dir)
  record="$dir/record"
  [[ -f "$record" ]] || { echo "no backup was taken before an offline upgrade on this host ($record)"; return; }
  from=$(manifest_value "$record" from_version)
  commit=$(manifest_value "$record" from_commit)
  to=$(manifest_value "$record" to_version)
  archive=$(manifest_value "$record" archive)
  env=$(manifest_value "$record" env)
  want=$(manifest_value "$OFFLINE_DIR/MANIFEST" commit)
  if [[ "$from" != "$OFFLINE_VERSION" ]]; then
    echo "the backup in $dir is of $from, not $OFFLINE_VERSION: roll back with the $from bundle"
  elif [[ -n "$commit" && "$commit" != unknown && -n "$want" && "$want" != unknown && "$commit" != "$want" ]]; then
    echo "the backup in $dir is of $from built from $commit, but this bundle is built from $want"
  elif [[ "$to" != "$installed" ]]; then
    echo "the backup in $dir was taken before the upgrade to $to, but this host runs $installed, which may have changed the database since"
  elif ! [[ "$archive" =~ ^superbot-pre-upgrade-[0-9A-Za-z._+-]+\.tar\.gz(\.age)?$ && "$env" =~ ^env-[0-9A-Z]+$ && -f "$dir/$archive" && -f "$dir/$env" ]]; then
    echo "the backup's files aren't all in $dir"
  elif [[ "$(sha256sum "$dir/$archive" | awk '{ print $1 }')" != "$(manifest_value "$record" archive_sha256)" ]]; then
    echo "$dir/$archive has changed since it was backed up (its SHA-256 differs)"
  fi
}

# The backup ARCHIVE, decrypted by root when it is encrypted, into the bundle's superbot-restore
# as botd's user, who owns DATA_DIR but can't read rollback_dir or the backup key. ARGS go to
# superbot-restore (--check only reads it).
rollback_feed_restore() {
  local home=$1 archive=$2
  shift 2
  local restore=(sudo -u "$SUPERBOT_USER" env -i PATH=/usr/bin:/bin HOME="$home" SUPERBOT_BOTD="$OFFLINE_DIR/bin/botd"
    bash "$OFFLINE_DIR/deploy/superbot-restore.sh" --home "$home" "$@" -)
  if [[ "$archive" == *.age ]]; then
    age -d -i "$BACKUP_IDENTITY_FILE" -- "$archive" | (cd / && "${restore[@]}")
  else
    (cd / && "${restore[@]}") <"$archive"
  fi
}

# Before anything changes on a rollback: the backup unpacks, opens and passes its checks.
prepare_rollback() {
  [[ "$ROLLBACK_RESTORE" == true ]] || return 0
  local dir archive out data_dir
  dir=$(rollback_dir)
  archive="$dir/$(manifest_value "$dir/record" archive)"
  # The restore puts DATA_DIR where the old .env points, and configure_env then points botd at
  # the installer's own, as on every install.
  data_dir=$(env_data_dir "$dir/$(manifest_value "$dir/record" env)" "$(user_home)")
  [[ "$data_dir" == "$(user_home)/superbot/data" ]] \
    || die "The .env from before the upgrade sets DATA_DIR=$data_dir, but the installer runs botd with $(user_home)/superbot/data, so the backup would go where botd won't read it. Nothing has changed. Restore it by hand instead (docs/ops/backup-restore.md)."
  if [[ "$archive" == *.age ]]; then
    command -v age >/dev/null 2>&1 || die "The backup taken before the upgrade, $archive, is encrypted, and age isn't installed. Nothing has changed."
    [[ -r "$BACKUP_IDENTITY_FILE" ]] \
      || die "The backup taken before the upgrade, $archive, is encrypted: put the age identity that opens it at $BACKUP_IDENTITY_FILE, or name it with BACKUP_IDENTITY_FILE=<file>. Nothing has changed."
  fi
  if ! out=$(rollback_feed_restore "$(user_home)" "$archive" --check 2>&1); then
    printf '%s\n' "$out" >&2
    die "The backup taken before the upgrade, $archive, doesn't restore: $(tail -n 1 <<<"$out"). Nothing has changed."
  fi
  log "Rollback: the backup taken before the upgrade to $OFFLINE_INSTALLED unpacks and checks out"
  grep -E '^(created|users|bots|messages|needs master key): ' <<<"$out" | sed 's/^/    /' || true
}

# An offline upgrade to a newer release: DATA_DIR, backed up by the running release's own
# superbot-backup as botd's user (encrypted as its backups are), and .env, kept root-only in
# rollback_dir for --rollback. One backup is kept: this one replaces the last once it is
# complete. A backup that fails stops the upgrade before anything changes. A rollback instead
# puts them back (rollback_restore).
offline_rollback_point() {
  [[ -n "$OFFLINE_BUNDLE" ]] || return 0
  if [[ "$ROLLBACK_RESTORE" == true ]]; then
    rollback_restore
    return
  fi
  if [[ -z "$OFFLINE_INSTALLED" ]] || ! semver_gt "$OFFLINE_VERSION" "$OFFLINE_INSTALLED"; then
    return 0
  fi
  local dir home env_file stamp partial name out commit
  local -a backup
  dir=$(rollback_dir)
  home=$(user_home)
  env_file="$home/superbot/.env"
  [[ -f "$env_file" ]] || return 0
  if [[ "$NO_UPGRADE_BACKUP" == true ]]; then
    warn "No backup before the upgrade (--no-upgrade-backup): --rollback can't take this host back to $OFFLINE_INSTALLED"
    return 0
  fi
  if [[ "$DRY_RUN" == true ]]; then
    log "[dry-run] would back up DATA_DIR and $env_file with $OFFLINE_INSTALLED's superbot-backup into $dir (root only), for --rollback"
    return 0
  fi
  backup=("$BIN_DIR/superbot-backup")
  [[ -x "$BIN_DIR/superbot-backup" ]] || backup=(bash "$OFFLINE_DIR/deploy/superbot-backup.sh")
  install -d -m 0700 -o root -g root "$dir"
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  partial="$dir/.partial-$stamp"
  install -m 0600 -o root -g root /dev/null "$partial"
  log "Backing up DATA_DIR and .env before the upgrade, so --rollback can go back to $OFFLINE_INSTALLED"
  if ! out=$( (cd / && sudo -u "$SUPERBOT_USER" env -i PATH=/usr/bin:/bin HOME="$home" SUPERBOT_BOTD="$BIN_DIR/botd" "${backup[@]}" --home "$home" -) 2>&1 >"$partial"); then
    rm -f -- "$partial"
    printf '%s\n' "$out" >&2
    die "Couldn't back up before the upgrade: $(tail -n 1 <<<"$out"). Nothing has changed. Fix it (free space under $dir, say) and run the upgrade again, or upgrade with no way back with --no-upgrade-backup."
  fi
  name="superbot-pre-upgrade-$OFFLINE_INSTALLED-$stamp.tar.gz"
  [[ "$(head -c 21 "$partial")" != age-encryption.org/v1 ]] || name+=.age
  mv -- "$partial" "$dir/$name"
  install -m 0600 -o root -g root "$env_file" "$dir/env-$stamp"
  commit=$(manifest_value "$(offline_release_file)" commit)
  printf 'format=1\nfrom_version=%s\nfrom_commit=%s\nto_version=%s\ncreated=%s\narchive=%s\narchive_sha256=%s\nenv=%s\n' \
    "$OFFLINE_INSTALLED" "$commit" "$OFFLINE_VERSION" "$(date -u +%FT%TZ)" "$name" \
    "$(sha256sum "$dir/$name" | awk '{ print $1 }')" "env-$stamp" >"$dir/record.new"
  chmod 0600 "$dir/record.new"
  mv -f -- "$dir/record.new" "$dir/record"
  find "$dir" -mindepth 1 -maxdepth 1 ! -name record ! -name "$name" ! -name "env-$stamp" -exec rm -rf -- {} +
  log "Rollback point: $dir/$name ($(du -h "$dir/$name" | cut -f1)). To go back to $OFFLINE_INSTALLED, losing everything since: install.sh --offline <its bundle> --upgrade --rollback (docs/ops/air-gapped.md#going-back)"
}

# --rollback, once every check has passed: botd stops, and the .env and DATA_DIR from before
# the upgrade go back, keeping what they replace beside them. If the restore fails before it
# touches DATA_DIR, the .env goes back too and botd starts again as it was; if it fails while
# swapping DATA_DIR, botd stays stopped. Then the install goes on with the bundle's release,
# and botd stays stopped until its binaries are in place. The folder .env is in belongs to
# botd's user, so root only replaces files there with install, which doesn't follow symlinks;
# the copies are made as that user.
rollback_restore() {
  local dir record archive env home env_file stamp out kept was_active=false data_dir before_swap
  dir=$(rollback_dir)
  record="$dir/record"
  archive="$dir/$(manifest_value "$record" archive)"
  env="$dir/$(manifest_value "$record" env)"
  home=$(user_home)
  env_file="$home/superbot/.env"
  if [[ "$DRY_RUN" == true ]]; then
    log "[dry-run] would stop superbot and put back $env_file and DATA_DIR from before the upgrade to $OFFLINE_INSTALLED ($archive), keeping what they replace"
    return 0
  fi
  [[ ! -L "$env_file" ]] || die "Refusing symlinked $env_file. Nothing has changed."
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  kept="$env_file.before-rollback-$stamp"
  (cd / && sudo -u "$SUPERBOT_USER" cp -p -- "$env_file" "$kept") \
    || die "Couldn't keep $env_file as $kept. Nothing has changed."
  data_dir=$(env_data_dir "$env" "$home")
  before_swap=$(pre_restore_dirs "$data_dir")
  if systemctl is-active --quiet superbot.service 2>/dev/null; then
    log "Stopping superbot to put back the backup"
    systemctl stop superbot.service
    was_active=true
  fi
  if ! out=$(install -m 0600 -o "$SUPERBOT_USER" -g "$(id -gn "$SUPERBOT_USER")" -- "$env" "$env_file" 2>&1) \
    || ! out=$(rollback_feed_restore "$home" "$archive" 2>&1); then
    printf '%s\n' "$out" >&2
    if [[ "$(pre_restore_dirs "$data_dir")" != "$before_swap" ]]; then
      die "Putting back the backup taken before the upgrade stopped while swapping $data_dir: $(tail -n 1 <<<"$out"). superbot is left stopped. What $data_dir held is in its newest .pre-restore-* folder: as $SUPERBOT_USER, move everything else in $data_dir aside and that folder's contents back, then run the rollback again, or put back $kept as $env_file and start superbot on $OFFLINE_INSTALLED (docs/ops/air-gapped.md#going-back)"
    fi
    (cd / && sudo -u "$SUPERBOT_USER" cp -- "$kept" "$env_file") && rm -f -- "$kept"
    [[ "$was_active" != true ]] || systemctl start superbot.service || true
    die "Couldn't put back the backup taken before the upgrade: $(tail -n 1 <<<"$out"). DATA_DIR wasn't touched, and superbot is back as it was on $OFFLINE_INSTALLED, with its .env."
  fi
  # The data is the bundle's release's again: a run that stops after this is repeated as an
  # install of that release, with nothing left to restore.
  record_offline_release
  rm -f -- "$record" "$archive" "$env"
  log "Put back DATA_DIR and .env from before the upgrade to $OFFLINE_INSTALLED"
  if [[ -n "$ROLLBACK_LICENSE" ]]; then
    local dest=${ROLLBACK_LICENSE_DEST:-$data_dir/license.key}
    # The backup's license wasn't judged, so the older release must not start without this one.
    if ! write_license_key "$ROLLBACK_LICENSE" "$dest"; then
      install -m 0600 -- "$ROLLBACK_LICENSE" "$dir/license.key" || true
      die "Couldn't write $ROLLBACK_LICENSE_WHAT as $dest. superbot is left stopped, on the data from before the upgrade. The key is kept in $dir/license.key (root's): as $SUPERBOT_USER, copy it to $dest, then run the same command again (docs/ops/air-gapped.md#going-back)"
    fi
    log "Kept $ROLLBACK_LICENSE_WHAT as $dest"
  fi
  grep -F 'Previous data kept' <<<"$out" | sed 's/^superbot-restore: /    /' || true
  log "The .env $OFFLINE_INSTALLED ran with is kept as $kept"
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
  check_backup_target
  prompt_missing
  check_offline_flags
  check_tls_files
  if [[ -n "$OFFLINE_BUNDLE" ]]; then
    prepare_offline
    prepare_hermes_bundle
    prepare_harness_bundle
    prepare_rollback
    offline_settings_start_check
    offline_license_check
  else
    detect_source_dir
  fi
  TZ_VALUE=${TZ_VALUE:-UTC}
  USER_NAME_VALUE=${USER_NAME_VALUE:-Owner}

  default_isolation
  if [[ -n "$OFFLINE_BUNDLE" ]]; then
    check_offline_tools
    ensure_user
  else
    ensure_user
    install_packages
    install_node
    install_rustup_user
  fi
  if [[ "$UPGRADE" == true && -n "$OFFLINE_BUNDLE" ]]; then
    log "Upgrade mode: replacing what the bundle carries"
  elif [[ "$UPGRADE" == true ]]; then
    log "Upgrade mode: updating source and rebuilding"
  fi
  # Last of the offline checks, first of the changes: the backup an upgrade can go back to, or
  # a rollback putting one back.
  offline_rollback_point
  sync_repo
  stage_trusted_deploy
  # Before the new binaries are in place: once they may have opened the database, the older
  # bundle must stay refused even if a later step fails.
  record_offline_release
  build_botd
  build_client
  install_site
  configure_env
  ensure_master_key
  install_license
  install_hermes
  install_harnesses
  configure_isolation
  machine_bot_user_notice "$(user_home)/superbot/.env"
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