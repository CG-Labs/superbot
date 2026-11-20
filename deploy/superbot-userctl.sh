#!/usr/bin/env bash
# Root helper for per-user accounts (docs/adr/0037-per-user-unix-accounts.md). Installed as
# /usr/local/sbin/superbot-userctl by deploy/install.sh --isolation. botd's service account may
# run exactly `superbot-userctl ensure <user id>` as root (sudoers), and nothing else.
#
#   superbot-userctl ensure <user id>
#
# Makes, if missing, and then fixes:
#   account  sb-u-<id>: a locked system account with no login shell, in its own group plus
#            superbot-users (whom botd may run harnesses as), never in botd's group
#   <dir>/<id>/            root:<svc> 2750; the account may enter (ACL r-x), other accounts not
#   <dir>/<id>/home/       the account's HOME (harness logins): account:<svc> 2770
#   <dir>/<id>/workspace/  where its Bots work: account:<svc> 2770
#   <dir>/<id>/memory/     USER.md and the Bots' memory, made by botd: root:<svc> 2770 + ACL
# <dir> and <svc> come from /etc/superbot/isolation.conf (root's), never from the caller.
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C

CONF=${SUPERBOT_USERCTL_CONF:-/etc/superbot/isolation.conf}
PREFIX=sb-u-
RUN_GROUP=superbot-users

die() { printf 'superbot-userctl: %s\n' "$*" >&2; exit 2; }

# The conf (and the CONF override, for tests) must be root's and only root's to change.
[[ "$(id -u)" == 0 ]] || die "must run as root"
[[ -f "$CONF" && ! -L "$CONF" ]] || die "missing $CONF (run deploy/install.sh --isolation)"
[[ "$(stat -c '%u' "$CONF")" == 0 ]] || die "$CONF must be owned by root"
(( (8#$(stat -c '%a' "$CONF") & 8#022) == 0 )) || die "$CONF must be writable only by root"

conf_value() {
  sed -n "s/^$1=//p" "$CONF" | tail -n 1
}

ISOLATION_DIR=$(conf_value ISOLATION_DIR)
SERVICE_GROUP=$(conf_value SERVICE_GROUP)
[[ "$ISOLATION_DIR" =~ ^(/[A-Za-z0-9._-]+)+$ && "$ISOLATION_DIR" != *"/.."* ]] || die "ISOLATION_DIR must be a plain absolute path"
[[ "$SERVICE_GROUP" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "SERVICE_GROUP must be a group name"
getent group "$SERVICE_GROUP" >/dev/null || die "no group $SERVICE_GROUP"
getent group "$RUN_GROUP" >/dev/null || die "no group $RUN_GROUP (run deploy/install.sh --isolation)"

# One at a time: two first runs for one user must not both run useradd.
exec 9>/run/superbot-userctl.lock
flock 9

# Every folder from / down to ISOLATION_DIR is a real folder only root can change, so no one
# else can swap a link into the path this script then chowns and chmods.
trusted_path() {
  local p=$1 part
  local -a parts
  IFS=/ read -r -a parts <<<"${p#/}"
  p=""
  for part in "${parts[@]}"; do
    p="$p/$part"
    [[ -d "$p" && ! -L "$p" ]] || die "$p must be a folder, not a link"
    [[ "$(stat -c '%u' "$p")" == 0 ]] || die "$p must be owned by root"
    (( (8#$(stat -c '%a' "$p") & 8#022) == 0 )) || die "$p must be writable only by root"
  done
}

# A folder this script owns the shape of: made if missing, never a link.
folder() {
  local p=$1 owner=$2 group=$3 mode=$4
  if [[ -L "$p" ]]; then
    die "$p is a link"
  fi
  [[ -e "$p" ]] || mkdir "$p"
  [[ -d "$p" ]] || die "$p isn't a folder"
  chown -h "$owner:$group" "$p"
  chmod "$mode" "$p"
}

ensure() {
  local id=$1 account root uid home
  [[ "$id" =~ ^[a-z0-9]{1,27}$ ]] || die "user id must be 1 to 27 lowercase letters and digits"
  account="$PREFIX$id"
  trusted_path "$ISOLATION_DIR"
  root="$ISOLATION_DIR/$id"
  home="$root/home"

  if getent passwd "$account" >/dev/null; then
    uid=$(id -u "$account")
    [[ "$uid" != 0 ]] || die "$account has uid 0"
    [[ "$(getent passwd "$account" | cut -d: -f6)" == "$home" ]] || die "$account exists with another home; fix or remove it by hand"
    if id -nG "$account" | tr ' ' '\n' | grep -qxF "$SERVICE_GROUP"; then
      die "$account is in $SERVICE_GROUP; it must not be"
    fi
  else
    useradd --system --user-group --groups "$RUN_GROUP" --home-dir "$home" --no-create-home \
      --shell /usr/sbin/nologin --comment "SuperBot user $id" "$account"
  fi
  usermod --append --groups "$RUN_GROUP" "$account"
  passwd --lock "$account" >/dev/null

  folder "$root" root "$SERVICE_GROUP" 2750
  setfacl --remove-all "$root"
  setfacl -m "u:$account:r-x" "$root"
  folder "$home" "$account" "$SERVICE_GROUP" 2770
  folder "$root/workspace" "$account" "$SERVICE_GROUP" 2770
  folder "$root/memory" root "$SERVICE_GROUP" 2770
  setfacl --remove-all "$root/memory"
  # New files there (botd seeds them 0660) are the account's to edit, and botd's to read back.
  setfacl -m "u:$account:rwx,d:u:$account:rwx,d:g:$SERVICE_GROUP:rwx,d:m::rwx,d:o::---" "$root/memory"
  for p in "$home" "$root/workspace"; do
    setfacl -m "d:g:$SERVICE_GROUP:rwx,d:m::rwx,d:o::---" "$p"
  done
  printf '%s %s\n' "$account" "$home"
}

case "${1:-}" in
  ensure)
    [[ $# == 2 ]] || die "usage: superbot-userctl ensure <user id>"
    ensure "$2"
    ;;
  *)
    die "usage: superbot-userctl ensure <user id>"
    ;;
esac
