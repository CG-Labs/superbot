#!/usr/bin/env bash
# Root helper for per-user accounts (docs/adr/0037-per-user-unix-accounts.md). Installed as
# /usr/local/sbin/superbot-userctl by deploy/install.sh --isolation. botd's service account may
# run exactly `superbot-userctl ensure ...` as root (sudoers), and nothing else.
#
#   superbot-userctl ensure <user id>
#   superbot-userctl ensure <owner id> <teammate id>
#
# The second is a teammate's account for one owner's shared Bots
# (docs/adr/0064-teammate-accounts-on-one-server.md): sb-t-<first 24 hex of
# sha256("<owner>:<teammate>")>, with the same folders under <dir>/<owner>-<teammate>/. Only
# that account may enter them: not the owner's, not the teammate's own.
#
# Makes, if missing, and then fixes:
#   account  sb-u-<id>: a locked system account with no login shell, in its own group plus
#            superbot-users (whom botd may run harnesses as), never in botd's group
#   <dir>/<id>/            root:<svc> 2750; the account may enter (ACL r-x), other accounts not
#   <dir>/<id>/home/       the account's HOME (harness logins): account:<svc> 2770
#   <dir>/<id>/workspace/  where its Bots work: account:<svc> 2770
#   <dir>/<id>/memory/     USER.md and the Bots' memory, made by botd: root:<svc> 2770 + ACL
#   <dir>/<id>/bots/       each Bot's harness state, made by botd for the account: root:<svc> 2770 + ACL
#   <dir>/<id>/settings/   files botd writes for the Bots' runs, read-only to the account:
#                          root:<svc> 2770 + ACL r-x (docs/adr/0058-harness-os-user-by-default.md)
# <dir> and <svc> come from /etc/superbot/isolation.conf (root's), never from the caller.
#
# The uid is the one the account's home already has, when it has one and no one else holds it:
# in a container /etc/passwd starts afresh, and the account must come back owning its files.
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C

CONF=${SUPERBOT_USERCTL_CONF:-/etc/superbot/isolation.conf}
PREFIX=sb-u-
TEAMMATE_PREFIX=sb-t-
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

# A system uid for a new account: free in passwd and group, and held by no other user's
# folder (whose account a recreated container hasn't made again yet).
free_uid() {
  local min max uid taken
  min=$(awk '$1 == "SYS_UID_MIN" { print $2 }' /etc/login.defs 2>/dev/null)
  max=$(awk '$1 == "SYS_UID_MAX" { print $2 }' /etc/login.defs 2>/dev/null)
  taken=$(stat -c '%u' "$ISOLATION_DIR"/*/home 2>/dev/null || true)
  for ((uid = ${max:-999}; uid >= ${min:-100}; uid--)); do
    getent passwd "$uid" >/dev/null && continue
    getent group "$uid" >/dev/null && continue
    grep -qx "$uid" <<<"$taken" && continue
    printf '%s\n' "$uid"
    return
  done
  die "no free system uid for a new account"
}

# The uid an account gets: its home's, if the home is there, else a free one.
account_uid() {
  local home=$1 uid holder
  if [[ -d "$home" && ! -L "$home" ]]; then
    uid=$(stat -c '%u' "$home")
    [[ "$uid" != 0 ]] || die "$home is owned by root; fix or remove it by hand"
    if holder=$(getent passwd "$uid"); then
      die "$home belongs to uid $uid, which is now ${holder%%:*}; fix or remove it by hand"
    fi
    printf '%s\n' "$uid"
  else
    free_uid
  fi
}

valid_id() {
  [[ "$1" =~ ^[a-z0-9]{1,27}$ ]] || die "user id must be 1 to 27 lowercase letters and digits"
}

# ensure <folder name under ISOLATION_DIR> <account> <comment>
ensure() {
  local dir=$1 account=$2 comment=$3 root uid home
  trusted_path "$ISOLATION_DIR"
  root="$ISOLATION_DIR/$dir"
  home="$root/home"

  if getent passwd "$account" >/dev/null; then
    uid=$(id -u "$account")
    [[ "$uid" != 0 ]] || die "$account has uid 0"
    [[ "$(getent passwd "$account" | cut -d: -f6)" == "$home" ]] || die "$account exists with another home; fix or remove it by hand"
    if grep -qxF "$SERVICE_GROUP" <<<"$(id -nG "$account" | tr ' ' '\n')"; then
      die "$account is in $SERVICE_GROUP; it must not be"
    fi
  else
    uid=$(account_uid "$home")
    getent group "$account" >/dev/null || groupadd --system --gid "$uid" "$account"
    useradd --system --uid "$uid" --gid "$account" --groups "$RUN_GROUP" --home-dir "$home" --no-create-home \
      --shell /usr/sbin/nologin --comment "$comment" "$account"
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
  # botd makes bots/<bot id> (0770); the account gets full access to it through the default ACL.
  folder "$root/bots" root "$SERVICE_GROUP" 2770
  setfacl --remove-all "$root/bots"
  setfacl -m "u:$account:r-x,d:u:$account:rwx,d:g:$SERVICE_GROUP:rwx,d:m::rwx,d:o::---" "$root/bots"
  # botd writes settings/<bot id>/ (0750, files 0640); the account may read, never write.
  folder "$root/settings" root "$SERVICE_GROUP" 2770
  setfacl --remove-all "$root/settings"
  setfacl -m "u:$account:r-x,d:u:$account:r-x,d:g:$SERVICE_GROUP:rwx,d:m::rwx,d:o::---" "$root/settings"
  printf '%s %s\n' "$account" "$home"
}

usage="usage: superbot-userctl ensure <user id> | ensure <owner id> <teammate id>"
case "${1:-}" in
  ensure)
    if [[ $# == 2 ]]; then
      valid_id "$2"
      ensure "$2" "$PREFIX$2" "SuperBot user $2"
    elif [[ $# == 3 ]]; then
      valid_id "$2"
      valid_id "$3"
      [[ "$2" != "$3" ]] || die "owner and teammate must differ"
      hash=$(printf '%s:%s' "$2" "$3" | sha256sum | cut -c1-24)
      ensure "$2-$3" "$TEAMMATE_PREFIX$hash" "SuperBot teammate of a shared Bot's owner"
    else
      die "$usage"
    fi
    ;;
  *)
    die "$usage"
    ;;
esac
