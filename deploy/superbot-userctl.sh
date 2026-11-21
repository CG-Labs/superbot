#!/usr/bin/env bash
# Root helper for per-user accounts (docs/adr/0037-per-user-unix-accounts.md). Installed as
# /usr/local/sbin/superbot-userctl by deploy/install.sh --isolation. botd's service account may
# run exactly `superbot-userctl ensure|remove|purge ...` as root (sudoers), and nothing else.
#
#   superbot-userctl ensure <user id>
#   superbot-userctl ensure <owner id> <teammate id>
#   superbot-userctl remove <owner id> <teammate id> <cleanup id> archive <name> | hold | delete
#   superbot-userctl purge <cleanup id>
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
#
# `remove` takes a leaving teammate's account for one owner's Bots away
# (docs/adr/0066-removing-teammate-accounts-on-one-server.md). Only ever an sb-t- account it
# derives from the two ids itself, with the home it gave it: never a user's own sb-u- account,
# nor any other. It kills every process of the account (as the account itself, so nothing
# else can be hit), deals with its workspace (archive: handed to the owner's account under
# workspace/from-teammates/<name>, recorded in <dir>/.left/<cleanup id>.to; hold: kept aside,
# root's alone, in <dir>/.left/<cleanup id> until `purge`; delete: gone), with any memory
# copy a run left unsaved, deletes its folder, its files in /tmp, /var/tmp and /dev/shm,
# its crontab, at jobs and lingering, then the account and its group. Each step can run again:
# a removal that stopped halfway finishes on the next try. It prints what it did as key=value.
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

# Run as the owner's account, in its workspace: moves the handed-over work from $2 into
# from-teammates/$3 (or $3-2, $3-3, ...), never over anything. Prints where it landed: $2
# if it couldn't, so the work is still the owner's, just not tidied away.
ARCHIVE_AS_OWNER='cd "$1" || exit 1
mkdir -p from-teammates 2>/dev/null
if [ ! -d from-teammates ] || [ -h from-teammates ]; then echo "$2"; exit 0; fi
n="" i=1
while [ -e "from-teammates/$3$n" ] || [ -h "from-teammates/$3$n" ]; do
  i=$((i + 1)); n="-$i"
  [ "$i" -lt 100 ] || { echo "$2"; exit 0; }
done
if mv -T -- "$2" "from-teammates/$3$n" 2>/dev/null; then echo "from-teammates/$3$n"; else echo "$2"; fi'

# Runs the rest as uid:gid, with no groups and no capabilities.
as_uid() {
  local uid=$1 gid=$2
  shift 2
  setpriv --reuid="$uid" --regid="$gid" --clear-groups --inh-caps=-all -- "$@"
}

# Moves work staged in the owner's workspace into from-teammates/<name>, as the owner's
# account (uid $1, gid $2), and keeps where it went in .left/<cleanup id>.to, root's, so a
# retry still reports it once it's moved. Uses remove's locals.
tidy_archive() {
  local p
  folder "$left" root root 0700
  printf '%s\n' "$to" >"$left/$id.to"
  p=$(as_uid "$1" "$2" /bin/sh -c "$ARCHIVE_AS_OWNER" sh "$owner_ws" "$staged" "$name" 2>/dev/null | tail -n 1) || p=""
  [[ -z "$p" || "$p" == "$staged" ]] || to="$owner_ws/$p"
  printf '%s\n' "$to" >"$left/$id.to"
}

valid_cleanup_id() {
  [[ "$1" =~ ^[a-f0-9]{8,32}$ ]] || die "cleanup id must be 8 to 32 lowercase hex digits"
}

# Makes a teammate's work, still in their folder (no process of theirs left), fit to hand
# over: the memory copies botd set aside, and any a run left unsaved, go in with it (not
# their USER.md), a hard link to anyone else's file goes (the file stays theirs), a file of
# theirs with other links gets a copy of its own, and no set-id bit is left.
prepare_work() {
  local root=$1 ws=$2 uid=$3 f tmp
  for f in "$root"/memory/*.md.unsaved "$root"/memory/*.md; do
    [[ -f "$f" && ! -L "$f" && "${f##*/}" != USER.md ]] || continue
    [[ -d "$ws/unsaved-memory" && ! -L "$ws/unsaved-memory" ]] || { rm -f -- "$ws/unsaved-memory"; mkdir -- "$ws/unsaved-memory"; }
    mv -n -- "$f" "$ws/unsaved-memory/"
  done
  find "$ws" -xdev ! -type d ! -uid "$uid" -links +1 -delete
  while IFS= read -r -d '' f; do
    tmp=$(mktemp -- "$(dirname -- "$f")/.superbot-copy.XXXXXX")
    cp --preserve=mode,timestamps -- "$f" "$tmp"
    mv -f -- "$tmp" "$f"
  done < <(find "$ws" -xdev -type f -uid "$uid" -links +1 -print0)
  find "$ws" -xdev -type f -perm /6000 -exec chmod ug-s -- {} +
}

# remove <owner> <teammate> <cleanup id> archive <name> | hold | delete
remove() {
  local owner=$1 teammate=$2 id=$3 mode=$4 name=${5:-}
  local hash account root home ws uid="" gid="" present=false rounds=0 temp=0 work=none to="" i p d
  hash=$(printf '%s:%s' "$owner" "$teammate" | sha256sum | cut -c1-24)
  account=$TEAMMATE_PREFIX$hash
  trusted_path "$ISOLATION_DIR"
  root="$ISOLATION_DIR/$owner-$teammate"
  home="$root/home"
  ws="$root/workspace"
  local left="$ISOLATION_DIR/.left"
  local owner_ws="$ISOLATION_DIR/$owner/workspace"
  local staged=".superbot-from-teammate-$id"

  if getent passwd "$account" >/dev/null; then
    [[ "$(getent passwd "$account" | cut -d: -f6)" == "$home" ]] || die "$account exists with another home; fix or remove it by hand"
    uid=$(id -u "$account")
    gid=$(id -g "$account")
    [[ "$uid" != 0 && "$gid" != 0 ]] || die "$account has uid or gid 0"
    present=true
    passwd --lock "$account" >/dev/null
  fi
  if [[ -e "$root" || -L "$root" ]]; then
    [[ -d "$root" && ! -L "$root" && "$(stat -c '%u' "$root")" == 0 ]] || die "$root isn't a folder this helper made; fix or remove it by hand"
    if [[ -z "$uid" && -d "$home" && ! -L "$home" ]]; then
      uid=$(stat -c '%u' "$home")
      [[ "$uid" != 0 ]] || uid=""
    fi
  fi

  # Every process of the account, signalled by the account itself: kill(-1) reaches only
  # its own processes, so a reused pid of anyone else's is never hit. Until none is left,
  # reaped too, or userdel refuses.
  if $present; then
    for ((i = 0; i < 100; i++)); do
      pgrep -u "$uid" >/dev/null || break
      as_uid "$uid" "$gid" kill -9 -1 2>/dev/null || true
      rounds=$((rounds + 1))
      sleep 0.1
    done
    ((i < 100)) || die "$account's processes keep coming back"
  fi

  # The owner's account and workspace, to hand work to: sets ou and og.
  local owner_acct=$PREFIX$owner ou="" og=""
  owner_ids() {
    getent passwd "$owner_acct" >/dev/null || die "can't archive: $owner_acct isn't there"
    ou=$(id -u "$owner_acct")
    og=$(id -g "$owner_acct")
    [[ "$ou" != 0 ]] || die "$owner_acct has uid 0"
    [[ -d "$ISOLATION_DIR/$owner" && ! -L "$ISOLATION_DIR/$owner" && "$(stat -c '%u' "$ISOLATION_DIR/$owner")" == 0 ]] || die "can't archive: $ISOLATION_DIR/$owner isn't a folder this helper made"
    [[ -d "$owner_ws" && ! -L "$owner_ws" && "$(stat -c '%u' "$owner_ws")" == "$ou" ]] || die "can't archive: $owner_ws isn't $owner_acct's workspace"
  }

  # Their work, unless an earlier try already moved it: still staged (tidied away now, when
  # archiving), moved on (where the record says), or held.
  if [[ -d "$owner_ws/$staged" && ! -L "$owner_ws/$staged" ]]; then
    work=archived to="$owner_ws/$staged"
    if [[ "$mode" == archive ]]; then
      owner_ids
      tidy_archive "$ou" "$og"
    fi
  elif [[ -f "$left/$id.to" && ! -L "$left/$id.to" ]] && p=$(head -n 1 -- "$left/$id.to") && [[ "$p" == "$owner_ws/"* ]]; then
    work=archived to=$p
    # Moved by the owner's account after the record was last written: it's in there.
    [[ "$to" != "$owner_ws/$staged" ]] || to="$owner_ws/from-teammates"
  elif [[ -d "$left/$id" && ! -L "$left/$id" ]]; then
    work=held to="$left/$id"
  fi
  if [[ "$work" == none && -d "$ws" && ! -L "$ws" ]]; then
    [[ -n "$uid" ]] || uid=$(stat -c '%u' "$ws")
    [[ "$uid" != 0 ]] || die "$ws is owned by root; fix or remove it by hand"
    prepare_work "$root" "$ws" "$uid"
    if [[ -z "$(find "$ws" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
      work=none
    elif [[ "$mode" == archive ]]; then
      owner_ids
      # Still in the teammate's folder, where the owner's account can't reach: no one can
      # swap anything in while it changes hands.
      chown -R -P -h "$ou:$SERVICE_GROUP" -- "$ws"
      # rename(2) never follows a link at the target, and won't replace one.
      mv -T -- "$ws" "$owner_ws/$staged"
      to="$owner_ws/$staged"
      tidy_archive "$ou" "$og"
      work=archived
    elif [[ "$mode" == hold ]]; then
      folder "$left" root root 0700
      mv -T -- "$ws" "$left/$id"
      work=held to="$left/$id"
    else
      work=deleted
    fi
  fi

  if [[ -d "$root" && ! -L "$root" ]]; then
    rm -rf --one-file-system -- "$root"
  fi
  # Their files in the shared temp folders, unless that uid is someone else's by now.
  if [[ -n "$uid" ]] && { $present || ! getent passwd "$uid" >/dev/null; }; then
    for d in /tmp /var/tmp /dev/shm; do
      [[ -d "$d" && ! -L "$d" ]] || continue
      while IFS= read -r -d '' p; do
        rm -rf --one-file-system -- "$p"
        temp=$((temp + 1))
      done < <(find "$d" -xdev -mindepth 1 -maxdepth 1 -uid "$uid" -print0)
    done
  fi
  if $present; then
    rm -f -- "/var/spool/cron/crontabs/$account" "/var/lib/systemd/linger/$account"
    if [[ -d /var/spool/cron/atjobs && ! -L /var/spool/cron/atjobs ]]; then
      find /var/spool/cron/atjobs -xdev -mindepth 1 -maxdepth 1 -type f -uid "$uid" -delete
    fi
    userdel "$account"
  fi
  if getent group "$account" >/dev/null; then
    groupdel "$account"
  fi
  printf 'account=%s\nprocesses=%s\ntemp=%s\nwork=%s\n' "$($present && echo removed || echo absent)" "$rounds" "$temp" "$work"
  [[ -z "$to" ]] || printf 'path=%s\n' "$to"
}

# purge <cleanup id>: deletes work `remove ... hold` kept aside.
purge() {
  local id=$1 left="$ISOLATION_DIR/.left"
  trusted_path "$ISOLATION_DIR"
  if [[ -e "$left/$id" || -L "$left/$id" ]]; then
    [[ -d "$left" && ! -L "$left" && "$(stat -c '%u' "$left")" == 0 ]] || die "$left isn't a folder this helper made"
    rm -rf --one-file-system -- "${left:?}/$id"
    echo purged=yes
  else
    echo purged=no
  fi
}

usage="usage: superbot-userctl ensure <user id> | ensure <owner id> <teammate id> | remove <owner id> <teammate id> <cleanup id> archive <name>|hold|delete | purge <cleanup id>"
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
  remove)
    (($# >= 5)) || die "$usage"
    valid_id "$2"
    valid_id "$3"
    [[ "$2" != "$3" ]] || die "owner and teammate must differ: a user's own account is never removed"
    valid_cleanup_id "$4"
    case "$5" in
      archive)
        [[ $# == 6 && "$6" =~ ^[a-z0-9_][a-z0-9._-]{0,63}$ ]] || die "archive needs a name: 1 to 64 lowercase letters, digits, . _ -, not starting with . or -"
        ;;
      hold | delete) [[ $# == 5 ]] || die "$usage" ;;
      *) die "$usage" ;;
    esac
    remove "$2" "$3" "$4" "$5" "${6:-}"
    ;;
  purge)
    [[ $# == 2 ]] || die "$usage"
    valid_cleanup_id "$2"
    purge "$2"
    ;;
  *)
    die "$usage"
    ;;
esac
