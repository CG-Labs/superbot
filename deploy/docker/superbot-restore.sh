#!/usr/bin/env bash
# Restore a superbot-backup archive into DATA_DIR. Installed as /usr/local/bin/superbot-restore.
# botd must be stopped. From deploy/docker:
#   docker compose stop botd backup
#   docker compose run --rm --no-deps -T botd superbot-restore - < superbot-<stamp>.tar.gz
#   docker compose start botd backup
# The previous DATA_DIR contents are kept in DATA_DIR/.pre-restore-<stamp>/ until you delete them.
set -euo pipefail

DATA_DIR=${DATA_DIR:-/data}
PORT=${PORT:-3000}

die() { printf 'superbot-restore: %s\n' "$*" >&2; exit 1; }

src=${1:-}
[[ -n "$src" ]] || die "usage: superbot-restore <archive.tar.gz | ->"
[[ "$src" == - || -f "$src" ]] || die "no such archive: $src"

# `compose run` containers do not answer to the service name, so this only reaches a running botd.
if curl -fsS --max-time 2 "http://botd:${PORT}/healthz" >/dev/null 2>&1; then
  die "botd is running; stop it first: docker compose stop botd backup"
fi

stamp=$(date -u +%Y%m%d-%H%M%S)
staging="$DATA_DIR/.restore-$stamp"
previous="$DATA_DIR/.pre-restore-$stamp"
mkdir -p "$staging"
trap 'rm -rf "$staging"' EXIT

tar -xzf "$src" -C "$staging" --no-same-owner --no-same-permissions
[[ -f "$staging/app.sqlite" ]] || die "archive has no app.sqlite; not a superbot-backup archive"
check=$(sqlite3 "$staging/app.sqlite" 'PRAGMA integrity_check;')
[[ "$check" == ok ]] || die "app.sqlite failed integrity_check: $check"

mkdir -p "$previous"
find "$DATA_DIR" -mindepth 1 -maxdepth 1 ! -name '.restore-*' ! -name '.pre-restore-*' -exec mv -t "$previous" {} +
find "$staging" -mindepth 1 -maxdepth 1 -exec mv -t "$DATA_DIR" {} +
printf 'Restored into %s. Previous data kept in %s (delete it once SuperBot looks right).\n' "$DATA_DIR" "$previous" >&2
