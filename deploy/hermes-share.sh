#!/bin/sh
# One Hermes Agent environment for every Bot on a computer (ADR 0072).
#
# Hermes keeps its Python dependency environment per data root (<root>/installs/<key>),
# and each Bot's HERMES_HOME is a data root of its own, so each new Bot built a 0.5 GB
# environment of its own on its first run. This shares the install's one instead.
#
# Run as the install's owner, with HOME the folder Hermes's installer ran with, it adds
# Hermes's anthropic extra, makes the committed environment usable read-only (Bots take no leases on it, so Hermes never
# collects it under them), removes environments left from earlier installs, and writes
# itself with the install's paths filled in to $HOME/.hermes/superbot/hermes, which it
# prints. Bots run that copy as `hermes`.
#
# That copy, run with a Bot's HERMES_HOME, gives the Bot's data root its own record of
# the install: facts.json and the input stamps, and a link to the shared environments,
# plus an empty config.yaml if it has none. A launch then writes only in the Bot's own
# folder: its lock, its record, and that file. Bots never
# install or update dependencies (HERMES_DISABLE_LAZY_INSTALLS); the installer does.
# Without a HERMES_HOME, or with the install's own, it just runs Hermes.
set -eu

root=
key=

die() {
  printf 'hermes-share: %s\n' "$*" >&2
  exit 1
}

# Hermes's install key: the start of the SHA-256 of the checkout's real path.
install_key() {
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s' "$1" | sha256sum | cut -c1-16
  else
    printf '%s' "$1" | shasum -a 256 | cut -c1-16
  fi
}

if [ -z "$key" ]; then
  [ -n "${HOME:-}" ] || die "HOME isn't set"
  root=$(cd "$HOME/.hermes" 2>/dev/null && pwd -P) || die "no Hermes install in $HOME/.hermes"
  case "$root" in *[\'\|\\\&]*) die "can't use an install path with quotes, |, & or \\: $root" ;; esac
  checkout=$(cd "$root/hermes-agent" 2>/dev/null && pwd -P) || die "no Hermes checkout in $root/hermes-agent"
  # A tier's endpoint may speak Anthropic Messages, whose client is an extra Hermes
  # leaves out, and Bots can't add it (ADR 0076). Done already, this changes nothing.
  "$checkout/.hermes/bin/hermes" pm install --extra anthropic >&2 || die "couldn't add Hermes's anthropic extra"
  key=$(install_key "$checkout")
  state="$root/installs/$key"
  [ -f "$state/facts.json" ] || die "Hermes committed no environment for $checkout"
  env=$(sed -n 's/.*"environment": *"\([^"]*\)".*/\1/p' "$state/facts.json" | head -n 1)
  [ -n "$env" ] || die "$state/facts.json names no environment"
  gen=$(cd "$env/.." 2>/dev/null && pwd -P) || die "the committed environment is missing: $env"
  case "$gen" in "$state/environments/"*) ;; *) die "the committed environment isn't in $state/environments" ;; esac
  rm -f "$gen/.lease-managed"
  rm -rf "$gen/.leases"
  for g in "$state/environments"/*; do
    if [ -d "$g" ] && [ "$g" != "$gen" ]; then
      rm -rf "$g"
    fi
  done
  mkdir -p "$root/superbot"
  out="$root/superbot/hermes"
  sed -e "s|^root=\$|root='$root'|" -e "s|^key=\$|key=$key|" "$0" >"$out.tmp"
  chmod 0755 "$out.tmp"
  mv -f "$out.tmp" "$out"
  printf '%s\n' "$out"
  exit 0
fi

shared="$root/installs/$key"
home=${HERMES_HOME:-}
if [ -n "$home" ] && [ -f "$shared/facts.json" ] && [ "$(cd "$home" 2>/dev/null && pwd -P)" != "$root" ]; then
  own="$home/installs/$key"
  # A Bot from before this has an environment of its own here, which goes.
  if [ "$(readlink "$own/environments" 2>/dev/null)" != "$shared/environments" ]; then
    rm -rf "$own"
  fi
  if ! cmp -s "$shared/facts.json" "$own/facts.json" 2>/dev/null; then
    (umask 077 && mkdir -p "$own")
    chmod -R u+w "$own/inputs" "$own/inputs.new" 2>/dev/null || true
    rm -rf "$own/inputs" "$own/inputs.new"
    if [ -d "$shared/inputs" ]; then
      # -p: Hermes compares the stamps' times. u+w: the copy is the Bot's to replace.
      cp -pR "$shared/inputs" "$own/inputs.new"
      chmod -R u+w "$own/inputs.new"
      mv "$own/inputs.new" "$own/inputs"
    fi
    [ -L "$own/environments" ] || ln -s "$shared/environments" "$own/environments"
    cp -p "$shared/facts.json" "$own/facts.json.new"
    mv -f "$own/facts.json.new" "$own/facts.json"
  fi
  # Hermes reads the fallback chain only from a data root with a config.yaml of its
  # own, even when the chain is in the managed one (ADR 0076). Empty is no settings.
  if [ ! -e "$home/config.yaml" ]; then
    (umask 077 && : >>"$home/config.yaml")
  fi
  HERMES_DISABLE_LAZY_INSTALLS=1
  export HERMES_DISABLE_LAZY_INSTALLS
fi
exec "$root/hermes-agent/.hermes/bin/hermes" "$@"
