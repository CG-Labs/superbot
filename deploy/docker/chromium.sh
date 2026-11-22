#!/bin/sh
# The image's chromium (/usr/local/bin/chromium, ahead of Debian's /usr/bin/chromium on PATH, and
# AGENT_BROWSER_EXECUTABLE_PATH). agent-browser adds --no-sandbox whenever it sees a container, so
# this takes the flags that turn Chromium's sandbox off back out, unless the operator turned it
# off with SUPERBOT_CHROMIUM_SANDBOX=off (docs/adr/0107-chromium-sandbox-in-the-container.md).
# Chromium never falls back quietly: where the sandbox can't start, it stops with "No usable sandbox!".
set -eu

case "${SUPERBOT_CHROMIUM_SANDBOX:-on}" in
  on)
    for arg; do
      shift
      case "$arg" in
        --no-sandbox | --disable-namespace-sandbox | --disable-seccomp-filter-sandbox) ;;
        *) set -- "$@" "$arg" ;;
      esac
    done
    ;;
  off)
    echo "chromium: running without its sandbox (SUPERBOT_CHROMIUM_SANDBOX=off)" >&2
    set -- --no-sandbox "$@"
    ;;
  *)
    echo "chromium: SUPERBOT_CHROMIUM_SANDBOX must be on or off, not \"$SUPERBOT_CHROMIUM_SANDBOX\"" >&2
    exit 2
    ;;
esac
exec /usr/bin/chromium "$@"
