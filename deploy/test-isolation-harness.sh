#!/bin/sh
# A fake `claude`, `pi` and `hermes` for deploy/test-isolation.sh (installed under each
# name): botd runs it as a per-user account and it reports, as one reply in that harness's
# format, what that account could reach. The prompt says what to do:
#   WRITE-CREDS                       write a fake login into $HOME
#   SLEEP                             keep a heartbeat in the workspace until stopped
#   LEAVE                             answer and exit, leaving the heartbeat going
#   PROBE <other account> <name:path>...  try to read (and write next to) each path
# Run as `claude auth login` (a teammate's login, ADR 0064), it writes a login into $HOME.
# As hermes, a probe also leaves a gateway.pid, so botd runs `hermes gateway stop` after.
set -u
harness=$(basename "$0")
me=$(id -un)
if [ "$harness" = hermes ] && [ "${1:-}" = gateway ]; then
  id -un >"$HERMES_HOME/stopped-by" && rm -f "$HERMES_HOME/gateway.pid"
  exit
fi
if [ "$harness" = claude ] && [ "${1:-}" = auth ] && [ "${2:-}" = login ]; then
  mkdir -p "$HOME/.claude" && printf 'LOGIN-%s\n' "$me" >"$HOME/.claude/.credentials.json"
  echo "logged in as $me"
  exit
fi
if [ "$harness" = hermes ]; then
  prompt=$(cat)
else
  for prompt; do :; done
fi

try_read() {
  if [ -d "$1" ]; then ls -A "$1" >/dev/null 2>&1; else head -c 1 "$1" >/dev/null 2>&1; fi && echo read || echo denied
}
try_write() {
  (: >"$1/probe-$me") 2>/dev/null && echo wrote || echo denied
}
# botd's files for the run: the account may read them, never change or replace them.
try_change() {
  (: >>"$1") 2>/dev/null && echo wrote || echo denied
}
try_replace() {
  mv -f "$1" "$1.moved" 2>/dev/null && echo wrote || echo denied
}
verdict() {
  if "$@" >/dev/null 2>&1; then echo allowed; else echo denied; fi
}

case "$prompt" in
  WRITE-CREDS)
    mkdir -p "$HOME/.claude" && printf 'A-SECRET\n' >"$HOME/.claude/.credentials.json" && out=wrote || out=failed
    ;;
  SLEEP)
    # A tool that ignores TERM and would outlive the harness: only KILL stops it.
    (trap '' TERM; while :; do date +%s.%N >"$PWD/heartbeat"; sleep 0.2; done) &
    sleep 300
    out=slept
    ;;
  LEAVE)
    # Left behind holding stdout, so botd would wait for it forever.
    (trap '' TERM; while :; do date +%s.%N >"$PWD/heartbeat"; sleep 0.2; done) &
    sleep 1
    out=left
    ;;
  PROBE*)
    # shellcheck disable=SC2086 # the prompt is words on purpose
    set -- $prompt
    other=$2
    shift 2
    out="user=$me;home=$HOME;pwd=$(pwd -P);tmpdir=${TMPDIR:-}"
    for t; do
      k=${t%%:*} p=${t#*:}
      out="$out;$k=$(try_read "$p")"
      case $k in
        a_workspace | all_users) out="$out;write_$k=$(try_write "$p")" ;;
        a_memory) out="$out;write_a_memory=$(try_write "$(dirname "$p")")" ;;
        guard | managed) out="$out;write_$k=$(try_change "$p");replace_$k=$(try_replace "$p")" ;;
        state) out="$out;write_state=$(try_write "$p")" ;;
      esac
    done
    out="$out;sudo_root=$(verdict sudo -n true)"
    out="$out;sudo_other=$(verdict sudo -n -u "$other" true)"
    out="$out;sudo_userctl=$(verdict sudo -n /usr/local/sbin/superbot-userctl ensure x)"
    n=0
    for d in /proc/[0-9]*; do
      u=$(stat -c %U "$d" 2>/dev/null) || continue
      [ "$u" = "$me" ] || n=$((n + 1))
    done
    out="$out;other_procs=$n"
    if [ -n "${AUTH_PASSWORD:-}${SUPERBOT_MASTER_KEY:-}" ]; then s=present; else s=absent; fi
    out="$out;server_secrets=$s"
    if [ -n "${BOT_TOKEN:-}" ]; then s=present; else s=absent; fi
    out="$out;bot_token=$s;bot_token_bot=${BOT_TOKEN%%.*}"
    out="$out;harness=$harness"
    [ "$harness" != hermes ] || { mkdir -p "$HERMES_HOME" && : >"$HERMES_HOME/gateway.pid"; }
    ;;
  *)
    out="unknown prompt"
    ;;
esac
case "$harness" in
  pi) printf '{"type":"message_end","message":{"role":"assistant","content":[{"type":"text","text":"%s"}]}}\n' "$out" ;;
  hermes) printf '{"type": "text", "text": "%s"}\n{"type": "result", "session_id": "local-1", "exit_code": 0}\n' "$out" ;;
  *) printf '{"type":"assistant","message":{"content":[{"type":"text","text":"%s"}]}}\n' "$out" ;;
esac
