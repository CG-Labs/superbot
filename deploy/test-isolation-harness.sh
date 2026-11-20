#!/bin/sh
# A fake `claude` for deploy/test-isolation.sh: botd runs it as a per-user account and it
# reports, as one Claude Code reply, what that account could reach. The prompt says what to do:
#   WRITE-CREDS                       write a fake login into $HOME
#   SLEEP                             keep a heartbeat in the workspace until stopped
#   PROBE <other account> <name:path>...  try to read (and write next to) each path
set -u
for prompt; do :; done
me=$(id -un)

try_read() {
  if [ -d "$1" ]; then ls -A "$1" >/dev/null 2>&1; else head -c 1 "$1" >/dev/null 2>&1; fi && echo read || echo denied
}
try_write() {
  (: >"$1/probe-$me") 2>/dev/null && echo wrote || echo denied
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
    out="$out;bot_token=$s"
    ;;
  *)
    out="unknown prompt"
    ;;
esac
printf '{"type":"assistant","message":{"content":[{"type":"text","text":"%s"}]}}\n' "$out"
