#!/usr/bin/env bash
# Checks SuperBot's approvals end to end through each harness CLI on this server, with
# the harnesses' own logins and real models (ADR 0056). CI runs the same test with a
# fake model; this is the part only a logged-in server can do.
#
# It starts a throwaway botd (its own temp data, a free loopback port, a fresh policy
# in ask mode) and never touches the running service. Per harness, four calls:
#   - an allowed command runs without asking;
#   - a command a deny rule matches is blocked at once and never runs;
#   - a `git push` (to a local test repo) waits for approval and runs once approved;
#   - another waits and fails once denied.
#
# Run it from a checkout as the user whose harness logins you want to test, e.g.:
#   sudo -u superbot -H bash -lc 'cd ~/superbot && deploy/harness-e2e.sh'
# It needs cargo (the installer's build user has it) and git. Each run makes a few
# short model calls per harness on the logged-in account.
#
# Options:
#   --harness LIST   comma-separated: claude,codex,pi,hermes (default: those on PATH)
#   --env-file FILE  read KEY=VALUE lines (e.g. the server's .env) for provider keys
#                    and Hermes settings; only harness and provider variables reach
#                    the throwaway botd, never botd's own settings or secrets
#   --pass-env LIST  more variables, by name, to hand to the throwaway botd
#   --model NAME     the test Bot's model (else each harness's default)
#   --fake           use the fake model instead, as CI does (no login needed)
# Exit status: 0 when every check passed, 1 when one failed, 2 on bad usage.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/.." && pwd)

harnesses=""
mode=real
usage() { sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d; s/^# \{0,1\}//'; exit 2; }
die() { printf 'harness-e2e: %s\n' "$*" >&2; exit 2; }

while (( $# )); do
  case "$1" in
    --harness) [[ $# -ge 2 ]] || die "--harness needs a value"; harnesses=$2; shift 2 ;;
    --env-file)
      [[ $# -ge 2 && -r "$2" ]] || die "--env-file needs a readable file"
      # Literal KEY=VALUE lines, never run as shell: .env values aren't quoted.
      while IFS= read -r line || [[ -n "$line" ]]; do
        line=${line%$'\r'}
        if [[ "$line" =~ ^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
          key=${BASH_REMATCH[2]} value=${BASH_REMATCH[3]}
          if [[ "$value" =~ ^\"(.*)\"$ || "$value" =~ ^\'(.*)\'$ ]]; then value=${BASH_REMATCH[1]}; fi
          export "$key=$value"
        fi
      done <"$2"
      shift 2 ;;
    --pass-env) [[ $# -ge 2 ]] || die "--pass-env needs a value"; export SUPERBOT_E2E_PASS_ENV=$2; shift 2 ;;
    --model) [[ $# -ge 2 ]] || die "--model needs a value"; export SUPERBOT_E2E_BOT_MODEL=$2; shift 2 ;;
    --fake) mode=fake; shift ;;
    -h|--help) usage ;;
    *) die "unknown option $1 (see --help)" ;;
  esac
done

command -v cargo >/dev/null || die "cargo isn't on PATH (run as the user that builds SuperBot)"
command -v git >/dev/null || die "git isn't on PATH"

if [[ -z "$harnesses" ]]; then
  found=()
  for h in claude codex pi hermes; do
    command -v "$h" >/dev/null && found+=("$h")
  done
  (( ${#found[@]} )) || die "no harness CLI on PATH (claude, codex, pi, hermes)"
  harnesses=$(IFS=,; echo "${found[*]}")
fi
for h in ${harnesses//,/ }; do
  case "$h" in claude|codex|pi|hermes) ;; *) die "unknown harness $h" ;; esac
  command -v "$h" >/dev/null || die "$h isn't on PATH"
  version=$("$h" --version 2>&1 || true)
  printf '%-7s %s (%s)\n' "$h" "$(command -v "$h")" "${version%%$'\n'*}"
done

printf 'Building botd and the test (release)...\n'
(cd "$repo" && cargo test --release --test harness_e2e --no-run --quiet)

printf 'Checking %s against the %s model...\n\n' "$harnesses" "$mode"
log=$(mktemp)
trap 'rm -f "$log"' EXIT
status=0
# One at a time, so each harness's output stays together.
(cd "$repo" && SUPERBOT_E2E_MODEL=$mode SUPERBOT_E2E_HARNESSES=$harnesses SUPERBOT_E2E_REQUIRE=1 \
  cargo test --release --test harness_e2e --quiet -- --ignored --nocapture --test-threads=1) 2>&1 | tee "$log" || status=1

printf '\nSummary\n'
for h in ${harnesses//,/ }; do
  passed=$(grep -c "^PASS $h:" "$log" || true)
  if [[ "$passed" == 4 ]]; then
    printf '  PASS  %-7s 4 of 4 checks\n' "$h"
  else
    printf '  FAIL  %-7s %s of 4 checks (see the output above)\n' "$h" "$passed"
    status=1
  fi
done
exit "$status"
