#!/usr/bin/env bash
# Measures each harness CLI's per-Bot footprint on this machine (ADR 0070): disk for the
# install and per Bot, cold and warm start, memory (RSS and PSS), CPU and processes per
# run, what is left running when idle, several Bots at once, and how many runs fit each
# tier's machine. Writes footprint.json and footprint.md.
#
# It starts a throwaway botd per harness (its own temp data, a free loopback port) and
# never touches the running service. By default the model is the fake one CI uses, so no
# login or key is needed and nothing costs money; each fake call is held for a moment
# (--model-delay-ms) so a run stays up about as long as with a fast real model.
#
# Run it from a checkout, e.g. on a machine sized like a tier's:
#   deploy/harness-footprint.sh --install-clis /tmp/clis --out /tmp/footprint
# It needs cargo (the installer's build user has it) and git.
#
# Options:
#   --harness LIST       comma-separated: hermes,claude,codex,pi (default: those on PATH)
#   --install-clis DIR   first install the pinned CLIs for LIST (or all four) under DIR
#                        with deploy/install-harness-clis.sh, and use those
#   --out DIR            where the report goes (default: target/footprint)
#   --runs N             typical runs per harness (default 3)
#   --concurrency N      Bots running at once (default 4)
#   --model-delay-ms N   how long each fake model call takes (default 1500)
#   --reserve-mib N      memory a machine keeps before any run (default 512)
#   --cpus N             run everything on the first N CPUs (taskset), e.g. 1 to see a
#                        Starter machine's single vCPU; memory is not limited
#   --report-only        don't fail on a broken ceiling, just report it
#   --real               use the harnesses' own logins and real models instead (opt-in;
#                        each run makes a few short model calls on the logged-in account)
#   --env-file FILE      with --real: KEY=VALUE lines for provider keys and Hermes settings
#   --model NAME         with --real: the test Bots' model (Hermes needs one)
# Exit status: 0 when measured within the ceilings, 1 otherwise, 2 on bad usage.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/.." && pwd)

harnesses=""
clis=""
out="$repo/target/footprint"
mode=fake
cpus=""
caller_path=$PATH
usage() { sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d; s/^# \{0,1\}//'; exit 2; }
die() { printf 'harness-footprint: %s\n' "$*" >&2; exit 2; }
number() { [[ "$2" =~ ^[0-9]+$ ]] || die "$1 needs a number"; }

while (( $# )); do
  case "$1" in
    --harness) [[ $# -ge 2 ]] || die "--harness needs a value"; harnesses=$2; shift 2 ;;
    --install-clis) [[ $# -ge 2 ]] || die "--install-clis needs a folder"; clis=$2; shift 2 ;;
    --out) [[ $# -ge 2 ]] || die "--out needs a folder"; out=$2; shift 2 ;;
    --runs) [[ $# -ge 2 ]] || die "--runs needs a value"; number "$1" "$2"; export SUPERBOT_FOOTPRINT_RUNS=$2; shift 2 ;;
    --concurrency) [[ $# -ge 2 ]] || die "--concurrency needs a value"; number "$1" "$2"; export SUPERBOT_FOOTPRINT_CONCURRENCY=$2; shift 2 ;;
    --model-delay-ms) [[ $# -ge 2 ]] || die "--model-delay-ms needs a value"; number "$1" "$2"; export SUPERBOT_FOOTPRINT_MODEL_DELAY_MS=$2; shift 2 ;;
    --reserve-mib) [[ $# -ge 2 ]] || die "--reserve-mib needs a value"; number "$1" "$2"; export SUPERBOT_FOOTPRINT_RESERVE_MIB=$2; shift 2 ;;
    --cpus) [[ $# -ge 2 ]] || die "--cpus needs a value"; number "$1" "$2"; (( $2 >= 1 )) || die "--cpus needs at least 1"; cpus=$2; shift 2 ;;
    --report-only) export SUPERBOT_FOOTPRINT_CEILINGS=off; shift ;;
    --real) mode=real; shift ;;
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
    --model) [[ $# -ge 2 ]] || die "--model needs a value"; export SUPERBOT_E2E_BOT_MODEL=$2; shift 2 ;;
    -h|--help) usage ;;
    *) die "unknown option $1 (see --help)" ;;
  esac
done

# shellcheck disable=SC2030 # PATH only widened for this lookup
cargo=$(PATH="$PATH:$caller_path"; command -v cargo) || die "cargo isn't on PATH (run as the user that builds SuperBot)"
command -v git >/dev/null || die "git isn't on PATH"

if [[ -n "$clis" ]]; then
  mkdir -p "$clis"
  clis=$(cd "$clis" && pwd)
  list=${harnesses:-hermes,claude,codex,pi}
  # shellcheck disable=SC2086 # one word per harness
  "$here/install-harness-clis.sh" "$clis" ${list//,/ } | tee "$clis.paths"
  while IFS= read -r p; do
    # shellcheck disable=SC2031 # the PATH this script runs with, not the lookup's
    [[ "$p" == /* ]] && PATH="$p:$PATH"
  done <"$clis.paths"
  export PATH
  harnesses=$list
fi

if [[ -z "$harnesses" ]]; then
  found=()
  for h in hermes claude codex pi; do
    command -v "$h" >/dev/null && found+=("$h")
  done
  (( ${#found[@]} )) || die "no harness CLI on PATH (hermes, claude, codex, pi); try --install-clis DIR"
  harnesses=$(IFS=,; echo "${found[*]}")
fi
for h in ${harnesses//,/ }; do
  case "$h" in claude|codex|pi|hermes) ;; *) die "unknown harness $h" ;; esac
  command -v "$h" >/dev/null || die "$h isn't on PATH"
done

mkdir -p "$out"
out=$(cd "$out" && pwd)
printf 'Building botd and the measurement (release)...\n'
(cd "$repo" && "$cargo" test --release --test harness_footprint --no-run --quiet)

pin=()
if [[ -n "$cpus" ]]; then
  command -v taskset >/dev/null || die "--cpus needs taskset (util-linux)"
  # The first N CPUs this process may use (a container's need not start at 0).
  allowed=()
  IFS=, read -ra ranges < <(awk '/^Cpus_allowed_list:/ {print $2}' /proc/self/status)
  for r in "${ranges[@]}"; do
    mapfile -t -O "${#allowed[@]}" allowed < <(seq "${r%-*}" "${r#*-}")
  done
  (( cpus <= ${#allowed[@]} )) || die "--cpus $cpus: only ${#allowed[@]} CPUs available"
  pin=(taskset -c "$(IFS=,; echo "${allowed[*]:0:cpus}")")
  export SUPERBOT_FOOTPRINT_CPUS=$cpus
fi

printf 'Measuring %s against the %s model...\n\n' "$harnesses" "$mode"
status=0
(cd "$repo" && SUPERBOT_E2E_MODEL=$mode SUPERBOT_E2E_HARNESSES=$harnesses SUPERBOT_E2E_REQUIRE=1 SUPERBOT_FOOTPRINT_OUT=$out \
  "${pin[@]}" "$cargo" test --release --test harness_footprint --quiet -- --ignored --nocapture --test-threads=1) || status=1

[[ -s "$out/footprint.json" ]] || { printf 'harness-footprint: no report was written\n' >&2; exit 1; }
printf '\nReport: %s/footprint.md and %s/footprint.json\n' "$out" "$out"
exit "$status"
