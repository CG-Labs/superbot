#!/usr/bin/env bash
# Makes a throwaway Ubuntu host into an Incus host for the real-Incus end-to-end test
# (server/src/machines_incus_e2e_tests.rs, ADR 0069), the way docs/ops/incus-containers.md
# sets one up: a storage pool, a SuperBot-only bridge, a restricted project, the API on
# the bridge's address, and a trusted client certificate for botd. A second restricted
# project stands in for a second Incus host, for the host-loss drill (ADR 0076).
#
# Usage: sudo SUPERBOT_INCUS_E2E_THROWAWAY=1 deploy/incus-e2e-host.sh <out-dir>
#
# It writes <out-dir>/incus-e2e.env with the settings the test reads, and botd's
# certificate and key beside it, owned by the user who ran sudo.
#
# INCUS_SOURCE: zabbly (default, the current stable release), zabbly-lts-7.0 (or another
# Zabbly LTS channel), or ubuntu (the distro's). 6.0 is too old for botd (ADR 0069).
# POOL_DRIVER: btrfs (default, on a loop file; it enforces disk sizes) or dir.
set -euo pipefail

out=${1:?usage: deploy/incus-e2e-host.sh <out-dir>}
if [[ ${SUPERBOT_INCUS_E2E_THROWAWAY:-} != 1 ]]; then
  echo "This reconfigures the host's Incus and firewall. Run it only on a throwaway host, with SUPERBOT_INCUS_E2E_THROWAWAY=1." >&2
  exit 1
fi
if [[ $(id -u) != 0 ]]; then
  echo "Run it as root." >&2
  exit 1
fi
source_=${INCUS_SOURCE:-zabbly}
driver=${POOL_DRIVER:-btrfs}
gateway=10.150.0.1
network=superbot0
project=superbot
# The second "host": the same Incus, another project.
project_b=superbot-b

say() { printf '==> %s\n' "$*"; }

install_incus() {
  if command -v incus >/dev/null 2>&1; then
    return
  fi
  export DEBIAN_FRONTEND=noninteractive
  case $source_ in
    zabbly | zabbly-lts-*)
      channel=stable
      [[ $source_ == zabbly-lts-* ]] && channel=${source_#zabbly-}
      say "Installing Incus from the Zabbly $channel repository"
      mkdir -p /etc/apt/keyrings
      curl -fsSL https://pkgs.zabbly.com/key.asc -o /etc/apt/keyrings/zabbly.asc
      # shellcheck source=/dev/null
      codename=$(. /etc/os-release && echo "$VERSION_CODENAME")
      echo "deb [signed-by=/etc/apt/keyrings/zabbly.asc] https://pkgs.zabbly.com/incus/$channel $codename main" \
        >"/etc/apt/sources.list.d/zabbly-incus-$channel.list"
      ;;
    ubuntu) say "Installing Incus from Ubuntu's archive" ;;
    *) echo "INCUS_SOURCE must be zabbly, zabbly-lts-<version> or ubuntu" >&2; exit 1 ;;
  esac
  apt-get update -qq
  apt-get install -y -qq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
    incus btrfs-progs >/dev/null
}

install_incus
incus admin waitready --timeout=120
say "Incus $(incus version | sed -n 's/^Server version: //p')"

if ! incus storage show default >/dev/null 2>&1; then
  say "Storage pool default ($driver)"
  case $driver in
    btrfs) incus storage create default btrfs size=15GiB ;;
    dir) incus storage create default dir ;;
    *) echo "POOL_DRIVER must be btrfs or dir" >&2; exit 1 ;;
  esac
fi

if ! incus network show "$network" >/dev/null 2>&1; then
  say "Bridge $network ($gateway/24)"
  incus network create "$network" ipv4.address="$gateway/24" ipv4.nat=true
fi

for p in "$project" "$project_b"; do
  if ! incus project show "$p" >/dev/null 2>&1; then
    say "Restricted project $p"
    incus project create "$p" -c restricted=true -c restricted.networks.access="$network"
  fi
  # Off-host backups export containers (ADR 0071); a restricted project blocks that otherwise.
  incus project set "$p" restricted.backups=allow
done

say "API on $gateway:8443"
incus config set core.https_address="$gateway:8443"

# Docker's FORWARD policy is drop, which would cut containers off the internet.
if command -v iptables >/dev/null 2>&1 && iptables -n -L DOCKER-USER >/dev/null 2>&1; then
  say "Letting $network through Docker's forwarding rules"
  iptables -C DOCKER-USER -i "$network" -j ACCEPT 2>/dev/null || iptables -I DOCKER-USER -i "$network" -j ACCEPT
  iptables -C DOCKER-USER -o "$network" -j ACCEPT 2>/dev/null || iptables -I DOCKER-USER -o "$network" -j ACCEPT
fi

mkdir -p "$out"
if [[ $(incus config trust list --format csv) != *client,superbot-botd,* ]]; then
  say "botd's client certificate, trusted"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -sha384 -nodes -days 30 \
    -subj "/CN=superbot-botd" -keyout "$out/botd-incus.key" -out "$out/botd-incus.crt" 2>/dev/null
  incus config trust add-certificate "$out/botd-incus.crt" --name superbot-botd
fi
cp /var/lib/incus/server.crt "$out/server.crt"

cat >"$out/incus-e2e.env" <<EOF
SUPERBOT_INCUS_E2E=1
INCUS_URL=https://$gateway:8443
INCUS_CLIENT_CERT_FILE=$out/botd-incus.crt
INCUS_CLIENT_KEY_FILE=$out/botd-incus.key
INCUS_SERVER_CERT_FILE=$out/server.crt
INCUS_PROJECT=$project
INCUS_NETWORK=$network
INCUS_STORAGE_POOL=default
SUPERBOT_INCUS_E2E_PROJECT_B=$project_b
INCUS_SERVER_CERT_B_FILE=$out/server.crt
EOF
if [[ -n ${SUDO_USER:-} ]]; then
  chown -R "$SUDO_USER:" "$out"
fi
chmod 600 "$out/botd-incus.key"
say "Wrote $out/incus-e2e.env"
