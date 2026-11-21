# Per-user containers on an Incus host

This guide covers running each user's machine as an unprivileged system container on an Incus host instead of a Linode VM ([ADR 0064](../adr/0064-incus-container-machines.md)). Everything else is unchanged: enrollment, Bots, harness logins, the user's folder, the Bots' own OS user and screens. Read the isolation boundary in the ADR before you choose containers over VMs.

These steps change only the Incus host you run them on. Placeholders look like `<incus-host-ip>`.

## 1. The host

Use a dedicated Linux host for SuperBot containers, with a current kernel and Incus 6 or later. Choose a storage pool driver that enforces disk sizes: zfs, btrfs or lvm. `dir` does not enforce sizes, and the preflight check flags it.

```bash
incus admin init            # pick zfs, btrfs or lvm for the pool
```

## 2. A bridge for SuperBot only

```bash
incus network create superbot0 ipv4.address=10.150.0.1/24 ipv4.nat=true
```

Keep the subnet private. Containers may never reach private ranges, and that includes this bridge's gateway, so a private subnet is what keeps them off the host.

## 3. A restricted project

```bash
incus project create superbot \
  -c restricted=true \
  -c restricted.networks.access=superbot0
```

`restricted=true` makes Incus refuse privileged containers, nesting, host paths, raw id maps and unmanaged devices in this project, for every client. Don't set any `restricted.*` option to `allow`. botd checks the project before every create and refuses if it is loosened.

## 4. botd's certificate

Make a key and certificate for botd, and trust it on the host:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -sha384 -nodes \
  -days 3650 -subj "/CN=superbot-botd" -keyout botd-incus.key -out botd-incus.crt
incus config trust add-certificate botd-incus.crt --name superbot-botd
```

The certificate is not project-restricted. On a plain bridge, Incus keeps network ACLs in the `default` project, and a restricted certificate can't manage them. So this key can administer the Incus host. Keep it like `LINODE_TOKEN`: in a secret file readable only by botd, never in a Bot's environment.

Expose the API on a private address only, and firewall it to botd's address:

```bash
incus config set core.https_address <incus-host-private-ip>:8443
```

The host's certificate is `/var/lib/incus/server.crt` (`cluster.crt` on a cluster). Copy it to botd's host.

## 5. botd

In botd's `.env`:

`INCUS_URL` must use the host's IP address, not a name, so botd can deny containers that address.

```bash
MACHINE_PROVIDER=incus
INCUS_URL=https://<incus-host-private-ip>:8443
INCUS_CLIENT_CERT_FILE=/etc/superbot/incus/botd-incus.crt
INCUS_CLIENT_KEY_FILE=/etc/superbot/incus/botd-incus.key
INCUS_SERVER_CERT_FILE=/etc/superbot/incus/server.crt
INCUS_PROJECT=superbot
INCUS_NETWORK=superbot0
MACHINE_CONTROL_URL=https://<botd-address>:8444
MACHINE_FIREWALL=on
```

Optional settings:

- `MACHINE_TIERS`, for example `starter=c1-m2-d20,pro=c2-m4-d40,max=c4-m8-d80`.
- `MACHINE_REGIONS`, with cluster member names.
- `INCUS_IMAGE_SERVER=local`, if images are imported by hand.
- `INCUS_EGRESS_DENY`, with the host's other public addresses and anything else containers must never reach.

botd dials each container's agent at its bridge address, so botd needs a route to `10.150.0.0/24`:

- **botd on the Incus host:** the route is already there. Set `MACHINE_FIREWALL_SOURCES=10.150.0.1/32`, because botd reaches containers from the bridge's gateway.
- **botd on another host (recommended):** route the subnet through the Incus host, for example `ip route add 10.150.0.0/24 via <incus-host-private-ip>`. Leave `MACHINE_FIREWALL_SOURCES` at its default, the control URL's address.

If `MACHINE_CONTROL_URL` uses a private IP, botd carves that address and port out of the containers' outbound deny list. If it uses a host name, it must resolve to an address containers may reach.

## 6. Check

```bash
botctl machine substrate check
```

The check confirms four things: botd is trusted and Incus has the API extensions botd needs, the project is restricted, the network is a managed bridge, and the pool enforces sizes. Then give someone a machine and watch it enroll:

```bash
botctl machine request <user> starter
botctl machine reconcile
botctl machine show <user>        # state running, enrollment enrolled, agentSeenAt set
```

## Limits to know

- Containers share the host's kernel. A kernel escape crosses every boundary. Use VMs for tiers that need their own kernel.
- Snapshots (daily, kept 7 days) stay on the same pool. They don't protect against losing the host.
- Switching `MACHINE_PROVIDER` leaves machines made by the other provider as they are. botd reaches their agents but won't change them until you switch back.
