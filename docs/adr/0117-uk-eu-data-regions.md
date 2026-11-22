# 0117: UK and EU data regions for machines and their backups

## Status

Accepted (22 Nov 2026). Closes [#49](https://github.com/CG-Labs/superbot/issues/49) (M4, "UK/EU region option") and the "Data residency" row of the [roadmap](../ROADMAP.md) for managed plans. Builds on [ADR 0025](0025-control-plane-linode.md) (the Linode control plane and `MACHINE_REGIONS`), [ADR 0065](0065-incus-container-machines.md) (Incus containers), [ADR 0081](0081-placing-machines-by-host-load.md) (placing machines by host load), [ADR 0071](0071-off-host-machine-backups.md) (off-host machine backups) and [ADR 0108](0108-deleting-a-destroyed-machines-backups.md) (deleting a destroyed machine's backups). Server backups ([ADR 0109](0109-server-backups-off-the-host.md)) are unchanged.

0116 is the highest number on `main` (from [#179](https://github.com/CG-Labs/superbot/pull/179)).

## Context

Managed customers in the UK and the EU ask where their data lives. A user's machine holds the most personal data SuperBot keeps: their working folder, Bot memory and harness logins. Its off-host backups are full copies of the disk.

Before this change the operator chose regions (`MACHINE_REGIONS`), and any admin could ask for a machine in any of them with each request. Nothing remembered a customer's choice. An Incus fleet had no idea of region at all: placement put a machine on whichever host had room. And every backup went to one bucket, wherever that was. A customer could not be promised "London" or "Frankfurt" and have the product hold to it.

Linode region ids, checked against Linode's region list in November 2026:

| Place | Compute region | Object Storage endpoint | Note |
|--|--|--|--|
| London | `gb-lon` (London 2) | `gb-lon-1.linodeobjects.com` | `eu-west` is the older London site, closed to new customers |
| Frankfurt | `de-fra-2` (Frankfurt 2) | `de-fra-1.linodeobjects.com` | `eu-central` (the older Frankfurt site) still takes compute; its Object Storage is `eu-central-1.linodeobjects.com` |

We recommend `gb-lon` and `de-fra-2`. botd doesn't hard-code either: any id the operator lists works.

## Options

1. **A region field on each request only** (as before). It's easy, but nothing stops the next request, a retry or a recovery from landing elsewhere.
2. **A region per account and per team, binding on every path that makes or moves a machine** (chosen).
3. **A separate deployment per region.** This is full isolation, but it doubles the operations work, and one organisation can't have people in both regions. It stays the answer for enterprise dedicated hosting (M5).

## Decision

### The setting and who wins

- A server admin sets a region on a user (`PUT /api/users/{key}/region`) or on a team (`PUT /api/teams/{id}/region`), with a body of `{"region": "<id>"}`, or `{"region": null}` to clear it.
- The value must be one of `MACHINE_REGIONS`. That list is the operator's allowlist, and its first entry is the server's default.
- The most specific setting wins: the user's own region, else their team's, else the default.
- Admins see the result as `dataRegion` (`{region, source: user|team|default, offered}`) on users and machines. `GET /api/regions` lists every region, how many users, teams and machines are in each, and (for Incus) its hosts and backup store.

A region set on a user or their team is **binding**:

- A machine request that names another region is refused with 409 and audited as `machine.refused` with reason `data_region`.
- A request that names no region goes to the binding region.
- If the binding region is no longer in `MACHINE_REGIONS`, the request is refused rather than sent to the default.

A user with no setting, and no team setting, behaves as before. Each request may still name a region, and one that names none gets the default.

### Linode

A new machine is created in the user's region, as the Linode `region` field. Retries keep the region of the failed machine, unless a binding region says otherwise. Linode Backups (`MACHINE_BACKUPS=on`) are kept by Linode in the same data centre as the Linode, so they follow it.

### Incus hosts are tagged with a region

- `INCUS_REGION` sets a region for every host. `INCUS_REGION_<NAME>` sets it for one host and overrides `INCUS_REGION`.
- Either every host has a region or none does. botd refuses to start with only some tagged, or with a tag that isn't a region id (lowercase letters, digits and dashes).
- In a tagged fleet, `MACHINE_REGIONS` defaults to the tags in host order. If the operator sets it, every region listed must have at least one host.
- Regions are no longer sent to Incus as a cluster `target`. A fleet with no tags keeps the old meaning: cluster member names, or `local`.

Placement ([ADR 0081](0081-placing-machines-by-host-load.md)) only considers hosts in the machine's region. If none of them has room, the request fails with "No Incus host has room for a pro machine in gb-lon: ...". It never falls back to another region. The same check covers every path that moves a machine:

- restoring onto another host;
- recovering from a lost host;
- draining a host;
- an admin choosing a host, which is refused with "Host b is in de-fra-2, and this machine's data stays in gb-lon".

The hosts view shows each host's region, and placement grouped by region.

### Backups go to a store in the machine's region

A store can be set for each region. Its settings are the default store's, with the region in the name: `MACHINE_BACKUP_S3_<REGION>_BUCKET`, `_ENDPOINT`, `_REGION`, `_ACCESS_KEY_ID` and `_SECRET_ACCESS_KEY`. `<REGION>` is the id in upper case with `-` as `_`, for example `MACHINE_BACKUP_S3_GB_LON_BUCKET`.

- The secret access key is a server secret: Bots never get it, and it is redacted from logs.
- The default store (`MACHINE_BACKUP_S3_BUCKET`) still turns off-host backups on. The prefix, age recipients, interval and retention are shared by every store.
- `MACHINE_BACKUP_S3_DATA_REGION` says which region the default store is in, if any.
- A region may not have both its own store and the default store said to be in it.

A backup goes to its machine's region store, else to the default store. The store is recorded on each backup (`machine_backups.store_region`, with `NULL` meaning the default store). Pruning, restores, imports and deletion all use the recorded store, so changing settings never loses track of a backup. The `machine.backup_created` event and the manifest record the store, and `inRegion`.

`MACHINE_BACKUP_RESIDENCY` decides what happens when a region has no store of its own:

- **`warn`** (the default). The backup goes to the default store. botd logs a warning at startup, and the backups view and `GET /api/regions` show it, naming the setting that fixes it. Each out-of-region backup is logged too. Warn is the default because refusing to back up would leave a user with no copy at all.
- **`strict`**. botd refuses to start unless every region in `MACHINE_BACKUP_S3_*` has a store in it, and refuses a backup that has nowhere in-region to go. This mode is for customers who are promised residency in their contract.

### Changing a region with a machine is refused

There are two ways to handle a change of region for someone who already has a machine:

- move them through the existing rebuild or restore path;
- refuse the change.

**We refuse it.** A user's change is refused (409, `user.region_change_refused`) while they have a live machine outside the new region. A team's change is refused (`team.region_change_refused`) while any member without their own region has one. The error lists the steps to do it on purpose:

1. Destroy the machine.
2. Delete its backups if they must go too ([ADR 0108](0108-deleting-a-destroyed-machines-backups.md)).
3. Set the region.
4. Request a new machine.

We chose refusing over moving because:

- A move copies the user's whole disk across a border. That is a data transfer the customer, and perhaps their DPA, has to agree to. It shouldn't happen as a side effect of an admin changing a setting.
- The restore path ([ADR 0071](0071-off-host-machine-backups.md)) restores onto a host that can import the backup. The backup stays in the old region's store, so a "move" would leave copies behind anyway. Destroying first makes the operator decide about those copies.
- A Linode can't be moved to another data centre through our API. Migrating it would mean a new machine in any case.

A successful change records `user.region_changed` or `team.region_changed`, with the region before and after (both set and effective). If backups of an earlier machine are left in another region's store, the response says how many. They stay until their retention ends or they are deleted.

### Teams

- Joining a team that has a region is refused (409, `team.join_refused` with reason `data_region`) if the new member has no region of their own and already has a machine elsewhere. An admin can give them their own region first, or destroy the machine.
- Leaving a team moves nothing. A machine the team gave is released as before ([ADR 0087](0087-team-accounts-and-machines.md)), and the user's next machine follows their own region or the default.

### What stays where botd runs

The region covers users' machines and their backups only. botd's own database (users, chats, routines, the audit log), its local backups and its off-host copies ([ADR 0109](0109-server-backups-off-the-host.md)) stay where the operator runs botd. Model calls go wherever [Annex III](../security/dpa-template.md) says. For full residency in one country, run botd in that country too. The [subprocessor list](../security/subprocessors.md), [data flows](../security/data-flows.md) and [DPA template](../security/dpa-template.md) say so.

## Where it shows

- **botctl**:
  - `botctl regions`
  - `botctl user region <user> [<region>|default]`
  - `botctl team region <team> <region>|default`
  - `botctl machine request <user> [<tier>] [<region>]` is unchanged, but is checked against the binding region.
- **Console**:
  - a Data region column and button on Users;
  - a team's region and a Data region button on Teams;
  - each machine's region, and a line of regions and residency warnings on Machines.
- **App**: the team screen says where the team's machines and backups stay when it has a region. Each teammate's machine already shows its region to managers.

## Consequences

- An operator can offer "London" or "Frankfurt" and enforce it: a binding region is never silently ignored.
- Without a region store, a region's backups go to the default store, with warnings. Operators who promise residency set a store per region and `MACHINE_BACKUP_RESIDENCY=strict`.
- Moving a customer between regions is a deliberate, audited process with downtime, not a button. A tool that moves machines across regions could come later, if customers ask for it.
- A tagged Incus fleet with no room in a region refuses the request, even if other regions have room. The capacity view shows placement per region so operators can add hosts where they are needed.
- Self-hosting is unchanged unless the operator sets regions.

## Tests

- Unit tests:
  - precedence and validation (`region.rs`);
  - host tags, all-or-none and bad ids (`fleet.rs`);
  - per-region placement and refusal messages (`placement.rs`);
  - region stores, residency modes, stray settings and duplicates (`backup.rs`);
  - `MACHINE_REGIONS` against host tags (`machines/mod.rs`);
  - botctl's commands.
- End to end, against the fake Linode and the Incus stand-in (`machines_region_tests.rs`):
  - a user's Linode is made in their region;
  - a request elsewhere is refused and audited;
  - a team's region applies to members without their own;
  - region changes and team joins are refused while a machine is elsewhere, and audited;
  - Incus machines are placed only on hosts in their region;
  - backups go to that region's store, and are deleted from it;
  - a restore onto a host in another region is refused, and so is a new machine when its region has no room left;
  - after a destroy and purge, the region change goes through.
- The app's team screen and its region line (`team.test.ts`, `TeamView.test.tsx`).
