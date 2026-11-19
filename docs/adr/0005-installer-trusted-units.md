# 0005: Root installs units only from a root-controlled source

Date: 2026-11-19. Status: accepted.

## Decision

- `deploy/install.sh` runs as root but never reads systemd units or the backup script from `~superbot/superbot`. The service user owns that tree and could edit a unit to run as root.
- `curl | bash`: root fetches `REPO_URL` into a root-owned bare repo (`/usr/local/share/superbot/src.git`) and stages `deploy/` with `git show` into `/usr/local/share/superbot/deploy`.
- Local checkout: copied to the same place, and refused if owned by or under the service user's home.
- Units are rendered, not copied: `User=`, `Group=`, `WorkingDirectory=`, `EnvironmentFile=`, and `ExecStart=` are set by the installer. Other `Exec*=`, `DynamicUser=`, `AmbientCapabilities=` and similar make the install fail.

## Why

- Upgrades used to copy whatever the service user left in the checkout into `/etc/systemd/system` and restart it as root.
