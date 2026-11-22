# Rotating the master key

How to replace the key botd encrypts the database and seals saved secrets with, for both supported installs: the [VPS installer](../../deploy/README.md) (systemd) and [Docker Compose](../../deploy/README.md#docker-compose-supported). Design: [ADR 0096](../adr/0096-master-key-rotation.md); the key itself: [ADR 0010](../adr/0010-secrets.md).

## How it works

You give botd the new key as its master key and the old key as the **previous** key, then restart. On start, botd opens every sealed value with the old key and seals it again under the new one, in one database transaction with a `secret.master_key_rotated` audit event. If botd stops part-way, nothing has changed: restart with both keys and it tries again. Once it has rotated, the old key is no longer needed and you remove it.

An encrypted database ([database encryption](database-encryption.md), [ADR 0116](../adr/0116-database-encrypted-at-rest.md)) is re-encrypted first: botd writes a copy under a key derived from the new master key, checks every table's rows came across, and swaps it in, before it seals values again. Each step can be repeated: a database already under the new key is left as it is, and one still under the old key is re-encrypted on the next start with both keys. No copy under the old key is kept.

What is sealed again: saved secrets (`botctl secret set`, `/api/secrets`), each user's own secrets, approvals' tool input, push tokens, and TOTP secrets for two-factor sign-in. Derived keys, such as the machine CA, are kept, so enrolled machines keep working (see [after a leak](#after-a-leak)). Backup encryption uses age keys, not the master key ([backup guide](backup-restore.md#encryption)).

| Setting | Meaning |
|---------|---------|
| `SUPERBOT_MASTER_KEY_PREVIOUS` | The old key: 64 hex characters or base64 of 32 bytes |
| `SUPERBOT_MASTER_KEY_PREVIOUS_FILE` | Or a file holding it: owner-only (`0600`), outside `DATA_DIR`. Not both |
| `SUPERBOT_ROTATE_DERIVED_KEYS=1` | Also replace derived keys: a new machine CA, and every machine enrolls again; MFA recovery codes are deleted |

## Before you start

1. Copy the **current** key off the host, labelled with today's date, apart from the backups. Backups taken until now are encrypted and sealed under it, and restoring one needs it.
2. Take a backup (`sudo systemctl start superbot-backup`, or `docker compose exec botd superbot-backup`).

## Docker Compose

From `deploy/docker`:

```sh
./init.sh --rotate-master-key   # current key -> SUPERBOT_MASTER_KEY_PREVIOUS, new SUPERBOT_MASTER_KEY in .env
docker compose up -d            # botd restarts, re-encrypts the database and seals everything again under the new key
docker compose logs botd | grep -E 'Master key rotated|nothing to rotate'
```

Then copy the new `SUPERBOT_MASTER_KEY` off the host, delete the `SUPERBOT_MASTER_KEY_PREVIOUS=` line from `.env`, and run `docker compose up -d` again.

`init.sh --rotate-master-key` refuses while `SUPERBOT_MASTER_KEY_PREVIOUS` is set, so a second run can't overwrite the key the data is still sealed under. To bring your own key instead, set the two lines in `.env` by hand.

## VPS installer

The installer keeps the key in a file, `~superbot/.config/superbot/master.key` unless `.env` names another with `SUPERBOT_MASTER_KEY_FILE`. As root:

```sh
H=$(getent passwd superbot | cut -d: -f6)
K=$H/.config/superbot/master.key        # or the SUPERBOT_MASTER_KEY_FILE in $H/superbot/.env
if sudo test -e "$K.previous" || sudo grep -q '^SUPERBOT_MASTER_KEY_PREVIOUS' "$H/superbot/.env"; then
  echo "A rotation is pending: restart botd and check its log instead of repeating these steps."
else
  sudo -u superbot cp -p "$K" "$K.previous"                   # the old key, still 0600
  sudo -u superbot sh -c 'umask 077 && openssl rand -base64 32 > "$1.new" && mv "$1.new" "$1"' sh "$K"
  echo "SUPERBOT_MASTER_KEY_PREVIOUS_FILE=$K.previous" | sudo tee -a "$H/superbot/.env" >/dev/null
fi
sudo systemctl restart superbot
journalctl -u superbot --since -5min | grep -E 'Master key rotated|nothing to rotate'
```

Run the block once. If the restart fails before the log says `Master key rotated`, fix the cause and run `sudo systemctl restart superbot` again; don't repeat the block, or the old key would be overwritten. The check at the top refuses while `master.key.previous` or the `.env` line exists.

Then copy the new key off the host, delete the `SUPERBOT_MASTER_KEY_PREVIOUS_FILE=` line from `.env`, run `sudo systemctl restart superbot`, and remove the old file with `sudo shred -u "$K.previous"` once its off-host copy is safe.

If `.env` holds the key itself (`SUPERBOT_MASTER_KEY=`), add `SUPERBOT_MASTER_KEY_PREVIOUS=<old key>` and replace the `SUPERBOT_MASTER_KEY=` value with `openssl rand -hex 32` instead.

## Check it worked

- The log says `Master key rotated from ...: sealed N values again under the new key`, and, for an encrypted database, `Database encryption: ... re-encrypted under the new master key`.
- The audit log has one `secret.master_key_rotated` event (`/api/audit?action=secret.master_key_rotated`, or the console's audit page), with the counts. `unreadable` above 0 means some values were already unreadable before the rotation; they are left as they were, and botd warns.
- After removing the previous key and restarting, botd starts with the new key alone and `botctl secrets` lists what it did before.

## If something goes wrong

| What you see | What it means | What to do |
|--------------|---------------|------------|
| botd stopped or crashed during the rotation | Nothing was committed; everything is still under the old key | Start again with both keys set. Don't run the rotation steps again: they would replace the old key |
| `neither the master key nor SUPERBOT_MASTER_KEY_PREVIOUS opens this database` | The previous key is not the one the data is sealed with | Fix the previous key and start again. Nothing changed |
| `neither the master key nor SUPERBOT_MASTER_KEY_PREVIOUS opens the encrypted database (wrong key)` | The database is encrypted under neither key | Set the previous key to the one it was encrypted under and start again. Nothing changed |
| `SUPERBOT_MASTER_KEY_PREVIOUS is set but there is no new master key` | The new key is missing | Set it. botd never makes a key during a rotation |
| `wrong key` after removing the previous key | The previous key was removed before botd rotated | Put it back and restart |
| `nothing to rotate` | The current key already opens everything (already rotated, or the same key twice) | Remove the previous key |
| The new key is lost after the rotation | The old key no longer opens the data | As for any lost key: restore a backup from before the rotation with the old key. With a plain database, `SUPERBOT_FORGET_SEALED=1` also works ([master key](../../deploy/README.md#master-key)); an encrypted one can't be opened without its key |

## Restoring a backup from before a rotation

The archive's database and sealed values are under the old key. Restore as usual ([backup guide](backup-restore.md#restore)), and before starting botd set the old key as the previous key and keep the current key: botd rotates the restored database on start. Or start it with the old key alone.

## After a leak

If the old key may have leaked:

- Rotate with `SUPERBOT_ROTATE_DERIVED_KEYS=1` set for that start, then remove it. Derived keys then come from the new key, so the machine CA changes and every managed machine must enroll again with a new token ([ADR 0031](../adr/0031-machine-enrollment-mtls.md)). MFA recovery codes are deleted too, since they are hashed under a derived key: tell users with two-factor sign-in to make new ones (their authenticator app keeps working). Without it, the CA is kept, and whoever holds the old key can derive the CA's key.
- Rotate the secrets themselves (API keys, tokens) at their providers: anyone with the old key and a copy of the database or a backup from before can read the values in it, and the database itself.
- Old backups stay readable with the old key. Delete the ones you don't need.
