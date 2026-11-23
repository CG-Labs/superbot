# 0188: Service accounts off their owner's team, flagged in access reviews

## Status

Accepted (23 Nov 2026). Ninth slice of [#53](https://github.com/CG-Labs/superbot/issues/53) (M5, "Advanced RBAC"), on top of [ADR 0165](0165-service-accounts-in-access-reviews.md) (service accounts in access reviews) and [ADR 0182](0182-delegates-own-service-accounts.md) (a team's service account acts in its team only while its owner is on it).

0188 was set aside for this change; other open pull requests hold 0180, 0185, 0186 and 0187.

## Context

ADR 0182 made a team's service account one of its team only while its owner is an admin or on that team. Otherwise it acts in no team: team routes answer 404 to its tokens. The Service accounts screen shows this as `ownerOnTeam` and flags it ("owner off its team").

The access review didn't. It listed such an account as "member, in Alpha", with Alpha's custom role and permissions, as if it still acted there. A reviewer couldn't tell an account doing its job from one stranded by its owner leaving the team. That second kind usually needs a decision: move it, hand it to someone on the team, or delete it. The flags the review already works out (ADR 0165) are where a reviewer looks for that.

## Decision

- Each service account in `GET /api/access-review` gets `ownerOnTeam`, worked out as the Service accounts screen does: whether its owner is an admin or on its team, or `null` when it's in no team. Both come from the same `Holdings`, so they can't disagree.
- A new flag, `owner_off_team`, is set when the owner is active but `ownerOnTeam` is false. An inactive owner already gets `owner_inactive` and lends nothing anywhere, so it gets only that one.
- The digest covers it, but only while the account acts in no team, so reports where every owner is on their account's team keep their digests. An owner leaving the team, or coming back, changes the digest, and the old sign-off is refused with 409.
- The CSV's `service_flags` column and the evidence bundle's `access-review.json` carry the flag, since both copy the server's flags. The bundle's service accounts also get `ownerOnTeam`. Its `format` stays 2: the field is added, and nothing changes shape.
- In the app, the flag reads "Owner off its team", and the role line says "in Alpha (acts in no team)". Against a server from before this change there's no `ownerOnTeam`, and the line is as before.

The review only reports this. It doesn't change what the account can do, which ADR 0182 already decides on every request.

## Alternatives considered

- **Drop the team from the review while the owner is off it.** That hides where the account was put, which is what the reviewer needs to fix it. Keeping the team and saying it acts in none shows both.
- **Flag it even when the owner is inactive.** Two flags for one cause. `owner_inactive` already means it can do nothing.
- **Leave it to the Service accounts screen.** The review is the dated record an auditor reads. Access that's stranded should show there, and in its CSV and bundle.

## Consequences

- A reviewer sees, beside each team's service account, whether it acts in its team, and is pointed at ones whose owner left.
- Reports that had a service account whose owner was off its team get a new digest after upgrading, so a review loaded before then needs a reload to sign off.
- Still to do for #53: service accounts owning Bots. That needs a rule for whose machine, plan, keys and memory a service account's Bot uses, and touches the machine code throughout.
