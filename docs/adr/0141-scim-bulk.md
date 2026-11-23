# 0141: SCIM Bulk

## Status

Accepted (22 Nov 2026). Part of SCIM provisioning in M5, [#51](https://github.com/CG-Labs/superbot/issues/51). Builds on the SCIM stub and its review ([ADR 0023](0023-scim.md), [ADR 0026](0026-scim-review-hardening.md)), groups as teams ([ADR 0095](0095-scim-groups-as-teams.md)) and deprovisioning ([ADR 0124](0124-deprovisioning-stops-bots-and-machines.md)).

Numbering: first merged as 0149, renumbered to 0141 because 0149 was also taken by the audit checkpoints ADR.

## Context

#51's remaining items were group-to-role mapping (its own pull request), Google Workspace (no generic SCIM client; the guide's workaround stands), and Bulk. `ServiceProviderConfig` said `bulk.supported: false`.

RFC 7644 section 3.7 defines `POST /Bulk`: one request carrying many POST, PUT, PATCH and DELETE operations, with client-chosen `bulkId`s that later operations use (`bulkId:qwerty`) to refer to a resource an earlier POST made, `failOnErrors` to stop after that many errors, and a `maxOperations` and `maxPayloadSize` the server must advertise and enforce with 413. Entra ID and Okta don't send Bulk, but other SCIM clients and provisioning connectors (and customers' own sync scripts) do, and an initial load of thousands of people is far fewer round trips with it.

What Bulk must not be is a second way in: every check a single request gets (the token's tenant, attribute validation, body limits, the rate limit, the seat check, never a role) and every side effect (sessions ended, routines paused, Bots stopped, the machine suspended, team joins and leaves, audit events) has to happen exactly as it does for that request.

## Decision

### Each operation is its single request

`POST /scim/v2/Bulk` sits behind the same guard as every SCIM route: the Host, `SCIM=on`, a live `sbp_` token, the tenant's rate limit. After the whole request is checked (below), each operation is handed to the very handler its single request would reach (`create_user`, `replace_user`, `patch_user`, `delete_user`, and the four group handlers), with the same `Caller` (token, tenant, audit actor) and the request's own Host. There is no second implementation of any SCIM behaviour, so:

- **Tenant scoping** is the handlers': another tenant's user or group is 404, a group member who isn't this tenant's user is 400, an email another user has is 409.
- **Deprovisioning** (`active: false`, `DELETE`) runs ADR 0124's step, with `user.deprovisioned` (`via: scim` or `scim_delete`), and enabling resumes the machine.
- **Audit**: each operation records the events its single request would, with the token as the actor. That includes the guard's `scim.request_failed` for a failed operation (not a 404, nor a 429, as for single requests), with the operation's method and resource, since the Bulk request itself is 200 and the guard sees no failure. The request as a whole also records **`scim.bulk`**: `tenant`, `operations` (sent), `run`, `failed`, `failOnErrors`, `stopped` (`failOnErrors`, `rateLimited`, or null) and `results` (each operation's method, path with `bulkId`s resolved, `bulkId`, and status), outcome `failure` if any failed. Request bodies are never logged.
- **Groups** follow `SCIM_GROUPS`: off, a group operation gets the same 501 as `POST /Groups`.

The group code is untouched: Bulk calls its public handlers.

### The request is checked whole first

Before anything runs, the request must be a JSON object with a non-empty `Operations` list, no attribute twice in any case (as everywhere in SCIM), `failOnErrors` absent or a whole number of at least 1, and each operation an object with:

- `method` POST, PUT, PATCH or DELETE (any case). GET isn't a Bulk method.
- `path` `/Users` or `/Groups` for a POST, `/Users/{id}` or `/Groups/{id}` otherwise (the id may be `bulkId:<id>`); nothing else (`/Bulk`, `/Schemas`, a query string).
- `bulkId` (1 to 256 characters) on every POST, and no two POSTs with the same one.
- `data` an object for POST, PUT and PATCH: the body the single request would send. Ignored for DELETE. `version` is ignored, as ETags aren't supported.

Anything wrong is a 400 (`invalidSyntax`, `invalidValue` or `invalidPath`, naming `Operations[i]`) and nothing runs. A typo in operation 80 shouldn't leave 79 people half-provisioned and the client guessing which.

### Limits, advertised and enforced

`ServiceProviderConfig` says `bulk: {supported: true, maxOperations: 100, maxPayloadSize: 1048576}`.

- **More than 100 operations**: 413, "The bulk request has N operations, more than maxOperations (100).", nothing runs.
- **A body over 1 MiB**: 413, "The size of the bulk operation exceeds the maxPayloadSize (1048576).", the RFC's own wording. The route's body limit enforces it while reading, so a larger body is never buffered.
- **Each operation keeps its endpoint's own limit**: a user's `data` over 64 KiB, or a group's over 1 MiB, is a 413 for that operation, as the single request would be.
- **The rate limit**: the request counts once at the guard, as any request does, and each operation after the first counts once more against the tenant's 600 a minute. One over the limit gets a 429 result and processing stops there (`stopped: rateLimited`); the client sends it and the rest again later, and the next request is 429 with `Retry-After` until the window passes. Bulk is not a way to send 100 times the rate.

100 operations of at most 64 KiB each stays well inside a minute's rate and one request's time; a client with more sends more requests.

### Order, references and partial failure

- **Order**: operations run one at a time, in the order sent, except that the POST defining `bulkId:x` is moved forward to run just before the first operation that refers to `x` (after the POSTs it refers to itself, the same way). So a group that lists a user created later in the same request works, as RFC 7644 section 3.7.2 shows, and the user is created first. Nothing else is reordered: the operation that needed `x` stays in its place, so writes sent after it still run after it. Holding back the operation instead would let later writes pass it (a PATCH adding a new member, then a PUT emptying the group, would end with the member in the group).
- **References**: every string `bulkId:x` in an operation's path or data, and every quoted `"bulkId:x"` inside a PATCH operation's `path` filter (`members[value eq "bulkId:x"]`), is replaced with the id x's POST made. Only POSTs in the same request define `bulkId`s; one request can't refer to another's.
- **409 for a reference that can't resolve**, without running the operation: `x` isn't the `bulkId` of a POST in this request; x's POST failed; or the references are circular (two POSTs naming each other, or a POST naming itself), which since groups don't hold groups can only be a mistake. RFC 7644 section 3.7.1 allows stopping at a circular reference with 409.
- **Partial failure**: by default every operation is tried, whatever others did, as the RFC asks. Each succeeds or fails on its own and is never rolled back: there is no transaction across operations, as there is none across single requests.
- **`failOnErrors: n`**: once n operations have failed, processing stops; the rest aren't run.
- **The response** is 200 with a `BulkResponse` whenever the request was read, even if every operation failed. Its `Operations` are the operations that ran, in the order they ran; any after the last weren't run. Each has `method`, its `bulkId` if sent, `status` (what the single request would have answered, as a string), `location` (all but a failed POST), and on failure `response`, the SCIM error body. A successful operation's body is left out, as the RFC allows; the `location` carries the new id.

Concurrent requests behave as they do one by one: a group operation takes the same group-write lock as its single request, for the length of that operation.

## Consequences

- SCIM clients that batch can provision, update and deprovision with far fewer requests, and new users can go into new groups in one request.
- Bulk adds no SCIM behaviour of its own, so later changes to the Users and Groups handlers (such as group-to-role mapping) apply to Bulk with no further work.
- A client must read each operation's status: a 200 doesn't mean every operation worked.
- A request stopped by the rate limit or `failOnErrors` leaves what ran done; the client works out what's left from the results.

## Alternatives considered

- **All or nothing in one database transaction.** Not what RFC 7644 asks (it says to carry on past failures), and impossible here: deprovisioning suspends machines and stops runs, and team joins call the billing provider, none of which a database rollback undoes.
- **Calling the router again for each operation** (an internal sub-request). Same effect, but it would pass through the guard again, so each operation would need its token re-sent and re-checked, and would hide which handler ran. Calling the handlers directly with the already-checked caller is simpler and as strict.
- **Fail a malformed operation on its own** rather than the whole request. Closer to "carry on past failures", but a request with a malformed operation is a broken client; running the rest of it leaves an unpredictable state. Processing failures (a 409 on one user) still don't stop others.
- **Dependency ordering across all operations** (for example, every POST first). Changes the order of PATCHes and DELETEs relative to each other, which the client may rely on. Moving only referenced POSTs keeps the client's order otherwise.
- **No limit on operations beyond the payload.** The RFC requires both; a per-request cap also bounds how long one request holds a connection.

## Not done

- Google Workspace, which has no generic SCIM client (the guide's workaround stands).
- ETags (`version`), sorting, and groups in groups, as before.
