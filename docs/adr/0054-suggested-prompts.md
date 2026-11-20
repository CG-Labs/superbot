# 0054: Suggested prompts in Bot details

## Status

Accepted (20 Nov 2026). Issue [#83](https://github.com/CG-Labs/superbot/issues/83), M3. It follows [ADR 0027](0027-expo-primary-hermes-default.md) (the Expo client is the one primary interface) and builds on [ADR 0017](0017-bot-acls.md) (Bot access) and [ADR 0046](0046-shared-bots-under-isolation.md) (shared Bots under isolation).

## Context

The old console had a "Suggested" card in a Bot's details: "Create a routine" and "Give it a job". Each put a fixed start of a message in the box. The console's end-user features were retired ([ADR 0032](0032-console-admin-only.md)), and the client never had them. We needed to decide:

- where prompts come from, and who can change them;
- what tapping one does;
- what a Bot shows before anyone sets them.

## Decision

### Per-Bot prompts, saved on the server

- `bots.prompts` is a JSON array of strings, or NULL. NULL means "the client's defaults". An empty array means "none".
- `PATCH /api/bots/:id` takes `prompts`: a list, or `null` to go back to the defaults. Like the Bot's name and harness, only those who **manage** the Bot (its owner and admins, and the Bot itself, which acts as its owner) can change them.
- The server trims each prompt and drops blanks and repeats. At most 6 prompts of at most 200 characters; more is a 400, and nothing in that request is saved.
- Every Bot view has `prompts`, so everyone who can see the Bot gets them, and no one else. A shared Bot's prompts are its owner's, the same for every teammate. They are not per user: they describe what the Bot is for, like its name.
- Changes are audited in `bot.updated` as `changes.prompts: {from, to}`.

### Tapping a prompt

- Only those who can **operate** the Bot see the prompts. Viewers and read-only users can't send messages, so they see none.
- A prompt that ends in "…" (or "...") is a **starter**: tapping it closes the details and puts it in the message box, without the "…", for the person to finish. This keeps the console's two starters working.
- Any other prompt is **sent** at once, as the person, like typing it. It starts a run that goes through the usual approvals and tier limits. Nothing new is allowed by a prompt.

### Defaults

Bots have no role or description field, so there is nothing to derive defaults from. The client's defaults are the console's two starters, worded as starters, and one prompt any Bot with a computer can answer:

- "Set up a routine to…"
- "Your job is to…"
- "What can you do on your computer?"

They live in the client (`src/prompts.ts`), not the database, so changing them later reaches every Bot that never had its own.

## Consequences

- One small migration (a nullable column). Servers from before send no `prompts`; the client shows the defaults.
- Editing is in Bot details: "Edit" opens a list of fields, with "Use defaults" when the Bot has its own.
- If Bots get a role or description later, defaults can be built from it without changing the API: NULL still means "defaults".
- Prompts are plain text the Bot's owner wrote. They are shown and sent as text, never run as anything else.
