// node --test server/src/bin/superbot-site/assets/search.test.js
const test = require("node:test");
const assert = require("node:assert/strict");
const { tokens, search, snippet } = require("./search.js");

const index = [
  { t: "Microsoft Entra ID", u: "docs/sso/entra.html", s: "Single sign-on", h: ["Setup", "SCIM"], x: "Register an app in Entra ID and set ENTRA_TENANT_ID." },
  { t: "Backups and restores", u: "docs/ops/backup-restore.html", s: "Operations", h: ["Restore"], x: "superbot-backup writes an archive. Entra is not involved." },
  { t: "0094: TOTP second factor", u: "docs/adr/0094-totp-second-factor.html", s: "Decisions", h: ["Decision"], x: "Second factor for sign-in codes." },
];

test("queries split into lower-case words", () => {
  assert.deepEqual(tokens("  SCIM, Entra-ID! "), ["scim", "entra", "id"]);
  assert.deepEqual(tokens("ENTRA_TENANT_ID"), ["entra_tenant_id"]);
  assert.deepEqual(tokens(" ... "), []);
});

test("every word must match, and title matches rank first", () => {
  assert.deepEqual(search(index, "entra", 10).map((p) => p.u), ["docs/sso/entra.html", "docs/ops/backup-restore.html"]);
  assert.deepEqual(search(index, "entra restore", 10).map((p) => p.u), ["docs/ops/backup-restore.html"]);
  assert.deepEqual(search(index, "second factor", 10).map((p) => p.u), ["docs/adr/0094-totp-second-factor.html"]);
  assert.deepEqual(search(index, "kubernetes", 10), []);
  assert.deepEqual(search(index, "", 10), []);
  assert.equal(search(index, "e", 1).length, 1);
});

test("snippets show the text around the first match", () => {
  const page = { x: "a".repeat(200) + " ENTRA_TENANT_ID here " + "b".repeat(200) };
  const s = snippet(page, "entra_tenant_id", 60);
  assert.ok(s.startsWith("…") && s.endsWith("…"), s);
  assert.ok(s.includes("ENTRA_TENANT_ID"), s);
  assert.equal(snippet({ x: "short" }, "missing", 60), "short");
});
