// node --test scripts/store.test.mjs
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { APPLE, PLAY, checkAll, checkAppStore, checkEas, checkGooglePlay, checkScreenshots, placeholders, pngSize } from "./store.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const read = (rel) => JSON.parse(fs.readFileSync(path.join(repo, rel), "utf8"));
const appStore = () => read("docs/store/app-store.config.json");
const googlePlay = () => read("docs/store/google-play.json");
const eas = () => read("apps/client/eas.json");
const info = (cfg) => cfg.apple.info["en-US"];

test("the committed listings, submit profile and screenshots pass", () => {
  assert.deepEqual(checkAll().errors, []);
});

test("only the owner's values are left as placeholders, and store:ready refuses them", () => {
  const { placeholders: left, errors } = checkAll({ ready: true });
  assert.ok(left.length > 0);
  assert.equal(errors.length, left.length);
  for (const l of left) assert.match(l, /(copyright|Url|contactEmail|contactWebsite|appleTeamId|ascAppId):/, l);
});

test("text over a store's limit fails", () => {
  const a = appStore();
  info(a).title = "x".repeat(APPLE.title[1] + 1);
  info(a).subtitle = "y".repeat(APPLE.subtitle + 1);
  info(a).promoText = "z".repeat(APPLE.promoText + 1);
  info(a).description = "d".repeat(APPLE.description[1] + 1);
  const errors = checkAppStore(a, "SuperBot");
  for (const field of ["title", "subtitle", "promotional text", "description"]) assert.ok(errors.some((e) => e.startsWith(`app store ${field}:`)), field);

  const g = googlePlay();
  g.appName = "SuperBot " + "x".repeat(PLAY.appName);
  g.shortDescription = "s".repeat(PLAY.shortDescription + 1);
  g.fullDescription = "f".repeat(PLAY.fullDescription + 1);
  g.releaseNotes = "r".repeat(PLAY.releaseNotes + 1);
  const playErrors = checkGooglePlay(g, "SuperBot");
  for (const field of ["app name", "short description", "full description", "release notes"]) assert.ok(playErrors.some((e) => e.startsWith(`google play ${field}:`)), field);
});

test("limits count characters, not UTF-16 units, and keywords count bytes joined with commas", () => {
  const a = appStore();
  info(a).subtitle = "•".repeat(APPLE.subtitle);
  assert.deepEqual(checkAppStore(a, "SuperBot").filter((e) => e.includes("subtitle")), []);
  const b = appStore();
  info(b).keywords = Array.from({ length: 20 }, (_, i) => `keyword${i}`);
  assert.ok(checkAppStore(b, "SuperBot").some((e) => /keywords: \d+ bytes/.test(e)));
  info(b).keywords = ["agents"];
  assert.ok(checkAppStore(b, "SuperBot").some((e) => e.includes('"agents" is already in the title')));
});

test("App Store text can't name other platforms, and nothing names the vendor product SuperBot replaces", () => {
  const a = appStore();
  info(a).description += " Also on Android.";
  assert.ok(checkAppStore(a, "SuperBot").some((e) => e.includes("another platform")));
  const g = googlePlay();
  g.fullDescription += " Like Grok.";
  assert.ok(checkGooglePlay(g, "SuperBot").some((e) => e.includes("another vendor")));
});

test("the listing name starts with the app's installed name", () => {
  const a = appStore();
  info(a).title = "Teammates by SuperBot";
  assert.ok(checkAppStore(a, "SuperBot").some((e) => e.includes("installed name")));
});

test("the submit profile keeps credentials out of the repo", () => {
  const e = eas();
  e.submit.production.android.serviceAccountKeyPath = "./play-service-account.json";
  e.submit.production.ios.ascApiKeyPath = "./AuthKey_ABC123.p8";
  const errors = checkEas(e);
  assert.ok(errors.some((x) => x.includes("serviceAccountKeyPath")));
  assert.ok(errors.some((x) => x.includes("ascApiKeyPath")));
});

test("the submit profile checks real ids' shape once the owner fills them in", () => {
  const e = eas();
  e.submit.production.ios.appleTeamId = "AB12XYZ34S";
  e.submit.production.ios.ascAppId = "1234567890";
  assert.deepEqual(checkEas(e), []);
  e.submit.production.ios.appleTeamId = "team";
  e.submit.production.ios.ascAppId = "app";
  assert.equal(checkEas(e).length, 2);
  delete e.submit.production;
  assert.deepEqual(checkEas(e), ["eas.json: no submit.production profile"]);
});

test("the submit profile's track and release status are ones Play takes", () => {
  const e = eas();
  e.submit.production.android.track = "beta-testers";
  e.submit.production.android.releaseStatus = "live";
  assert.equal(checkEas(e).length, 2);
});

test("a missing or wrongly sized screenshot fails", (t) => {
  const dir = fs.mkdtempSync(path.join(fs.realpathSync(process.env.TMPDIR ?? "/tmp"), "store-shots-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const errors = checkScreenshots(dir);
  assert.ok(errors.some((e) => e.includes("missing")));
  const src = path.join(repo, "docs/store/screenshots/ipad-13/01-chat.png");
  fs.mkdirSync(path.join(dir, "iphone-6.9"), { recursive: true });
  fs.copyFileSync(src, path.join(dir, "iphone-6.9/01-chat.png"));
  assert.ok(checkScreenshots(dir).some((e) => e.includes("iphone-6.9/01-chat.png: 2064 x 2752, want 1320 x 2868")));
});

test("pngSize reads the header and rejects other files", () => {
  assert.deepEqual(pngSize(fs.readFileSync(path.join(repo, "apps/client/assets/images/icon.png"))), [1024, 1024]);
  assert.equal(pngSize(Buffer.from("not a png at all, really not")), null);
});

test("placeholders lists where each one is", () => {
  assert.deepEqual(placeholders({ a: ["x", "OWNER_TODO_ID"], b: { c: "https://owner-todo.invalid/x" } }), ["a[1]: OWNER_TODO_ID", "b.c: https://owner-todo.invalid/x"]);
});
