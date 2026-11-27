// Checks the store listings, the `eas submit` profile and the screenshots (docs/store/README.md).
//
//   npm run store:check   CI: text within each store's limits, the submit profile, screenshot sizes
//   npm run store:ready   Before `eas submit`: the same, and no OWNER_TODO placeholder left
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { DEVICES, SHOTS } from "./store-screenshots.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repo = path.resolve(root, "../..");

export const FILES = {
  appStore: "docs/store/app-store.config.json",
  googlePlay: "docs/store/google-play.json",
  eas: "apps/client/eas.json",
  app: "apps/client/app.json",
  screenshots: "docs/store/screenshots",
};

/** App Store Connect's limits, in characters (keywords: bytes, joined with commas). */
export const APPLE = { title: [2, 30], subtitle: 30, promoText: 170, description: [10, 4000], keywords: 100, releaseNotes: 4000, url: 255 };
/** Google Play Console's limits, in characters. */
export const PLAY = { appName: 30, shortDescription: 80, fullDescription: 4000, releaseNotes: 500 };

/** Screenshot sizes each store takes for the device classes SHOTS are made for. */
export const SIZES = {
  "iphone-6.9": [[1320, 2868], [1290, 2796], [1260, 2736]],
  "ipad-13": [[2064, 2752], [2048, 2732]],
};

/** Marks a value only the owner can fill in (store accounts, URLs, legal name). */
export const PLACEHOLDER = /OWNER_TODO|owner-todo/i;

const PLAY_TRACKS = ["production", "beta", "alpha", "internal"];
const RELEASE_STATUSES = ["completed", "draft", "halted", "inProgress"];

const len = (s) => [...s].length;

function within(errors, where, value, limit) {
  if (typeof value !== "string") return errors.push(`${where}: missing`);
  const [min, max] = Array.isArray(limit) ? limit : [1, limit];
  const n = len(value);
  if (n < min || n > max) errors.push(`${where}: ${n} characters, must be ${min}–${max}`);
}

/** Words that get a listing rejected or that this project never publishes under. */
function wording(errors, where, text, { apple }) {
  if (/\bgrok\b/i.test(text)) errors.push(`${where}: names another vendor's product (AGENTS.md)`);
  // App Review guideline 2.3.10: no other mobile platforms in App Store metadata.
  if (apple && /\b(android|google play)\b/i.test(text)) errors.push(`${where}: names another platform, which App Review rejects`);
}

function url(errors, where, value) {
  if (typeof value !== "string" || !/^https:\/\/[^\s]+$/.test(value)) errors.push(`${where}: must be an https URL`);
  else if (value.length > APPLE.url) errors.push(`${where}: longer than ${APPLE.url} characters`);
}

export function checkAppStore(cfg, appName) {
  const errors = [];
  const apple = cfg?.apple;
  if (cfg?.configVersion !== 0 || !apple) return ["app store: not an EAS Metadata store config (configVersion 0, apple)"];
  const info = apple.info?.["en-US"];
  if (!info) return ["app store: no en-US info"];
  within(errors, "app store title", info.title, APPLE.title);
  within(errors, "app store subtitle", info.subtitle, APPLE.subtitle);
  within(errors, "app store promotional text", info.promoText, APPLE.promoText);
  within(errors, "app store description", info.description, APPLE.description);
  within(errors, "app store release notes", info.releaseNotes, APPLE.releaseNotes);
  for (const k of ["marketingUrl", "supportUrl", "privacyPolicyUrl"]) url(errors, `app store ${k}`, info[k]);
  if (appName && typeof info.title === "string" && !info.title.startsWith(appName)) {
    errors.push(`app store title: should start with the installed name "${appName}"`);
  }
  const kw = info.keywords;
  if (!Array.isArray(kw) || kw.length === 0) errors.push("app store keywords: missing");
  else {
    const joined = kw.join(",");
    if (Buffer.byteLength(joined) > APPLE.keywords) errors.push(`app store keywords: ${Buffer.byteLength(joined)} bytes joined, must be at most ${APPLE.keywords}`);
    if (new Set(kw.map((k) => k.toLowerCase())).size !== kw.length) errors.push("app store keywords: repeated");
    const named = `${info.title} ${info.subtitle}`.toLowerCase().split(/[^a-z0-9-]+/);
    for (const k of kw) if (named.includes(k.toLowerCase())) errors.push(`app store keywords: "${k}" is already in the title or subtitle`);
  }
  if (!Array.isArray(apple.categories) || apple.categories.length < 1 || apple.categories.length > 2) errors.push("app store categories: one primary and at most one secondary");
  if (!apple.advisory || typeof apple.advisory.unrestrictedWebAccess !== "boolean") errors.push("app store advisory: the age rating answers are missing");
  for (const k of ["title", "subtitle", "promoText", "description", "releaseNotes"]) if (typeof info[k] === "string") wording(errors, `app store ${k}`, info[k], { apple: true });
  for (const k of kw ?? []) wording(errors, "app store keywords", k, { apple: true });
  return errors;
}

export function checkGooglePlay(cfg, appName) {
  const errors = [];
  if (!cfg) return ["google play: missing"];
  within(errors, "google play app name", cfg.appName, PLAY.appName);
  within(errors, "google play short description", cfg.shortDescription, PLAY.shortDescription);
  within(errors, "google play full description", cfg.fullDescription, PLAY.fullDescription);
  within(errors, "google play release notes", cfg.releaseNotes, PLAY.releaseNotes);
  for (const k of ["contactWebsite", "privacyPolicyUrl", "accountDeletionUrl"]) url(errors, `google play ${k}`, cfg[k]);
  if (typeof cfg.contactEmail !== "string" || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cfg.contactEmail)) errors.push("google play contactEmail: must be an email address");
  if (appName && typeof cfg.appName === "string" && !cfg.appName.startsWith(appName)) errors.push(`google play app name: should start with the installed name "${appName}"`);
  // Play's metadata policy: no prices, rankings or calls to action in the name.
  if (/\b(free|best|#1|top|new|sale)\b/i.test(cfg.appName ?? "")) errors.push("google play app name: no promotional words");
  for (const k of ["appName", "shortDescription", "fullDescription", "releaseNotes"]) if (typeof cfg[k] === "string") wording(errors, `google play ${k}`, cfg[k], { apple: false });
  for (const k of ["icon", "featureGraphic"]) {
    if (!cfg.graphics?.[k] || !fs.existsSync(path.join(repo, cfg.graphics[k]))) errors.push(`google play graphics.${k}: no such file`);
  }
  return errors;
}

export function checkEas(eas, easDir = path.join(repo, "apps/client")) {
  const errors = [];
  const p = eas?.submit?.production;
  if (!p) return ["eas.json: no submit.production profile"];
  if (!eas.build?.production) errors.push("eas.json: no build.production profile to submit");
  const ios = p.ios ?? {};
  for (const k of ["appleTeamId", "ascAppId"]) if (typeof ios[k] !== "string" || !ios[k]) errors.push(`eas.json submit.production.ios.${k}: missing`);
  if (ios.appleTeamId && !PLACEHOLDER.test(ios.appleTeamId) && !/^[A-Z0-9]{10}$/.test(ios.appleTeamId)) errors.push("eas.json submit.production.ios.appleTeamId: an Apple team id is 10 letters and digits");
  if (ios.ascAppId && !PLACEHOLDER.test(ios.ascAppId) && !/^\d+$/.test(ios.ascAppId)) errors.push("eas.json submit.production.ios.ascAppId: an App Store Connect app id is a number");
  if (!ios.metadataPath || !fs.existsSync(path.resolve(easDir, ios.metadataPath))) errors.push("eas.json submit.production.ios.metadataPath: no such file");
  for (const k of ["ascApiKeyPath", "ascApiKeyIssuerId", "ascApiKeyId", "appleId"]) {
    if (ios[k] && !String(ios[k]).startsWith("$")) errors.push(`eas.json submit.production.ios.${k}: give it as an environment variable, never in the repo`);
  }
  const android = p.android ?? {};
  // The key is a credential: it comes from the environment (or EAS's own store), never a file in the repo.
  if (typeof android.serviceAccountKeyPath !== "string" || !android.serviceAccountKeyPath.startsWith("$")) {
    errors.push("eas.json submit.production.android.serviceAccountKeyPath: must be an environment variable, like $GOOGLE_SERVICE_ACCOUNT_KEY_PATH");
  }
  if (!PLAY_TRACKS.includes(android.track)) errors.push(`eas.json submit.production.android.track: one of ${PLAY_TRACKS.join(", ")}`);
  if (!RELEASE_STATUSES.includes(android.releaseStatus)) errors.push(`eas.json submit.production.android.releaseStatus: one of ${RELEASE_STATUSES.join(", ")}`);
  return errors;
}

/** Width and height of a PNG, from its IHDR chunk. */
export function pngSize(buf) {
  if (buf.length < 24 || buf.toString("latin1", 1, 4) !== "PNG") return null;
  return [buf.readUInt32BE(16), buf.readUInt32BE(20)];
}

export function checkScreenshots(dir = path.join(repo, FILES.screenshots)) {
  const errors = [];
  for (const d of DEVICES) {
    const want = [Math.round(d.width * d.scale), Math.round(d.height * d.scale)];
    const sizes = SIZES[d.id];
    if (sizes && !sizes.some(([w, h]) => w === want[0] && h === want[1])) errors.push(`${d.id}: ${want.join(" x ")} isn't a size the App Store takes`);
    if (d.id.startsWith("android")) {
      // Play: 320–3840 px a side, the long side at most twice the short one.
      const [w, h] = want;
      if (Math.min(w, h) < 320 || Math.max(w, h) > 3840 || Math.max(w, h) > 2 * Math.min(w, h)) errors.push(`${d.id}: ${want.join(" x ")} isn't a size Google Play takes`);
    }
    for (const s of SHOTS) {
      const file = path.join(dir, d.id, `${s.id}.png`);
      if (!fs.existsSync(file)) {
        errors.push(`${path.relative(repo, file)}: missing (npm run store:screenshots)`);
        continue;
      }
      const got = pngSize(fs.readFileSync(file));
      if (!got || got[0] !== want[0] || got[1] !== want[1]) errors.push(`${path.relative(repo, file)}: ${got?.join(" x ") ?? "not a PNG"}, want ${want.join(" x ")}`);
    }
  }
  if (SHOTS.length < 2 || SHOTS.length > 8) errors.push(`${SHOTS.length} screenshots: Google Play takes 2–8 phone screenshots`);
  return errors;
}

/** Every string in `value` still holding an owner placeholder, as `where: value`. */
export function placeholders(value, where = "") {
  if (typeof value === "string") return PLACEHOLDER.test(value) ? [`${where}: ${value}`] : [];
  if (Array.isArray(value)) return value.flatMap((v, i) => placeholders(v, `${where}[${i}]`));
  if (value && typeof value === "object") return Object.entries(value).flatMap(([k, v]) => placeholders(v, where ? `${where}.${k}` : k));
  return [];
}

const readJson = (rel) => JSON.parse(fs.readFileSync(path.join(repo, rel), "utf8"));

export function checkAll({ ready = false } = {}) {
  const appStore = readJson(FILES.appStore);
  const googlePlay = readJson(FILES.googlePlay);
  const eas = readJson(FILES.eas);
  const appName = readJson(FILES.app).expo?.name;
  const errors = [...checkAppStore(appStore, appName), ...checkGooglePlay(googlePlay, appName), ...checkEas(eas), ...checkScreenshots()];
  const left = [...placeholders(appStore, FILES.appStore), ...placeholders(googlePlay, FILES.googlePlay), ...placeholders(eas.submit, `${FILES.eas} submit`)];
  if (ready) errors.push(...left.map((l) => `owner placeholder left: ${l}`));
  return { errors, placeholders: left };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const ready = process.argv.includes("--ready");
  const { errors, placeholders: left } = checkAll({ ready });
  for (const e of errors) console.error(e);
  if (errors.length) process.exit(1);
  console.log(ready ? "Store listings are ready to submit." : `Store listings fit the stores' limits; ${left.length} owner placeholders left (npm run store:ready lists them).`);
}
