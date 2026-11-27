// Store screenshots from the web build, with made-up demo data (docs/store/screenshots.md).
//
//   npm run build:web && npm run store:screenshots [-- --out <dir>] [-- --only <shot>]
//   npm run store:screenshots -- --serve [port]
//
// Serves dist/ beside a stand-in for botd's API (scripts/store-fixtures.mjs), so no server,
// account or network is needed, then drives headless Chrome over the DevTools protocol at
// each store's required sizes. Needs Node 22+ (for its WebSocket) and Chrome or Chromium:
// set CHROME to its path if it isn't found. `--serve` only runs the stand-in, for a
// simulator or emulator to sign in to with any code.
import { spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { demoData } from "./store-fixtures.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dist = path.join(root, "dist");

/** Each store's required size, as a CSS viewport and a pixel ratio. */
export const DEVICES = [
  // App Store: 6.9" iPhone, 1320 x 2868.
  { id: "iphone-6.9", width: 440, height: 956, scale: 3, mobile: true },
  // App Store: 13" iPad, 2064 x 2752 (the app supports tablets, so this is required).
  { id: "ipad-13", width: 1032, height: 1376, scale: 2, mobile: true },
  // Google Play: phone, 1080 x 1920 (9:16).
  { id: "android-phone", width: 432, height: 768, scale: 2.5, mobile: true },
];

/** What each screenshot shows; `steps` run in the page after it loads. */
export const SHOTS = [
  { id: "01-chat", path: "/home?bot=b_ledger" },
  { id: "02-approval", path: "/home?approval=ap_push" },
  { id: "03-bots", path: "/home" },
  { id: "04-routines", path: "/home?bot=b_scout", steps: ["openDetails"] },
  { id: "05-sign-in", path: "/", signedOut: true, steps: ["fillServer"] },
];

const MIME = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".png": "image/png", ".ico": "image/x-icon", ".ttf": "font/ttf", ".json": "application/json", ".svg": "image/svg+xml" };

function json(res, status, body) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

function serve(data, signedIn, { port = 0, host = "127.0.0.1" } = {}) {
  const api = (req, res, url) => {
    const p = url.pathname;
    let m;
    if (p === "/api/auth/login" && req.method === "POST") return json(res, 200, { token: "demo" });
    if (p === "/api/auth/me") return signedIn() ? json(res, 200, { ...data.me, session: true }) : json(res, 401, { error: "unauthorized" });
    if (p === "/api/auth/sso") return json(res, 200, { providers: [{ id: "entra", label: "Microsoft", type: "entra" }, { id: "apple", label: "Apple", type: "apple" }] });
    if (p === "/api/events") {
      res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
      res.write(": demo\n\n");
      return;
    }
    if (p === "/api/state") return json(res, 200, data.state);
    if ((m = p.match(/^\/api\/bots\/([^/]+)\/messages$/))) return json(res, 200, data.messages[m[1]] ?? []);
    if ((m = p.match(/^\/api\/bots\/([^/]+)\/routines$/))) return json(res, 200, data.routines[m[1]] ?? []);
    if ((m = p.match(/^\/api\/bots\/([^/]+)\/read$/))) return json(res, 200, {});
    if ((m = p.match(/^\/api\/bots\/([^/]+)\/access$/))) {
      const b = data.bots.find((x) => x.id === m[1]);
      return json(res, 200, { botId: m[1], owner: { ...data.me }, visibility: b?.visibility ?? "private", access: "manage", grants: [], keepers: [] });
    }
    if (p.startsWith("/api/harnesses/")) return json(res, 200, [{ id: "sonnet", label: "Sonnet", efforts: ["low", "medium", "high"] }, { id: "opus", label: "Opus", efforts: ["low", "medium", "high"] }]);
    // Anything else this demo doesn't fill in: the app treats it as a feature the server lacks.
    if (process.env.STORE_SHOTS_DEBUG) console.error(`demo api: no fixture for ${req.method} ${p}`);
    return json(res, 404, { error: "not in the demo" });
  };
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://localhost");
    if (url.pathname.startsWith("/api/")) return api(req, res, url);
    let file = path.join(dist, path.normalize(url.pathname));
    if (!file.startsWith(dist) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) file = path.join(dist, "index.html");
    if (!fs.existsSync(file)) return json(res, 404, { error: "no web build" });
    res.writeHead(200, { "content-type": MIME[path.extname(file)] ?? "application/octet-stream" });
    fs.createReadStream(file).pipe(res);
  });
  return new Promise((resolve) => server.listen(port, host, () => resolve(server)));
}

function findChrome() {
  const candidates = [
    process.env.CHROME,
    "/usr/bin/google-chrome",
    "/usr/local/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  ];
  const found = candidates.find((c) => c && fs.existsSync(c));
  if (!found) throw new Error("Chrome not found: set CHROME to its path.");
  return found;
}

async function launchChrome() {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "store-shots-"));
  const proc = spawn(findChrome(), ["--headless=new", "--remote-debugging-port=0", `--user-data-dir=${profile}`, "--no-first-run", "--hide-scrollbars", "--mute-audio", "about:blank"], { stdio: "ignore" });
  const portFile = path.join(profile, "DevToolsActivePort");
  for (let i = 0; i < 100 && !fs.existsSync(portFile); i++) await sleep(100);
  const [port, wsPath] = fs.readFileSync(portFile, "utf8").trim().split("\n");
  const ws = new WebSocket(`ws://127.0.0.1:${port}${wsPath}`);
  await new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = reject;
  });
  let next = 0;
  const pending = new Map();
  const listeners = new Map();
  ws.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    if (process.env.STORE_SHOTS_DEBUG && (msg.method === "Runtime.exceptionThrown" || msg.method === "Runtime.consoleAPICalled")) {
      console.error(JSON.stringify(msg.params).slice(0, 600));
    }
    if (msg.method) listeners.get(msg.method)?.(msg.params, msg.sessionId);
    const p = pending.get(msg.id);
    if (!p) return;
    pending.delete(msg.id);
    if (msg.error) p.reject(new Error(msg.error.message));
    else p.resolve(msg.result);
  };
  const send = (method, params = {}, sessionId) =>
    new Promise((resolve, reject) => {
      const id = ++next;
      pending.set(id, { resolve, reject });
      ws.send(JSON.stringify({ id, method, params, sessionId }));
    });
  const close = () => {
    ws.close();
    proc.kill();
    setTimeout(() => fs.rmSync(profile, { recursive: true, force: true, maxRetries: 5 }), 500);
  };
  const on = (method, fn) => listeners.set(method, fn);
  return { send, on, close };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** The address the sign-in screenshot shows; its requests are answered by the demo server. */
const DEMO_SERVER = "https://superbot.example.com";

/** In-page actions, run as plain DOM code so they work on any layout. */
const STEPS = {
  openDetails: `(() => {
    const b = [...document.querySelectorAll('[role="button"]')].find((e) => /^Scout, /.test(e.getAttribute("aria-label") ?? ""));
    b?.click();
    return Boolean(b);
  })()`,
  fillServer: `(() => {
    const input = [...document.querySelectorAll("input")].find((e) => /^https?:/.test(e.value));
    if (!input) return false;
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(input, "${DEMO_SERVER}");
    input.dispatchEvent(new Event("input", { bubbles: true }));
    return true;
  })()`,
};

async function capture(chrome, origin, device, shot, file) {
  const { targetId } = await chrome.send("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await chrome.send("Target.attachToTarget", { targetId, flatten: true });
  const s = (method, params) => chrome.send(method, params, sessionId);
  await s("Emulation.setDeviceMetricsOverride", { width: device.width, height: device.height, deviceScaleFactor: device.scale, mobile: device.mobile });
  await s("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "dark" }, { name: "prefers-reduced-motion", value: "reduce" }] });
  await s("Emulation.setTimezoneOverride", { timezoneId: "UTC" });
  await s("Emulation.setLocaleOverride", { locale: "en-US" });
  if (device.mobile) await s("Emulation.setTouchEmulationEnabled", { enabled: true, maxTouchPoints: 5 });
  await s("Fetch.enable", { patterns: [{ urlPattern: `${DEMO_SERVER}/*` }] });
  chrome.on("Fetch.requestPaused", async ({ requestId, request }, from) => {
    try {
      const res = await fetch(origin + new URL(request.url).pathname);
      const body = Buffer.from(await res.arrayBuffer()).toString("base64");
      const headers = [
        { name: "content-type", value: res.headers.get("content-type") ?? "application/json" },
        { name: "access-control-allow-origin", value: "*" },
      ];
      await chrome.send("Fetch.fulfillRequest", { requestId, responseCode: res.status, responseHeaders: headers, body }, from);
    } catch {
      await chrome.send("Fetch.failRequest", { requestId, errorReason: "Failed" }, from).catch(() => {});
    }
  });
  await s("Page.enable");
  if (process.env.STORE_SHOTS_DEBUG) await s("Runtime.enable");
  await s("Page.navigate", { url: origin + shot.path });
  await sleep(4000);
  for (const step of shot.steps ?? []) {
    const { result } = await s("Runtime.evaluate", { expression: STEPS[step], returnByValue: true });
    if (!result.value) console.warn(`${device.id}/${shot.id}: step ${step} found nothing to press`);
    await sleep(1500);
  }
  await s("Runtime.evaluate", { expression: "document.activeElement?.blur()" });
  await sleep(300);
  if (process.env.STORE_SHOTS_DEBUG) {
    const { result } = await s("Runtime.evaluate", { expression: "location.href + ' | ' + document.body.innerText.slice(0, 400)", returnByValue: true });
    console.error(result.value);
  }
  const { data } = await s("Page.captureScreenshot", { format: "png", captureBeyondViewport: false });
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, Buffer.from(data, "base64"));
  await chrome.send("Target.closeTarget", { targetId });
}

async function main() {
  const args = process.argv.slice(2);
  const opt = (name) => {
    const i = args.indexOf(name);
    return i >= 0 ? args[i + 1] : undefined;
  };
  const out = path.resolve(opt("--out") ?? path.join(root, "../../docs/store/screenshots"));
  const only = opt("--only");
  if (args.includes("--serve")) {
    const port = Number(opt("--serve") ?? 8090) || 8090;
    await serve(demoData(), () => true, { port, host: "0.0.0.0" });
    console.log(`Demo server on port ${port}. Sign in with any code: iOS Simulator http://localhost:${port}, Android emulator http://10.0.2.2:${port}.`);
    return;
  }
  if (typeof WebSocket === "undefined") throw new Error("Needs Node 22 or later (for its WebSocket).");
  if (!fs.existsSync(path.join(dist, "index.html"))) throw new Error("No web build: run `npm run build:web` first.");

  const data = demoData();
  let signedIn = true;
  const server = await serve(data, () => signedIn);
  const origin = `http://127.0.0.1:${server.address().port}`;
  const chrome = await launchChrome();
  try {
    for (const device of DEVICES) {
      for (const shot of SHOTS) {
        if (only && only !== shot.id) continue;
        signedIn = !shot.signedOut;
        const file = path.join(out, device.id, `${shot.id}.png`);
        await capture(chrome, origin, device, shot, file);
        console.log(`wrote ${path.relative(process.cwd(), file)}`);
      }
    }
  } finally {
    chrome.close();
    server.close();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((e) => {
    console.error(e.message);
    process.exit(1);
  });
}
