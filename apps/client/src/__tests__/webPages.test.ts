// The console's sign-in page and the setup wizard's first run on the design system (ADR 0341):
// the real pages from web/, each run in its own jsdom window against a stubbed server.
import fs from "fs";
import { JSDOM, type DOMWindow } from "jsdom";
import path from "path";

const web = path.resolve(__dirname, "../../../../web");
const LOGIN = fs.readFileSync(path.join(web, "login.html"), "utf8");
const CONSOLE = fs.readFileSync(path.join(web, "index.html"), "utf8");
const CONSOLE_JS = fs.readFileSync(path.join(web, "app.js"), "utf8");

type Reply = { status?: number; body?: unknown } | Error;
type Route = (method: string, path: string, body?: Record<string, unknown>) => Reply;
type Call = { method: string; path: string; body?: Record<string, unknown>; headers?: Record<string, string> };
let calls: Call[] = [];
let win: DOMWindow;

/** Opens `html` at `url` with `route` as the server, and runs its inline scripts, then `extra` (its script files). */
function load(html: string, url: string, route: Route, extra: string[] = []) {
  calls = [];
  win = new JSDOM(html, { url, runScripts: "outside-only" }).window;
  win.fetch = (async (to: string, init: RequestInit = {}) => {
    const method = init.method || "GET";
    const body = init.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ method, path: to, body, headers: init.headers as Record<string, string> });
    const r = route(method, to, body);
    if (r instanceof Error) throw r;
    const status = r.status ?? 200;
    return { ok: status >= 200 && status < 300, status, json: async () => r.body ?? {} } as Response;
  }) as typeof fetch;
  const inline = [...win.document.querySelectorAll("script")].filter((s) => !s.src).map((s) => s.textContent || "");
  for (const code of [...inline, ...extra]) win.eval(code);
}

const flush = async () => {
  for (let i = 0; i < 10; i++) await new Promise((r) => setTimeout(r, 0));
};
const $ = (id: string) => win.document.getElementById(id) as HTMLElement & HTMLInputElement & HTMLFormElement;
const all = <E extends Element = HTMLElement>(sel: string) => [...win.document.querySelectorAll<E>(sel)];
const posts = (p: string) => calls.filter((c) => c.method !== "GET" && c.path === p);
const shown = (id: string) => !$(id).hidden && !$(id).closest("[hidden]");

/** The page's CSS outside the generated token block. */
function ownCss(text: string) {
  const end = "/* tokens:end */";
  return text.slice(text.indexOf(end) + end.length);
}
/** Every hex colour in a declaration of `css`, ignoring `#id` selectors. */
const hexColours = (css: string) =>
  css
    .split(/[{}]/)
    .filter((part) => part.includes(";"))
    .flatMap((decls) => decls.match(/#[0-9a-f]{3,8}\b/gi) || []);

describe("the console's sign-in page", () => {
  const signIn = (route: (method: string, path: string, body?: Record<string, unknown>) => Reply | undefined, search = "") => {
    load(LOGIN, `http://localhost/login${search}`, (m, p, b) => route(m, p, b) ?? (p === "/api/auth/sso" ? { body: { providers: [] } } : { status: 401, body: { error: "Not signed in." } }));
    return flush();
  };
  const submit = async (value?: string) => {
    if (value !== undefined) $("secret").value = value;
    $("form").requestSubmit();
    await flush();
  };

  it("shows one card frame with the mark, a title, a labelled field and the one primary button", async () => {
    await signIn(() => undefined);
    expect($("form").classList.contains("card")).toBe(true);
    expect(win.document.querySelector("img.mark")?.getAttribute("src")).toMatch(/^data:image\/svg\+xml,/);
    expect($("title").textContent).toBe("Welcome to SuperBot");
    expect(win.document.querySelector('label[for="secret"]')?.textContent).toBe("Enter your sign-in code, or the server password.");
    expect($("secret").getAttribute("placeholder")).toBe("Sign-in code or password");
    expect($("go").textContent).toBe("Sign in");
    expect($("error").getAttribute("role")).toBe("alert");
    expect($("error").textContent).toBe("");
    expect(shown("mfa") || shown("saved")).toBe(false);
  });

  it("offers each provider as a pill, in the server's order, and drops bad ids", async () => {
    await signIn((_, p) =>
      p === "/api/auth/sso"
        ? { body: { providers: [{ id: "entra", label: "Microsoft Entra", type: "oidc" }, { id: "apple", type: "apple", label: "Apple ID" }, { id: "Bad id" }, { id: "entra" }] } }
        : undefined,
    );
    const pills = all<HTMLAnchorElement>("#sso a");
    expect(pills.map((a) => [a.textContent, a.getAttribute("href"), a.dataset.type])).toEqual([
      ["Sign in with Microsoft Entra", "/api/auth/sso/entra/start?label=Web", "oidc"],
      ["Sign in with Apple", "/api/auth/sso/apple/start?label=Web", "apple"],
    ]);
    expect($("or").style.display).toBe("flex");
  });

  it("posts the same fields as before: a password, or a sign-in code", async () => {
    await signIn((m, p) => (m === "POST" && p === "/api/auth/login" ? { status: 401, body: { error: "Wrong password." } } : undefined));
    await submit("  hunter2 ");
    await submit("sbc_abc");
    const sent = posts("/api/auth/login");
    expect(sent.map((c) => c.body)).toEqual([
      { session: "cookie", label: "Web", password: "hunter2" },
      { session: "cookie", label: "Web", code: "sbc_abc" },
    ]);
    expect(sent[0].headers).toEqual({ "content-type": "application/json" });
    expect($("error").textContent).toBe("Wrong password.");
  });

  it("asks for the second factor in the same frame, and posts the challenge with a code or a recovery code", async () => {
    await signIn((m, p, b) => {
      if (m !== "POST" || p !== "/api/auth/login") return undefined;
      return b?.challenge ? { status: 401, body: { error: "That code didn't work.", challenge: "ch1", mfa: "verify" } } : { status: 401, body: { error: "Enter the code from your app.", challenge: "ch1", mfa: "verify" } };
    });
    await submit("hunter2");
    expect($("title").textContent).toBe("Two-factor authentication");
    expect($("mfa-say").textContent).toBe("Enter the code from your app.");
    expect(shown("mfa") && shown("mfa-say") && !shown("first")).toBe(true);
    expect($("go").textContent).toBe("Verify");

    $("totp").value = "123 456";
    await submit();
    $("use-recovery").click();
    $("recovery").value = " abcd-efgh ";
    await submit();
    expect(posts("/api/auth/login").slice(1).map((c) => c.body)).toEqual([
      { session: "cookie", label: "Web", challenge: "ch1", totp: "123456" },
      { session: "cookie", label: "Web", challenge: "ch1", recoveryCode: "abcd-efgh" },
    ]);
    expect($("error").textContent).toBe("That code didn't work.");
  });

  it("sets up an authenticator app, then shows the recovery codes under their own title", async () => {
    await signIn((m, p, b) => {
      if (m !== "POST" || p !== "/api/auth/login") return undefined;
      if (!b?.challenge) return { status: 401, body: { error: "Scan this code.", challenge: "ch2", mfa: "enroll", secret: "ABCDEFGHIJKL", qrSvg: "<svg/>", otpauthUrl: "otpauth://totp/x" } };
      return { body: { recoveryCodes: ["one", "two"] } };
    });
    await submit("hunter2");
    expect($("title").textContent).toBe("Set up two-factor authentication");
    expect(shown("qr") && shown("setup")).toBe(true);
    expect($("key").textContent).toBe("ABCD EFGH IJKL");
    expect($("otpauth").getAttribute("href")).toBe("otpauth://totp/x");
    expect(shown("use-recovery")).toBe(false);
    expect($("go").textContent).toBe("Turn on and sign in");

    $("totp").value = "654321";
    await submit();
    expect(posts("/api/auth/login")[1].body).toEqual({ session: "cookie", label: "Web", challenge: "ch2", totp: "654321" });
    expect($("title").textContent).toBe("Two-factor authentication is on");
    expect(shown("saved") && !shown("mfa") && !shown("mfa-say")).toBe(true);
    expect(all("#codes li").map((li) => li.textContent)).toEqual(["one", "two"]);
    expect($("go").textContent).toBe("I saved them. Continue");
  });

  it("explains a failed single sign-on from the address, with what to do next", async () => {
    await signIn(() => undefined, "?error=sso_not_linked");
    expect($("error").textContent).toBe("Your account isn't set up on this server yet. Ask an admin to add you.");
    await signIn(() => undefined, "?error=%3Cscript%3E");
    expect($("error").textContent).toBe("Single sign-on failed. Try again, or ask an admin to check the audit log.");
  });

  it("says what to do when the server can't be reached or gives no reason", async () => {
    await signIn((m, p) => (m === "POST" && p === "/api/auth/login" ? new TypeError("Failed to fetch") : undefined));
    await submit("hunter2");
    expect($("error").textContent).toBe("Can't reach the SuperBot server. Check your connection, then try again.");
    expect(($("go") as unknown as HTMLButtonElement).disabled).toBe(false);

    await signIn((m, p) => (m === "POST" && p === "/api/auth/login" ? { status: 400, body: {} } : undefined));
    await submit("hunter2");
    expect($("error").textContent).toBe("Sign-in failed. Check your code or password, then try again.");
  });

  it("takes every colour from the tokens, apart from Apple's black and white and the QR code's white", () => {
    const style = LOGIN.slice(LOGIN.indexOf("<style>"), LOGIN.indexOf("</style>"));
    expect(style).toContain("/* tokens:start");
    const own = ownCss(style);
    expect(new Set(hexColours(own).map((h) => h.toLowerCase()))).toEqual(new Set(["#000", "#fff"]));
    const defined = new Set(style.match(/--[a-z-]+(?=:)/g));
    for (const used of own.match(/var\(--[a-z-]+\)/g) || []) expect(defined).toContain(used.slice(4, -1));
    expect(own).toMatch(/@media \(prefers-color-scheme: dark\)\s*{\s*#sso a\[data-type="apple"\] { background: #fff; border-color: #fff; color: #000; }/);
  });
});

describe("the setup wizard's first run", () => {
  const SETUP = {
    steps: ["domain", "signin", "tiers", "finish"],
    progress: { step: "domain", show: true, dismissed: false, completedAt: null },
    done: 2,
    total: 5,
    checklist: [{ id: "domain", label: "A public address with HTTPS", done: false, detail: "PUBLIC_URL isn't set." }],
    domain: { ok: false, detail: "PUBLIC_URL isn't set.", publicUrl: null, instructions: [{ title: "Set PUBLIC_URL", text: "In .env:", commands: ["PUBLIC_URL=https://bots.example.com"] }] },
    signIn: {
      ok: false, detail: "No single sign-on yet.", providers: [], admins: [], breakGlass: true, scim: false, signups: false,
      templates: [{ id: "entra", label: "Microsoft Entra ID", configured: false, docs: "docs/sso.md", secret: "SSO_ENTRA_SECRET", callbackUrl: "https://bots.example.com/cb", env: "SSO_ENTRA_ID=<id>" }],
      restart: [{ title: "Restart botd", text: "Then reload this page.", commands: ["sudo systemctl restart botd"] }],
    },
  };

  const open = async (setup: () => Reply, hash = "") => {
    load(CONSOLE, `http://localhost/console/${hash}`, (m, p, b) => {
      if (p === "/api/auth/me") return { body: { permissions: ["admin"], user: { id: "u1", name: "Ada" } } };
      if (p === "/api/setup" && m === "PATCH") return { body: { ...SETUP, progress: { ...SETUP.progress, ...b } } };
      if (p === "/api/setup") return setup();
      return { body: [] };
    }, [CONSOLE_JS]);
    await flush();
  };

  it("lands a new admin on setup, in one card with the steps, the step's notice and the way forward", async () => {
    await open(() => ({ body: SETUP }));
    expect(win.location.hash).toBe("#setup");
    expect(shown("tab-setup")).toBe(true);
    const card = win.document.querySelector("#tab-setup > .setup-card")!;
    for (const id of ["setup-steps", "setup-body", "setup-failed", "setup-back", "setup-next", "setup-hide"]) expect(card.contains($(id))).toBe(true);
    expect($("setup-state").textContent).toBe("2 of 5 done.");
    expect($("setup-count").textContent).toBe("3");
    const steps = all<HTMLButtonElement>("#setup-steps .step");
    expect(steps.map((s) => s.textContent?.trim())).toEqual(["1Domain", "2Sign-in", "3Plans", "4Finish"]);
    expect(steps[0].getAttribute("aria-current")).toBe("step");
    expect(win.document.querySelector("#setup-body .verdict.todo")?.textContent).toBe("! PUBLIC_URL isn't set.");
    expect(shown("setup-back")).toBe(false);
    expect(shown("setup-next") && shown("setup-hide")).toBe(true);
    expect(shown("setup-failed")).toBe(false);
  });

  it("saves the step as before when you go next", async () => {
    await open(() => ({ body: SETUP }));
    $("setup-next").click();
    await flush();
    expect(posts("/api/setup").map((c) => [c.method, c.body])).toEqual([["PATCH", { step: "signin" }]]);
    expect(win.document.querySelector("#setup-steps .step.on")?.getAttribute("data-step")).toBe("signin");
    expect(shown("setup-back")).toBe(true);
  });

  it("shows a load failure as a notice with a way to try again", async () => {
    let reply: Reply = new TypeError("Failed to fetch");
    await open(() => reply, "#setup");
    expect(shown("setup-failed")).toBe(true);
    expect($("setup-failed").getAttribute("role")).toBe("alert");
    expect($("setup-empty").textContent).toBe("Can't reach the server. Check your connection, then try again.");
    expect(shown("setup-next")).toBe(false);

    reply = { status: 500, body: { error: "Database is locked." } };
    $("setup-retry").click();
    await flush();
    expect($("setup-empty").textContent).toBe("Setup didn't load: Database is locked.");

    reply = { body: SETUP };
    $("setup-retry").click();
    await flush();
    expect(shown("setup-failed")).toBe(false);
    expect(all("#setup-steps .step")).toHaveLength(4);
  });

  it("styles the wizard from the tokens, in light and dark", () => {
    const css = fs.readFileSync(path.join(web, "styles.css"), "utf8");
    const setup = css.slice(css.indexOf("/* The setup wizard's first run"), css.indexOf(".warn-text"));
    expect(setup).toContain(".setup-card");
    expect(hexColours(setup)).toEqual([]);
    expect(css).toContain("@media (prefers-color-scheme: dark)");
  });
});
