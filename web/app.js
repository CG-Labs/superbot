// The admin console (ADR 0032): people, requests for access, machines, the audit log,
// and server settings. Chat, Bots, approvals of Bot actions, and screens are in the app
// at /app/. The server decides what each role may do; this page only shows admin tools.

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const key = (id) => encodeURIComponent(id);
const fmt = (ms) => (ms ? new Date(ms).toLocaleString() : "Never");

async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: body ? { "content-type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) location.href = "/login";
  if (res.status === 403) stillAdmin();
  if (!res.ok) throw Object.assign(new Error(data.error || `HTTP ${res.status}`), { status: res.status });
  return data;
}

// Someone who stops being an admin goes to the app, as the server sends them there on reload.
async function stillAdmin() {
  const r = await fetch("/api/auth/me").catch(() => null);
  const me = r?.ok ? await r.json().catch(() => null) : null;
  if (me && !(me.permissions || []).includes("admin")) location.replace("/app/");
}

let noticeTimer = null;
function notice(msg, isError = true) {
  const el = $("error");
  el.textContent = msg;
  el.classList.toggle("ok", !isError);
  el.hidden = !msg;
  clearTimeout(noticeTimer);
  if (msg) noticeTimer = setTimeout(() => { el.hidden = true; }, isError ? 8000 : 4000);
}
const fail = (err) => notice(err.message || String(err));

// Shown-once values: sign-in codes and SCIM tokens. Closing forgets them; the server keeps only hashes.
function showOnce({ title, note, value, link }) {
  $("once-title").textContent = title;
  $("once-note").textContent = note;
  $("once-value").textContent = value;
  $("once-copy-link").hidden = !link;
  $("once-copy-link").dataset.link = link || "";
  $("once").hidden = false;
  $("once-copy").focus();
}
function closeOnce() {
  $("once").hidden = true;
  $("once-value").textContent = "";
  $("once-copy-link").dataset.link = "";
}
async function copy(text, done, shown = $("once-value")) {
  try {
    await navigator.clipboard.writeText(text);
    notice(done, false);
  } catch {
    getSelection().selectAllChildren(shown);
    notice("Copy isn't available here. The value is selected; copy it yourself.");
  }
}
$("once-copy").addEventListener("click", () => copy($("once-value").textContent, "Copied."));
$("once-copy-link").addEventListener("click", () => copy($("once-copy-link").dataset.link, "Invite link copied."));
$("once-close").addEventListener("click", closeOnce);
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("once").hidden) closeOnce(); });

const ROLES = { admin: "Admin", member: "Member", readonly: "Read-only" };
const SIGN_IN = { password: "Password (break-glass)", code: "Sign-in code", sso: "SSO", none: "No auth (dev)", bot_token: "Bot token" };
const roleOptions = (current) => Object.entries(ROLES).map(([v, l]) => `<option value="${v}" ${v === current ? "selected" : ""}>${l}</option>`).join("");

// Users

let users = [];

async function loadUsers() {
  try {
    users = await api("GET", "/api/users");
    $("users-empty").hidden = users.length > 0;
    $("users-empty").textContent = "No users yet.";
  } catch (err) {
    users = [];
    $("users-empty").textContent = err.message;
    $("users-empty").hidden = false;
  }
  renderUsers();
}

function lastLogin(u) {
  const l = u.lastLogin;
  if (!l) return "Never";
  const how = l.authMethod === "sso" && (l.idp || l.idpProvider) ? `SSO · ${l.idp || l.idpProvider}` : SIGN_IN[l.authMethod] || l.authMethod || "";
  return `${esc(fmt(l.at))}<div class="sub">${esc(how)}</div>`;
}

function renderUsers() {
  $("users-rows").innerHTML = users.map((u) => {
    const active = u.status === "active";
    return `<tr data-user="${esc(u.id)}">
      <td><div>${esc(u.name)}${u.breakGlass ? ' <span class="tag">owner</span>' : ""}</div><div class="sub">${esc(u.email || u.id)}</div></td>
      <td><select data-act="role" title="Role" ${u.breakGlass ? "disabled" : ""}>${roleOptions(u.role)}</select></td>
      <td>${active ? "Active" : '<span class="bad">Disabled</span>'}</td>
      <td>${lastLogin(u)}</td>
      <td>${u.pendingCodes ? `Waiting<div class="sub">until ${esc(fmt(u.pendingCodes.expiresAt))}</div>` : ""}</td>
      <td class="actions">
        <button type="button" class="btn" data-act="code" ${active ? "" : "disabled"}>New code</button>
        ${u.breakGlass ? "" : `<button type="button" class="btn" data-act="status">${active ? "Disable" : "Enable"}</button>`}
        <button type="button" class="btn" data-act="sessions">Sign out everywhere</button>
      </td>
    </tr>`;
  }).join("");
}

function codeNote(expiresAt, extra = "") {
  return `Works once, until ${fmt(expiresAt)}. It can't be shown again. ${extra}`.trim();
}

async function newCode(u, replace) {
  const r = await api("POST", `/api/users/${key(u.id)}/login-codes`, { ttlMinutes: +$("code-ttl").value, replace });
  showOnce({
    title: `Sign-in code for ${u.name}`,
    note: codeNote(r.expiresAt, replace ? "Earlier unused codes no longer work." : ""),
    value: r.code,
    link: `${location.origin}/app/#code=${encodeURIComponent(r.code)}`,
  });
}

$("users-rows").addEventListener("click", async (e) => {
  const t = e.target.closest("button[data-act]");
  if (!t) return;
  const u = users.find((x) => x.id === t.closest("tr").dataset.user);
  if (!u) return;
  t.disabled = true;
  try {
    if (t.dataset.act === "code") await newCode(u, true);
    if (t.dataset.act === "status") {
      const disable = u.status === "active";
      if (disable && !confirm(`Disable ${u.name}? They are signed out everywhere and can't sign in until enabled.`)) return;
      await api("PATCH", `/api/users/${key(u.id)}`, { status: disable ? "disabled" : "active" });
    }
    if (t.dataset.act === "sessions") {
      if (!confirm(`Sign ${u.name} out of every session?`)) return;
      const r = await api("DELETE", `/api/users/${key(u.id)}/sessions`);
      notice(`Ended ${r.revoked} session${r.revoked === 1 ? "" : "s"}.`, false);
    }
  } catch (err) {
    fail(err);
  } finally {
    t.disabled = false;
    loadUsers();
  }
});

$("users-rows").addEventListener("change", async (e) => {
  if (e.target.dataset.act !== "role") return;
  const u = users.find((x) => x.id === e.target.closest("tr").dataset.user);
  try {
    await api("PATCH", `/api/users/${key(u.id)}`, { role: e.target.value });
  } catch (err) {
    fail(err);
  }
  loadUsers();
});

$("add-user").addEventListener("submit", async (e) => {
  e.preventDefault();
  const body = { email: $("add-email").value.trim(), role: $("add-role").value };
  const name = $("add-name").value.trim();
  if (name) body.name = name;
  try {
    const u = await api("POST", "/api/users", body);
    $("add-email").value = "";
    $("add-name").value = "";
    await newCode(u, false);
  } catch (err) {
    fail(err);
  }
  loadUsers();
});

// Requests for access (ADR 0022)

let requests = [];
const REQUEST_LIMIT = 1000;

async function loadRequests() {
  const status = $("requests-status").value;
  try {
    requests = await api("GET", `/api/signups?status=${status}&limit=${REQUEST_LIMIT}`);
    $("requests-empty").textContent = status === "pending" ? "Nobody is waiting." : "No requests.";
    $("requests-empty").hidden = requests.length > 0;
    $("requests-capped").textContent = `Showing the newest ${REQUEST_LIMIT}. Older requests are in the audit log.`;
    $("requests-capped").hidden = requests.length < REQUEST_LIMIT;
    if (status === "pending") setRequestCount(requests.length);
  } catch (err) {
    requests = [];
    $("requests-capped").hidden = true;
    $("requests-empty").textContent = err.message;
    $("requests-empty").hidden = false;
  }
  renderRequests();
}

function setRequestCount(n) {
  $("requests-count").textContent = n || "";
}
async function refreshRequestCount() {
  try { setRequestCount((await api("GET", `/api/signups?status=pending&limit=${REQUEST_LIMIT}`)).length); } catch {}
}

function renderRequests() {
  $("requests-list").innerHTML = requests.map((s) => {
    const decided = s.status === "approved"
      ? `<p class="sub">Approved as ${esc(ROLES[s.role] || s.role)} on ${esc(fmt(s.decidedAt))}.</p>`
      : `<p class="sub">Rejected on ${esc(fmt(s.decidedAt))}${s.reason ? `: ${esc(s.reason)}` : "."}</p>`;
    const actions = s.existingUser
      ? `<p class="warn">A user with this email exists already. Reject this request, or give them a code from Users.</p>
         <div class="actions"><button type="button" class="btn" data-act="reject">Reject</button></div>`
      : `<div class="actions">
           <select data-role title="Role">${roleOptions("member")}</select>
           <button type="button" class="btn primary" data-act="approve">Approve</button>
           <button type="button" class="btn" data-act="reject">Reject</button>
         </div>`;
    return `<div class="card" data-signup="${esc(s.id)}">
      <div><b>${esc(s.name)}</b> <span class="sub">${esc(s.email)}</span></div>
      <div class="sub">${esc(s.company)} · ${esc(s.teamSize)} people · signs in with ${esc(s.signIn)} · ${esc(fmt(s.createdAt))}</div>
      <p class="use">${esc(s.useCase)}</p>
      ${s.status === "pending" ? actions : decided}
    </div>`;
  }).join("");
}

$("requests-status").addEventListener("change", loadRequests);
$("requests-list").addEventListener("click", async (e) => {
  const t = e.target.closest("button[data-act]");
  if (!t) return;
  const card = t.closest(".card");
  const s = requests.find((x) => x.id === card.dataset.signup);
  if (!s) return;
  try {
    if (t.dataset.act === "approve") {
      t.disabled = true;
      const role = card.querySelector("[data-role]").value;
      const r = await api("POST", `/api/signups/${key(s.id)}/approve`, { role, ttlMinutes: +$("request-ttl").value });
      const sso = (r.sso || []).map((p) => p.label || p.id).join(", ");
      const extra = [r.emailed ? "It was emailed to them too." : "", sso ? `They could use ${sso} once you link it in the app's Users page.` : ""].join(" ");
      showOnce({ title: `Sign-in code for ${r.user.name}`, note: codeNote(r.expiresAt, extra), value: r.code, link: `${location.origin}/app/#code=${encodeURIComponent(r.code)}` });
    }
    if (t.dataset.act === "reject") {
      const reason = prompt(`Reject ${s.name}'s request? Reason (optional, only admins see it):`, "");
      if (reason === null) return;
      await api("POST", `/api/signups/${key(s.id)}/reject`, { reason: reason.trim() || null });
    }
  } catch (err) {
    fail(err);
  } finally {
    t.disabled = false;
  }
  loadRequests();
  refreshRequestCount();
});

// Machines: one per user from the control plane (ADR 0025). Off unless it's configured.

let machines = [];

async function loadMachines() {
  let off = false;
  try {
    machines = await api("GET", "/api/machines");
    $("machines-empty").textContent = "No machines yet.";
  } catch (err) {
    machines = [];
    off = err.status === 503;
    $("machines-empty").textContent = err.message;
  }
  $("give-machine").hidden = off;
  renderMachines();
}

function machineActions(m) {
  const b = (act, label) => `<button type="button" class="btn" data-act="${act}">${label}</button>`;
  switch (m.state) {
    case "running": return b("suspend", "Suspend") + b("resize", "Resize") + b("destroy", "Destroy");
    case "suspended": return b("resume", "Resume") + b("resize", "Resize") + b("destroy", "Destroy");
    case "error": return b("retry", "Retry") + b("destroy", "Destroy");
    case "destroyed": return "";
    default: return b("destroy", "Destroy");
  }
}

function renderMachines() {
  const list = $("machines-destroyed").checked ? machines : machines.filter((m) => m.state !== "destroyed");
  $("machines-empty").hidden = list.length > 0;
  $("machines-rows").innerHTML = list.map((m) => `<tr data-machine="${esc(m.id)}">
      <td>${esc(m.userEmail || m.userId)}</td>
      <td>${esc(m.state)}${m.providerStatus ? `<div class="sub">${esc(m.providerStatus)}</div>` : ""}${m.lastError ? `<div class="sub bad">${esc(m.lastError)}</div>` : ""}${m.enrollOverdueAt && m.enrollment !== "enrolled" ? `<div class="sub bad">Didn't enroll in time (since ${esc(fmt(m.enrollOverdueAt))})</div>` : ""}</td>
      <td>${esc(m.tier)}<div class="sub">${esc(m.plan)}</div></td>
      <td>${esc(m.region)}</td>
      <td>${esc(m.ipv4 || "")}</td>
      <td>${esc(fmt(m.updatedAt))}</td>
      <td class="actions">${machineActions(m)}</td>
    </tr>`).join("");
}

$("machines-destroyed").addEventListener("change", renderMachines);
$("machines-rows").addEventListener("click", async (e) => {
  const t = e.target.closest("button[data-act]");
  if (!t) return;
  const m = machines.find((x) => x.id === t.closest("tr").dataset.machine);
  if (!m) return;
  const who = m.userEmail || m.userId;
  t.disabled = true;
  try {
    if (t.dataset.act === "suspend") await api("POST", `/api/users/${key(m.userId)}/machine/suspend`);
    if (t.dataset.act === "resume") await api("POST", `/api/users/${key(m.userId)}/machine/resume`);
    if (t.dataset.act === "retry") await api("POST", `/api/users/${key(m.userId)}/machine`);
    if (t.dataset.act === "resize") {
      const tier = prompt(`Move ${who}'s machine to which tier? The provider may restart it.`, m.tier)?.trim();
      if (!tier || tier === m.tier) return;
      await api("POST", `/api/users/${key(m.userId)}/machine/resize`, { tier });
    }
    if (t.dataset.act === "destroy") {
      if (!confirm(`Destroy ${who}'s machine and its disks? This can't be undone.`)) return;
      await api("DELETE", `/api/users/${key(m.userId)}/machine`);
    }
  } catch (err) {
    fail(err);
  } finally {
    t.disabled = false;
    loadMachines();
  }
});

$("give-machine").addEventListener("submit", async (e) => {
  e.preventDefault();
  const body = {};
  for (const f of ["tier", "region"]) {
    const v = $(`machine-${f}`).value.trim();
    if (v) body[f] = v;
  }
  try {
    await api("POST", `/api/users/${key($("machine-user").value.trim())}/machine`, body);
    $("machine-user").value = "";
  } catch (err) {
    fail(err);
  }
  loadMachines();
});

$("machines-reconcile").addEventListener("click", async () => {
  try {
    const r = await api("POST", "/api/machines/reconcile");
    notice(`Checked ${r.checked}, changed ${r.changed}.`, false);
  } catch (err) {
    fail(err);
  }
  loadMachines();
});

// Audit log: append-only record of sign-ins and admin actions (docs/adr/0009-audit-events.md),
// with who acted and how they signed in (docs/adr/0019-audit-actors.md).
// `query` is the filter the shown rows came from; Load more pages with it, not the form.
const audit = { events: [], next: null, query: "", error: "", seq: 0 };

function auditQuery() {
  const p = new URLSearchParams();
  const action = $("au-action").value.trim();
  if (action) p.set("action", action);
  const person = $("au-person").value.trim();
  if (person) p.set("actor", `user:${person}`);
  else if ($("au-actor").value) p.set("actor", $("au-actor").value);
  if ($("au-method").value) p.set("method", $("au-method").value);
  // Whole days in the browser's time zone, sent as unix ms.
  const day = (id, add) => {
    const v = $(id).value;
    if (!v) return null;
    const [y, m, d] = v.split("-").map(Number);
    return new Date(y, m - 1, d + add).getTime();
  };
  const from = day("au-from", 0), to = day("au-to", 1);
  if (from != null) p.set("from", from);
  if (to != null) p.set("to", to);
  return p;
}

async function loadAudit(more) {
  if (more && !audit.next) return;
  const seq = ++audit.seq;
  const p = more ? new URLSearchParams(audit.query) : auditQuery();
  if (more) {
    p.set("before", audit.next);
  } else {
    audit.query = p.toString();
    audit.next = null;
    $("au-more").hidden = true;
    $("au-export").href = `/api/audit/export.csv?${p}`;
  }
  p.set("limit", 100);
  try {
    const page = await api("GET", `/api/audit?${p}`);
    if (seq !== audit.seq) return;
    audit.events = more ? audit.events.concat(page.events) : page.events;
    audit.next = page.nextBefore;
    audit.error = "";
  } catch (err) {
    if (seq !== audit.seq) return;
    audit.error = err.message;
    if (!more) { audit.events = []; audit.next = null; }
  }
  renderAudit();
}

function renderAudit() {
  const who = (e) => {
    if (e.actorKind === "bot") return e.actorName || e.actorId || "A Bot";
    if (e.actorKind === "user") return e.actorName || e.actorEmail || e.actorId || "Unknown person";
    return `System${e.actorId ? ` · ${e.actorId}` : ""}`;
  };
  // A user's name from any loaded event, for "on behalf of".
  const nameOf = (id) => audit.events.find((x) => x.actorKind === "user" && x.actorId === id && x.actorName)?.actorName || id;
  const how = (e) => {
    const ids = e.idp || e.idpProvider;
    const sso = e.authMethod === "sso" && ids ? `SSO · ${ids}${e.idpProvider && e.idpProvider !== e.idp ? ` (${e.idpProvider})` : ""}` : null;
    return [e.actorRole, sso || SIGN_IN[e.authMethod] || e.authMethod, e.onBehalfOf && `for ${nameOf(e.onBehalfOf)}`].filter(Boolean).join(" · ");
  };
  const tip = (e) => [
    e.actorEmail, e.actorId && `id ${e.actorId}`, e.actorSubject && `IdP subject ${e.actorSubject}`,
    e.sessionId && `session ${e.sessionId}`, e.onBehalfOf && `on behalf of ${e.onBehalfOf}`,
  ].filter(Boolean).join("\n");
  const target = (e) => [e.targetType, e.targetId].filter(Boolean).join(" ");
  const details = (e) => { const s = JSON.stringify(e.details ?? {}); return s === "{}" ? "" : s; };
  $("au-rows").innerHTML = audit.events.map((e) => `<tr class="${e.outcome === "success" ? "" : "au-bad"}">
      <td title="${esc(e.time)}">${esc(new Date(e.at).toLocaleString())}</td>
      <td class="au-who" title="${esc(tip(e))}">${esc(who(e))}${how(e) ? `<span class="sub">${esc(how(e))}</span>` : ""}</td>
      <td><code>${esc(e.action)}</code></td>
      <td>${esc(target(e))}</td>
      <td>${esc(e.outcome)}</td>
      <td title="${esc(e.userAgent || "")}">${esc(e.ip || "")}</td>
      <td class="au-detail" title="${esc(details(e))}">${esc(details(e))}</td>
    </tr>`).join("");
  $("au-empty").textContent = audit.error || "No events match.";
  $("au-empty").hidden = !audit.error && audit.events.length > 0;
  $("au-more").hidden = !audit.next || !!audit.error;
}

let auditTimer = null;
$("au-more").addEventListener("click", () => loadAudit(true));
$("au-filters").addEventListener("submit", (e) => { e.preventDefault(); loadAudit(); });
$("au-filters").addEventListener("change", () => loadAudit());
for (const id of ["au-action", "au-person"]) {
  $(id).addEventListener("input", () => { clearTimeout(auditTimer); auditTimer = setTimeout(() => loadAudit(), 300); });
}

// Settings

let policyMode = "ask";

async function loadSettings() {
  try {
    policyMode = (await api("GET", "/api/policy")).policy.mode;
    $("policy-mode").value = policyMode;
  } catch (err) {
    fail(err);
  }
  loadLicense();
  loadSignIn();
  loadSecrets();
  loadScim();
}

// The license (ADR 0038). botd checks the key; once saved it's never sent back.

const LICENSE_MODES = { community: "Community edition", active: "Licensed", grace: "Grace period", expired: "Ended", invalid: "Invalid key" };

function licenseView(l) {
  const lic = l.license;
  const day = (ms) => new Date(ms).toLocaleDateString();
  const facts = lic
    ? `<p>${esc(lic.licensee)} · ${esc(lic.edition)} edition · ends ${esc(day(lic.expiresAt))}${lic.features.length ? ` · ${esc(lic.features.join(", "))}` : ""}<span class="sub">License ${esc(lic.id)}</span></p>`
    : "";
  const seats = l.seats.limit == null ? `${l.seats.used} active, no seat limit.` : `${l.seats.used} of ${l.seats.limit} seats in use.`;
  const warnings = l.warnings.filter((w) => w !== l.detail);
  const change = l.savable
    ? `<form class="secret-inline" data-license autocomplete="off">
        <textarea rows="2" placeholder="Paste the license key from CG-Labs" required spellcheck="false" autocomplete="off"></textarea>
        <button type="submit" class="btn primary">${lic ? "Replace" : "Install"}</button>
        ${l.source === "file" ? '<button type="button" class="btn" data-act="license-remove">Remove</button>' : ""}
      </form>`
    : `<p class="hint">Set by <code>LICENSE_KEY</code> or <code>LICENSE_KEY_FILE</code> in botd's environment, which wins. To change it, edit .env and restart botd.</p>`;
  return verdict(l.ok && !warnings.length, `${LICENSE_MODES[l.mode] || l.mode}. ${l.detail}`)
    + facts
    + `<p class="hint">${esc(seats)} Active people other than the owner account take a seat; over the limit, nobody is signed out, but nobody new can be added.</p>`
    + warnings.map((w) => `<p class="warn">${esc(w)}</p>`).join("")
    + change;
}

async function loadLicense() {
  try {
    $("license-box").innerHTML = licenseView(await api("GET", "/api/license"));
  } catch (err) {
    $("license-box").innerHTML = `<p class="warn">${esc(err.message)}</p>`;
  }
}

async function installLicense(form) {
  try {
    const l = await api("PUT", "/api/license", { key: form.querySelector("textarea").value.trim() });
    notice(`License installed: ${l.detail}`, false);
  } catch (err) {
    fail(err);
  }
}

async function removeLicense() {
  if (!confirm("Remove the license? The server becomes the community edition, free for up to 10 active people. Nobody is signed out.")) return;
  try {
    await api("DELETE", "/api/license");
    notice("License removed.", false);
  } catch (err) {
    fail(err);
  }
}

$("license-box").addEventListener("submit", async (e) => {
  e.preventDefault();
  await installLicense(e.target);
  loadLicense();
});
$("license-box").addEventListener("click", async (e) => {
  if (!e.target.closest("button[data-act=license-remove]")) return;
  await removeLicense();
  loadLicense();
});

$("policy-mode").addEventListener("change", async (e) => {
  const mode = e.target.value;
  if (mode === "bypass" && !confirm("Let every Bot run risky actions without asking? Use this only on a dev machine.")) {
    e.target.value = policyMode;
    return;
  }
  try {
    policyMode = (await api("PUT", "/api/policy", { mode })).policy.mode;
  } catch (err) {
    fail(err);
  }
  e.target.value = policyMode;
});

async function loadSignIn() {
  let providers = [];
  try { providers = (await api("GET", "/api/auth/sso")).providers || []; } catch {}
  const sso = providers.length ? `SSO: ${providers.map((p) => `${p.label || p.id} (${p.type || "oidc"})`).join(", ")}.` : "No SSO providers are set up (SSO_PROVIDERS).";
  const glass = me.breakGlass ? "Break-glass password sign-in at /login is on (AUTH_BREAK_GLASS)." : "Break-glass password sign-in is off.";
  $("signin-info").textContent = `${glass} ${sso} Sign-in codes come from Users.`;
}

let secrets = [];

async function loadSecrets() {
  try {
    secrets = (await api("GET", "/api/secrets")).secrets || [];
    $("secrets-empty").textContent = "No server secrets.";
  } catch (err) {
    secrets = [];
    $("secrets-empty").textContent = err.message;
  }
  $("secrets-empty").hidden = secrets.length > 0;
  $("secrets-rows").innerHTML = secrets.map((s) => {
    const notes = [s.shadowedBy && `Overridden by ${s.shadowedBy}`, s.forBots === false && "Server only, no Bot gets it"].filter(Boolean).join(" · ");
    return `<tr data-secret="${esc(s.name)}">
      <td><code>${esc(s.name)}</code></td><td>${esc(s.store)}</td><td><span class="sub">${esc(notes)}</span></td>
      <td class="actions">${s.writable ? '<button type="button" class="btn" data-act="delete">Delete</button>' : ""}</td>
    </tr>`;
  }).join("");
}

$("secret-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const name = $("secret-name").value.trim();
  try {
    await api("PUT", `/api/secrets/${key(name)}`, { value: $("secret-value").value });
    $("secret-name").value = "";
    $("secret-value").value = "";
    notice(`Saved ${name}.`, false);
  } catch (err) {
    fail(err);
  }
  loadSecrets();
});

$("secrets-rows").addEventListener("click", async (e) => {
  const t = e.target.closest("button[data-act=delete]");
  if (!t) return;
  const name = t.closest("tr").dataset.secret;
  if (!confirm(`Delete the secret ${name}? Bots that use it lose it on their next run.`)) return;
  try { await api("DELETE", `/api/secrets/${key(name)}`); } catch (err) { fail(err); }
  loadSecrets();
});

let scimTokens = [];

async function loadScim() {
  try {
    const r = await api("GET", "/api/scim/tokens");
    scimTokens = r.tokens || [];
    $("scim-info").textContent = `${r.enabled ? "SCIM is on" : "SCIM is off (set SCIM=on to turn it on)"}. Provisioned people get the ${ROLES[r.defaultRole] || r.defaultRole} role. Endpoint: ${location.origin}/scim/v2`;
    $("scim-empty").textContent = "No SCIM tokens.";
  } catch (err) {
    scimTokens = [];
    $("scim-info").textContent = "";
    $("scim-empty").textContent = err.message;
  }
  $("scim-empty").hidden = scimTokens.length > 0;
  $("scim-rows").innerHTML = scimTokens.map((t) => `<tr data-token="${esc(t.id)}" class="${t.revokedAt ? "revoked" : ""}">
      <td>${esc(t.tenant)}</td><td>${esc(t.label || "")}</td><td>${esc(t.ssoProvider || "")}</td>
      <td>${esc(fmt(t.createdAt))}</td><td>${esc(fmt(t.lastUsedAt))}</td>
      <td class="actions">${t.revokedAt ? `Revoked ${esc(fmt(t.revokedAt))}` : '<button type="button" class="btn" data-act="revoke">Revoke</button>'}</td>
    </tr>`).join("");
}

$("scim-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const body = { tenant: $("scim-tenant").value.trim() };
  const label = $("scim-label").value.trim(), sso = $("scim-sso").value.trim();
  if (label) body.label = label;
  if (sso) body.sso = sso;
  try {
    const r = await api("POST", "/api/scim/tokens", body);
    for (const id of ["scim-tenant", "scim-label", "scim-sso"]) $(id).value = "";
    showOnce({ title: `SCIM token for ${r.scimToken.tenant}`, note: "Paste it into your identity provider's provisioning settings now. It can't be shown again.", value: r.token });
  } catch (err) {
    fail(err);
  }
  loadScim();
});

$("scim-rows").addEventListener("click", async (e) => {
  const t = e.target.closest("button[data-act=revoke]");
  if (!t) return;
  const tok = scimTokens.find((x) => x.id === t.closest("tr").dataset.token);
  if (!tok || !confirm(`Revoke this ${tok.tenant} token? The identity provider can't provision with it any more.`)) return;
  try { await api("DELETE", `/api/scim/tokens/${key(tok.id)}`); } catch (err) { fail(err); }
  loadScim();
});

// Setup: the onboarding wizard (ADR 0034). The server reports what's set up. This page saves
// where you are, SSO secrets (secrets API), and the approval mode (policy API); settings botd
// reads at startup come back as commands and .env lines to copy.

const SETUP_STEPS = { domain: "Domain", signin: "Sign-in", tiers: "Plans", finish: "Finish" };
// `seq` numbers requests; only the newest one's reply is used, so a slow reply can't move
// the page back to an older step.
const setup = { data: null, step: "domain", template: "", copies: [], seq: 0 };

async function loadSetup() {
  const seq = ++setup.seq;
  try {
    const data = await api("GET", "/api/setup");
    if (seq !== setup.seq) return;
    setup.data = data;
    setup.step = data.progress.step;
    $("setup-empty").hidden = true;
  } catch (err) {
    if (seq !== setup.seq) return;
    setup.data = null;
    $("setup-empty").textContent = err.message;
    $("setup-empty").hidden = false;
  }
  renderSetup();
}

async function saveSetup(body) {
  const seq = ++setup.seq;
  try {
    const data = await api("PATCH", "/api/setup", body);
    if (seq !== setup.seq) return;
    setup.data = data;
    setup.step = data.progress.step;
  } catch (err) {
    fail(err);
  }
  if (seq === setup.seq) renderSetup();
}

// Shows the step at once and saves it in the background. The reply redraws the step only
// if the server's state changed meanwhile and nothing has been typed into it yet.
async function goSetup(step) {
  setup.step = step;
  renderSetup();
  const seq = ++setup.seq;
  try {
    const data = await api("PATCH", "/api/setup", { step });
    if (seq !== setup.seq) return;
    const changed = setupState(setup.data) !== setupState(data);
    setup.data = data;
    const typed = [...$("setup-body").querySelectorAll("textarea")].some((t) => t.value);
    if (changed && !typed) renderSetup();
    else renderSetupHead();
  } catch (err) {
    fail(err);
  }
}

const setupState = (s) => JSON.stringify(s && { ...s, progress: { ...s.progress, step: null } });

// Open checklist items on the tab while admins are still sent here.
function setupCount(s) {
  $("setup-count").textContent = s?.progress?.show ? s.total - s.done || "" : "";
}

function copyBlock(text) {
  const i = setup.copies.push(text) - 1;
  return `<div class="cmd"><pre>${esc(text)}</pre><button type="button" class="btn" data-copy="${i}">Copy</button></div>`;
}
const howto = (steps) => steps.map((s) => `<div class="howto"><h3>${esc(s.title)}</h3><p class="hint">${esc(s.text)}</p>${s.commands.length ? copyBlock(s.commands.join("\n")) : ""}</div>`).join("");
const verdict = (ok, text) => `<p class="verdict ${ok ? "good" : "todo"}">${ok ? "✓" : "!"} ${esc(text)}</p>`;

function setupDomain(d) {
  return verdict(d.ok, d.detail)
    + (d.publicUrl ? `<p>Public address: <code>${esc(d.publicUrl)}</code></p>` : "")
    + `<h2>Set the domain</h2><p class="hint">botd and Caddy read it at startup, so run these on the server. This page can't change them.</p>`
    + howto(d.instructions);
}

const providerRow = (p) => `<tr>
    <td>${esc(p.label)}<div class="sub">${esc(p.id)} · ${esc(p.type)}${p.jitRole ? ` · new people join as ${esc(ROLES[p.jitRole] || p.jitRole)}` : ""}</div></td>
    <td>${p.ready ? "Ready" : `<span class="warn-text">${esc(p.problem || "Not ready")}</span>`}</td>
    <td>${copyBlock(p.callbackUrl)}</td>
    <td>${p.secretSavable === false ? envSecret(p.secret) : secretForm(p)}</td>
  </tr>`;
const secretForm = (p) => `<form class="secret-inline" data-secret="${esc(p.secret)}" autocomplete="off">
    <textarea rows="1" placeholder="${esc(p.secret)}" required spellcheck="false" autocomplete="off"></textarea>
    <button type="submit" class="btn">${p.ready ? "Replace" : "Save"}</button>
  </form>`;
// botd's environment wins over a saved value, so saving here would change nothing.
const envSecret = (name) => `<span class="sub">Set by <code>${esc(name)}</code> (or <code>${esc(name)}_FILE</code>) in botd's environment. To change it, edit .env and restart botd.</span>`;

function setupSignIn(s) {
  const providers = s.providers.length
    ? `<table class="grid"><thead><tr><th>Provider</th><th>State</th><th>Redirect URI to register at the IdP</th><th>Secret</th></tr></thead>
      <tbody>${s.providers.map(providerRow).join("")}</tbody></table>
      <p class="hint">Secrets saved here go to the server's secrets store and take effect at once, no restart. They're never shown again.</p>`
    : "";
  const admins = s.admins.length
    ? `<p>Admins besides the owner: ${s.admins.map((a) => esc(a.name || a.email || a.id)).join(", ")}.</p>`
    : `<p class="warn">Only the break-glass owner is an admin. <a href="#users">Add a second admin in Users</a> so you aren't locked out if the password is lost or turned off.</p>`;
  const glass = s.breakGlass ? "Break-glass password sign-in at /login is on." : "Break-glass password sign-in is off.";
  const extra = [glass, s.scim ? "SCIM provisioning is on." : "", s.signups ? "People can request access." : ""].filter(Boolean).join(" ");
  const pick = s.templates.find((t) => t.id === setup.template) || s.templates.find((t) => !t.configured) || s.templates[0];
  setup.template = pick.id;
  const template = `<h2>Add a provider</h2>
    <div class="bar"><label>Provider <select id="setup-template">${s.templates.map((t) => `<option value="${esc(t.id)}" ${t.id === pick.id ? "selected" : ""}>${esc(t.label)}${t.configured ? " (set up)" : ""}</option>`).join("")}</select></label></div>
    <p class="hint">1. Register SuperBot at the provider (see ${esc(pick.docs)}) with this redirect URI:</p>${copyBlock(pick.callbackUrl)}
    <p class="hint">2. Add these lines to .env, filling in the &lt;placeholders&gt;:</p>${copyBlock(pick.env)}
    <p class="hint">3. Restart botd (below). 4. The provider then shows up on this page: save its secret, <code>${esc(pick.secret)}</code>, there.</p>
    ${howto(s.restart)}`;
  return verdict(s.ok, s.detail) + providers + `<h2>Admins</h2>${admins}<p class="hint">${esc(extra)}</p>` + template;
}

function limitsText(l) {
  const n = (v) => Number(v).toLocaleString();
  return [l?.maxBots != null && `${n(l.maxBots)} Bots`, l?.monthlyRuns != null && `${n(l.monthlyRuns)} runs a month`, l?.monthlyTokens != null && `${n(l.monthlyTokens)} tokens a month (not enforced yet)`]
    .filter(Boolean).join(" · ") || "No limits";
}

function setupTiers(t) {
  const rows = t.tiers.map((x) => `<tr>
      <td>${esc(x.label)}<div class="sub">${esc(x.name)}${x.name === t.default ? " · default" : ""}</div></td>
      <td>${x.managed ? "Set harnesses and models" : "Any harness and model"}</td>
      <td>${esc(limitsText(x.limits))}</td>
    </tr>`).join("");
  return verdict(true, t.detail)
    + `<table class="grid"><thead><tr><th>Plan</th><th>Harnesses and models</th><th>Limits</th></tr></thead><tbody>${rows}</tbody></table>`
    + `<h2>${t.fileLoaded ? "Change the plans" : "Sell plans or set limits"}</h2><p class="hint">botd reads the tiers file at startup. Skip this to keep the open self-host tier.</p>`
    + howto(t.instructions);
}

function setupLicense(l) {
  return `<h2>License</h2><p class="hint">Without one, SuperBot is the community edition: every feature, for up to ${esc(l.seats.community)} active people. A license from CG-Labs sets your seats.</p>`
    + licenseView(l)
    + howto(l.instructions);
}

function setupFinish(s) {
  const fix = (c) => {
    if (c.done) return "";
    if (c.id === "admin") return '<a class="btn" href="#users">Open Users</a>';
    if (c.id === "approvals") return '<button type="button" class="btn" data-act="approvals">Turn approvals on</button>';
    if (c.id === "license") return '<button type="button" class="btn" data-go="tiers">Go to Plans</button>';
    return c.id in SETUP_STEPS ? `<button type="button" class="btn" data-go="${esc(c.id)}">Go to ${esc(SETUP_STEPS[c.id])}</button>` : "";
  };
  const row = (c) => `<li class="${c.done ? "good" : "todo"}">
      <div><b>${c.done ? "✓" : "○"} ${esc(c.label)}</b><span class="sub">${esc(c.detail)}</span></div>${fix(c)}
    </li>`;
  const list = `<ul class="checklist">${s.checklist.map(row).join("")}</ul>`;
  const p = s.progress;
  if (p.completedAt) {
    const by = p.completedBy === me.user?.id ? "you" : s.signIn.admins.find((a) => a.id === p.completedBy)?.name;
    return list + verdict(true, `Setup was finished ${fmt(p.completedAt)}${by ? ` by ${by}` : ""}.`)
      + '<div class="bar"><button type="button" class="btn" data-act="reopen">Reopen setup</button></div>';
  }
  const open = s.total - s.done;
  return list + `<p class="hint">${open ? `${open} item${open === 1 ? " is" : "s are"} still open. You can finish anyway and come back to them.` : "Everything is set."} Finishing stops sending admins here; the Setup tab stays.</p>`
    + '<div class="bar"><button type="button" class="btn primary" data-act="finish">Finish setup</button></div>';
}

function renderSetup() {
  const s = setup.data;
  setup.copies = [];
  $("setup-body").innerHTML = "";
  renderSetupHead();
  if (!s) return;
  const view = { domain: () => setupDomain(s.domain), signin: () => setupSignIn(s.signIn), tiers: () => setupTiers(s.tiers) + setupLicense(s.license), finish: () => setupFinish(s) }[setup.step];
  $("setup-body").innerHTML = view ? view() : "";
}

// Everything but the step's own content: the count, the step buttons, and the controls.
function renderSetupHead() {
  const s = setup.data;
  setupCount(s);
  $("setup-steps").innerHTML = "";
  for (const id of ["setup-hide", "setup-unhide", "setup-back", "setup-next"]) $(id).hidden = true;
  $("setup-state").textContent = "";
  if (!s) return;
  const done = (id) => (id === "finish" ? !!s.progress.completedAt : s.checklist.find((c) => c.id === id)?.done);
  $("setup-steps").innerHTML = s.steps.map((id, i) => `<button type="button" class="step ${id === setup.step ? "on" : ""}" data-step="${esc(id)}" ${id === setup.step ? 'aria-current="step"' : ""}>
      <span class="n">${done(id) ? "✓" : i + 1}</span>${esc(SETUP_STEPS[id] || id)}</button>`).join("");
  const i = s.steps.indexOf(setup.step);
  $("setup-back").hidden = i <= 0;
  $("setup-next").hidden = i < 0 || i >= s.steps.length - 1;
  const p = s.progress;
  $("setup-state").textContent = p.completedAt ? "Finished." : p.dismissed ? "Hidden: admins aren't sent here." : `${s.done} of ${s.total} done.`;
  $("setup-hide").hidden = !p.show;
  $("setup-unhide").hidden = !(p.dismissed && !p.completedAt);
}

$("setup-steps").addEventListener("click", (e) => {
  const t = e.target.closest("button[data-step]");
  if (t) goSetup(t.dataset.step);
});
$("setup-back").addEventListener("click", () => goSetup(setup.data.steps[setup.data.steps.indexOf(setup.step) - 1]));
$("setup-next").addEventListener("click", () => goSetup(setup.data.steps[setup.data.steps.indexOf(setup.step) + 1]));
$("setup-hide").addEventListener("click", async () => {
  await saveSetup({ dismissed: true });
  if (setup.data?.progress.dismissed) {
    notice("Setup is hidden. It's still under the Setup tab.", false);
    location.hash = "users";
  }
});
$("setup-unhide").addEventListener("click", () => saveSetup({ dismissed: false }));

$("setup-body").addEventListener("click", async (e) => {
  const c = e.target.closest("button[data-copy]");
  if (c) return copy(setup.copies[+c.dataset.copy], "Copied.", c.previousElementSibling);
  const g = e.target.closest("button[data-go]");
  if (g) return goSetup(g.dataset.go);
  const t = e.target.closest("button[data-act]");
  if (!t) return;
  t.disabled = true;
  if (t.dataset.act === "license-remove") {
    await removeLicense();
    return loadSetup();
  }
  if (t.dataset.act === "approvals") {
    try { await api("PUT", "/api/policy", { mode: "ask" }); } catch (err) { fail(err); }
    return loadSetup();
  }
  if (t.dataset.act === "finish") {
    await saveSetup({ completed: true });
    if (setup.data?.progress.completedAt) notice("Setup is finished. You can reopen it from the Setup tab.", false);
  }
  if (t.dataset.act === "reopen") await saveSetup({ completed: false, step: "domain" });
});

$("setup-body").addEventListener("change", (e) => {
  if (e.target.id !== "setup-template") return;
  setup.template = e.target.value;
  renderSetup();
});

$("setup-body").addEventListener("submit", async (e) => {
  const l = e.target.closest("form[data-license]");
  if (l) {
    e.preventDefault();
    await installLicense(l);
    return loadSetup();
  }
  const f = e.target.closest("form[data-secret]");
  if (!f) return;
  e.preventDefault();
  const name = f.dataset.secret;
  try {
    const r = await api("PUT", `/api/secrets/${key(name)}`, { value: f.querySelector("textarea").value });
    if (r.secret?.shadowedBy) notice(`Saved ${name}, but botd's environment sets it too, and that value still wins. Remove ${name} (and ${name}_FILE) from .env and restart botd.`);
    else notice(`Saved ${name}.`, false);
  } catch (err) {
    fail(err);
  }
  loadSetup();
});

// Tabs, from the address bar's #fragment so a reload keeps your place.

const TABS = { users: loadUsers, requests: loadRequests, machines: loadMachines, audit: () => loadAudit(), settings: loadSettings, setup: loadSetup };

function showTab() {
  const name = location.hash.slice(1);
  const tab = name in TABS ? name : "users";
  for (const t of Object.keys(TABS)) $(`tab-${t}`).hidden = t !== tab;
  for (const a of document.querySelectorAll("#tabs a")) a.classList.toggle("on", a.dataset.tab === tab);
  TABS[tab]();
}
window.addEventListener("hashchange", showTab);

$("signout-btn").addEventListener("click", async () => {
  await api("POST", "/api/auth/logout").catch(() => {});
  location.href = "/login";
});

let me = {};
async function start() {
  me = await api("GET", "/api/auth/me");
  if (!(me.permissions || []).includes("admin")) return location.replace("/app/");
  $("me-name").textContent = me.user?.name || "";
  // Admins land on the setup wizard until someone finishes or hides it.
  const s = await api("GET", "/api/setup").catch(() => null);
  setupCount(s);
  if (!location.hash && s?.progress?.show) history.replaceState(null, "", "#setup");
  showTab();
  refreshRequestCount();
}

start().catch((err) => notice(`Can't reach the server: ${err.message}`));
