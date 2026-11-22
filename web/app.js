// The admin console (ADR 0032): people, requests for access, machines, teams, the audit log,
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
function showOnce({ title, note, value, link, lines = false }) {
  $("once-title").textContent = title;
  $("once-note").textContent = note;
  $("once-value").textContent = value;
  $("once-value").classList.toggle("lines", lines);
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

// Where their machine and backups live (ADR 0117): their own region, their team's, or the default.
const REGION_FROM = { user: "their own", team: "their team's", default: "the default" };
function regionCell(r) {
  if (!r) return "";
  const gone = r.offered ? "" : '<div class="sub bad">No longer offered</div>';
  return `${esc(r.region)}<div class="sub">${esc(REGION_FROM[r.source] || r.source)}</div>${gone}`;
}

// A residency pin (ADR 0129): their data held to a region under an agreement.
function pinNote(p) {
  if (!p) return "";
  return `<div class="sub">Pinned${p.subjectType === "team" ? " by team" : ""} to ${esc(p.region)} · ${esc(p.reference)}</div>`;
}

async function setResidency(path, who, pin, region) {
  if (pin) {
    const why = prompt(`${who}'s data is pinned to ${pin.region} under "${pin.reference}". To unpin, give the reason; it is audited. The data region stays as it is.`);
    if (!why?.trim()) return;
    await api("DELETE", path, { reason: why.trim() });
    return;
  }
  const r = prompt(`Pin ${who}'s data to a region under an agreement: machines, backups and restores stay there or are refused. Refused while any of it is elsewhere. Region:`, region || "");
  if (!r?.trim()) return;
  const ref = prompt("The agreement it is under (for example a DPA reference):");
  if (!ref?.trim()) return;
  await api("PUT", path, { region: r.trim(), reference: ref.trim() });
}

async function setRegion(path, who, current) {
  const r = prompt(`Data region for ${who}: where their machines and backups live. Leave empty for the default. Refused while a machine is elsewhere.`, current || "");
  if (r === null || r.trim() === (current || "")) return;
  await api("PUT", path, { region: r.trim() || null });
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
      <td>${u.mfa?.enabled ? `On<div class="sub">since ${esc(fmt(u.mfa.enabledAt))}</div>` : ""}</td>
      <td>${regionCell(u.dataRegion)}${pinNote(u.residency)}${u.ownResidency && u.residency?.subjectType === "team" ? pinNote(u.ownResidency) : ""}</td>
      <td class="actions">
        <button type="button" class="btn" data-act="code" ${active ? "" : "disabled"}>New code</button>
        ${u.mfa?.enabled && u.id !== me.user?.id ? '<button type="button" class="btn" data-act="mfa">Reset 2FA</button>' : ""}
        ${u.breakGlass ? "" : `<button type="button" class="btn" data-act="status">${active ? "Disable" : "Enable"}</button>`}
        <button type="button" class="btn" data-act="sessions">Sign out everywhere</button>
        ${u.dataRegion ? '<button type="button" class="btn" data-act="region">Data region</button>' : ""}
        ${u.dataRegion && (u.ownResidency || !u.residency) ? `<button type="button" class="btn" data-act="residency">${u.ownResidency ? "Unpin" : "Pin region"}</button>` : ""}
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
    if (t.dataset.act === "mfa") {
      if (!confirm(`Reset two-factor authentication for ${u.name}? Use this if they lost their authenticator app. If it's required, they set it up again at their next sign-in.`)) return;
      await api("DELETE", `/api/users/${key(u.id)}/mfa`);
      notice(`Two-factor authentication reset for ${u.name}.`, false);
    }
    if (t.dataset.act === "region") await setRegion(`/api/users/${key(u.id)}/region`, u.name, u.region);
    if (t.dataset.act === "residency") await setResidency(`/api/users/${key(u.id)}/residency`, u.name, u.ownResidency, u.dataRegion?.region);
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
  loadRegions(off);
}

// The data regions offered (ADR 0117), and any whose backups would leave them.
async function loadRegions(off) {
  const el = $("machines-regions");
  el.hidden = true;
  if (off) return;
  try {
    const r = await api("GET", "/api/regions");
    const pinned = (x) => (x.pinned?.users || x.pinned?.teams ? `, ${x.pinned.users + x.pinned.teams} pinned` : "");
    const each = r.regions.map((x) => `${x.id}${x.default ? " (default)" : ""}${x.offered ? "" : " (no longer offered)"}: ${x.machines} machine${x.machines === 1 ? "" : "s"}${pinned(x)}`);
    const warn = [...(r.backups?.warnings || []), ...(r.residency?.warnings || [])].join(" ");
    el.textContent = `Data regions: ${each.join(", ")}.${warn ? ` ${warn}` : ""}`;
    el.className = warn ? "warn" : "hint";
    el.hidden = false;
  } catch {
    // Older servers have no regions.
  }
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

// Against its tier's RPO and RTO (ADR 0074), when off-host backups are on.
function recoveryCell(m) {
  const r = m.recovery;
  if (!r) return "";
  const hours = (ms) => (ms < 3600000 ? `${Math.floor(ms / 60000)} min` : `${(ms / 3600000).toFixed(1)} h`);
  const age = r.lastBackupAt ? `${hours(Date.now() - r.lastBackupAt)} ago` : "None yet";
  const rpo = `<div class="sub">RPO ${r.rpoHours} h · RTO ${r.rtoMinutes} min</div>`;
  const late = r.breach ? `<div class="sub bad">Past its RPO since ${esc(fmt(r.breachedAt || r.coveredSince + r.rpoHours * 3600000))}</div>` : "";
  const restore = r.lastRestore && r.lastRestore.withinRto === false ? `<div class="sub bad">Last restore took longer than its RTO</div>` : "";
  return `${esc(age)}${rpo}${late}${restore}`;
}

function renderMachines() {
  const list = $("machines-destroyed").checked ? machines : machines.filter((m) => m.state !== "destroyed");
  $("machines-empty").hidden = list.length > 0;
  const late = machines.filter((m) => m.recovery && m.recovery.breach);
  $("machines-rpo").hidden = late.length === 0;
  $("machines-rpo").textContent = late.length
    ? `${late.length} machine${late.length === 1 ? " has" : "s have"} no off-host backup within ${late.length === 1 ? "its" : "their"} RPO: ${late.map((m) => m.userEmail || m.userId).join(", ")}. The audit log says why (machine.rpo_breached).`
    : "";
  $("machines-rows").innerHTML = list.map((m) => `<tr data-machine="${esc(m.id)}">
      <td>${esc(m.userEmail || m.userId)}</td>
      <td>${esc(m.state)}${m.providerStatus ? `<div class="sub">${esc(m.providerStatus)}</div>` : ""}${m.lastError ? `<div class="sub bad">${esc(m.lastError)}</div>` : ""}${m.enrollOverdueAt && m.enrollment !== "enrolled" ? `<div class="sub bad">Didn't enroll in time (since ${esc(fmt(m.enrollOverdueAt))})</div>` : ""}</td>
      <td>${esc(m.tier)}<div class="sub">${esc(m.plan)} · ${esc(m.provider)}</div></td>
      <td>${esc(m.region)}</td>
      <td>${esc(m.ipv4 || "")}</td>
      <td>${recoveryCell(m)}</td>
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

// Teams (ADR 0087, 0088, 0093): every team, its people, roles, machine states and plan. Each team's
// own owners and admins manage it in the app; this is the server admins' fallback.

const TEAM_ROLES = { owner: "Owner", admin: "Admin", member: "Member" };
const teamRoleOptions = (current) => Object.entries(TEAM_ROLES).map(([v, l]) => `<option value="${v}" ${v === current ? "selected" : ""}>${l}</option>`).join("");
let teams = { teams: [], settings: {} };

async function loadTeams() {
  try {
    teams = await api("GET", "/api/teams");
    $("teams-empty").textContent = "No teams yet.";
  } catch (err) {
    teams = { teams: [], settings: {} };
    $("teams-empty").textContent = err.message;
  }
  renderTeams();
}

function teamMachine(m) {
  if (!m) return '<span class="sub">No machine</span>';
  const whose = m.team ? "team's" : "their own";
  const released = m.releaseAt ? `<div class="sub bad">Released; deleted ${esc(fmt(m.releaseAt))}</div>` : "";
  return `${esc(m.state)}<div class="sub">${esc(whose)} · ${esc(m.tier)} · ${esc(m.enrollment)}</div>${released}`;
}

// The team's plan and seats (ADR 0093), when this server sells plans. Changed in Stripe or by the team's managers.
function teamPlan(b) {
  if (!b) return "";
  if (!b.plan) return " · no team plan";
  const seats = b.seats ? ` · ${b.seats.billed ?? 0} of ${b.seats.members} seats billed${b.seats.error ? " (Stripe hasn't caught up; retrying)" : b.seats.syncing ? " (updating)" : ""}` : "";
  const status = b.subscription ? ` (${b.subscription.status}${b.subscription.cancelAt ? `, ends ${fmt(b.subscription.cancelAt * 1000)}` : ""})` : "";
  return ` · team pays for ${b.plan.label}${status}${seats}`;
}

function renderTeams() {
  const s = teams.settings || {};
  $("teams-settings").textContent = `${s.strict ? "TEAMS=on: people in no team share with nobody." : "People in no team share with each other (TEAMS=on stops that)."} A leaver's team machine is ${s.machineDays ? `suspended, then deleted after ${s.machineDays} days` : "deleted at once"}.`;
  $("teams-empty").hidden = teams.teams.length > 0;
  $("teams-list").innerHTML = teams.teams.map((t) => `<div class="card" data-team="${esc(t.id)}">
      <div class="bar"><b>${esc(t.name)}</b> <span class="sub">${t.members.length} people · ${t.machines ? "joining gives a machine" : "no machines given"} · data in ${esc(t.region || "the default region")}${t.residency ? ` · pinned under ${esc(t.residency.reference || "an agreement")}` : ""}${esc(teamPlan(t.billing))}</span>
        <button type="button" class="btn push" data-act="team-region">Data region</button>
        <button type="button" class="btn" data-act="team-residency">${t.residency ? "Unpin" : "Pin region"}</button>
        <button type="button" class="btn" data-act="delete-team">Delete team</button></div>
      <table class="grid">
        <thead><tr><th>Person</th><th>Role</th><th>Machine</th><th></th></tr></thead>
        <tbody>${t.members.map((m) => `<tr data-user="${esc(m.id)}">
          <td><div>${esc(m.name || m.id)}${m.active ? "" : ' <span class="bad">Disabled</span>'}</div><div class="sub">${esc(m.email || "")}</div></td>
          <td><select data-act="team-role" title="Role">${teamRoleOptions(m.role)}</select></td>
          <td>${teamMachine(m.machine)}</td>
          <td class="actions"><button type="button" class="btn" data-act="remove-member">Remove</button></td>
        </tr>`).join("")}</tbody>
      </table>
      ${(t.invites || []).length ? `<p class="sub">Invited: ${t.invites.map((i) => `${esc(i.email)} (${esc(TEAM_ROLES[i.role] || i.role)})`).join(", ")}</p>` : ""}
      <form class="bar" data-act="add-member" autocomplete="off">
        <input name="user" placeholder="Add someone: email or id" required spellcheck="false" />
        <select name="role" title="Role">${teamRoleOptions("member")}</select>
        <button type="submit" class="btn">Add to team</button>
      </form>
    </div>`).join("");
}

function offboardNote(name, team) {
  const days = teams.settings?.machineDays;
  const machine = days ? `suspended now and deleted after ${days} days unless they join a team again` : "deleted now, with its disks";
  const work = teams.settings?.work || {};
  const files = [workNote("teammates' machines", work.machines), workNote("their accounts on this server", work.accounts)].filter(Boolean).join(" ");
  return `Take ${name} off ${team}?\n\nThey lose access to teammates' shared Bots and teammates lose access to theirs; grants between them are revoked and runs between them stop.${files ? ` ${files}` : ""} A machine the team gave them is ${machine}. Their own Bots, chats and secrets stay theirs.`;
}

function workNote(where, w) {
  if (!w) return "";
  const files = w.files === "archive" ? "their work there goes to the Bots' owner" : w.graceDays > 0 ? `their work there is deleted for good after ${w.graceDays} day${w.graceDays === 1 ? "" : "s"}` : "their work there is deleted for good";
  return `Their users on ${where} are removed, and ${files}.`;
}

const teamOf = (el) => teams.teams.find((t) => t.id === el.closest("[data-team]").dataset.team);

$("teams-list").addEventListener("click", async (e) => {
  const b = e.target.closest("button[data-act]");
  if (!b) return;
  const t = teamOf(b);
  if (!t) return;
  b.disabled = true;
  try {
    if (b.dataset.act === "remove-member") {
      const m = t.members.find((x) => x.id === b.closest("tr").dataset.user);
      if (!m || !confirm(offboardNote(m.name || m.email || m.id, t.name))) return;
      await api("DELETE", `/api/teams/${key(t.id)}/members/${key(m.id)}`);
    }
    if (b.dataset.act === "team-region") await setRegion(`/api/teams/${key(t.id)}/region`, `${t.name}'s members without their own`, t.region);
    if (b.dataset.act === "team-residency") await setResidency(`/api/teams/${key(t.id)}/residency`, t.name, t.residency, t.region);
    if (b.dataset.act === "delete-team") {
      if (!confirm(`Delete ${t.name}? Everyone on it leaves, as if each had: ${offboardNote("each of them", t.name).split("\n\n")[1]}`)) return;
      await api("DELETE", `/api/teams/${key(t.id)}`);
    }
  } catch (err) {
    fail(err);
  } finally {
    b.disabled = false;
    loadTeams();
  }
});

$("teams-list").addEventListener("change", async (e) => {
  if (e.target.dataset.act !== "team-role") return;
  const t = teamOf(e.target);
  try {
    await api("PUT", `/api/teams/${key(t.id)}/members/${key(e.target.closest("tr").dataset.user)}`, { role: e.target.value });
  } catch (err) {
    fail(err);
  }
  loadTeams();
});

$("teams-list").addEventListener("submit", async (e) => {
  const f = e.target.closest("form[data-act=add-member]");
  if (!f) return;
  e.preventDefault();
  const t = teamOf(f);
  try {
    const r = await api("PUT", `/api/teams/${key(t.id)}/members/${key(f.user.value.trim())}`, { role: f.role.value });
    if (r.provisioned === "failed") notice("Added, but their machine couldn't be made. The audit log says why (team.machine_failed).");
  } catch (err) {
    fail(err);
  }
  loadTeams();
});

$("add-team").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await api("POST", "/api/teams", { name: $("team-name").value.trim(), owner: $("team-owner").value.trim() });
    $("team-name").value = "";
    $("team-owner").value = "";
  } catch (err) {
    fail(err);
  }
  loadTeams();
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
  const target = $("au-target").value.trim();
  if (target) p.set("target", target);
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
let policySandbox = true;

async function loadSettings() {
  await queuePolicy(loadPolicy);
  loadNotifications();
  loadLicense();
  loadSignIn();
  loadSecrets();
  loadScim();
}

// Approval notifications (ADR 0061): email through botd's SMTP settings and a webhook.
// The webhook URL is a secret: botd keeps it sealed and shows only its host.

function showNotifications(v) {
  const s = v.settings;
  $("notify-email").checked = s.email.enabled;
  $("notify-email").disabled = !v.email.configured && !s.email.enabled;
  $("notify-to").value = s.email.to.join(", ");
  $("notify-deciders").checked = s.email.deciders;
  $("notify-webhook").checked = s.webhook.enabled;
  $("notify-format").value = s.webhook.format;
  const url = $("notify-url");
  url.value = "";
  url.disabled = !v.webhook.writable;
  url.placeholder = v.webhook.set ? `Replace the URL (now ${v.webhook.host || "set"})` : "Webhook URL, like https://hooks.slack.com/services/...";
  $("notify-url-remove").hidden = !v.webhook.set || !v.webhook.writable;
  $("notify-delay").value = s.delaySeconds;
  $("notify-throttle").value = s.throttleSeconds;
  $("notify-detail").value = s.detail;
  const lines = [
    v.email.configured ? `Email goes through ${v.email.server}.` : "Email isn't set up: set SMTP_HOST and SMTP_FROM in .env and restart botd.",
    v.webhook.set
      ? `Webhook URL set (${v.webhook.host || "unknown host"})${v.webhook.writable ? "" : ", by botd's environment: change it in .env"}.`
      : "No webhook URL yet.",
  ];
  $("notify-status").innerHTML = lines.map((l) => `<p class="hint">${esc(l)}</p>`).join("")
    + (v.links.problem ? `<p class="warn">${esc(v.links.problem)}</p>` : "");
}

async function loadNotifications() {
  try {
    showNotifications(await api("GET", "/api/notifications"));
  } catch (err) {
    $("notify-status").innerHTML = `<p class="warn">${esc(err.message)}</p>`;
  }
}

$("notify-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const seconds = (id) => ($(id).value === "" ? undefined : Number($(id).value));
  const body = {
    email: { enabled: $("notify-email").checked, to: $("notify-to").value.split(/[\s,;]+/).filter(Boolean), deciders: $("notify-deciders").checked },
    webhook: { enabled: $("notify-webhook").checked, format: $("notify-format").value },
    delaySeconds: seconds("notify-delay"),
    throttleSeconds: seconds("notify-throttle"),
    detail: $("notify-detail").value,
  };
  const url = $("notify-url").value.trim();
  if (url) body.webhook.url = url;
  try {
    showNotifications(await api("PUT", "/api/notifications", body));
    notice("Notifications saved.", false);
  } catch (err) {
    fail(err);
  }
});

$("notify-url-remove").addEventListener("click", async () => {
  if (!confirm("Remove the webhook URL? The webhook turns off.")) return;
  try {
    showNotifications(await api("PUT", "/api/notifications", { webhook: { url: null } }));
    notice("Webhook URL removed.", false);
  } catch (err) {
    fail(err);
  }
});

$("notify-test").addEventListener("click", async () => {
  try {
    const r = await api("POST", "/api/notifications/test", {});
    const name = (c) => (c === "email" ? "Email" : c === "webhook" ? "Webhook" : c);
    if (r.ok) notice(`Test sent: ${r.results.map((x) => name(x.channel).toLowerCase()).join(" and ")}.`, false);
    else notice(r.results.filter((x) => !x.ok).map((x) => `${name(x.channel)} failed: ${x.error || "see the audit log"}`).join(" "));
  } catch (err) {
    fail(err);
  }
});

// The license (ADR 0038). botd checks the key; once saved it's never sent back. There is
// no free tier (ADR 0068): no license means testing mode, or Bots don't run.

const LICENSE_MODES = { unlicensed: "No license", active: "Licensed", grace: "Grace period", expired: "Ended", invalid: "Invalid key" };

function licenseMode(l) {
  return l.testing ? "Testing mode" : LICENSE_MODES[l.mode] || l.mode;
}

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
  const billing = l.billing && !l.billing.enabled ? `<p class="warn" data-billing-off>${esc(l.billing.detail)}</p>` : "";
  return verdict(l.ok && !warnings.length, `${licenseMode(l)}. ${l.detail}`)
    + billing
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
  if (!confirm("Remove the license? SuperBot has no free tier: unless testing mode is on, Bots stop running and nobody new can be added. Nobody is signed out.")) return;
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

// The global approval policy (ADR 0007, 0049): mode, an action per risky class, the timeout,
// and rules for all Bots. Each Bot's own settings and rules are edited in the app.

const ACTIONS = { allow: "Allow", ask: "Ask", deny: "Deny" };
const HARNESS_NAMES = { claude: "Claude Code", codex: "Codex", pi: "Pi", hermes: "Hermes Agent" };
const TOOLS = { "*": "Any tool", shell: "Shell", file: "Files", web: "Web", mcp: "MCP", other: "Other tools" };

// Saves run one at a time, so an older answer never replaces a newer one on screen.
let policyQueue = Promise.resolve();
const queuePolicy = (fn) => (policyQueue = policyQueue.then(fn, fn));

// The timeout last shown from the server: a different number in the box is a draft to keep.
let shownTimeout = null;

function showPolicy(policy, { timeout = false } = {}) {
  policyMode = policy.mode;
  $("policy-mode").value = policyMode;
  policySandbox = policy.sandbox !== false;
  $("policy-sandbox").value = policySandbox ? "on" : "off";
  const box = $("policy-timeout");
  if (timeout || box.value === "" || box.value === String(shownTimeout)) box.value = policy.timeoutMinutes;
  shownTimeout = policy.timeoutMinutes;
  for (const sel of document.querySelectorAll("#policy-classes select")) sel.value = policy.classes[sel.dataset.class] || "ask";
}

async function loadPolicy() {
  let v;
  try {
    v = await api("GET", "/api/policy");
  } catch (err) {
    fail(err);
    return;
  }
  $("policy-classes").innerHTML = v.classes.map((c) => `<tr>
      <td>${esc(c.label)}</td>
      <td><select data-class="${esc(c.id)}" aria-label="${esc(c.label)}">${Object.entries(ACTIONS).map(([a, l]) => `<option value="${a}">${l}</option>`).join("")}</select></td>
    </tr>`).join("");
  showPolicy(v.policy);
  const sb = v.sandbox;
  $("policy-sandbox-hint").textContent = "Codex and Claude Code run commands in their own sandbox: they write only in the workspace, temp folders, the Bot's memory, and package caches. It holds in Bypass too."
    + (sb && sb.harnesses.some((h) => !sb.available.includes(h))
      ? ` ${sb.harnesses.filter((h) => !sb.available.includes(h)).map((h) => HARNESS_NAMES[h] || h).join(" and ")}'s sandbox can't start on this server, so those runs go without: install bubblewrap and socat.`
      : "");
  const rules = v.rules || [];
  $("rules-empty").textContent = "No rules for all Bots.";
  $("rules-empty").hidden = rules.length > 0;
  $("rules-rows").innerHTML = rules.map((r) => `<tr data-rule="${esc(r.id)}">
      <td>${esc(ACTIONS[r.action] || r.action)}</td><td>${esc(TOOLS[r.tool] || r.tool)}</td>
      <td><code>${esc(r.pattern)}</code></td><td><span class="sub">${esc(r.note || "")}</span></td><td>${esc(fmt(r.at))}</td>
      <td class="actions"><button type="button" class="btn" data-act="delete">Delete</button></td>
    </tr>`).join("");
}

function patchPolicy(patch, done) {
  return queuePolicy(async () => {
    try {
      showPolicy((await api("PUT", "/api/policy", patch)).policy, { timeout: "timeoutMinutes" in patch });
      notice(done, false);
    } catch (err) {
      fail(err);
      await loadPolicy();
    }
  });
}

$("policy-classes").addEventListener("change", (e) => {
  const sel = e.target.closest("select[data-class]");
  if (!sel) return;
  patchPolicy({ classes: { [sel.dataset.class]: sel.value } }, `${sel.getAttribute("aria-label")}: ${ACTIONS[sel.value]}.`);
});

$("policy-timeout-save").addEventListener("click", () => {
  const m = Number($("policy-timeout").value);
  if (!Number.isInteger(m) || m < 1 || m > 1440) {
    notice("Use whole minutes from 1 to 1440 (24 hours).");
    return;
  }
  patchPolicy({ timeoutMinutes: m }, `Approvals now wait ${m} minute${m === 1 ? "" : "s"}.`);
});

$("rule-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const submit = e.target.querySelector("button[type=submit]");
  if (submit.disabled) return;
  submit.disabled = true;
  const body = { action: $("rule-action").value, tool: $("rule-tool").value.trim() || "*", pattern: $("rule-pattern").value.trim() };
  const note = $("rule-note").value.trim();
  if (note) body.note = note;
  queuePolicy(async () => {
    try {
      await api("POST", "/api/policy/rules", body);
      for (const id of ["rule-tool", "rule-pattern", "rule-note"]) $(id).value = "";
      notice(`${ACTIONS[body.action]} rule added for all Bots.`, false);
    } catch (err) {
      fail(err);
    }
    await loadPolicy();
  }).finally(() => { submit.disabled = false; });
});

$("rules-rows").addEventListener("click", async (e) => {
  const t = e.target.closest("button[data-act=delete]");
  if (!t) return;
  const row = t.closest("tr");
  if (!confirm(`Delete this rule for all Bots?\n\n${row.querySelector("code").textContent}`)) return;
  queuePolicy(async () => {
    try { await api("DELETE", `/api/policy/rules/${key(row.dataset.rule)}`); } catch (err) { fail(err); }
    await loadPolicy();
  });
});

$("policy-mode").addEventListener("change", async (e) => {
  const mode = e.target.value;
  if (mode === "bypass" && !confirm("Let every Bot run risky actions without asking? Use this only on a dev machine.")) {
    e.target.value = policyMode;
    return;
  }
  queuePolicy(async () => {
    try {
      showPolicy((await api("PUT", "/api/policy", { mode })).policy);
    } catch (err) {
      fail(err);
      e.target.value = policyMode;
    }
  });
});

$("policy-sandbox").addEventListener("change", (e) => {
  const on = e.target.value === "on";
  if (!on && !confirm("Turn the harness sandbox off for every Bot? Their commands could write anywhere the harness can.")) {
    e.target.value = policySandbox ? "on" : "off";
    return;
  }
  patchPolicy({ sandbox: on }, `Sandbox ${on ? "on" : "off"} for all Bots.`);
});

async function loadSignIn() {
  let providers = [];
  try { providers = (await api("GET", "/api/auth/sso")).providers || []; } catch {}
  const sso = providers.length ? `SSO: ${providers.map((p) => `${p.label || p.id} (${p.type || "oidc"})`).join(", ")}.` : "No SSO providers are set up (SSO_PROVIDERS).";
  const glass = me.breakGlass ? "Break-glass password sign-in at /login is on (AUTH_BREAK_GLASS)." : "Break-glass password sign-in is off.";
  $("signin-info").textContent = `${glass} ${sso} Sign-in codes come from Users.`;
  loadMfa();
}

// Two-factor authentication (ADR 0094): the policy, and the admin's own.
const MFA_POLICY_NOTE = {
  off: "Nobody has to, but anyone can turn it on for themselves.",
  admins: "Admins, and the owner's break-glass password, need a code from an authenticator app at /login. The password no longer works over HTTP Basic.",
  all: "Everyone signing in with a sign-in code or the password needs a code from an authenticator app.",
};

async function loadMfa() {
  let m;
  try { m = await api("GET", "/api/auth/mfa"); } catch (err) { $("mfa-policy-note").textContent = err.message; return; }
  $("mfa-policy").value = m.policy;
  $("mfa-policy").disabled = m.policyPinned;
  const sso = " Single sign-on relies on your identity provider's MFA: require it there.";
  $("mfa-policy-note").textContent = MFA_POLICY_NOTE[m.policy] + sso + (m.policyPinned ? " Set by AUTH_MFA in botd's environment." : "");
  $("mfa-mine-state").textContent = m.enabled
    ? `Yours is on, with ${m.recoveryCodesLeft} recovery code${m.recoveryCodesLeft === 1 ? "" : "s"} left.`
    : m.required ? "Yours is off, so your next sign-in sets it up." : "Yours is off.";
  $("mfa-on").hidden = m.enabled;
  $("mfa-codes").hidden = !m.enabled;
  $("mfa-off").hidden = !m.enabled || m.required;
}

function showRecoveryCodes(codes) {
  showOnce({
    title: "Your recovery codes",
    note: "Each works once if you lose your authenticator app. Save them somewhere safe. They can't be shown again.",
    value: codes.join("\n"),
    lines: true,
  });
}

// A code from the app, or a recovery code, to prove a change.
function secondFactor(what) {
  const v = (prompt(`To ${what}, enter the code from your authenticator app, or a recovery code.`) || "").trim();
  if (!v) return null;
  return /^\d{6}$/.test(v.replace(/\s/g, "")) ? { totp: v.replace(/\s/g, "") } : { recoveryCode: v };
}

$("mfa-policy").addEventListener("change", async (e) => {
  try {
    await api("PUT", "/api/auth/mfa/policy", { require: e.target.value });
    notice("Two-factor policy saved.", false);
  } catch (err) {
    fail(err);
  }
  loadMfa();
});

$("mfa-on").addEventListener("click", async () => {
  try {
    const s = await api("POST", "/api/auth/mfa/enroll", {});
    $("mfa-qr").src = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(s.qrSvg);
    $("mfa-key").textContent = s.secret.replace(/(.{4})/g, "$1 ").trim();
    $("mfa-setup").hidden = false;
    $("mfa-code").focus();
  } catch (err) {
    fail(err);
  }
});

function closeMfaSetup() {
  $("mfa-setup").hidden = true;
  $("mfa-qr").removeAttribute("src");
  $("mfa-key").textContent = "";
  $("mfa-code").value = "";
}

$("mfa-cancel").addEventListener("click", async () => {
  closeMfaSetup();
  await api("POST", "/api/auth/mfa/disable", {}).catch(() => {});
  loadMfa();
});

$("mfa-confirm").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const r = await api("POST", "/api/auth/mfa/confirm", { totp: $("mfa-code").value.replace(/\s/g, "") });
    closeMfaSetup();
    showRecoveryCodes(r.recoveryCodes);
  } catch (err) {
    fail(err);
  }
  loadMfa();
});

$("mfa-codes").addEventListener("click", async () => {
  const proof = secondFactor("make new recovery codes");
  if (!proof) return;
  try {
    showRecoveryCodes((await api("POST", "/api/auth/mfa/recovery-codes", proof)).recoveryCodes);
  } catch (err) {
    fail(err);
  }
  loadMfa();
});

$("mfa-off").addEventListener("click", async () => {
  const proof = secondFactor("turn two-factor authentication off");
  if (!proof) return;
  try {
    await api("POST", "/api/auth/mfa/disable", proof);
    notice("Two-factor authentication is off for you.", false);
  } catch (err) {
    fail(err);
  }
  loadMfa();
});

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
      <td>${esc(HARNESS_NAMES[x.newBots] || x.newBots || "")}</td>
      <td>${esc(limitsText(x.limits))}</td>
    </tr>`).join("");
  return verdict(true, t.detail)
    + `<table class="grid"><thead><tr><th>Plan</th><th>Harnesses and models</th><th>New Bots get</th><th>Limits</th></tr></thead><tbody>${rows}</tbody></table>`
    + `<h2>${t.fileLoaded ? "Change the plans" : "Sell plans or set limits"}</h2><p class="hint">botd reads the tiers file at startup. Skip this to keep the built-in self-host tier your license covers.</p>`
    + howto(t.instructions);
}

function setupLicense(l) {
  return `<h2>License</h2><p class="hint">SuperBot has no free tier. A license from CG-Labs sets your plan and seats. Without one, Bots don't run unless the operator turns on testing mode (<code>TESTING_MODE=on</code>), where billing is off.</p>`
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

// Status page (ADR 0090): incident notes shown at /status. Anyone can read them, so the
// form says so; the server drops control characters and known secrets.

const IMPACTS = { none: "None", minor: "Minor", major: "Major", critical: "Critical", maintenance: "Maintenance" };
const INC_STATES = ["investigating", "identified", "monitoring", "resolved"];
const stateOptions = (current) => INC_STATES.map((s) => `<option value="${s}" ${s === current ? "selected" : ""}>${s[0].toUpperCase()}${s.slice(1)}</option>`).join("");
let incidents = { incidents: [], components: [], enabled: true };

async function loadStatus() {
  try {
    incidents = await api("GET", "/api/status/incidents");
    $("incidents-empty").textContent = "No incidents yet.";
  } catch (err) {
    incidents = { incidents: [], components: [], enabled: true };
    $("incidents-empty").textContent = err.message;
  }
  renderStatus();
}

function componentName(id) {
  return incidents.components.find((c) => c.id === id)?.name || id;
}

function renderStatus() {
  $("status-note").innerHTML = incidents.enabled
    ? 'The public status page is <a href="/status" target="_blank" rel="noopener">/status</a> (and <a href="/status.json" target="_blank" rel="noopener">/status.json</a>). It shows component health from botd\'s own checks, raised by open incidents on the components they name. Anyone can read what you post: no customer names, hostnames or internal details.'
    : "The public status page is off (STATUS_PAGE=off). You can still prepare incidents; they show once it's on.";
  const picked = new Set([...document.querySelectorAll("#inc-components input:checked")].map((i) => i.value));
  $("inc-components").innerHTML = '<span class="sub">Affects:</span> ' + incidents.components
    .map((c) => `<label><input type="checkbox" value="${esc(c.id)}" ${picked.has(c.id) ? "checked" : ""} /> ${esc(c.name)}</label>`).join("");
  $("incidents-empty").hidden = incidents.incidents.length > 0;
  $("incidents-list").innerHTML = incidents.incidents.map((i) => `<div class="card" data-incident="${esc(i.id)}">
      <div class="bar"><b>${esc(i.title)}</b>
        <span class="sub">${esc(IMPACTS[i.impact] || i.impact)} · ${esc(i.state)}${i.components.length ? ` · ${esc(i.components.map(componentName).join(", "))}` : ""}${i.resolvedAt ? ` · resolved ${esc(fmt(i.resolvedAt))}` : ""}</span>
        <button type="button" class="btn push" data-act="delete-incident" title="For one posted by mistake. Resolve real ones.">Delete</button></div>
      ${i.updates.map((u) => `<p class="use"><b>${esc(u.state)}</b> ${esc(u.body)} <span class="sub">${esc(fmt(u.createdAt))}</span></p>`).join("")}
      <form class="bar" data-act="incident-update" autocomplete="off">
        <select name="state" title="State">${stateOptions(i.state === "resolved" ? "resolved" : i.state)}</select>
        <textarea name="body" rows="2" required maxlength="2000" placeholder="An update, for the public"></textarea>
        <select name="impact" title="Impact">${Object.entries(IMPACTS).map(([v, l]) => `<option value="${v}" ${v === i.impact ? "selected" : ""}>${l}</option>`).join("")}</select>
        <button type="submit" class="btn">Post update</button>
      </form>
    </div>`).join("");
}

$("inc-new").addEventListener("submit", async (e) => {
  e.preventDefault();
  const components = [...document.querySelectorAll("#inc-components input:checked")].map((i) => i.value);
  try {
    await api("POST", "/api/status/incidents", { title: $("inc-title").value, body: $("inc-body").value, impact: $("inc-impact").value, state: $("inc-state").value, components });
    $("inc-new").reset();
    for (const i of document.querySelectorAll("#inc-components input")) i.checked = false;
    notice("Posted. It's on the status page now.", false);
    loadStatus();
  } catch (err) {
    fail(err);
  }
});

$("incidents-list").addEventListener("submit", async (e) => {
  const f = e.target.closest('form[data-act="incident-update"]');
  if (!f) return;
  e.preventDefault();
  const id = f.closest("[data-incident]").dataset.incident;
  const current = incidents.incidents.find((i) => i.id === id);
  // A failed post keeps the form as typed, so no reload then. A saved impact change is
  // remembered so a retry doesn't send it again.
  try {
    if (current && f.impact.value !== current.impact) {
      await api("PATCH", `/api/status/incidents/${key(id)}`, { impact: f.impact.value });
      current.impact = f.impact.value;
    }
    await api("POST", `/api/status/incidents/${key(id)}/updates`, { state: f.state.value, body: f.body.value });
    notice("Update posted.", false);
    loadStatus();
  } catch (err) {
    fail(err);
    if (err.status === 404) loadStatus();
  }
});

$("incidents-list").addEventListener("click", async (e) => {
  const b = e.target.closest('button[data-act="delete-incident"]');
  if (!b) return;
  const id = b.closest("[data-incident]").dataset.incident;
  if (!confirm("Delete this incident and its updates from the status page? Resolve it instead if it really happened.")) return;
  try {
    await api("DELETE", `/api/status/incidents/${key(id)}`);
    loadStatus();
  } catch (err) {
    fail(err);
    if (err.status === 404) loadStatus();
  }
});

// Tabs, from the address bar's #fragment so a reload keeps your place.

const TABS = { users: loadUsers, requests: loadRequests, machines: loadMachines, teams: loadTeams, audit: () => loadAudit(), status: loadStatus, settings: loadSettings, setup: loadSetup };

// `#audit?target=approval:<id>`: a notification's link to one approval's trail (ADR 0061).
function showTab() {
  const [name, query] = location.hash.slice(1).split("?");
  const tab = name in TABS ? name : "users";
  if (tab === "audit" && query) {
    const q = new URLSearchParams(query);
    $("au-target").value = q.get("target") || "";
  }
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
