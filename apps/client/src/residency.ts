import type { KeptFrom, MyResidency } from "./types";

function day(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

/** " under <reference>", or for a pin kept from a team you left (ADR 0171), that team. */
function under(reference?: string, kept?: KeptFrom): string {
  if (kept) return `, kept from ${kept.team.name ? `${kept.team.name}'s` : "your former team's"} pin when you left it`;
  return reference ? ` under ${reference}` : "";
}

/** What the residency card says about a pin (ADR 0168): whose it is, where your data is against it, and what isn't held. */
export function residencyLines(v: MyResidency): { lines: string[]; warnings: string[] } {
  const p = v.pin;
  if (!p) return { lines: [], warnings: [] };
  const whose = p.on === "team" ? `Your team${p.team?.name ? `, ${p.team.name},` : ""} has its data` : "Your data is";
  const lines = [`${whose} pinned to ${p.region}${under(p.reference, p.keptFrom)}, since ${day(p.pinnedAt)}.`];
  if (v.ownPin) lines.push(`Your own data is also pinned to ${v.ownPin.region}${under(v.ownPin.reference, v.ownPin.keptFrom)}.`);
  if ((p.keptFrom ?? v.ownPin?.keptFrom)?.endsWhenDataGone) lines.push("That pin ends by itself once your computer and its backups are gone.");
  const warnings: string[] = [];
  if (v.machine) {
    const m = v.machine;
    if (m.inRegion) lines.push(`Your computer is in ${m.region}.`);
    else if (m.region !== p.region) warnings.push(`Your computer is in ${m.region}, not ${p.region}. Your admins see a warning about it.`);
    else if (m.hostRegion) warnings.push(`Your computer is on a server in ${m.hostRegion}, not ${p.region}. Your admins see a warning about it.`);
    else warnings.push(`Your computer is on a server with no data region set, so nothing shows it is in ${p.region}. Your admins see a warning about it.`);
  }
  const b = v.backups;
  if (b && b.kept > 0) {
    if (b.outside === 0) lines.push(`All ${b.kept} of your computer's backups are in ${p.region}.`);
    else warnings.push(`${b.outside} of your computer's ${b.kept} backups are outside ${p.region}. Your admins see a warning about it.`);
  }
  const s = v.serverData;
  const c = v.chats;
  const chatsHeld = !!c?.store && c.inRegion && !s?.inRegion;
  if (chatsHeld) lines.push(`Your chats are kept in ${p.region}, in a database of their own there.`);
  else if (c?.store && !c.inRegion) lines.push(`Your chats are being moved to ${p.region}'s own database.`);
  const what = chatsHeld ? "account" : "account and chats";
  if (s?.inRegion) lines.push(`SuperBot's own copy of your ${what} is in ${p.region}.`);
  else if (s) {
    const where =
      s.region === p.region && s.backupsInRegion === false
        ? `SuperBot's own copy of your ${what} is in ${p.region}, but its backups aren't kept there`
        : `SuperBot's own copy of your ${what} isn't in ${p.region}${s.region ? `; it is in ${s.region}` : ""}`;
    if (s.required) warnings.push(`${where}. Your admins see a warning about it.`);
    else lines.push(`${where}. Your agreement says where it is.`);
  }
  if (v.status === "data_outside" && warnings.length === 0) warnings.push(`Some of your data is outside ${p.region}. Your admins see a warning about it.`);
  if (v.modelRoutes && !v.modelRoutes.inRegion) {
    warnings.push(`Your plan has no AI model in ${p.region}, so your Bots don't run until your admin adds one. Nothing is sent outside the region instead.`);
  } else if (v.modelRoutes?.inRegion) {
    lines.push(`Your Bots use AI models in ${p.region} only.`);
  }
  return { lines, warnings };
}

/** The button for one report. */
export function reportLabel(on: "user" | "team"): string {
  return on === "team" ? "Download the team's report" : "Download your report";
}

/** The file to save a report as: the server's name, or a dated one. */
export function reportFileName(on: "user" | "team", given: string | null, now = Date.now()): string {
  return given && /^[\w.-]+\.md$/.test(given) ? given : `superbot-residency-${on}-${day(now).replace(/-/g, "")}.md`;
}
