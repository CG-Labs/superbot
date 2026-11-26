import React, { useCallback, useEffect, useState } from "react";
import { Pressable, ScrollView, StyleSheet, Text, TextInput, useWindowDimensions, View } from "react-native";
import { ApiError, type SuperBotApi } from "../src/api";
import { confirmAsync } from "../src/dialogs";
import { errorText, friendlyError } from "../src/errors";
import {
  approveCap,
  approveChoices,
  awaitsSecond,
  BASES,
  baseChangeWarning,
  defaultEnd,
  draftChanges,
  draftError,
  draftOf,
  effectivePermissions,
  emptyDraft,
  endChoices,
  endsAt,
  endsLabel,
  firstApprovalLabel,
  holdersLabel,
  MAX_DAYS_HINT,
  parseMaxDays,
  permissionLabel,
  requestStatusLabel,
  requestSummary,
  teamPermissions,
  togglePermission,
} from "../src/roles";
import { hairline, themedStyles, type, useTheme } from "../src/theme";
import type { AdminUser, BuiltInRole, CustomRole, RoleDraft, RoleGiving, RoleRequest, RolesView, Team } from "../src/types";
import { EmptyState } from "./EmptyState";
import { ErrorState, InlineError } from "./ErrorState";
import { ListSkeleton } from "./Skeleton";
import { Chips } from "./Chips";
import { DetailSheet, PaneTransition } from "./Shell";
import { kit, PageHeader, Spinner } from "./ui";

interface Props {
  api: SuperBotApi;
  meId?: string | null;
  onBack: () => void;
}

type Picked = { kind: "builtIn"; id: string } | { kind: "custom"; id: string } | { kind: "new" } | null;

const personName = (p: { id: string; name?: string | null; email?: string | null }) => p.name || p.email || p.id;

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  const styles = useStyles();
  return (
    <View style={styles.section}>
      <Text style={styles.sectionTitle} role="heading">
        {title}
      </Text>
      {children}
    </View>
  );
}

function Button({ label, a11y, onPress, danger, primary, disabled }: { label: string; a11y?: string; onPress: () => void; danger?: boolean; primary?: boolean; disabled?: boolean }) {
  const styles = useStyles();
  return (
    <Pressable
      style={({ pressed }) => [styles.btn, pressed && !primary && !danger && styles.pressed, primary && styles.primaryBtn, danger && styles.dangerBtn, disabled && styles.disabled]}
      disabled={disabled}
      onPress={onPress}
      accessibilityRole="button"
      accessibilityLabel={a11y ?? label}
    >
      <Text style={[styles.btnText, primary && styles.primaryText, danger && styles.dangerText]}>{label}</Text>
    </Pressable>
  );
}

function Tags({ names, view }: { names: string[]; view: RolesView }) {
  const styles = useStyles();
  return (
    <View style={styles.tags}>
      {names.map((p) => (
        <Text key={p} style={[styles.tag, p === "admin" && styles.adminTag]}>
          {permissionLabel(view, p)}
        </Text>
      ))}
    </View>
  );
}

function BuiltInDetail({ role, view }: { role: BuiltInRole; view: RolesView }) {
  const styles = useStyles();
  return (
    <View style={styles.wrap}>
      <View>
        <Text style={styles.name} role="heading">
          {role.name}
        </Text>
        <Text style={styles.faint}>Built in. It can&apos;t be changed; give it from Users.</Text>
      </View>
      <Section title="Can do">
        <Tags names={role.permissions} view={view} />
      </Section>
    </View>
  );
}

/** Make or change a custom role, and give it to people across the server or within a team. */
function RoleEditor({ api, view, role, meId, onSaved, onDeleted }: { api: SuperBotApi; view: RolesView; role: CustomRole | null; meId?: string | null; onSaved: (id: string) => Promise<void>; onDeleted: () => Promise<void> }) {
  const styles = useStyles();
  const t = useTheme();
  const [draft, setDraft] = useState<RoleDraft>(role ? draftOf(role) : emptyDraft());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [holders, setHolders] = useState<CustomRole["holders"] | null>(null);
  const [holdersError, setHoldersError] = useState<string | null>(null);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [teams, setTeams] = useState<Team[]>([]);
  const [query, setQuery] = useState("");
  const [teamId, setTeamId] = useState("");
  const [limit, setLimit] = useState(role?.maxDays ? String(role.maxDays) : "");
  const [ends, setEnds] = useState(defaultEnd(role?.maxDays));
  const [reason, setReason] = useState("");

  const loadHolders = useCallback(async () => {
    if (!role) return;
    const [full, people, allTeams] = await Promise.all([api.role(role.id), api.users().catch(() => []), api.teams().catch(() => [])]);
    setHolders(full.holders ?? { users: [], teams: [] });
    setUsers(people);
    setTeams(allTeams);
  }, [api, role]);

  const fetchHolders = useCallback(async () => {
    try {
      await loadHolders();
      setHoldersError(null);
    } catch (err) {
      setHoldersError(errorText(err, "Couldn't load who has it"));
    }
  }, [loadHolders]);

  useEffect(() => {
    void fetchHolders();
  }, [fetchHolders]);

  const run = async (action: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (err) {
      setError(friendlyError(err));
    } finally {
      setBusy(false);
    }
  };

  const maxDays = parseMaxDays(limit);
  const invalid = draftError(view, draft, role?.id) ?? (maxDays === undefined ? MAX_DAYS_HINT : null);
  const requestable = !!maxDays && !!draft.requestable;
  // Two approvers (ADR 0320) only matter for a role people may request.
  const approvals = requestable && draft.approvals === 2 ? 2 : 1;
  const changes = role ? draftChanges(role, { ...draft, maxDays, requestable, approvals: requestable || role.approvals === 2 ? approvals : undefined }) : null;
  const effective = effectivePermissions(view, draft.base, draft.permissions);
  const inTeam = teamPermissions(view, draft.permissions);

  const save = async () => {
    if (role) {
      const warning = baseChangeWarning(role, draft);
      if (warning && !(await confirmAsync(`Move ${role.name}'s holders?`, warning, "Save"))) return;
    }
    void run(async () => {
      const saved = role
        ? await api.updateRole(role.id, changes ?? {})
        : await api.createRole({
            name: draft.name.trim(),
            description: draft.description.trim(),
            base: draft.base,
            permissions: draft.permissions,
            ...(maxDays ? { maxDays } : {}),
            ...(requestable ? { requestable } : {}),
            ...(approvals === 2 ? { approvals } : {}),
          });
      await onSaved(saved.id);
    });
  };

  const remove = async () => {
    if (!role || !(await confirmAsync(`Delete ${role.name}?`, "Nobody has it, so nobody's access changes. The audit log keeps its history.", "Delete"))) return;
    void run(async () => {
      await api.deleteRole(role.id);
      await onDeleted();
    });
  };

  /** The end and reason picked, or nothing when neither is. */
  const giving = (): RoleGiving | undefined => {
    const expiresAt = endsAt(ends, Date.now());
    const why = reason.trim();
    if (expiresAt == null && !why) return undefined;
    return { ...(expiresAt != null ? { expiresAt } : {}), ...(why ? { reason: why } : {}) };
  };
  const endNote = () => {
    const at = endsAt(ends, Date.now());
    return at == null ? "" : ` It ends by itself on ${new Date(at).toLocaleString()}.`;
  };

  const give = async (u: AdminUser) => {
    if (!role) return;
    const body =
      u.role === "admin"
        ? `They stop being an admin: their role becomes ${role.base === "readonly" ? "read-only" : "member"}, with ${role.name}'s permissions on top.`
        : `Their role becomes ${role.base === "readonly" ? "read-only" : "member"}, with ${role.name}'s permissions on top. Any other custom role they have is replaced.`;
    if (!(await confirmAsync(`Give ${role.name} to ${personName(u)}?`, body + endNote(), "Give"))) return;
    void run(async () => {
      await api.assignRole(role.id, u.id, giving());
      setReason("");
      setQuery("");
      await onSaved(role.id);
      await loadHolders();
    });
  };

  const takeAway = async (userId: string, name: string, team?: string) => {
    if (!role) return;
    const keeps = `They keep ${role.base === "readonly" ? "read-only" : "member"} as their role.`;
    if (!(await confirmAsync(`Take ${role.name} away from ${name}?`, team ? "Their role across the server doesn't change." : keeps, "Take away"))) return;
    void run(async () => {
      if (team) await api.unassignTeamRole(role.id, team, userId);
      else await api.unassignRole(role.id, userId);
      await onSaved(role.id);
      await loadHolders();
    });
  };

  /** Gives it again to someone who holds it, so its end becomes the one picked above. */
  const renew = async (userId: string, name: string, team?: string) => {
    if (!role) return;
    const at = endsAt(ends, Date.now());
    const body = at == null ? "It will have no end." : `It will end on ${new Date(at).toLocaleString()}.`;
    if (!(await confirmAsync(`Change when ${name}'s ${role.name} ends?`, body, "Change"))) return;
    void run(async () => {
      if (team) await api.assignTeamRole(role.id, team, userId, giving());
      else await api.assignRole(role.id, userId, giving());
      setReason("");
      await onSaved(role.id);
      await loadHolders();
    });
  };

  const giveInTeam = (team: Team, userId: string) => {
    if (!role) return;
    void run(async () => {
      await api.assignTeamRole(role.id, team.id, userId, giving());
      setReason("");
      await onSaved(role.id);
      await loadHolders();
    });
  };

  const holderIds = new Set(holders?.users.map((u) => u.id));
  const q = query.trim().toLowerCase();
  const matches = q ? users.filter((u) => !holderIds.has(u.id) && [u.name, u.email ?? "", u.id].some((v) => v.toLowerCase().includes(q))).slice(0, 6) : [];
  const team = teams.find((t) => t.id === teamId) ?? teams[0];
  const teamHolders = new Set(holders?.teams.filter((h) => h.team.id === team?.id).map((h) => h.user.id));
  const userRole = (id: string) => users.find((u) => u.id === id)?.role;
  const now = Date.now();

  return (
    <View style={styles.wrap}>
      <View>
        <Text style={styles.name} role="heading">
          {role ? role.name : "New role"}
        </Text>
        <Text style={styles.faint}>
          {role ? `${holdersLabel(role)} · changed ${new Date(role.updatedAt).toLocaleDateString()}` : "A base role plus permissions an admin gives away. It never adds up to admin."}
        </Text>
      </View>
      {error ? <InlineError message={error} /> : null}

      <Section title="Name">
        <TextInput
          style={styles.input}
          value={draft.name}
          onChangeText={(name) => setDraft({ ...draft, name })}
          placeholder="Help desk"
          placeholderTextColor={t.c.textFaint}
          maxLength={60}
          accessibilityLabel="Role name"
        />
        <TextInput
          style={[styles.input, styles.multiline]}
          value={draft.description}
          onChangeText={(description) => setDraft({ ...draft, description })}
          placeholder="What it's for (optional)"
          placeholderTextColor={t.c.textFaint}
          multiline
          maxLength={500}
          accessibilityLabel="Role description"
        />
      </Section>

      <Section title="Based on">
        <Chips options={BASES} value={draft.base} onChange={(base) => setDraft({ ...draft, base })} disabled={busy} />
        <Text style={styles.faint}>{draft.base === "member" ? "Uses Bots and decides approvals, like a member." : "Sees, changes nothing, like a read-only user. Team permissions do nothing for them."}</Text>
      </Section>

      <Section title="Time limit">
        <TextInput
          style={styles.input}
          value={limit}
          onChangeText={setLimit}
          placeholder="No limit"
          placeholderTextColor={t.c.textFaint}
          keyboardType="number-pad"
          maxLength={3}
          editable={!busy}
          accessibilityLabel="Most days it can be given for"
        />
        <Text style={styles.faint}>
          {maxDays
            ? `Time-bound: given only by hand, for at most ${maxDays} day${maxDays === 1 ? "" : "s"} at a time, then it ends by itself. Never to SCIM or SAML groups or service accounts.`
            : "Blank: it can be given with no end. Set days to make it time-bound, for elevated access."}
        </Text>
        <Pressable
          style={[styles.perm, !maxDays && styles.disabled]}
          disabled={busy || !maxDays}
          onPress={() => setDraft({ ...draft, requestable: !draft.requestable })}
          accessibilityRole="checkbox"
          accessibilityState={{ checked: requestable, disabled: busy || !maxDays }}
          accessibilityLabel="People may request it"
        >
          <Text style={[styles.check, requestable && styles.checkOn]} maxFontSizeMultiplier={1.3}>{requestable ? "✓" : ""}</Text>
          <View style={styles.fill}>
            <Text style={styles.text}>People may request it</Text>
            <Text style={styles.dim}>
              {maxDays ? "Anyone it fits can ask for it, with a reason, from Settings. An admin approves each request; it ends by itself." : "Only a time-bound role can be requested. Set days first."}
            </Text>
          </View>
        </Pressable>
        <Pressable
          style={[styles.perm, !requestable && styles.disabled]}
          disabled={busy || !requestable}
          onPress={() => setDraft({ ...draft, approvals: draft.approvals === 2 ? 1 : 2 })}
          accessibilityRole="checkbox"
          accessibilityState={{ checked: approvals === 2, disabled: busy || !requestable }}
          accessibilityLabel="Needs two approvers"
        >
          <Text style={[styles.check, approvals === 2 && styles.checkOn]} maxFontSizeMultiplier={1.3}>{approvals === 2 ? "✓" : ""}</Text>
          <View style={styles.fill}>
            <Text style={styles.text}>Needs two approvers</Text>
            <Text style={styles.dim}>
              {requestable
                ? "Two different people approve each request before it's given, for as long as the first approved or less. Needs two active admins."
                : "Only for a role people may request."}
            </Text>
          </View>
        </Pressable>
      </Section>

      <Section title="Permissions">
        {view.permissions.map((p) => {
          const on = draft.permissions.includes(p.name);
          return (
            <Pressable
              key={p.name}
              style={styles.perm}
              disabled={busy}
              onPress={() => setDraft({ ...draft, permissions: togglePermission(view, draft.permissions, p.name) })}
              accessibilityRole="checkbox"
              accessibilityState={{ checked: on, disabled: busy }}
              accessibilityLabel={p.name}
            >
              <Text style={[styles.check, on && styles.checkOn]} maxFontSizeMultiplier={1.3}>{on ? "✓" : ""}</Text>
              <View style={styles.fill}>
                <Text style={styles.text}>
                  {p.name}
                  {p.team ? <Text style={styles.faint}> · also within a team</Text> : null}
                </Text>
                <Text style={styles.dim}>{p.description}</Text>
              </View>
            </Pressable>
          );
        })}
        {role?.unknown.length ? <Text style={styles.warn}>Saved by another version and unknown here, so they grant nothing: {role.unknown.join(", ")}. Saving drops them.</Text> : null}
      </Section>

      <Section title="Can do">
        <Tags names={effective} view={view} />
        <Text style={styles.faint}>Within a team: {inTeam.length ? inTeam.join(", ") : "nothing (it has no team permissions)"}.</Text>
      </Section>

      <View style={styles.row}>
        <Button label={role ? "Save" : "Create role"} primary disabled={busy || !!invalid || (!!role && !changes)} onPress={() => void save()} />
        {role ? <Button label="Delete" danger disabled={busy || role.users + role.teamMembers > 0} onPress={() => void remove()} /> : null}
        {draft.name && invalid ? <Text style={styles.faint}>{invalid}</Text> : null}
        {role && role.users + role.teamMembers > 0 ? <Text style={styles.faint}>Take it away from everyone to delete it.</Text> : null}
      </View>

      {role ? (
        <>
          <Section title="Giving it">
            <Chips options={endChoices(role.maxDays)} value={ends} onChange={setEnds} disabled={busy} />
            <TextInput
              style={styles.input}
              value={reason}
              onChangeText={setReason}
              placeholder="Why (optional, kept in the audit log)"
              placeholderTextColor={t.c.textFaint}
              maxLength={500}
              editable={!busy}
              accessibilityLabel="Why it's given"
            />
            <Text style={styles.faint}>
              {role.maxDays ? `Time-bound: it ends by itself within ${role.maxDays} day${role.maxDays === 1 ? "" : "s"}. ` : ""}"Change end" sets it for someone who has it already.
            </Text>
          </Section>

          <Section title="Across the server">
            {holders == null ? (
              holdersError ? (
                <InlineError message={holdersError} onRetry={fetchHolders} />
              ) : (
                <ListSkeleton label="Loading who has it" rows={2} />
              )
            ) : holders.users.length ? (
              holders.users.map((u) => (
                <View key={u.id} style={styles.item}>
                  <Text style={styles.itemText} numberOfLines={1}>
                    {personName(u)}
                    {u.email && u.name ? <Text style={styles.faint}> · {u.email}</Text> : null}
                    {u.expiresAt ? <Text style={styles.faint}> · {endsLabel(u.expiresAt, now)}</Text> : null}
                  </Text>
                  <Button label="Change end" a11y={`Change end for ${personName(u)}`} disabled={busy} onPress={() => void renew(u.id, personName(u))} />
                  <Button label="Take away" a11y={`Take away from ${personName(u)}`} disabled={busy} onPress={() => void takeAway(u.id, personName(u))} />
                </View>
              ))
            ) : (
              <EmptyState compact glyph="+" title="Nobody has it across the server" message="Search people below to give it to someone." />
            )}
            <TextInput
              style={styles.input}
              value={query}
              onChangeText={setQuery}
              placeholder="Give it to: search people"
              placeholderTextColor={t.c.textFaint}
              autoCapitalize="none"
              autoCorrect={false}
              accessibilityLabel="Search people to give the role to"
            />
            {matches.map((u) => {
              const locked = u.breakGlass || u.id === meId;
              return (
                <View key={u.id} style={styles.item}>
                  <Text style={styles.itemText} numberOfLines={1}>
                    {personName(u)}
                    <Text style={styles.faint}>
                      {" "}
                      · {u.customRole ? u.customRole.name : u.role}
                      {u.breakGlass ? " · the owner stays an admin" : u.id === meId ? " · another admin changes yours" : ""}
                    </Text>
                  </Text>
                  <Button label="Give" a11y={`Give to ${personName(u)}`} disabled={busy || locked} onPress={() => void give(u)} />
                </View>
              );
            })}
          </Section>

          <Section title="Within a team">
            <Text style={styles.faint}>Only its team permissions apply, only in that team, while they stay on it. Their role across the server doesn&apos;t change.</Text>
            {holders?.teams.map((h) => (
              <View key={`${h.team.id}:${h.user.id}`} style={styles.item}>
                <Text style={styles.itemText} numberOfLines={1}>
                  {personName(h.user)}
                  <Text style={styles.faint}>
                    {" "}
                    · {h.team.name}
                    {h.expiresAt ? ` · ${endsLabel(h.expiresAt, now)}` : ""}
                  </Text>
                </Text>
                <Button label="Change end" a11y={`Change end for ${personName(h.user)} in ${h.team.name}`} disabled={busy} onPress={() => void renew(h.user.id, personName(h.user), h.team.id)} />
                <Button label="Take away" a11y={`Take away from ${personName(h.user)} in ${h.team.name}`} disabled={busy} onPress={() => void takeAway(h.user.id, personName(h.user), h.team.id)} />
              </View>
            ))}
            {teams.length && team ? (
              <>
                <Chips options={teams.map((t) => ({ value: t.id, label: t.name }))} value={team.id} onChange={setTeamId} disabled={busy} />
                {team.members
                  .filter((m) => !teamHolders.has(m.id))
                  .map((m) => {
                    const readonly = userRole(m.id) === "readonly";
                    return (
                      <View key={m.id} style={styles.item}>
                        <Text style={styles.itemText} numberOfLines={1}>
                          {personName(m)}
                          <Text style={styles.faint}>
                            {" "}
                            · team {m.role}
                            {m.customRole ? ` · has ${m.customRole.name}` : ""}
                            {readonly ? " · read-only, so it would do nothing" : ""}
                          </Text>
                        </Text>
                        <Button label="Give" a11y={`Give to ${personName(m)} in ${team.name}`} disabled={busy || readonly} onPress={() => giveInTeam(team, m.id)} />
                      </View>
                    );
                  })}
              </>
            ) : holders ? (
              <EmptyState compact glyph="+" title="No teams yet" message="Make a team first to give the role within it." />
            ) : null}
          </Section>
        </>
      ) : null}
    </View>
  );
}

/**
 * One pending request: approve it for as long as asked or shorter, or deny it with a note.
 * Server admins decide through `/api/role-requests`, a team's owners and admins through
 * `/api/team/role-requests` (ADR 0263), so the calls come from the screen.
 */
export function RequestRow({
  q,
  meId,
  onDecided,
  approve,
  deny,
  decidesYours = "another admin",
  approveBlocked,
}: {
  q: RoleRequest;
  meId?: string | null;
  onDecided: () => Promise<void>;
  approve: (id: string, body: { hours?: number; note?: string }) => Promise<unknown>;
  deny: (id: string, note?: string) => Promise<unknown>;
  /** Who decides your own request. */
  decidesYours?: string;
  /** Why you can't approve it, though you may deny it. */
  approveBlocked?: string | null;
}) {
  const styles = useStyles();
  const t = useTheme();
  const cap = approveCap(q);
  const second = awaitsSecond(q);
  const needsTwo = (q.approvals ?? 1) >= 2;
  const [hours, setHours] = useState(String(cap));
  // A first approval made elsewhere can lower the cap after a reload.
  useEffect(() => setHours(String(cap)), [cap]);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const yours = !!meId && q.user?.id === meId;
  const name = q.user ? personName(q.user) : "them";
  const gaveFirst = second && !!meId && q.firstApproval?.by.id === meId;
  const blocked = approveBlocked ?? (gaveFirst ? "You gave the first approval. Someone else gives the second." : null);
  const first = firstApprovalLabel(q);

  const decide = async (yes: boolean) => {
    const firstOfTwo = yes && needsTwo && !second;
    const title = !yes ? `Deny ${name}'s request?` : firstOfTwo ? `Approve ${name}'s request for ${q.role?.name ?? "the role"}?` : `Give ${q.role?.name ?? "the role"} to ${name}?`;
    const body = !yes
      ? "They see your note. They can ask again."
      : firstOfTwo
        ? "This role needs two people to approve it. Yours is the first: nothing is given until someone else approves it too, for as long as you pick or less."
        : "It starts now and ends by itself. The audit log keeps the request and your approval.";
    if (!(await confirmAsync(title, body, yes ? "Approve" : "Deny"))) return;
    setBusy(true);
    setError(null);
    try {
      const why = note.trim() || undefined;
      if (yes) await approve(q.id, { hours: Number(hours), note: why });
      else await deny(q.id, why);
      await onDecided();
    } catch (err) {
      setError(friendlyError(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <View style={styles.request} accessibilityLabel={`Request from ${name}`}>
      <Text style={styles.text}>{requestSummary(q)}</Text>
      <Text style={styles.dim}>“{q.reason}”</Text>
      <Text style={styles.faint}>
        {q.current ? `Has ${q.current.name} now. ` : ""}
        {q.role?.applies.length ? `Adds: ${q.role.applies.join(", ")}. ` : ""}
        {requestStatusLabel(q, Date.now())}
      </Text>
      {first ? <Text style={styles.faint}>{first}.</Text> : null}
      {error ? <InlineError message={error} /> : null}
      {yours ? (
        <Text style={styles.faint}>Your own request: {decidesYours} decides it.</Text>
      ) : (
        <>
          {blocked ? (
            <Text style={styles.faint}>{blocked}</Text>
          ) : (
            <Chips options={approveChoices(cap, second ? "as first approved" : "as asked")} value={hours} onChange={setHours} disabled={busy} />
          )}
          <TextInput
            style={styles.input}
            value={note}
            onChangeText={setNote}
            placeholder="Note (optional, they see it)"
            placeholderTextColor={t.c.textFaint}
            maxLength={500}
            editable={!busy}
            accessibilityLabel={`Note for ${name}`}
          />
          <View style={styles.row}>
            {blocked ? null : <Button label={needsTwo && !second ? "Approve (1 of 2)" : "Approve"} a11y={`Approve ${name}'s request`} primary disabled={busy} onPress={() => void decide(true)} />}
            <Button label="Deny" a11y={`Deny ${name}'s request`} danger disabled={busy} onPress={() => void decide(false)} />
          </View>
        </>
      )}
    </View>
  );
}

/** Custom roles (ADR 0123, 0132): build them from the fixed permissions, see what they add up to, and give them. */
export function RolesAdmin({ api, meId, onBack }: Props) {
  const styles = useStyles();
  const { width } = useWindowDimensions();
  const wide = width >= 900;
  const [view, setView] = useState<RolesView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [picked, setPicked] = useState<Picked>(null);
  const [requests, setRequests] = useState<RoleRequest[]>([]);
  const [requestsError, setRequestsError] = useState<string | null>(null);

  const loadRequests = useCallback(async () => {
    try {
      setRequests((await api.roleRequests("pending")).requests);
      setRequestsError(null);
    } catch (err) {
      setRequests([]);
      // A server from before requests for roles (ADR 0209) has none to show.
      setRequestsError(err instanceof ApiError && err.status === 404 ? null : errorText(err, "Couldn't load requests for roles"));
    }
  }, [api]);

  const load = useCallback(async () => {
    try {
      setView(await api.roles());
      setError(null);
    } catch (err) {
      setError(friendlyError(err));
    }
    await loadRequests();
  }, [api, loadRequests]);

  useEffect(() => {
    void load();
  }, [load]);

  const builtIn = picked?.kind === "builtIn" ? view?.builtIn.find((r) => r.id === picked.id) : undefined;
  const custom = picked?.kind === "custom" ? view?.roles.find((r) => r.id === picked.id) : undefined;
  const detail = !view ? null : builtIn ? (
    <BuiltInDetail role={builtIn} view={view} />
  ) : custom || picked?.kind === "new" ? (
    <RoleEditor
      key={custom ? `${custom.id}:${custom.updatedAt}` : "new"}
      api={api}
      view={view}
      role={custom ?? null}
      meId={meId}
      onSaved={async (id) => {
        await load();
        setPicked({ kind: "custom", id });
      }}
      onDeleted={async () => {
        setPicked(null);
        await load();
      }}
    />
  ) : null;

  return (
    <View style={styles.root}>
      <PageHeader title="Roles" onBack={onBack} right={<Button label="New role" primary disabled={!view} onPress={() => setPicked({ kind: "new" })} />} />
      <View style={styles.body}>
        <View style={wide ? styles.listPaneWide : styles.listPane}>
          {error && !view ? <ErrorState title="Couldn't load roles" message={error} onRetry={load} /> : null}
          {!view && !error ? <ListSkeleton label="Loading roles" rows={3} /> : null}
          {view ? (
            <ScrollView contentContainerStyle={styles.list}>
              {error ? <InlineError message={`Couldn't load roles. ${error}`} onRetry={load} /> : null}
              {requestsError ? <InlineError message={requestsError} onRetry={loadRequests} /> : null}
              {requests.length ? (
                <>
                  <Text style={styles.heading} role="heading">
                    Requests ({requests.length})
                  </Text>
                  {requests.map((q) => (
                    <RequestRow
                      key={q.id}
                      q={q}
                      meId={meId}
                      onDecided={load}
                      approve={(id, body) => api.approveRoleRequest(id, body)}
                      deny={(id, note) => api.denyRoleRequest(id, note)}
                    />
                  ))}
                </>
              ) : null}
              <Text style={styles.heading} role="heading">
                Built in
              </Text>
              <View style={styles.listCard}>
                {view.builtIn.map((r, i) => (
                  <Pressable
                    key={r.id}
                    style={({ pressed }) => [styles.listRow, i === 0 && styles.listRowFirst, pressed && styles.pressed, picked?.kind === "builtIn" && picked.id === r.id && styles.selected]}
                    onPress={() => setPicked({ kind: "builtIn", id: r.id })}
                    accessibilityRole="button"
                    accessibilityLabel={`Role ${r.name}`}
                    accessibilityState={{ selected: picked?.kind === "builtIn" && picked.id === r.id }}
                  >
                    <Text style={styles.rowName}>{r.name}</Text>
                    <Text style={styles.faint}>{r.permissions.length} permissions</Text>
                  </Pressable>
                ))}
              </View>
              <Text style={styles.heading} role="heading">
                Custom
              </Text>
              <View style={styles.listCard}>
                {view.roles.map((r, i) => (
                  <Pressable
                    key={r.id}
                    style={({ pressed }) => [styles.listRow, i === 0 && styles.listRowFirst, pressed && styles.pressed, picked?.kind === "custom" && picked.id === r.id && styles.selected]}
                    onPress={() => setPicked({ kind: "custom", id: r.id })}
                    accessibilityRole="button"
                    accessibilityLabel={`Role ${r.name}`}
                    accessibilityState={{ selected: picked?.kind === "custom" && picked.id === r.id }}
                  >
                    <Text style={styles.rowName}>{r.name}</Text>
                    <Text style={styles.faint}>
                      {r.base === "readonly" ? "Read-only" : "Member"} + {r.permissions.length ? r.permissions.join(", ") : "nothing"} · {holdersLabel(r)}
                    </Text>
                  </Pressable>
                ))}
                {!view.roles.length ? <EmptyState compact glyph="+" title="No custom roles yet" message="Make one to give part of admin away." /> : null}
              </View>
            </ScrollView>
          ) : null}
        </View>
        {wide ? (
          <ScrollView style={styles.detailPane} contentContainerStyle={styles.detailBody}>
            <PaneTransition paneKey={picked ? `${picked.kind}:${"id" in picked ? picked.id : ""}` : ""}>
              {detail ?? <Text style={styles.empty}>Pick a role to see what it can do, or make a new one.</Text>}
            </PaneTransition>
          </ScrollView>
        ) : null}
      </View>
      {!wide ? (
        <DetailSheet visible={!!detail} onClose={() => setPicked(null)} backText="‹ Roles" backLabel="Back to roles">
          {detail}
        </DetailSheet>
      ) : null}
    </View>
  );
}

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    root: k.root,
    body: { flex: 1, flexDirection: "row" },
    listPane: { flex: 1, padding: t.space.md },
    listPaneWide: { width: 400, padding: t.space.md, backgroundColor: t.c.surface, borderRightWidth: hairline, borderRightColor: t.c.border },
    list: { gap: t.space.md, paddingBottom: t.space.xl },
    heading: k.section,
    listCard: { ...k.card, padding: 0, gap: 0, overflow: "hidden" },
    listRow: { paddingVertical: t.space.md, paddingHorizontal: t.space.lg, gap: t.space.xxs, borderTopWidth: hairline, borderTopColor: t.c.border },
    listRowFirst: { borderTopWidth: 0 },
    rowName: { ...k.text, fontWeight: t.font.weight.medium },
    pressed: k.btnPressed,
    selected: { backgroundColor: t.c.selected },
    detailPane: { flex: 1 },
    detailBody: { padding: t.space.xl, width: "100%", maxWidth: 760, alignSelf: "center" },
    request: { ...k.card, padding: t.space.md, gap: t.space.sm },
    wrap: { gap: t.space.lg },
    name: { color: t.c.text, ...type(t, "xl"), fontWeight: t.font.weight.semibold },
    text: k.text,
    dim: k.dim,
    faint: k.faint,
    warn: k.warn,
    empty: k.empty,
    section: k.card,
    sectionTitle: k.cardTitle,
    row: k.actions,
    item: { ...k.row, flexWrap: "wrap" },
    itemText: { ...k.text, flex: 1 },
    fill: { flex: 1 },
    perm: { flexDirection: "row", gap: t.space.md, alignItems: "flex-start", paddingVertical: t.space.xs },
    check: {
      width: 22,
      height: 22,
      borderRadius: t.radius.sm,
      borderWidth: 1.5,
      borderColor: t.c.borderStrong,
      color: t.c.onAccent,
      textAlign: "center",
      ...type(t, "sm"),
      lineHeight: 19,
      fontWeight: t.font.weight.bold,
      overflow: "hidden",
    },
    checkOn: { backgroundColor: t.c.accent, borderColor: t.c.accent },
    tags: k.tags,
    tag: k.tag,
    adminTag: k.tagAccent,
    input: k.input,
    multiline: k.inputMultiline,
    btn: { ...k.btn, alignSelf: "flex-start" },
    btnText: k.btnText,
    primaryBtn: k.primary,
    primaryText: k.primaryText,
    dangerBtn: k.danger,
    dangerText: k.dangerText,
    disabled: k.disabled,
  });
});
