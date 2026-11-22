import React, { useCallback, useEffect, useState } from "react";
import { ActivityIndicator, Modal, Pressable, ScrollView, StyleSheet, Text, TextInput, useWindowDimensions, View } from "react-native";
import type { SuperBotApi } from "../src/api";
import { confirmAsync } from "../src/dialogs";
import {
  BASES,
  baseChangeWarning,
  draftChanges,
  draftError,
  draftOf,
  effectivePermissions,
  emptyDraft,
  holdersLabel,
  permissionLabel,
  teamPermissions,
  togglePermission,
} from "../src/roles";
import { colors } from "../src/theme";
import type { AdminUser, BuiltInRole, CustomRole, RoleDraft, RolesView, Team } from "../src/types";
import { Chips } from "./Chips";

interface Props {
  api: SuperBotApi;
  meId?: string | null;
  onBack: () => void;
}

type Picked = { kind: "builtIn"; id: string } | { kind: "custom"; id: string } | { kind: "new" } | null;

const message = (err: unknown) => (err instanceof Error ? err.message : "Failed");
const personName = (p: { id: string; name?: string | null; email?: string | null }) => p.name || p.email || p.id;

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <View style={styles.section}>
      <Text style={styles.sectionTitle}>{title}</Text>
      {children}
    </View>
  );
}

function Button({ label, a11y, onPress, danger, primary, disabled }: { label: string; a11y?: string; onPress: () => void; danger?: boolean; primary?: boolean; disabled?: boolean }) {
  return (
    <Pressable
      style={[styles.btn, primary && styles.primaryBtn, danger && styles.dangerBtn, disabled && styles.disabled]}
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
  return (
    <View style={styles.wrap}>
      <View>
        <Text style={styles.name}>{role.name}</Text>
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
  const [draft, setDraft] = useState<RoleDraft>(role ? draftOf(role) : emptyDraft());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [holders, setHolders] = useState<CustomRole["holders"] | null>(null);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [teams, setTeams] = useState<Team[]>([]);
  const [query, setQuery] = useState("");
  const [teamId, setTeamId] = useState("");

  const loadHolders = useCallback(async () => {
    if (!role) return;
    const [full, people, allTeams] = await Promise.all([api.role(role.id), api.users().catch(() => []), api.teams().catch(() => [])]);
    setHolders(full.holders ?? { users: [], teams: [] });
    setUsers(people);
    setTeams(allTeams);
  }, [api, role]);

  useEffect(() => {
    loadHolders().catch((err) => setError(message(err)));
  }, [loadHolders]);

  const run = async (action: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (err) {
      setError(message(err));
    } finally {
      setBusy(false);
    }
  };

  const invalid = draftError(view, draft, role?.id);
  const changes = role ? draftChanges(role, draft) : null;
  const effective = effectivePermissions(view, draft.base, draft.permissions);
  const inTeam = teamPermissions(view, draft.permissions);

  const save = async () => {
    if (role) {
      const warning = baseChangeWarning(role, draft);
      if (warning && !(await confirmAsync(`Move ${role.name}'s holders?`, warning, "Save"))) return;
    }
    void run(async () => {
      const saved = role ? await api.updateRole(role.id, changes ?? {}) : await api.createRole({ ...draft, name: draft.name.trim(), description: draft.description.trim() });
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

  const give = async (u: AdminUser) => {
    if (!role) return;
    const body =
      u.role === "admin"
        ? `They stop being an admin: their role becomes ${role.base === "readonly" ? "read-only" : "member"}, with ${role.name}'s permissions on top.`
        : `Their role becomes ${role.base === "readonly" ? "read-only" : "member"}, with ${role.name}'s permissions on top. Any other custom role they have is replaced.`;
    if (!(await confirmAsync(`Give ${role.name} to ${personName(u)}?`, body, "Give"))) return;
    void run(async () => {
      await api.assignRole(role.id, u.id);
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

  const giveInTeam = (team: Team, userId: string) => {
    if (!role) return;
    void run(async () => {
      await api.assignTeamRole(role.id, team.id, userId);
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

  return (
    <View style={styles.wrap}>
      <View>
        <Text style={styles.name}>{role ? role.name : "New role"}</Text>
        <Text style={styles.faint}>
          {role ? `${holdersLabel(role)} · changed ${new Date(role.updatedAt).toLocaleDateString()}` : "A base role plus permissions an admin gives away. It never adds up to admin."}
        </Text>
      </View>
      {error ? <Text style={styles.error}>{error}</Text> : null}

      <Section title="Name">
        <TextInput
          style={styles.input}
          value={draft.name}
          onChangeText={(name) => setDraft({ ...draft, name })}
          placeholder="Help desk"
          placeholderTextColor={colors.textFaint}
          maxLength={60}
          accessibilityLabel="Role name"
        />
        <TextInput
          style={[styles.input, styles.multiline]}
          value={draft.description}
          onChangeText={(description) => setDraft({ ...draft, description })}
          placeholder="What it's for (optional)"
          placeholderTextColor={colors.textFaint}
          multiline
          maxLength={500}
          accessibilityLabel="Role description"
        />
      </Section>

      <Section title="Based on">
        <Chips options={BASES} value={draft.base} onChange={(base) => setDraft({ ...draft, base })} disabled={busy} />
        <Text style={styles.faint}>{draft.base === "member" ? "Uses Bots and decides approvals, like a member." : "Sees, changes nothing, like a read-only user. Team permissions do nothing for them."}</Text>
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
              <Text style={[styles.check, on && styles.checkOn]}>{on ? "✓" : ""}</Text>
              <View style={{ flex: 1 }}>
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
          <Section title="Across the server">
            {holders == null ? (
              <ActivityIndicator color={colors.textDim} />
            ) : holders.users.length ? (
              holders.users.map((u) => (
                <View key={u.id} style={styles.row}>
                  <Text style={[styles.text, { flex: 1 }]} numberOfLines={1}>
                    {personName(u)}
                    {u.email && u.name ? <Text style={styles.faint}> · {u.email}</Text> : null}
                  </Text>
                  <Button label="Take away" a11y={`Take away from ${personName(u)}`} disabled={busy} onPress={() => void takeAway(u.id, personName(u))} />
                </View>
              ))
            ) : (
              <Text style={styles.dim}>Nobody has it across the server.</Text>
            )}
            <TextInput
              style={styles.input}
              value={query}
              onChangeText={setQuery}
              placeholder="Give it to: search people"
              placeholderTextColor={colors.textFaint}
              autoCapitalize="none"
              autoCorrect={false}
              accessibilityLabel="Search people to give the role to"
            />
            {matches.map((u) => {
              const locked = u.breakGlass || u.id === meId;
              return (
                <View key={u.id} style={styles.row}>
                  <Text style={[styles.text, { flex: 1 }]} numberOfLines={1}>
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
              <View key={`${h.team.id}:${h.user.id}`} style={styles.row}>
                <Text style={[styles.text, { flex: 1 }]} numberOfLines={1}>
                  {personName(h.user)}
                  <Text style={styles.faint}> · {h.team.name}</Text>
                </Text>
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
                      <View key={m.id} style={styles.row}>
                        <Text style={[styles.text, { flex: 1 }]} numberOfLines={1}>
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
              <Text style={styles.dim}>No teams yet.</Text>
            ) : null}
          </Section>
        </>
      ) : null}
    </View>
  );
}

/** Custom roles (ADR 0123, 0132): build them from the fixed permissions, see what they add up to, and give them. */
export function RolesAdmin({ api, meId, onBack }: Props) {
  const { width } = useWindowDimensions();
  const wide = width >= 900;
  const [view, setView] = useState<RolesView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [picked, setPicked] = useState<Picked>(null);

  const load = useCallback(async () => {
    try {
      setView(await api.roles());
      setError(null);
    } catch (err) {
      setError(message(err));
    }
  }, [api]);

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
      <View style={styles.header}>
        <Pressable onPress={onBack} accessibilityRole="button" accessibilityLabel="Back to Bots">
          <Text style={styles.back}>‹ Bots</Text>
        </Pressable>
        <Text style={styles.title}>Roles</Text>
        <Button label="New role" primary disabled={!view} onPress={() => setPicked({ kind: "new" })} />
      </View>
      <View style={styles.body}>
        <View style={wide ? styles.listPaneWide : styles.listPane}>
          {error ? <Text style={styles.error}>{error}</Text> : null}
          {!view && !error ? <ActivityIndicator color={colors.textDim} style={{ marginTop: 20 }} /> : null}
          {view ? (
            <ScrollView contentContainerStyle={{ gap: 4, paddingBottom: 24 }}>
              <Text style={styles.sectionTitle}>Built in</Text>
              {view.builtIn.map((r) => (
                <Pressable
                  key={r.id}
                  style={[styles.listRow, picked?.kind === "builtIn" && picked.id === r.id && styles.selected]}
                  onPress={() => setPicked({ kind: "builtIn", id: r.id })}
                  accessibilityRole="button"
                  accessibilityLabel={`Role ${r.name}`}
                >
                  <Text style={styles.text}>{r.name}</Text>
                  <Text style={styles.faint}>{r.permissions.length} permissions</Text>
                </Pressable>
              ))}
              <Text style={[styles.sectionTitle, { marginTop: 12 }]}>Custom</Text>
              {view.roles.map((r) => (
                <Pressable
                  key={r.id}
                  style={[styles.listRow, picked?.kind === "custom" && picked.id === r.id && styles.selected]}
                  onPress={() => setPicked({ kind: "custom", id: r.id })}
                  accessibilityRole="button"
                  accessibilityLabel={`Role ${r.name}`}
                >
                  <Text style={styles.text}>{r.name}</Text>
                  <Text style={styles.faint}>
                    {r.base === "readonly" ? "Read-only" : "Member"} + {r.permissions.length ? r.permissions.join(", ") : "nothing"} · {holdersLabel(r)}
                  </Text>
                </Pressable>
              ))}
              {!view.roles.length ? <Text style={styles.empty}>No custom roles yet. Make one to give part of admin away.</Text> : null}
            </ScrollView>
          ) : null}
        </View>
        {wide ? (
          <ScrollView style={styles.detailPane} contentContainerStyle={{ padding: 20 }}>
            {detail ?? <Text style={styles.empty}>Pick a role to see what it can do, or make a new one.</Text>}
          </ScrollView>
        ) : null}
      </View>
      {!wide ? (
        <Modal visible={!!detail} animationType="slide" onRequestClose={() => setPicked(null)}>
          <View style={styles.modalRoot}>
            <Pressable style={styles.modalHeader} onPress={() => setPicked(null)} accessibilityRole="button">
              <Text style={styles.back}>‹ Roles</Text>
            </Pressable>
            <ScrollView contentContainerStyle={{ padding: 16, paddingRight: 20 }}>{detail}</ScrollView>
          </View>
        </Modal>
      ) : null}
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.bgMain },
  header: { flexDirection: "row", alignItems: "center", gap: 16, padding: 16, borderBottomWidth: 1, borderBottomColor: colors.border },
  back: { color: colors.blueDot, fontSize: 16 },
  title: { color: colors.text, fontSize: 20, fontWeight: "600", flex: 1 },
  body: { flex: 1, flexDirection: "row" },
  listPane: { flex: 1, padding: 12 },
  listPaneWide: { width: 400, padding: 12, borderRightWidth: 1, borderRightColor: colors.border },
  detailPane: { flex: 1 },
  listRow: { padding: 12, borderRadius: 14, gap: 2 },
  selected: { backgroundColor: colors.bgActive },
  wrap: { gap: 16 },
  name: { color: colors.text, fontSize: 22, fontWeight: "600" },
  text: { color: colors.text },
  dim: { color: colors.textDim },
  faint: { color: colors.textFaint, fontSize: 13 },
  warn: { color: colors.warning },
  error: { color: colors.danger, padding: 4 },
  empty: { color: colors.textFaint, padding: 12, textAlign: "center" },
  section: { gap: 8, borderTopWidth: 1, borderTopColor: colors.border, paddingTop: 12 },
  sectionTitle: { color: colors.textDim, fontSize: 13, fontWeight: "600", textTransform: "uppercase", letterSpacing: 0.5 },
  row: { flexDirection: "row", alignItems: "center", gap: 10, flexWrap: "wrap" },
  perm: { flexDirection: "row", gap: 10, alignItems: "flex-start", paddingVertical: 4 },
  check: { width: 22, height: 22, borderRadius: 6, borderWidth: 1, borderColor: "#3a3a3a", color: "#111", textAlign: "center", lineHeight: 20, fontSize: 14 },
  checkOn: { backgroundColor: "#f2f2f2", borderColor: "#f2f2f2" },
  tags: { flexDirection: "row", flexWrap: "wrap", gap: 6 },
  tag: { color: colors.textDim, fontSize: 12, borderWidth: 1, borderColor: colors.border, borderRadius: 999, paddingHorizontal: 8, paddingVertical: 2 },
  adminTag: { color: colors.blueDot, borderColor: "#24406e" },
  input: {
    backgroundColor: colors.bgBubble,
    borderColor: colors.border,
    borderWidth: 1,
    borderRadius: 12,
    paddingHorizontal: 14,
    paddingVertical: 10,
    color: colors.text,
    fontSize: 15,
  },
  multiline: { minHeight: 64, textAlignVertical: "top" },
  btn: { paddingVertical: 7, paddingHorizontal: 16, borderRadius: 999, borderWidth: 1, borderColor: "#3a3a3a" },
  btnText: { color: colors.text, fontSize: 14 },
  primaryBtn: { backgroundColor: "#f2f2f2", borderColor: "#f2f2f2" },
  primaryText: { color: "#111" },
  dangerBtn: { borderColor: "#5a2a2c" },
  dangerText: { color: colors.danger },
  disabled: { opacity: 0.5 },
  modalRoot: { flex: 1, backgroundColor: colors.bgMain, paddingTop: 32 },
  modalHeader: { padding: 16, borderBottomWidth: 1, borderBottomColor: colors.border, backgroundColor: colors.bgMain },
});
