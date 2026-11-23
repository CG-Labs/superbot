import React, { useCallback, useEffect, useState } from "react";
import { ActivityIndicator, Pressable, StyleSheet, Text, TextInput, View } from "react-native";
import { ApiError, type SuperBotApi } from "../src/api";
import { hoursLabel, requestChoices, requestDraftError, requestStatusLabel } from "../src/roles";
import { colors } from "../src/theme";
import type { MyRoleRequests, RequestableRole } from "../src/types";
import { Chips } from "./Chips";

export type RoleRequestsApi = Pick<SuperBotApi, "myRoleRequests" | "requestRole" | "withdrawRoleRequest">;

type Scope = "org" | "team";

const message = (err: unknown) => (err instanceof Error ? err.message : String(err));

/** The scope to start on: across the server if it may be asked for there, else the team. */
function firstScope(r: RequestableRole | undefined): Scope {
  return r && !r.org.ok && r.team?.ok ? "team" : "org";
}

/**
 * Requests for roles (ADR 0209): ask for a time-bound role, with a reason, for a few hours or days.
 * An admin approves it and it ends by itself. Nothing shows when no role may be requested and you've asked for none,
 * nor on a server from before requests.
 */
export function RoleRequestsCard({ api }: { api: RoleRequestsApi }) {
  const [view, setView] = useState<MyRoleRequests | null | undefined>(undefined);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [roleId, setRoleId] = useState("");
  const [scope, setScope] = useState<Scope>("org");
  const [hours, setHours] = useState("8");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoadError(null);
    try {
      setView(await api.myRoleRequests());
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) setView(null);
      else setLoadError(message(e));
    }
  }, [api]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (!view || view.requestable.some((r) => r.id === roleId)) return;
    const first = view.requestable[0];
    setRoleId(first?.id ?? "");
    setScope(firstScope(first));
  }, [view, roleId]);

  const role = view?.requestable.find((r) => r.id === roleId);
  const pick = (id: string) => {
    const r = view?.requestable.find((x) => x.id === id);
    setRoleId(id);
    setScope(firstScope(r));
    if (r && Number(hours) > r.maxHours) setHours("8");
  };

  if (view === undefined) {
    return (
      <View style={styles.card} accessibilityLabel="Request access">
        <Text style={styles.cardTitle}>Request access</Text>
        {loadError ? (
          <>
            <Text style={styles.error} accessibilityRole="alert">
              {`Couldn't load the roles you may request: ${loadError}`}
            </Text>
            <Pressable style={styles.btn} onPress={() => void load()} accessibilityRole="button" accessibilityLabel="Try again">
              <Text style={styles.btnText}>Try again</Text>
            </Pressable>
          </>
        ) : (
          <ActivityIndicator color={colors.textDim} />
        )}
      </View>
    );
  }
  if (!view || (!view.requestable.length && !view.requests.length)) return null;

  const offer = role ? (scope === "team" ? role.team : role.org) : null;
  const invalid = requestDraftError({ role: roleId, reason }) ?? (offer && !offer.ok ? offer.why : null);

  const run = async (action: () => Promise<string>) => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      setNotice(await action());
      await load();
    } catch (e) {
      setError(message(e));
    } finally {
      setBusy(false);
    }
  };

  const ask = () =>
    void run(async () => {
      await api.requestRole({ role: roleId, scope, hours: Number(hours), reason: reason.trim() });
      setReason("");
      return `Asked. An admin decides; it lapses in ${view.pendingDays} days if nobody does.`;
    });

  const withdraw = (id: string) =>
    void run(async () => {
      await api.withdrawRoleRequest(id);
      return "Withdrawn.";
    });

  const now = Date.now();
  return (
    <View style={styles.card} accessibilityLabel="Request access">
      <Text style={styles.cardTitle}>Request access</Text>
      {view.requestable.length ? (
        <>
          <Text style={styles.dim}>Ask for a role for a while, with a reason. An admin approves it, and it ends by itself.</Text>
          <Chips options={view.requestable.map((r) => ({ value: r.id, label: r.name }))} value={roleId} onChange={pick} disabled={busy} />
          {role ? (
            <>
              {role.description ? <Text style={styles.line}>{role.description}</Text> : null}
              <Text style={styles.dim}>
                Adds {(scope === "team" ? role.teamPermissions : role.permissions).join(", ") || "nothing"}. At most {hoursLabel(role.maxHours)}.
              </Text>
              {view.team && role.team ? (
                <Chips
                  options={[
                    { value: "org", label: "Across the server" },
                    { value: "team", label: `In ${view.team.name}` },
                  ]}
                  value={scope}
                  onChange={(s: Scope) => setScope(s)}
                  disabled={busy}
                />
              ) : null}
              {offer && !offer.ok ? <Text style={styles.warn}>{offer.why}</Text> : null}
              <Chips options={requestChoices(role.maxHours)} value={hours} onChange={setHours} disabled={busy} />
            </>
          ) : null}
          <TextInput
            style={styles.input}
            value={reason}
            onChangeText={setReason}
            placeholder="Why you need it (an admin sees this)"
            placeholderTextColor={colors.textFaint}
            maxLength={500}
            multiline
            editable={!busy}
            accessibilityLabel="Why you need it"
          />
          <Pressable style={[styles.btn, (busy || !!invalid) && styles.busy]} disabled={busy || !!invalid} onPress={ask} accessibilityRole="button" accessibilityLabel="Ask for it">
            <Text style={styles.btnText}>{busy ? "Asking…" : "Ask for it"}</Text>
          </Pressable>
          {reason && invalid ? <Text style={styles.faint}>{invalid}</Text> : null}
        </>
      ) : (
        <Text style={styles.dim}>No role may be requested now.</Text>
      )}
      {notice ? (
        <Text style={styles.good} accessibilityRole="alert">
          {notice}
        </Text>
      ) : null}
      {error ? (
        <Text style={styles.error} accessibilityRole="alert">
          {error}
        </Text>
      ) : null}
      {view.requests.length ? (
        <View style={styles.list}>
          <Text style={styles.sectionTitle}>Your requests</Text>
          {view.requests.map((q) => (
            <View key={q.id} style={styles.row}>
              <View style={{ flex: 1 }}>
                <Text style={styles.line}>
                  {q.role?.name ?? "A deleted role"} · {hoursLabel(q.hours)} · {q.team ? `in ${q.team.name ?? "a team"}` : "across the server"}
                </Text>
                <Text style={styles.faint}>{requestStatusLabel(q, now)}</Text>
              </View>
              {q.status === "pending" ? (
                <Pressable style={[styles.btn, busy && styles.busy]} disabled={busy} onPress={() => withdraw(q.id)} accessibilityRole="button" accessibilityLabel={`Withdraw request for ${q.role?.name ?? "a role"}`}>
                  <Text style={styles.btnText}>Withdraw</Text>
                </Pressable>
              ) : null}
            </View>
          ))}
        </View>
      ) : null}
    </View>
  );
}

const styles = StyleSheet.create({
  card: { backgroundColor: colors.bgSidebar, borderRadius: 14, padding: 16, gap: 10, borderWidth: 1, borderColor: colors.border },
  cardTitle: { color: colors.text, fontSize: 17, fontWeight: "600" },
  sectionTitle: { color: colors.textDim, fontSize: 13, fontWeight: "600", textTransform: "uppercase", letterSpacing: 0.5 },
  line: { color: colors.text, fontSize: 14 },
  good: { color: colors.accent },
  error: { color: colors.danger },
  warn: { color: colors.warning },
  dim: { color: colors.textDim },
  faint: { color: colors.textFaint, fontSize: 13 },
  list: { gap: 8, borderTopWidth: 1, borderTopColor: colors.border, paddingTop: 10 },
  row: { flexDirection: "row", alignItems: "center", gap: 10 },
  input: {
    backgroundColor: colors.bgBubble,
    borderColor: colors.border,
    borderWidth: 1,
    borderRadius: 12,
    paddingHorizontal: 14,
    paddingVertical: 10,
    color: colors.text,
    fontSize: 15,
    minHeight: 64,
    textAlignVertical: "top",
  },
  btn: { alignSelf: "flex-start", borderRadius: 999, borderWidth: 1, borderColor: colors.border, paddingVertical: 8, paddingHorizontal: 16 },
  btnText: { color: colors.text, fontSize: 15 },
  busy: { opacity: 0.6 },
});
