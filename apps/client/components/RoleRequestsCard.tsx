import React, { useCallback, useEffect, useState } from "react";
import { Pressable, StyleSheet, Text, TextInput, View } from "react-native";
import { ApiError, type SuperBotApi } from "../src/api";
import { hoursLabel, requestChoices, requestDraftError, requestStatusLabel } from "../src/roles";
import { themedStyles, useTheme } from "../src/theme";
import type { MyRoleRequests, RequestableRole } from "../src/types";
import { Chips } from "./Chips";
import { kit, Spinner } from "./ui";

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
  const styles = useStyles();
  const t = useTheme();
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
          <Spinner />
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
      const who = (role?.approvals ?? 1) >= 2 ? "Two people approve it before it starts" : "An admin decides";
      return `Asked. ${who}; it lapses in ${view.pendingDays} days if nobody does.`;
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
                {(role.approvals ?? 1) >= 2 ? " Two people approve it before it starts." : ""}
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
            placeholderTextColor={t.c.textFaint}
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

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    card: k.card,
    cardTitle: k.cardTitle,
    sectionTitle: { ...k.section, marginTop: 0, marginBottom: 0, paddingHorizontal: 0 },
    line: k.text,
    good: k.good,
    error: k.error,
    warn: k.warn,
    dim: k.dim,
    faint: k.faint,
    list: { ...k.field, gap: t.space.sm },
    row: { flexDirection: "row", alignItems: "center", gap: t.space.md },
    input: { ...k.input, ...k.inputMultiline, minHeight: 64 },
    btn: { ...k.btn, alignSelf: "flex-start" },
    btnText: k.btnText,
    busy: k.disabled,
  });
});
