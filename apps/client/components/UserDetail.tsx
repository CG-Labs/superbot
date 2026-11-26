import React, { useCallback, useEffect, useState } from "react";
import { Pressable, StyleSheet, Text, TextInput, View } from "react-native";
import type { SuperBotApi } from "../src/api";
import { confirmAsync } from "../src/dialogs";
import { CODE_TTLS, formatExpiry, relativeTime, ROLES, signInMethod } from "../src/invite";
import { overLimits, planUsageLines } from "../src/plan";
import type { SsoProvider } from "../src/sso";
import { themedStyles, type } from "../src/theme";
import type { AdminUser, CustomRole, LoginCode, Role, SessionView, TeammateAccounts, TeammateRemoval, UserBots, UserIdentity } from "../src/types";
import { BotAvatar } from "./BotAvatar";
import { Chips } from "./Chips";
import { CodeReveal } from "./CodeReveal";
import { kit, Spinner, usePlaceholder } from "./ui";

interface Props {
  api: SuperBotApi;
  user: AdminUser;
  meId?: string | null;
  providers: SsoProvider[];
  /** Custom roles to give (ADR 0123); none on servers from before them. */
  roles?: CustomRole[];
  /** Called after any change, so the list can reload. */
  onChanged: () => Promise<void> | void;
}

const ACCESS_LABEL = { view: "Can view", operate: "Can use", manage: "Manages" } as const;

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  const styles = useStyles();
  return (
    <View style={styles.section}>
      <Text style={styles.sectionTitle}>{title}</Text>
      {children}
    </View>
  );
}

function Button({ label, onPress, danger, disabled }: { label: string; onPress: () => void; danger?: boolean; disabled?: boolean }) {
  const styles = useStyles();
  return (
    <Pressable style={({ pressed }) => [styles.btn, danger && styles.dangerBtn, pressed && styles.pressed, disabled && styles.disabled]} disabled={disabled} onPress={onPress}>
      <Text style={[styles.btnText, danger && styles.dangerText]}>{label}</Text>
    </Pressable>
  );
}

/** What to type to link an account, per provider type: its id there, never an email. */
const SUBJECT_HINT: Record<string, string> = {
  entra: "Object id",
  github: "GitHub user id (number)",
  saml: "NameID at the SAML IdP",
};

/** SAML links are by NameID, so it's shown even once a sign-in has filled in an email. */
function identityName(i: UserIdentity, providers: SsoProvider[]): string {
  const saml = (i.idp ?? providers.find((p) => p.id === i.provider)?.type) === "saml";
  if (saml && i.subject) return i.email ? `${i.subject} (${i.email})` : i.subject;
  return i.email ?? i.subject ?? i.id;
}

const personName = (p: { id: string; name?: string | null; email?: string | null }) => p.name || p.email || p.id;

/** Where a removal of a teammate's account on this server stands (ADR 0066). */
function removalStatus(r: TeammateRemoval): string {
  if (r.state === "pending") return r.lastError ? `Removal pending: ${r.lastError}` : "Removal pending";
  if (r.state === "held") return `Removed; work held until ${r.purgeAt ? new Date(r.purgeAt).toLocaleDateString() : "an admin purges it"}`;
  if (r.state === "cancelled") return "Removal cancelled: access is back";
  return r.archivedTo ? "Removed; work handed to the owner" : "Removed";
}

/** What happens to a teammate's work when their account here goes, as the server is set. */
function workOutcome(t: TeammateAccounts | null): string {
  if (t?.files === "delete") {
    if (!t.graceDays) return "their work is deleted for good";
    return `their work is held for ${t.graceDays} day${t.graceDays === 1 ? "" : "s"}, then deleted`;
  }
  return "their work goes to the Bots' owner";
}

function LoadFailed({ message, onRetry }: { message: string; onRetry: () => void }) {
  const styles = useStyles();
  return (
    <View style={styles.line}>
      <Text style={[styles.error, styles.grow]}>{message}</Text>
      <Button label="Retry" onPress={onRetry} />
    </View>
  );
}

export function UserDetail({ api, user, meId, providers, roles = [], onChanged }: Props) {
  const styles = useStyles();
  const placeholder = usePlaceholder();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [ttl, setTtl] = useState<number>(CODE_TTLS[1].minutes);
  const [code, setCode] = useState<LoginCode | null>(null);
  const [sessions, setSessions] = useState<SessionView[] | null>(null);
  const [bots, setBots] = useState<UserBots | null>(null);
  const [sessionsError, setSessionsError] = useState<string | null>(null);
  const [botsError, setBotsError] = useState<string | null>(null);
  const [teammates, setTeammates] = useState<TeammateAccounts | null>(null);
  const [teammatesError, setTeammatesError] = useState<string | null>(null);
  const [pickedProvider, setLinkProvider] = useState("");
  // Providers can arrive after this opens; until someone picks, link with the first.
  const linkProvider = providers.some((p) => p.id === pickedProvider) ? pickedProvider : (providers[0]?.id ?? "");
  const [subject, setSubject] = useState("");
  const [tenant, setTenant] = useState("");
  const self = user.id === meId;
  const locked = user.breakGlass || self;
  const active = user.status === "active";

  const loadExtras = useCallback(async () => {
    const failed = (err: unknown) => (err instanceof Error ? err.message : "Couldn't load");
    setSessionsError(null);
    setBotsError(null);
    setTeammatesError(null);
    await Promise.all([
      api.userSessions(user.id).then(setSessions, (err) => setSessionsError(failed(err))),
      api.userBots(user.id).then(setBots, (err) => setBotsError(failed(err))),
      api.teammateAccounts(user.id).then(setTeammates, (err) => setTeammatesError(failed(err))),
    ]);
  }, [api, user.id]);

  useEffect(() => {
    void loadExtras();
  }, [loadExtras, user.role, user.status]);

  const run = async (action: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await action();
      await onChanged();
      await loadExtras();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed");
    } finally {
      setBusy(false);
    }
  };

  const setRole = async (role: Role) => {
    if (role === user.role && !user.customRole) return;
    if (user.customRole && !(await confirmAsync(`Make ${user.name} ${ROLES.find((r) => r.role === role)?.label ?? role}?`, `Setting a built-in role takes ${user.customRole.name} away from them.`, "Change"))) return;
    void run(() => api.patchUser(user.id, { role }));
  };

  const setCustomRole = async (id: string) => {
    if (id === (user.roleId ?? "")) return;
    const next = roles.find((r) => r.id === id);
    if (!next && !(await confirmAsync(`Take ${user.customRole?.name ?? "their custom role"} away from ${user.name}?`, `They keep ${ROLES.find((r) => r.role === user.role)?.label.toLowerCase() ?? user.role} as their role.`, "Take away"))) return;
    if (next && user.role === "admin" && !(await confirmAsync(`Give ${next.name} to ${user.name}?`, `They stop being an admin: their role becomes ${next.base === "readonly" ? "read-only" : "member"}, with ${next.name}'s permissions on top.`, "Give"))) return;
    void run(() => (next ? api.assignRole(next.id, user.id) : api.unassignRole(user.roleId ?? "", user.id)));
  };

  const toggleStatus = async () => {
    if (active && !(await confirmAsync(`Disable ${user.name}?`, "They are signed out everywhere and can't sign in until you enable them again.", "Disable"))) return;
    void run(async () => {
      await api.patchUser(user.id, { status: active ? "disabled" : "active" });
      if (active) setCode(null);
    });
  };

  const newCode = async () => {
    if (user.pendingCodes && !(await confirmAsync("Replace the waiting code?", "The code you made before stops working.", "Replace"))) return;
    void run(async () => setCode(await api.createLoginCode(user.id, ttl, true)));
  };

  const signOutEverywhere = async () => {
    if (!(await confirmAsync(`Sign ${user.name} out everywhere?`, "Ends every session and drops any unused sign-in code.", "Sign out"))) return;
    void run(async () => {
      await api.revokeUserSessions(user.id);
      setCode(null);
    });
  };

  const resetMfa = async () => {
    if (!(await confirmAsync(`Reset ${user.name}'s two-factor authentication?`, "Use this if they lost their authenticator app. If it's required, they set it up again at their next sign-in.", "Reset"))) return;
    void run(() => api.resetUserMfa(user.id));
  };

  const unlink = async (id: string, what: string) => {
    if (!(await confirmAsync(`Unlink ${what}?`, "They can't sign in with it any more. Their current sessions stay until you sign them out.", "Unlink"))) return;
    void run(() => api.unlinkIdentity(user.id, id));
  };

  const link = () =>
    void run(async () => {
      await api.linkIdentity(user.id, { provider: linkProvider, subject: subject.trim(), tenant: (linkType === "entra" && tenant.trim()) || undefined });
      setSubject("");
      setTenant("");
    });

  const removeTeammate = async (owner: string, teammate: string, who: string) => {
    const body = `Their processes stop, ${workOutcome(teammates)}, and their login is deleted. A later run makes a new one if they still have access.`;
    if (!(await confirmAsync(`Remove ${who}'s account here?`, body, "Remove"))) return;
    void run(async () => {
      const res = await api.removeTeammateAccount(owner, teammate);
      if (res.error) throw new Error(`Still pending: ${res.error}`);
    });
  };

  const providerLabel = (id: string) => providers.find((p) => p.id === id)?.label ?? id;
  const linkType = providers.find((p) => p.id === linkProvider)?.type;

  return (
    <View style={styles.wrap}>
      <View style={styles.head}>
        <Text style={styles.name}>{user.name}</Text>
        <Text style={styles.dim}>{user.email ?? "No email"}</Text>
        <Text style={styles.faint}>
          {user.breakGlass ? "Owner (break-glass) · " : ""}
          {self ? "You · " : ""}Added {new Date(user.createdAt).toLocaleDateString()} · Last sign-in {relativeTime(user.lastLoginAt).toLowerCase()}
          {user.lastLogin?.authMethod ? ` with ${signInMethod(user.lastLogin.authMethod, user.lastLogin.idpProvider && providerLabel(user.lastLogin.idpProvider))}` : ""}
        </Text>
      </View>
      {error ? <Text style={styles.error}>{error}</Text> : null}

      <Section title="Role">
        <Chips options={ROLES.map((r) => ({ value: r.role, label: r.label }))} value={user.role} onChange={(r) => void setRole(r)} disabled={busy || locked} />
        {roles.length ? (
          <>
            <Text style={styles.faint}>Custom role: its base becomes their role, with its permissions on top.</Text>
            <Chips
              options={[{ value: "", label: "None" }, ...roles.map((r) => ({ value: r.id, label: r.name }))]}
              value={user.roleId ?? ""}
              onChange={(id) => void setCustomRole(id)}
              disabled={busy || locked}
            />
          </>
        ) : null}
        {locked ? (
          <Text style={styles.faint}>{user.breakGlass ? "The owner stays an active admin: it's the way back in." : "Another admin changes your own role and status."}</Text>
        ) : null}
        {user.permissions?.length ? <Text style={styles.dim}>Can do: {user.permissions.join(", ")}</Text> : null}
      </Section>

      {user.plan ? (
        <Section title="Plan and usage">
          <Text style={styles.text}>{user.plan.label}</Text>
          {planUsageLines(user.plan).map((line) => (
            <Text key={line} style={styles.dim}>
              {line}
            </Text>
          ))}
          {overLimits(user.plan).length ? (
            <Text style={styles.error}>Over the plan&apos;s limit for {overLimits(user.plan).join(", ")}: new ones are refused until they&apos;re under it.</Text>
          ) : null}
        </Section>
      ) : null}

      <Section title="Status">
        <View style={styles.line}>
          <Text style={styles.rowText}>{active ? "Active" : "Disabled: can't sign in"}</Text>
          <Button label={active ? "Disable" : "Enable"} danger={active} disabled={busy || locked} onPress={() => void toggleStatus()} />
        </View>
      </Section>

      <Section title="Sign-in code">
        {code ? (
          <CodeReveal code={code} name={user.name} serverUrl={api.baseUrl} onDone={() => setCode(null)} />
        ) : (
          <>
            <Text style={styles.dim}>
              {user.pendingCodes
                ? `A code is waiting, expires ${formatExpiry(user.pendingCodes.expiresAt)}. A new one replaces it.`
                : "No code waiting."}
            </Text>
            <View style={styles.row}>
              <Chips options={CODE_TTLS.map((t) => ({ value: t.minutes, label: t.label }))} value={ttl} onChange={setTtl} disabled={busy || !active} />
              <Button label="New code" disabled={busy || !active} onPress={() => void newCode()} />
            </View>
          </>
        )}
      </Section>

      <Section title="Sessions">
        {sessionsError ? (
          <>
            <LoadFailed message={sessionsError} onRetry={() => void loadExtras()} />
            <View style={styles.row}>
              <Button label="Sign out everywhere" danger disabled={busy} onPress={() => void signOutEverywhere()} />
            </View>
          </>
        ) : sessions == null ? (
          <Spinner />
        ) : (
          <>
            {sessions.length ? (
              <View style={styles.list}>
                {sessions.map((s) => (
                  <View key={s.id} style={styles.item}>
                    <Text style={styles.rowText}>
                      {s.label || (s.kind === "cookie" ? "Browser" : "App")} · {signInMethod(s.method, s.idpProvider && providerLabel(s.idpProvider))} · last used {relativeTime(s.lastSeenAt).toLowerCase()}
                    </Text>
                  </View>
                ))}
              </View>
            ) : (
              <Text style={styles.dim}>Not signed in anywhere.</Text>
            )}
            <View style={styles.row}>
              <Button label="Sign out everywhere" danger disabled={busy || (!sessions.length && !user.pendingCodes)} onPress={() => void signOutEverywhere()} />
            </View>
          </>
        )}
      </Section>

      <Section title="Two-factor authentication">
        <View style={styles.line}>
          <Text style={styles.rowText}>
            {user.mfa?.enabled ? `On since ${new Date(user.mfa.enabledAt ?? 0).toLocaleDateString()}` : "Off"}
          </Text>
          {user.mfa?.enabled && !self ? <Button label="Reset" danger disabled={busy} onPress={() => void resetMfa()} /> : null}
        </View>
        {user.mfa?.enabled && self ? <Text style={styles.faint}>Turn yours off in Settings. Another admin can reset it.</Text> : null}
      </Section>

      <Section title="Single sign-on">
        {user.identities?.length ? (
          <View style={styles.list}>
            {user.identities.map((i) => (
              <View key={i.id} style={styles.item}>
                <Text style={styles.rowText} numberOfLines={1}>
                  {providerLabel(i.provider)} · {identityName(i, providers)}
                  <Text style={styles.faint}> · used {relativeTime(i.lastLoginAt).toLowerCase()}</Text>
                </Text>
                <Button label="Unlink" disabled={busy} onPress={() => void unlink(i.id, providerLabel(i.provider))} />
              </View>
            ))}
          </View>
        ) : (
          <Text style={styles.dim}>No linked sign-ins.</Text>
        )}
        {providers.length ? (
          <View style={styles.linkBox}>
            <Text style={styles.faint}>Link an account. Email never links accounts, so give its id at the provider.</Text>
            <Chips options={providers.map((p) => ({ value: p.id, label: p.label }))} value={linkProvider} onChange={setLinkProvider} disabled={busy} />
            <TextInput
              style={styles.input}
              autoCapitalize="none"
              autoCorrect={false}
              placeholder={SUBJECT_HINT[linkType ?? ""] ?? "Subject (sub)"}
              placeholderTextColor={placeholder}
              value={subject}
              onChangeText={setSubject}
              accessibilityLabel="Subject"
            />
            {linkType === "entra" ? (
              <TextInput
                style={styles.input}
                autoCapitalize="none"
                autoCorrect={false}
                placeholder="Tenant id (optional)"
                placeholderTextColor={placeholder}
                value={tenant}
                onChangeText={setTenant}
                accessibilityLabel="Tenant"
              />
            ) : null}
            <View style={styles.row}>
              <Button label="Link" disabled={busy || !subject.trim() || !linkProvider} onPress={link} />
            </View>
          </View>
        ) : (
          <Text style={styles.faint}>No SSO providers are set up on this server (SSO_PROVIDERS).</Text>
        )}
      </Section>

      <Section title="Bot access">
        {botsError ? (
          <LoadFailed message={botsError} onRetry={() => void loadExtras()} />
        ) : bots == null ? (
          <Spinner />
        ) : bots.bots.length ? (
          <View style={styles.list}>
            {bots.bots.map((b) => (
              <View key={b.bot.id} style={styles.item}>
                <BotAvatar color={b.bot.color} shape={b.bot.shape} size={22} />
                <Text style={styles.rowText} numberOfLines={1}>
                  {b.bot.name}
                  <Text style={styles.faint}>
                    {" "}
                    · {b.owner.id === user.id ? "owner" : b.grant ? `${b.grant} grant` : b.visibility}
                  </Text>
                </Text>
                <Text style={styles.dim}>{ACCESS_LABEL[b.access]}</Text>
              </View>
            ))}
          </View>
        ) : (
          <Text style={styles.dim}>No Bots. Share one or grant access from the Bot's details.</Text>
        )}
        {!active && bots?.bots.length ? <Text style={styles.faint}>Applies once they're enabled again.</Text> : null}
      </Section>

      {teammatesError ? (
        <Section title="Teammate accounts here">
          <LoadFailed message={teammatesError} onRetry={() => void loadExtras()} />
        </Section>
      ) : teammates && (teammates.accounts.length || teammates.removals.length) ? (
        <Section title="Teammate accounts here">
          <View style={styles.list}>
            {teammates.accounts.map((a) => {
              const mine = a.owner.id === user.id;
              const who = personName(mine ? a.teammate : user);
              return (
                <View key={a.account} style={styles.item}>
                  <Text style={styles.rowText} numberOfLines={2}>
                    {mine ? `${personName(a.teammate)}, for these Bots` : `For ${personName(a.owner)}'s Bots`}
                    <Text style={styles.faint}> · {a.removal ? removalStatus(a.removal) : a.wanted ? "in use" : "no longer has access"}</Text>
                  </Text>
                  <Button label="Remove" danger disabled={busy} onPress={() => void removeTeammate(a.owner.id, a.teammate.id, who)} />
                </View>
              );
            })}
            {teammates.removals
              .filter((r) => r.state !== "pending")
              .slice(0, 5)
              .map((r) => (
                <View key={r.id} style={styles.item}>
                  <Text style={[styles.dim, styles.grow]}>
                    {r.ownerId === user.id ? personName(r.teammate) : `For ${personName(r.owner)}'s Bots`} · {removalStatus(r)}
                  </Text>
                </View>
              ))}
          </View>
        </Section>
      ) : null}
    </View>
  );
}

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    wrap: { gap: t.space.lg },
    head: { gap: t.space.xxs, paddingHorizontal: t.space.xs },
    name: { color: t.c.text, ...type(t, "xl"), fontWeight: t.font.weight.semibold },
    text: k.text,
    rowText: { ...k.text, flex: 1 },
    dim: k.dim,
    faint: k.faint,
    error: k.error,
    grow: { flex: 1 },
    section: k.card,
    sectionTitle: k.cardTitle,
    row: k.actions,
    line: { flexDirection: "row", alignItems: "center", gap: t.space.md },
    list: {},
    item: { ...k.row, paddingVertical: t.space.sm },
    linkBox: k.field,
    input: k.input,
    btn: { ...k.btn, ...k.btnSmall },
    btnText: k.btnText,
    dangerBtn: k.danger,
    dangerText: k.dangerText,
    pressed: k.btnPressed,
    disabled: k.disabled,
  });
});
