import React, { useCallback, useEffect, useState } from "react";
import { ActivityIndicator, Pressable, StyleSheet, Text, TextInput, View } from "react-native";
import type { SuperBotApi } from "../src/api";
import { confirmAsync } from "../src/dialogs";
import { CODE_TTLS, formatExpiry, relativeTime, ROLES, signInMethod } from "../src/invite";
import type { SsoProvider } from "../src/sso";
import { colors } from "../src/theme";
import type { AdminUser, LoginCode, Role, SessionView, UserBots } from "../src/types";
import { BotAvatar } from "./BotAvatar";
import { Chips } from "./Chips";
import { CodeReveal } from "./CodeReveal";

interface Props {
  api: SuperBotApi;
  user: AdminUser;
  meId?: string | null;
  providers: SsoProvider[];
  /** Called after any change, so the list can reload. */
  onChanged: () => Promise<void> | void;
}

const ACCESS_LABEL = { view: "Can view", operate: "Can use", manage: "Manages" } as const;

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <View style={styles.section}>
      <Text style={styles.sectionTitle}>{title}</Text>
      {children}
    </View>
  );
}

function Button({ label, onPress, danger, disabled }: { label: string; onPress: () => void; danger?: boolean; disabled?: boolean }) {
  return (
    <Pressable style={[styles.btn, danger && styles.dangerBtn, disabled && styles.disabled]} disabled={disabled} onPress={onPress}>
      <Text style={[styles.btnText, danger && styles.dangerText]}>{label}</Text>
    </Pressable>
  );
}

export function UserDetail({ api, user, meId, providers, onChanged }: Props) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [ttl, setTtl] = useState<number>(CODE_TTLS[1].minutes);
  const [code, setCode] = useState<LoginCode | null>(null);
  const [sessions, setSessions] = useState<SessionView[] | null>(null);
  const [bots, setBots] = useState<UserBots | null>(null);
  const [linkProvider, setLinkProvider] = useState(providers[0]?.id ?? "");
  const [subject, setSubject] = useState("");
  const [tenant, setTenant] = useState("");
  const self = user.id === meId;
  const locked = user.breakGlass || self;
  const active = user.status === "active";

  const loadExtras = useCallback(async () => {
    const [s, b] = await Promise.all([api.userSessions(user.id).catch(() => null), api.userBots(user.id).catch(() => null)]);
    setSessions(s);
    setBots(b);
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

  const setRole = (role: Role) => {
    if (role !== user.role) void run(() => api.patchUser(user.id, { role }));
  };

  const toggleStatus = async () => {
    if (active && !(await confirmAsync(`Disable ${user.name}?`, "They are signed out everywhere and can't sign in until you enable them again.", "Disable"))) return;
    void run(() => api.patchUser(user.id, { status: active ? "disabled" : "active" }));
  };

  const newCode = async () => {
    if (user.pendingCodes && !(await confirmAsync("Replace the waiting code?", "The code you made before stops working.", "Replace"))) return;
    void run(async () => setCode(await api.createLoginCode(user.id, ttl, true)));
  };

  const signOutEverywhere = async () => {
    if (!(await confirmAsync(`Sign ${user.name} out everywhere?`, "Ends every session and drops any unused sign-in code.", "Sign out"))) return;
    void run(() => api.revokeUserSessions(user.id));
  };

  const unlink = async (id: string, what: string) => {
    if (!(await confirmAsync(`Unlink ${what}?`, "They can't sign in with it any more. Their current sessions stay until you sign them out.", "Unlink"))) return;
    void run(() => api.unlinkIdentity(user.id, id));
  };

  const link = () =>
    void run(async () => {
      await api.linkIdentity(user.id, { provider: linkProvider, subject: subject.trim(), tenant: tenant.trim() || undefined });
      setSubject("");
      setTenant("");
    });

  const providerLabel = (id: string) => providers.find((p) => p.id === id)?.label ?? id;
  const linkType = providers.find((p) => p.id === linkProvider)?.type;

  return (
    <View style={styles.wrap}>
      <View>
        <Text style={styles.name}>{user.name}</Text>
        <Text style={styles.dim}>{user.email ?? "No email"}</Text>
        <Text style={styles.faint}>
          {user.breakGlass ? "Owner (break-glass) · " : ""}
          {self ? "You · " : ""}Added {new Date(user.createdAt).toLocaleDateString()} · Last sign-in {relativeTime(user.lastLoginAt).toLowerCase()}
          {user.lastLogin?.authMethod ? ` with ${signInMethod(user.lastLogin.authMethod, user.lastLogin.idpProvider)}` : ""}
        </Text>
      </View>
      {error ? <Text style={styles.error}>{error}</Text> : null}

      <Section title="Role">
        <Chips options={ROLES.map((r) => ({ value: r.role, label: r.label }))} value={user.role} onChange={setRole} disabled={busy || locked} />
        {locked ? (
          <Text style={styles.faint}>{user.breakGlass ? "The owner stays an active admin: it's the way back in." : "Another admin changes your own role and status."}</Text>
        ) : null}
      </Section>

      <Section title="Status">
        <View style={styles.row}>
          <Text style={[styles.text, { flex: 1 }]}>{active ? "Active" : "Disabled: can't sign in"}</Text>
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
        {sessions == null ? (
          <ActivityIndicator color={colors.textDim} />
        ) : (
          <>
            {sessions.length ? (
              sessions.map((s) => (
                <Text key={s.id} style={styles.dim}>
                  {s.label || (s.kind === "cookie" ? "Browser" : "App")} · {signInMethod(s.method, s.idpProvider)} · last used {relativeTime(s.lastSeenAt).toLowerCase()}
                </Text>
              ))
            ) : (
              <Text style={styles.dim}>Not signed in anywhere.</Text>
            )}
            <View style={styles.row}>
              <Button label="Sign out everywhere" danger disabled={busy || (!sessions.length && !user.pendingCodes)} onPress={() => void signOutEverywhere()} />
            </View>
          </>
        )}
      </Section>

      <Section title="Single sign-on">
        {user.identities?.length ? (
          user.identities.map((i) => (
            <View key={i.id} style={styles.row}>
              <Text style={[styles.text, { flex: 1 }]} numberOfLines={1}>
                {providerLabel(i.provider)} · {i.email ?? i.subject ?? i.id}
                <Text style={styles.faint}> · used {relativeTime(i.lastLoginAt).toLowerCase()}</Text>
              </Text>
              <Button label="Unlink" disabled={busy} onPress={() => void unlink(i.id, providerLabel(i.provider))} />
            </View>
          ))
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
              placeholder={linkType === "entra" ? "Object id" : linkType === "github" ? "GitHub user id (number)" : "Subject (sub)"}
              placeholderTextColor={colors.textFaint}
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
                placeholderTextColor={colors.textFaint}
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
        {bots == null ? (
          <ActivityIndicator color={colors.textDim} />
        ) : bots.bots.length ? (
          bots.bots.map((b) => (
            <View key={b.bot.id} style={styles.row}>
              <BotAvatar color={b.bot.color} shape={b.bot.shape} size={22} />
              <Text style={[styles.text, { flex: 1 }]} numberOfLines={1}>
                {b.bot.name}
                <Text style={styles.faint}>
                  {" "}
                  · {b.owner.id === user.id ? "owner" : b.grant ? `${b.grant} grant` : b.visibility}
                </Text>
              </Text>
              <Text style={styles.dim}>{ACCESS_LABEL[b.access]}</Text>
            </View>
          ))
        ) : (
          <Text style={styles.dim}>No Bots. Share one or grant access from the Bot's details.</Text>
        )}
        {!active && bots?.bots.length ? <Text style={styles.faint}>Applies once they're enabled again.</Text> : null}
      </Section>
    </View>
  );
}

const styles = StyleSheet.create({
  wrap: { gap: 16 },
  name: { color: colors.text, fontSize: 22, fontWeight: "600" },
  text: { color: colors.text },
  dim: { color: colors.textDim },
  faint: { color: colors.textFaint, fontSize: 13 },
  error: { color: colors.danger },
  section: { gap: 8, borderTopWidth: 1, borderTopColor: colors.border, paddingTop: 12 },
  sectionTitle: { color: colors.textDim, fontSize: 13, fontWeight: "600", textTransform: "uppercase", letterSpacing: 0.5 },
  row: { flexDirection: "row", alignItems: "center", gap: 10, flexWrap: "wrap" },
  linkBox: { gap: 8, marginTop: 4 },
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
  btn: { paddingVertical: 7, paddingHorizontal: 16, borderRadius: 999, borderWidth: 1, borderColor: "#3a3a3a" },
  btnText: { color: colors.text, fontSize: 14 },
  dangerBtn: { borderColor: "#5a2a2c" },
  dangerText: { color: colors.danger },
  disabled: { opacity: 0.5 },
});
