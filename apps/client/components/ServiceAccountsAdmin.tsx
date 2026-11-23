import React, { useCallback, useEffect, useState } from "react";
import { ActivityIndicator, Modal, Pressable, ScrollView, StyleSheet, Text, TextInput, useWindowDimensions, View } from "react-native";
import type { SuperBotApi } from "../src/api";
import { COPY_LABEL, copyText } from "../src/clipboard";
import { confirmAsync } from "../src/dialogs";
import {
  BUILT_IN_ROLES,
  KEEP_OLD,
  canRotate,
  createBody,
  draftChanges,
  draftError,
  draftOf,
  emptyDraft,
  expiresSoon,
  expiryChoices,
  heldScopes,
  lastUsedLabel,
  roleLabel,
  scopesLabel,
  toggleScope,
  tokenStatus,
} from "../src/serviceAccounts";
import { colors } from "../src/theme";
import type { CustomRole, MintedServiceToken, ServiceAccount, ServiceAccountDraft, ServiceAccountsView, Team } from "../src/types";
import { Chips } from "./Chips";

interface Props {
  api: SuperBotApi;
  onBack: () => void;
}

type Picked = { kind: "account"; id: string } | { kind: "new" } | null;

const message = (err: unknown) => (err instanceof Error ? err.message : "Failed");

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
      accessibilityState={{ disabled: !!disabled }}
    >
      <Text style={[styles.btnText, primary && styles.primaryText, danger && styles.dangerText]}>{label}</Text>
    </Pressable>
  );
}

function Tags({ names, empty }: { names: string[]; empty: string }) {
  if (!names.length) return <Text style={styles.dim}>{empty}</Text>;
  return (
    <View style={styles.tags}>
      {names.map((p) => (
        <Text key={p} style={styles.tag}>
          {p}
        </Text>
      ))}
    </View>
  );
}

/**
 * A new token's secret, shown this once. The server keeps only its hash, so closing this
 * is the end of it: rotating or making another token is the only way to get one.
 */
function TokenReveal({ minted, onDone }: { minted: MintedServiceToken; onDone: () => void }) {
  const [copied, setCopied] = useState<boolean | null>(null);
  return (
    <View style={styles.reveal} testID="token-reveal">
      <Text style={styles.warn}>Copy it now. This token is shown once and can&apos;t be shown again.</Text>
      <Text style={styles.secret} selectable testID="token-value">
        {minted.token}
      </Text>
      <Text style={styles.dim}>
        {minted.tokenInfo.name} · {scopesLabel(minted.tokenInfo.scopes)} · expires {new Date(minted.tokenInfo.expiresAt).toLocaleString()}
      </Text>
      {minted.replaced ? <Text style={styles.dim}>The old token stops {minted.replaced.endsAt <= Date.now() + 1000 ? "now" : new Date(minted.replaced.endsAt).toLocaleString()}.</Text> : null}
      <Text style={styles.faint}>Send it as Authorization: Bearer, or set it as SUPERBOT_TOKEN for botctl.</Text>
      <View style={styles.row}>
        <Button label={copied ? "Copied" : copied === false ? "Select and copy it" : `${COPY_LABEL} token`} onPress={() => void copyText(minted.token).then(setCopied)} />
        <Button label="Done" primary onPress={onDone} />
      </View>
    </View>
  );
}

/** Name, description, role and team; on an existing account, the owner too. */
function AccountForm({
  draft,
  setDraft,
  roles,
  teams,
  busy,
  editing,
}: {
  draft: ServiceAccountDraft;
  setDraft: (d: ServiceAccountDraft) => void;
  roles: CustomRole[];
  teams: Team[];
  busy: boolean;
  editing: boolean;
}) {
  const custom = roles.find((r) => r.id === draft.role);
  return (
    <>
      <Section title="Name">
        <TextInput
          style={styles.input}
          value={draft.name}
          onChangeText={(name) => setDraft({ ...draft, name })}
          placeholder="HR sync"
          placeholderTextColor={colors.textFaint}
          maxLength={60}
          accessibilityLabel="Service account name"
        />
        <TextInput
          style={[styles.input, styles.multiline]}
          value={draft.description}
          onChangeText={(description) => setDraft({ ...draft, description })}
          placeholder="What calls with it (optional)"
          placeholderTextColor={colors.textFaint}
          multiline
          maxLength={500}
          accessibilityLabel="Service account description"
        />
      </Section>
      <Section title="Role">
        <Chips options={[...BUILT_IN_ROLES, ...roles.map((r) => ({ value: r.id, label: r.name }))]} value={draft.role} onChange={(role) => setDraft({ ...draft, role })} disabled={busy} />
        <Text style={styles.faint}>
          {custom
            ? `${custom.base === "readonly" ? "Read-only" : "Member"} + ${custom.permissions.join(", ") || "nothing"}${draft.team ? ", only its team permissions, in its team" : ""}.`
            : draft.role === "member"
              ? "Reads and uses Bots."
              : "Reads, changes nothing."}{" "}
          Never admin, and never more than its owner holds.
        </Text>
      </Section>
      {teams.length ? (
        <Section title="Where">
          <Chips options={[{ value: "", label: "Across the server" }, ...teams.map((t) => ({ value: t.id, label: t.name }))]} value={draft.team} onChange={(team) => setDraft({ ...draft, team })} disabled={busy} />
          <Text style={styles.faint}>{draft.team ? "Acts in that team as a member, without a seat, and reaches the Bots shared with it." : "In no team, like a person in none."}</Text>
        </Section>
      ) : null}
      {editing ? (
        <Section title="Owner">
          <TextInput
            style={styles.input}
            value={draft.owner}
            onChangeText={(owner) => setDraft({ ...draft, owner })}
            placeholder="Owner's email or id"
            placeholderTextColor={colors.textFaint}
            autoCapitalize="none"
            autoCorrect={false}
            accessibilityLabel="Owner's email or id"
          />
          <Text style={styles.faint}>Its tokens never get more than its owner holds now. The owner must be an active person.</Text>
        </Section>
      ) : null}
    </>
  );
}

function NewAccount({ api, view, roles, teams, onBusy, onCreated }: { api: SuperBotApi; view: ServiceAccountsView; roles: CustomRole[]; teams: Team[]; onBusy: (busy: boolean) => void; onCreated: (account: ServiceAccount, minted: MintedServiceToken | null, error: string | null) => Promise<void> }) {
  const [draft, setDraft] = useState<ServiceAccountDraft>(emptyDraft());
  const [firstToken, setFirstToken] = useState(true);
  const [days, setDays] = useState(view.defaultDays);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const invalid = draftError(draft, roles);

  const create = async () => {
    setBusy(true);
    onBusy(true);
    setError(null);
    try {
      const sa = await api.createServiceAccount(createBody(draft));
      let minted: MintedServiceToken | null = null;
      let tokenError: string | null = null;
      if (firstToken) {
        try {
          minted = await api.createServiceToken(sa.id, { expiresInDays: days });
        } catch (err) {
          tokenError = `Made ${sa.name}, but not its token: ${message(err)}`;
        }
      }
      onBusy(false);
      await onCreated(sa, minted, tokenError);
    } catch (err) {
      setError(message(err));
      setBusy(false);
      onBusy(false);
    }
  };

  return (
    <View style={styles.wrap}>
      <View>
        <Text style={styles.name}>New service account</Text>
        <Text style={styles.faint}>For a script or integration: it can&apos;t sign in, takes no seat, and acts only through tokens you make for it. You own it.</Text>
      </View>
      {error ? <Text style={styles.error}>{error}</Text> : null}
      <AccountForm draft={draft} setDraft={setDraft} roles={roles} teams={teams} busy={busy} editing={false} />
      <Section title="First token">
        <Pressable style={styles.perm} onPress={() => setFirstToken(!firstToken)} accessibilityRole="checkbox" accessibilityState={{ checked: firstToken }} accessibilityLabel="Make a token now">
          <Text style={[styles.check, firstToken && styles.checkOn]}>{firstToken ? "✓" : ""}</Text>
          <Text style={styles.text}>Make a token now, with everything it holds</Text>
        </Pressable>
        {firstToken ? <Chips options={expiryChoices(view)} value={days} onChange={setDays} disabled={busy} /> : null}
      </Section>
      <View style={styles.row}>
        <Button label="Create service account" primary disabled={busy || !!invalid} onPress={() => void create()} />
        {draft.name && invalid ? <Text style={styles.faint}>{invalid}</Text> : null}
      </View>
    </View>
  );
}

function AccountDetail({
  api,
  view,
  account,
  roles,
  teams,
  minted,
  onMinted,
  onDismissMinted,
  onChanged,
  onDeleted,
  onBusy,
  notice,
}: {
  api: SuperBotApi;
  view: ServiceAccountsView;
  account: ServiceAccount;
  roles: CustomRole[];
  teams: Team[];
  minted: MintedServiceToken | null;
  onMinted: (m: MintedServiceToken) => void;
  onDismissMinted: () => void;
  onChanged: () => Promise<void>;
  onDeleted: () => Promise<void>;
  /** While a request runs, picking another account would lose a secret it returns. */
  onBusy: (busy: boolean) => void;
  notice: string | null;
}) {
  const [full, setFull] = useState<ServiceAccount | null>(null);
  const [draft, setDraft] = useState<ServiceAccountDraft>(draftOf(account));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(notice);
  const [tokenName, setTokenName] = useState("");
  const [scopes, setScopes] = useState<string[]>([]);
  const [days, setDays] = useState(view.defaultDays);
  const [rotating, setRotating] = useState<string | null>(null);
  const [keepOld, setKeepOld] = useState(0);
  const [rotateDays, setRotateDays] = useState(view.defaultDays);

  const loadFull = useCallback(async () => setFull(await api.serviceAccount(account.id)), [api, account.id]);
  useEffect(() => {
    loadFull().catch((err) => setError(message(err)));
  }, [loadFull]);

  const sa = full ?? account;
  const active = sa.status === "active";
  const held = heldScopes(view, sa);
  const changes = draftChanges(sa, draft);
  const invalid = draftError(draft, roles);
  const tokens = full?.tokenList;

  const run = async (action: () => Promise<unknown>) => {
    setBusy(true);
    onBusy(true);
    setError(null);
    try {
      await action();
    } catch (err) {
      setError(message(err));
    } finally {
      setBusy(false);
      onBusy(false);
    }
  };
  const refresh = async () => {
    await loadFull();
    await onChanged();
  };

  const save = () => run(async () => {
    if (!changes) return;
    await api.updateServiceAccount(sa.id, changes);
    await refresh();
  });

  const setStatus = async (status: ServiceAccount["status"]) => {
    if (status === "disabled" && !(await confirmAsync(`Disable ${sa.name}?`, "Its tokens stop working and its runs stop until it's enabled again. Its routines pause.", "Disable"))) return;
    void run(async () => {
      await api.updateServiceAccount(sa.id, { status });
      await refresh();
    });
  };

  const remove = async () => {
    if (!(await confirmAsync(`Delete ${sa.name}?`, "For good: all its tokens are revoked and its runs stop. The audit log keeps naming it.", "Delete"))) return;
    void run(async () => {
      await api.deleteServiceAccount(sa.id);
      await onDeleted();
    });
  };

  const makeToken = () => run(async () => {
    const m = await api.createServiceToken(sa.id, { name: tokenName.trim() || undefined, scopes: scopes.length ? scopes : undefined, expiresInDays: days });
    setTokenName("");
    setScopes([]);
    setDays(view.defaultDays);
    onMinted(m);
    await refresh();
  });

  const rotate = (tokenId: string) => run(async () => {
    const m = await api.rotateServiceToken(sa.id, tokenId, { expiresInDays: rotateDays, keepOldMinutes: keepOld || undefined });
    setRotating(null);
    onMinted(m);
    await refresh();
  });

  const revoke = async (tokenId: string, name: string) => {
    if (!(await confirmAsync(`Revoke ${name}?`, "It stops working at once. Whatever uses it needs a new token.", "Revoke"))) return;
    void run(async () => {
      await api.revokeServiceToken(sa.id, tokenId);
      await refresh();
    });
  };

  return (
    <View style={styles.wrap}>
      <View>
        <Text style={styles.name}>{sa.name}</Text>
        <Text style={styles.faint}>
          {roleLabel(sa)} · {active ? "active" : "disabled"} · owned by {sa.owner ? sa.owner.name || sa.owner.email || sa.owner.id : "nobody"} · {lastUsedLabel(sa.lastUsedAt).toLowerCase()}
        </Text>
      </View>
      {minted && minted.serviceAccount.id === sa.id ? <TokenReveal minted={minted} onDone={onDismissMinted} /> : null}
      {error ? <Text style={styles.error}>{error}</Text> : null}
      {!sa.ownerActive ? <Text style={styles.warn}>Its owner is disabled or gone, so its tokens are refused. Give it an active owner below.</Text> : null}
      {!active ? <Text style={styles.warn}>Disabled: its tokens don&apos;t work. Enable it to use or make tokens.</Text> : null}

      <Section title="Can use today">
        <Tags names={sa.effective} empty="Nothing" />
        {sa.team ? <Text style={styles.faint}>In {sa.team.name}: {sa.teamPermissions.length ? sa.teamPermissions.join(", ") : "no team permissions"}.</Text> : null}
      </Section>

      <Section title={`Tokens${tokens ? ` (${sa.tokens} live)` : ""}`}>
        {tokens == null ? (
          <ActivityIndicator color={colors.textDim} />
        ) : tokens.length ? (
          tokens.map((t) => (
            <View key={t.id} style={styles.token}>
              <View style={styles.row}>
                <Text style={[styles.text, { flex: 1 }]} numberOfLines={1}>
                  {t.name} <Text style={styles.mono}>{t.preview}</Text>
                </Text>
                {canRotate(t) ? (
                  <>
                    <Button label="Rotate" a11y={`Rotate ${t.name}`} disabled={busy || !active} onPress={() => setRotating(rotating === t.id ? null : t.id)} />
                    <Button label="Revoke" a11y={`Revoke ${t.name}`} danger disabled={busy} onPress={() => void revoke(t.id, t.name)} />
                  </>
                ) : t.state === "active" ? (
                  <Button label="Revoke" a11y={`Revoke ${t.name}`} danger disabled={busy} onPress={() => void revoke(t.id, t.name)} />
                ) : null}
              </View>
              <Text style={[styles.faint, expiresSoon(t) && styles.warn]}>
                {tokenStatus(t)} · {scopesLabel(t.scopes)}
              </Text>
              <Text style={styles.faint}>{lastUsedLabel(t.lastUsedAt, t.lastUsedIp)}</Text>
              {rotating === t.id ? (
                <View style={styles.rotate}>
                  <Text style={styles.dim}>A new token with the same name and scopes. The old one:</Text>
                  <Chips options={KEEP_OLD} value={keepOld} onChange={setKeepOld} disabled={busy} />
                  <Text style={styles.dim}>The new one expires in:</Text>
                  <Chips options={expiryChoices(view)} value={rotateDays} onChange={setRotateDays} disabled={busy} />
                  <View style={styles.row}>
                    <Button label="Rotate now" a11y={`Confirm rotate ${t.name}`} primary disabled={busy} onPress={() => void rotate(t.id)} />
                    <Button label="Cancel" disabled={busy} onPress={() => setRotating(null)} />
                  </View>
                </View>
              ) : null}
            </View>
          ))
        ) : (
          <Text style={styles.dim}>No tokens yet.</Text>
        )}
      </Section>

      {active ? (
        <Section title="New token">
          <TextInput
            style={styles.input}
            value={tokenName}
            onChangeText={setTokenName}
            placeholder="Token name (optional), e.g. CI"
            placeholderTextColor={colors.textFaint}
            maxLength={60}
            accessibilityLabel="Token name"
          />
          <Text style={styles.dim}>Scopes: {scopes.length ? scopes.join(", ") : "everything it holds"}</Text>
          {held.map((s) => {
            const on = scopes.includes(s);
            return (
              <Pressable key={s} style={styles.perm} disabled={busy} onPress={() => setScopes(toggleScope(held, scopes, s))} accessibilityRole="checkbox" accessibilityState={{ checked: on, disabled: busy }} accessibilityLabel={`Scope ${s}`}>
                <Text style={[styles.check, on && styles.checkOn]}>{on ? "✓" : ""}</Text>
                <Text style={styles.text}>{s}</Text>
              </Pressable>
            );
          })}
          <Text style={styles.dim}>Expires in:</Text>
          <Chips options={expiryChoices(view)} value={days} onChange={setDays} disabled={busy} />
          <View style={styles.row}>
            <Button label="Make token" primary disabled={busy} onPress={() => void makeToken()} />
          </View>
        </Section>
      ) : null}

      <Section title="Settings">
        <AccountForm draft={draft} setDraft={setDraft} roles={roles} teams={teams} busy={busy} editing />
        <View style={styles.row}>
          <Button label="Save" primary disabled={busy || !!invalid || !changes} onPress={() => void save()} />
          {invalid ? <Text style={styles.faint}>{invalid}</Text> : null}
        </View>
      </Section>

      <View style={styles.row}>
        {active ? <Button label="Disable" disabled={busy} onPress={() => void setStatus("disabled")} /> : <Button label="Enable" primary disabled={busy} onPress={() => void setStatus("active")} />}
        <Button label="Delete" danger disabled={busy} onPress={() => void remove()} />
      </View>
    </View>
  );
}

/** Service accounts (ADR 0143, 0152): make them, give them a role, and issue, rotate and revoke their tokens. */
export function ServiceAccountsAdmin({ api, onBack }: Props) {
  const { width } = useWindowDimensions();
  const wide = width >= 900;
  const [view, setView] = useState<ServiceAccountsView | null>(null);
  const [roles, setRoles] = useState<CustomRole[]>([]);
  const [teams, setTeams] = useState<Team[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [picked, setPicked] = useState<Picked>(null);
  const [minted, setMinted] = useState<MintedServiceToken | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setView(await api.serviceAccounts());
      setError(null);
    } catch (err) {
      setError(message(err));
    }
  }, [api]);

  useEffect(() => {
    void load();
    api.roles().then((r) => setRoles(r.roles), () => setRoles([]));
    api.teams().then(setTeams, () => setTeams([]));
  }, [api, load]);

  const pick = (p: Picked) => {
    if (busy) return;
    setPicked(p);
    setMinted(null);
    setNotice(null);
  };

  const account = picked?.kind === "account" ? view?.serviceAccounts.find((s) => s.id === picked.id) : undefined;
  const detail = !view ? null : account ? (
    <AccountDetail
      key={account.id}
      api={api}
      view={view}
      account={account}
      roles={roles}
      teams={teams}
      minted={minted}
      onMinted={setMinted}
      onDismissMinted={() => setMinted(null)}
      onChanged={load}
      onDeleted={async () => {
        setPicked(null);
        setMinted(null);
        await load();
      }}
      onBusy={setBusy}
      notice={notice}
    />
  ) : picked?.kind === "new" ? (
    <NewAccount
      api={api}
      view={view}
      roles={roles}
      teams={teams}
      onBusy={setBusy}
      onCreated={async (made, m, tokenError) => {
        await load();
        // If the refresh failed, the list still needs the new account so its token shows.
        setView((v) => (v && !v.serviceAccounts.some((s) => s.id === made.id) ? { ...v, serviceAccounts: [...v.serviceAccounts, made] } : v));
        setPicked({ kind: "account", id: made.id });
        setMinted(m);
        setNotice(tokenError);
      }}
    />
  ) : null;

  return (
    <View style={styles.root}>
      <View style={styles.header}>
        <Pressable onPress={onBack} accessibilityRole="button" accessibilityLabel="Back to Bots">
          <Text style={styles.back}>‹ Bots</Text>
        </Pressable>
        <Text style={styles.title}>Service accounts</Text>
        <Button label="New service account" primary disabled={!view || busy} onPress={() => pick({ kind: "new" })} />
      </View>
      <View style={styles.body}>
        <View style={wide ? styles.listPaneWide : styles.listPane}>
          {error ? <Text style={styles.error}>{error}</Text> : null}
          {!view && !error ? <ActivityIndicator color={colors.textDim} style={{ marginTop: 20 }} /> : null}
          {view ? (
            <ScrollView contentContainerStyle={{ gap: 4, paddingBottom: 24 }}>
              {view.serviceAccounts.map((s) => (
                <Pressable
                  key={s.id}
                  style={[styles.listRow, picked?.kind === "account" && picked.id === s.id && styles.selected]}
                  onPress={() => pick({ kind: "account", id: s.id })}
                  disabled={busy}
                  accessibilityState={{ disabled: busy }}
                  accessibilityRole="button"
                  accessibilityLabel={`Service account ${s.name}`}
                >
                  <Text style={styles.text}>
                    {s.name}
                    {s.status === "disabled" ? <Text style={styles.warn}> · disabled</Text> : null}
                    {!s.ownerActive ? <Text style={styles.warn}> · owner inactive</Text> : null}
                  </Text>
                  <Text style={styles.faint}>
                    {roleLabel(s)} · {s.tokens} live {s.tokens === 1 ? "token" : "tokens"} · {lastUsedLabel(s.lastUsedAt).toLowerCase()}
                  </Text>
                </Pressable>
              ))}
              {!view.serviceAccounts.length ? <Text style={styles.empty}>No service accounts yet. Make one for each script or integration that calls the API.</Text> : null}
            </ScrollView>
          ) : null}
        </View>
        {wide ? (
          <ScrollView style={styles.detailPane} contentContainerStyle={{ padding: 20 }}>
            {detail ?? <Text style={styles.empty}>Pick a service account to see its tokens, or make a new one.</Text>}
          </ScrollView>
        ) : null}
      </View>
      {!wide ? (
        <Modal visible={!!detail} animationType="slide" onRequestClose={() => pick(null)}>
          <View style={styles.modalRoot}>
            <Pressable style={styles.modalHeader} onPress={() => pick(null)} accessibilityRole="button">
              <Text style={styles.back}>‹ Service accounts</Text>
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
  mono: { color: colors.textDim, fontFamily: "monospace", fontSize: 13 },
  warn: { color: colors.warning },
  error: { color: colors.danger, padding: 4 },
  empty: { color: colors.textFaint, padding: 12, textAlign: "center" },
  section: { gap: 8, borderTopWidth: 1, borderTopColor: colors.border, paddingTop: 12 },
  sectionTitle: { color: colors.textDim, fontSize: 13, fontWeight: "600", textTransform: "uppercase", letterSpacing: 0.5 },
  row: { flexDirection: "row", alignItems: "center", gap: 10, flexWrap: "wrap" },
  token: { gap: 4, paddingVertical: 6, borderBottomWidth: 1, borderBottomColor: colors.border },
  rotate: { gap: 8, paddingTop: 6 },
  reveal: { gap: 10, backgroundColor: colors.bgBubble, borderRadius: 14, padding: 14, borderWidth: 1, borderColor: "#2d4a33" },
  secret: { color: colors.text, fontFamily: "monospace", fontSize: 13, backgroundColor: "#151515", borderRadius: 10, padding: 10 },
  perm: { flexDirection: "row", gap: 10, alignItems: "center", paddingVertical: 4 },
  check: { width: 22, height: 22, borderRadius: 6, borderWidth: 1, borderColor: "#3a3a3a", color: "#111", textAlign: "center", lineHeight: 20, fontSize: 14 },
  checkOn: { backgroundColor: "#f2f2f2", borderColor: "#f2f2f2" },
  tags: { flexDirection: "row", flexWrap: "wrap", gap: 6 },
  tag: { color: colors.textDim, fontSize: 12, borderWidth: 1, borderColor: colors.border, borderRadius: 999, paddingHorizontal: 8, paddingVertical: 2 },
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
