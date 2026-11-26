import React, { useCallback, useEffect, useRef, useState } from "react";
import { Modal, Pressable, ScrollView, StyleSheet, Text, TextInput, useWindowDimensions, View } from "react-native";
import { keeperQuestion, keepersQuestion } from "../src/access";
import type { SuperBotApi } from "../src/api";
import { COPY_LABEL, copyText } from "../src/clipboard";
import { confirmAsync } from "../src/dialogs";
import {
  KEEP_OLD,
  canRotate,
  choiceError,
  createBody,
  draftChanges,
  draftError,
  draftOf,
  emptyDraft,
  expiresSoon,
  expiryChoices,
  formChoices,
  heldScopes,
  keptRole,
  lastUsedLabel,
  rebaseDraft,
  roleLabel,
  roleOptions,
  scopesLabel,
  teamOptions,
  toggleScope,
  tokenStatus,
} from "../src/serviceAccounts";
import { hairline, themedStyles, type, useTheme } from "../src/theme";
import type { CustomRole, MintedServiceToken, ServiceAccount, ServiceAccountChoices, ServiceAccountDraft, ServiceAccountsView, Team } from "../src/types";
import { Chips } from "./Chips";
import { kit, PageHeader, Spinner } from "./ui";

interface Props {
  api: SuperBotApi;
  onBack: () => void;
  /** An admin manages every account and its owner; anyone else with users.manage only their own (ADR 0182). */
  admin: boolean;
}

/** The account's own role and team, kept in the pickers when they're no longer offered. */
type Kept = { role: { id: string; name: string }; team: { id: string; name: string } | null };

/** The custom roles `draftError` checks against, with the account's own if it's no longer offered. */
function customRoles(choices: ServiceAccountChoices, sa?: ServiceAccount): { id: string; base: ServiceAccount["role"] }[] {
  const out = choices.roles.filter((r) => !r.builtIn).map((r) => ({ id: r.id, base: r.base }));
  const own = sa?.customRole ?? sa?.teamRole;
  return own && !out.some((r) => r.id === own.id) ? [...out, { id: own.id, base: sa!.role }] : out;
}

type Picked = { kind: "account"; id: string } | { kind: "new" } | null;

const message = (err: unknown) => (err instanceof Error ? err.message : "Failed");

const InSection = React.createContext(false);

/** A card, or a titled part of one when it sits inside another section. */
function Section({ title, children }: { title: string; children: React.ReactNode }) {
  const styles = useStyles();
  const nested = React.useContext(InSection);
  return (
    <View style={nested ? styles.subsection : styles.section}>
      <Text style={nested ? styles.subsectionTitle : styles.sectionTitle}>{title}</Text>
      <InSection.Provider value>{children}</InSection.Provider>
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
      accessibilityState={{ disabled: !!disabled }}
    >
      <Text style={[styles.btnText, primary && styles.primaryText, danger && styles.dangerText]}>{label}</Text>
    </Pressable>
  );
}

function Tags({ names, empty }: { names: string[]; empty: string }) {
  const styles = useStyles();
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
  const styles = useStyles();
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

/** Name, description, role and team; on an existing account, for an admin, the owner too. */
function AccountForm({
  draft,
  setDraft,
  choices,
  kept,
  busy,
  editing,
  admin,
}: {
  draft: ServiceAccountDraft;
  setDraft: (d: ServiceAccountDraft) => void;
  choices: ServiceAccountChoices;
  kept?: Kept;
  busy: boolean;
  editing: boolean;
  admin: boolean;
}) {
  const styles = useStyles();
  const t = useTheme();
  const custom = choices.roles.find((r) => r.id === draft.role && !r.builtIn);
  const teams = teamOptions(choices, kept?.team);
  const keepRole = kept && draft.team === (kept.team?.id ?? "") ? kept.role : null;
  return (
    <>
      <Section title="Name">
        <TextInput
          style={styles.input}
          value={draft.name}
          onChangeText={(name) => setDraft({ ...draft, name })}
          placeholder="HR sync"
          placeholderTextColor={t.c.textFaint}
          maxLength={60}
          accessibilityLabel="Service account name"
        />
        <TextInput
          style={[styles.input, styles.multiline]}
          value={draft.description}
          onChangeText={(description) => setDraft({ ...draft, description })}
          placeholder="What calls with it (optional)"
          placeholderTextColor={t.c.textFaint}
          multiline
          maxLength={500}
          accessibilityLabel="Service account description"
        />
      </Section>
      <Section title="Role">
        <Chips options={roleOptions(choices, draft.team, keepRole)} value={draft.role} onChange={(role) => setDraft({ ...draft, role })} disabled={busy} />
        <Text style={styles.faint}>
          {custom
            ? `${custom.base === "readonly" ? "Read-only" : "Member"} + ${custom.permissions.join(", ") || "nothing"}${draft.team ? ", only its team permissions, in its team" : ""}.`
            : draft.role === "member"
              ? "Reads and uses Bots."
              : "Reads, changes nothing."}{" "}
          Never admin, and never more than its owner holds.
        </Text>
      </Section>
      {teams.length > 1 ? (
        <Section title="Where">
          <Chips options={teams} value={draft.team} onChange={(team) => setDraft({ ...draft, team })} disabled={busy} />
          <Text style={styles.faint}>
            {draft.team ? "Acts in that team as a member, without a seat, and reaches the Bots shared with it, while its owner is on it." : "In no team, like a person in none."}
          </Text>
        </Section>
      ) : null}
      {editing && admin ? (
        <Section title="Owner">
          <TextInput
            style={styles.input}
            value={draft.owner}
            onChangeText={(owner) => setDraft({ ...draft, owner })}
            placeholder="Owner's email or id"
            placeholderTextColor={t.c.textFaint}
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

function NewAccount({ api, view, choices, admin, onBusy, onCreated }: { api: SuperBotApi; view: ServiceAccountsView; choices: ServiceAccountChoices; admin: boolean; onBusy: (busy: boolean) => void; onCreated: (account: ServiceAccount, minted: MintedServiceToken | null, error: string | null) => Promise<void> }) {
  const styles = useStyles();
  const [draft, setDraft] = useState<ServiceAccountDraft>(emptyDraft());
  const [firstToken, setFirstToken] = useState(true);
  const [days, setDays] = useState(view.defaultDays);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const invalid = draftError(draft, customRoles(choices)) ?? choiceError(draft, choices);

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
      <AccountForm draft={draft} setDraft={setDraft} choices={choices} busy={busy} editing={false} admin={admin} />
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
  choices,
  admin,
  manage,
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
  choices: ServiceAccountChoices;
  admin: boolean;
  /** False for an owner without users.manage: they see it, revoke tokens and disable it, nothing more (ADR 0239). */
  manage: boolean;
  minted: MintedServiceToken | null;
  onMinted: (m: MintedServiceToken) => void;
  onDismissMinted: () => void;
  onChanged: () => Promise<void>;
  onDeleted: () => Promise<void>;
  /** While a request runs, picking another account would lose a secret it returns. */
  onBusy: (busy: boolean) => void;
  notice: string | null;
}) {
  const styles = useStyles();
  const t = useTheme();
  const [full, setFull] = useState<ServiceAccount | null>(null);
  const [draft, setDraft] = useState<ServiceAccountDraft>(draftOf(account));
  const base = useRef(draftOf(account));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(notice);
  const [tokenName, setTokenName] = useState("");
  const [scopes, setScopes] = useState<string[]>([]);
  const [days, setDays] = useState(view.defaultDays);
  const [rotating, setRotating] = useState<string | null>(null);
  const [keepOld, setKeepOld] = useState(0);
  const [rotateDays, setRotateDays] = useState(view.defaultDays);
  const [handing, setHanding] = useState<string[]>([]);

  const loadFull = useCallback(async () => {
    const next = await api.serviceAccount(account.id);
    const was = base.current;
    const now = draftOf(next);
    base.current = now;
    setDraft((d) => rebaseDraft(d, was, now));
    setFull(next);
  }, [api, account.id]);
  useEffect(() => {
    loadFull().catch((err) => setError(message(err)));
  }, [loadFull]);

  const sa = full ?? account;
  const active = sa.status === "active";
  const held = heldScopes(view, sa);
  const changes = draftChanges(sa, draft);
  const invalid = draftError(draft, customRoles(choices, sa)) ?? choiceError(draft, choices, draftOf(sa));
  const kept: Kept = { role: keptRole(sa), team: sa.team };
  const tokens = full?.tokenList;
  const keptBots = full?.keptBotList ?? [];
  const keepable = full?.keepable ?? [];
  const left = Math.max(0, (view.maxKeptBots ?? 20) - keptBots.length);
  // Only picks still offered, and no more than it has room for now: a reload may drop some
  // (a new owner) or fill the room.
  const picked = keepable.filter((k) => handing.includes(k.id)).slice(0, left);

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

  const handLabel = picked.length > 1 ? `Hand over ${picked.length} Bots` : "Hand it over";
  const handOver = async () => {
    if (!picked.length) return;
    const q = keepersQuestion(picked.map((b) => ({ name: b.name, from: b.keptBy?.name ?? null })), sa.name);
    if (!(await confirmAsync(q.title, q.body, handLabel))) return;
    void run(async () => {
      // One Bot keeps to the route servers from before ADR 0324 have too.
      if (picked.length === 1) await api.keepBot(picked[0].id, sa.id);
      else await api.keepBots(sa.id, picked.map((b) => b.id));
      setHanding([]);
      await refresh();
    });
  };

  const takeBack = async (bot: { id: string; name: string }) => {
    const q = keeperQuestion(bot.name, null, sa.name);
    if (!(await confirmAsync(q.title, q.body, "Take it back"))) return;
    void run(async () => {
      await api.releaseKeptBot(bot.id);
      await refresh();
    });
  };

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
      {!sa.ownerActive ? <Text style={styles.warn}>Its owner is disabled or gone, so its tokens are refused. {admin ? "Give it an active owner below." : "Ask an admin to give it another owner."}</Text> : null}
      {sa.ownerActive && sa.team && sa.ownerOnTeam === false ? (
        <Text style={styles.warn}>Its owner isn&apos;t on {sa.team.name}, so it acts in no team: it doesn&apos;t see the team or the Bots shared with it until they are.</Text>
      ) : null}
      {!active ? <Text style={styles.warn}>Disabled: its tokens don&apos;t work. {manage ? "Enable it to use or make tokens." : "Ask an admin to enable it again."}</Text> : null}
      {!manage ? <Text style={styles.faint}>You own it, so it acts with your access. You can revoke its tokens or disable it; an admin makes tokens and changes it.</Text> : null}

      <Section title="Can use today">
        <Tags names={sa.effective} empty="Nothing" />
        {sa.team ? <Text style={styles.faint}>In {sa.team.name}: {sa.teamPermissions.length ? sa.teamPermissions.join(", ") : "no team permissions"}.</Text> : null}
      </Section>

      {full && (keptBots.length || keepable.length) ? (
        <Section title={`Bots it keeps (${keptBots.length} of ${view.maxKeptBots ?? 20})`}>
          {keptBots.map((b) => (
            <View key={b.id} style={styles.item}>
              <Text style={styles.itemText} numberOfLines={1}>
                {b.name}
              </Text>
              <Button label="Take back" a11y={`Take ${b.name} back`} disabled={busy} onPress={() => void takeBack(b)} />
            </View>
          ))}
          {!keptBots.length ? <Text style={styles.dim}>None yet.</Text> : null}
          {keptBots.length ? <Text style={styles.faint}>They stay {sa.owner?.name || "its owner"}&apos;s: taking one back, deleting the account or changing its owner leaves them with the owner.</Text> : null}
          {keepable.length && left ? (
            <>
              <Text style={styles.dim}>
                Hand it {left > 1 ? `up to ${left}` : "one"} of {sa.owner?.name || "its owner"}&apos;s Bots to manage:
              </Text>
              {keepable.map((b) => {
                const ids = picked.map((p) => p.id);
                const on = ids.includes(b.id);
                const off = busy || (!on && ids.length >= left);
                return (
                  <Pressable
                    key={b.id}
                    style={styles.perm}
                    disabled={off}
                    onPress={() => setHanding(on ? ids.filter((id) => id !== b.id) : [...ids, b.id])}
                    accessibilityRole="checkbox"
                    accessibilityState={{ checked: on, disabled: off }}
                    accessibilityLabel={`Hand over ${b.name}`}
                  >
                    <Text style={[styles.check, on && styles.checkOn]}>{on ? "✓" : ""}</Text>
                    <Text style={styles.text}>{b.keptBy ? `${b.name} (from ${b.keptBy.name})` : b.name}</Text>
                  </Pressable>
                );
              })}
              <View style={styles.row}>
                <Button label={handLabel} primary disabled={busy || !picked.length} onPress={() => void handOver()} />
              </View>
            </>
          ) : null}
        </Section>
      ) : null}

      <Section title={`Tokens${tokens ? ` (${sa.tokens} live)` : ""}`}>
        {tokens == null ? (
          <Spinner />
        ) : tokens.length ? (
          tokens.map((t) => (
            <View key={t.id} style={styles.token}>
              <View style={styles.row}>
                <Text style={styles.itemText} numberOfLines={1}>
                  {t.name} <Text style={styles.mono}>{t.preview}</Text>
                </Text>
                {canRotate(t) && manage ? (
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

      {active && manage ? (
        <Section title="New token">
          <TextInput
            style={styles.input}
            value={tokenName}
            onChangeText={setTokenName}
            placeholder="Token name (optional), e.g. CI"
            placeholderTextColor={t.c.textFaint}
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

      {manage ? (
        <Section title="Settings">
          <AccountForm draft={draft} setDraft={setDraft} choices={choices} kept={kept} busy={busy} editing admin={admin} />
          <View style={styles.row}>
            <Button label="Save" primary disabled={busy || !!invalid || !changes} onPress={() => void save()} />
            {invalid ? <Text style={styles.faint}>{invalid}</Text> : null}
          </View>
        </Section>
      ) : null}

      <View style={styles.row}>
        {active ? <Button label="Disable" disabled={busy} onPress={() => void setStatus("disabled")} /> : manage ? <Button label="Enable" primary disabled={busy} onPress={() => void setStatus("active")} /> : null}
        {manage ? <Button label="Delete" danger disabled={busy} onPress={() => void remove()} /> : null}
      </View>
    </View>
  );
}

/**
 * Service accounts (ADR 0143, 0152): make them, give them a role, and issue, rotate and revoke
 * their tokens. Admins see every one; a delegate sees and manages the ones they own (ADR 0182);
 * any other owner sees theirs, revokes their tokens and disables them (ADR 0239).
 */
export function ServiceAccountsAdmin({ api, onBack, admin }: Props) {
  const styles = useStyles();
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
  }, [load]);

  // Only a server from before ADR 0182 sends no choices; then an admin reads every role and team.
  const needLists = admin && !!view && !view.choices;
  useEffect(() => {
    if (!needLists) return;
    api.roles().then((r) => setRoles(r.roles), () => setRoles([]));
    api.teams().then(setTeams, () => setTeams([]));
  }, [api, needLists]);

  const choices = view ? formChoices(view, roles, teams) : null;
  const own = !admin || view?.view === "own";
  const manage = view?.manage !== false;

  const pick = (p: Picked) => {
    if (busy) return;
    setPicked(p);
    setMinted(null);
    setNotice(null);
  };

  const account = picked?.kind === "account" ? view?.serviceAccounts.find((s) => s.id === picked.id) : undefined;
  const detail = !view || !choices ? null : account ? (
    <AccountDetail
      key={account.id}
      api={api}
      view={view}
      account={account}
      choices={choices}
      admin={admin}
      manage={manage}
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
  ) : picked?.kind === "new" && manage ? (
    <NewAccount
      api={api}
      view={view}
      choices={choices}
      admin={admin}
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
      <PageHeader
        title={own ? "Your service accounts" : "Service accounts"}
        onBack={onBack}
        backDisabled={busy}
        right={manage ? <Button label="New service account" primary disabled={!view || busy} onPress={() => pick({ kind: "new" })} /> : null}
      />
      <View style={styles.body}>
        <View style={wide ? styles.listPaneWide : styles.listPane}>
          {error ? <Text style={styles.error}>{error}</Text> : null}
          {!view && !error ? <Spinner style={styles.spinner} /> : null}
          {view ? (
            <ScrollView contentContainerStyle={styles.list}>
              <View style={styles.listCard}>
                {view.serviceAccounts.map((s, i) => (
                  <Pressable
                    key={s.id}
                    style={({ pressed }) => [styles.listRow, i === 0 && styles.listRowFirst, pressed && styles.pressed, picked?.kind === "account" && picked.id === s.id && styles.selected]}
                    onPress={() => pick({ kind: "account", id: s.id })}
                    disabled={busy}
                    accessibilityState={{ disabled: busy }}
                    accessibilityRole="button"
                    accessibilityLabel={`Service account ${s.name}`}
                  >
                    <Text style={styles.rowName}>
                      {s.name}
                      {s.status === "disabled" ? <Text style={styles.warn}> · disabled</Text> : null}
                      {!s.ownerActive ? <Text style={styles.warn}> · owner inactive</Text> : null}
                      {s.ownerActive && s.ownerOnTeam === false ? <Text style={styles.warn}> · owner off its team</Text> : null}
                    </Text>
                    <Text style={styles.faint}>
                      {roleLabel(s)} · {s.tokens} live {s.tokens === 1 ? "token" : "tokens"}
                      {s.keptBots ? ` · keeps ${s.keptBots} ${s.keptBots === 1 ? "Bot" : "Bots"}` : ""} · {lastUsedLabel(s.lastUsedAt).toLowerCase()}
                    </Text>
                  </Pressable>
                ))}
                {!view.serviceAccounts.length ? (
                  <Text style={styles.empty}>
                    {!manage ? "You own no service accounts." : own ? "You own no service accounts yet. Make one for each script or integration of yours that calls the API." : "No service accounts yet. Make one for each script or integration that calls the API."}
                  </Text>
                ) : null}
              </View>
            </ScrollView>
          ) : null}
        </View>
        {wide ? (
          <ScrollView style={styles.detailPane} contentContainerStyle={styles.detailBody}>
            {detail ?? <Text style={styles.empty}>{manage ? "Pick a service account to see its tokens, or make a new one." : "Pick a service account to see its tokens and what it can use."}</Text>}
          </ScrollView>
        ) : null}
      </View>
      {!wide ? (
        <Modal visible={!!detail} animationType="slide" onRequestClose={() => pick(null)}>
          <View style={styles.modalRoot}>
            <Pressable style={styles.modalHeader} onPress={() => pick(null)} accessibilityRole="button">
              <Text style={styles.back}>‹ Service accounts</Text>
            </Pressable>
            <ScrollView contentContainerStyle={styles.modalBody}>{detail}</ScrollView>
          </View>
        </Modal>
      ) : null}
    </View>
  );
}

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    root: k.root,
    back: k.backText,
    body: { flex: 1, flexDirection: "row" },
    listPane: { flex: 1, padding: t.space.md },
    listPaneWide: { width: 400, padding: t.space.md, backgroundColor: t.c.surface, borderRightWidth: hairline, borderRightColor: t.c.border },
    list: { gap: t.space.md, paddingBottom: t.space.xl },
    spinner: { marginTop: t.space.xl },
    listCard: { ...k.card, padding: 0, gap: 0, overflow: "hidden" },
    listRow: { paddingVertical: t.space.md, paddingHorizontal: t.space.lg, gap: t.space.xxs, borderTopWidth: hairline, borderTopColor: t.c.border },
    listRowFirst: { borderTopWidth: 0 },
    rowName: { ...k.text, fontWeight: t.font.weight.medium },
    pressed: k.btnPressed,
    selected: { backgroundColor: t.c.selected },
    detailPane: { flex: 1 },
    detailBody: { padding: t.space.xl, width: "100%", maxWidth: 760, alignSelf: "center" },
    wrap: { gap: t.space.lg },
    name: { color: t.c.text, ...type(t, "xl"), fontWeight: t.font.weight.semibold },
    text: k.text,
    dim: k.dim,
    faint: k.faint,
    mono: { ...k.mono, color: t.c.textMuted },
    warn: k.warn,
    error: k.error,
    empty: k.empty,
    section: k.card,
    sectionTitle: k.cardTitle,
    subsection: k.field,
    subsectionTitle: k.label,
    row: k.actions,
    item: { ...k.row, flexWrap: "wrap" },
    itemText: { ...k.text, flex: 1 },
    token: { gap: t.space.xs, paddingTop: t.space.md, borderTopWidth: hairline, borderTopColor: t.c.border },
    rotate: { ...k.inset, marginTop: t.space.xs },
    reveal: { ...k.noticeWarn, gap: t.space.md },
    secret: { ...k.mono, backgroundColor: t.c.raised, borderRadius: t.radius.sm, padding: t.space.md },
    perm: { flexDirection: "row", gap: t.space.md, alignItems: "center", paddingVertical: t.space.xs },
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
    input: k.input,
    multiline: k.inputMultiline,
    btn: { ...k.btn, alignSelf: "flex-start" },
    btnText: k.btnText,
    primaryBtn: k.primary,
    primaryText: k.primaryText,
    dangerBtn: k.danger,
    dangerText: k.dangerText,
    disabled: k.disabled,
    modalRoot: { flex: 1, backgroundColor: t.c.bg, paddingTop: t.space.xxl },
    modalHeader: { ...k.header, minHeight: 0 },
    modalBody: { padding: t.space.lg, paddingBottom: t.space.xxxl },
  });
});
