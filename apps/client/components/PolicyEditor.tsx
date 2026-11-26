import React, { useCallback, useEffect, useState } from "react";
import { Pressable, ScrollView, StyleSheet, Text, TextInput, View } from "react-native";
import type { SuperBotApi } from "../src/api";
import { confirmAsync } from "../src/dialogs";
import { errorText, friendlyError } from "../src/errors";
import { ACTION_LABELS, ACTIONS, classChoice, minutesLabel, newRule, parseTimeout, ruleProblem, RULE_TOOLS, sortRules, toolLabel } from "../src/policy";
import { hairline, themedStyles } from "../src/theme";
import type { Policy, PolicyAction, PolicyMode, PolicyPatch, PolicyRule, PolicyView } from "../src/types";
import { Chips } from "./Chips";
import { EmptyState } from "./EmptyState";
import { ErrorState, InlineError } from "./ErrorState";
import { NotificationsCard, type NotificationsApi } from "./NotificationsCard";
import { PageSkeleton } from "./Skeleton";
import { kit, PageHeader, usePlaceholder } from "./ui";

interface Props {
  api: Pick<SuperBotApi, "policyView" | "patchGlobalPolicy" | "patchBotPolicy" | "resetBotPolicy" | "addPolicyRule" | "deletePolicyRule">;
  /** Set to edit one Bot's policy; otherwise the global one. */
  bot?: { id: string; name: string };
  /** Admins only: the server refuses everyone else's changes (ADR 0012). */
  canEdit: boolean;
  /** Notification settings (ADR 0061), shown to admins when given. */
  notifications?: NotificationsApi;
  onBack: () => void;
  /** Asks before risky changes; `confirmAsync` unless a test swaps it. */
  confirm?: (title: string, message: string, confirmLabel?: string) => Promise<boolean>;
}

type Inherit = "inherit";
const MODE_LABELS: Record<PolicyMode, string> = { ask: "Ask", bypass: "Bypass" };
const onOff = (on: boolean) => (on ? "On" : "Off");
const HARNESS_NAMES: Record<string, string> = { claude: "Claude Code", codex: "Codex", pi: "Pi", hermes: "Hermes Agent" };

/**
 * The approval policy (ADR 0007, 0049): the mode, an action per risky class, how long an
 * approval waits, and the allow/deny rules. Global, or one Bot's on top of it.
 */
export function PolicyEditor({ api, bot, canEdit, notifications, onBack, confirm = confirmAsync }: Props) {
  const styles = useStyles();
  const placeholder = usePlaceholder();
  const botId = bot?.id;
  const [view, setView] = useState<PolicyView | undefined>(undefined);
  /** The global policy under a Bot's, for the "Default (…)" choices. */
  const [global, setGlobal] = useState<Policy | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  /** The policy didn't load: alone it fills the screen, after a refresh it sits above what's already shown. */
  const [loadError, setLoadError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [timeout, setTimeoutText] = useState("");
  const [ruleAction, setRuleAction] = useState<"allow" | "deny">("deny");
  const [ruleTool, setRuleTool] = useState<string>("*");
  const [customTool, setCustomTool] = useState("");
  const [pattern, setPattern] = useState("");
  const [note, setNote] = useState("");

  const load = useCallback(async () => {
    try {
      const [v, g] = await Promise.all([api.policyView(botId), botId ? api.policyView() : Promise.resolve(undefined)]);
      setView(v);
      setGlobal(g?.policy ?? v.policy);
      setLoadError(null);
    } catch (e) {
      setLoadError(e);
    }
  }, [api, botId]);

  useEffect(() => {
    void load();
  }, [load]);

  const effectiveTimeout = view?.policy.timeoutMinutes;
  useEffect(() => {
    if (effectiveTimeout !== undefined) setTimeoutText(String(effectiveTimeout));
  }, [effectiveTimeout]);

  const run = async (key: string, done: string, fn: () => Promise<void>) => {
    setBusy(key);
    setError(null);
    setNotice(null);
    try {
      await fn();
      setNotice(done);
    } catch (e) {
      setError(friendlyError(e));
    } finally {
      setBusy(null);
    }
  };

  const patch = (key: string, done: string, p: PolicyPatch) =>
    run(key, done, async () => {
      if (botId) {
        setView(await api.patchBotPolicy(botId, p));
      } else {
        const policy = await api.patchGlobalPolicy(p);
        setView((v) => (v ? { ...v, policy } : v));
        setGlobal(policy);
      }
    });

  const header = <PageHeader title={bot ? `Approvals for ${bot.name}` : "Approval policy"} onBack={onBack} backText="‹ Back" backLabel="Back" />;

  if (!view) {
    return (
      <View style={styles.root}>
        {header}
        {loadError ? (
          <ErrorState title="Couldn't load the policy" message={friendlyError(loadError)} onRetry={load} />
        ) : (
          <PageSkeleton label="Loading the policy" />
        )}
      </View>
    );
  }

  const o = view.override ?? null;
  const g = global ?? view.policy;
  const locked = !canEdit || !!busy;

  const setMode = async (m: PolicyMode | Inherit) => {
    const next = m === "inherit" ? g.mode : m;
    if (next === "bypass" && view.policy.mode !== "bypass") {
      const who = bot ? bot.name : "every Bot";
      const ok = await confirm("Turn approvals off?", `Let ${who} run risky actions without asking? Use this only on a dev machine.`, "Bypass");
      if (!ok) return;
    }
    await patch("mode", m === "inherit" ? "Following the default mode." : `Mode set to ${MODE_LABELS[m]}.`, { mode: m === "inherit" ? null : m });
  };

  const setClass = (cls: string, label: string, a: PolicyAction | Inherit) =>
    patch(`class:${cls}`, a === "inherit" ? `${label}: following the default.` : `${label}: ${ACTION_LABELS[a]}.`, { classes: { [cls]: a === "inherit" ? null : a } });

  const setSandbox = async (v: "on" | "off" | Inherit) => {
    const next = v === "inherit" ? g.sandbox : v === "on";
    if (!next && view.policy.sandbox) {
      const who = bot ? bot.name : "every Bot";
      const ok = await confirm("Turn the sandbox off?", `Let ${who}'s commands write anywhere its harness can, outside its workspace?`, "Turn off");
      if (!ok) return;
    }
    await patch("sandbox", v === "inherit" ? "Following the default sandbox." : `Sandbox ${v}.`, { sandbox: v === "inherit" ? null : v === "on" });
  };

  const parsedTimeout = parseTimeout(timeout);
  // A Bot following the default may still save the same number, to keep it when the default changes.
  const timeoutChanged = "minutes" in parsedTimeout && (parsedTimeout.minutes !== view.policy.timeoutMinutes || (!!bot && o?.timeoutMinutes === undefined));

  const saveTimeout = () => {
    if (!("minutes" in parsedTimeout)) return;
    void patch("timeout", `Approvals now wait ${minutesLabel(parsedTimeout.minutes)}.`, { timeoutMinutes: parsedTimeout.minutes });
  };

  const tool = customTool.trim() || ruleTool;
  const draftProblem = pattern || note || customTool ? ruleProblem({ pattern, tool, note }) : null;

  const addRule = () =>
    run("rule:add", `${ACTION_LABELS[ruleAction]} rule added.`, async () => {
      await api.addPolicyRule(newRule(ruleAction, tool, pattern, note, botId));
      setPattern("");
      setNote("");
      setCustomTool("");
      await load();
    });

  const removeRule = async (r: PolicyRule) => {
    const scope = r.botId ? (bot ? `${bot.name} only` : "one Bot") : "every Bot";
    const ok = await confirm(`Delete this ${r.action} rule?`, `${r.pattern}\n\nIt applies to ${scope}. This can't be undone.`);
    if (!ok) return;
    await run(`rule:${r.id}`, "Rule deleted.", async () => {
      await api.deletePolicyRule(r.id);
      await load();
    });
  };

  const resetAll = async () => {
    if (!bot) return;
    const ok = await confirm(`Reset ${bot.name}?`, "It follows the default policy for all Bots again. Its rules stay.", "Reset");
    if (!ok) return;
    await run("reset", `${bot.name} follows the default policy again.`, async () => setView(await api.resetBotPolicy(bot.id)));
  };

  const modeOptions = [
    ...(bot ? [{ value: "inherit" as const, label: `Default (${MODE_LABELS[g.mode]})` }] : []),
    { value: "ask" as const, label: "Ask" },
    { value: "bypass" as const, label: "Bypass" },
  ];
  const sandboxOptions = [
    ...(bot ? [{ value: "inherit" as const, label: `Default (${onOff(g.sandbox)})` }] : []),
    { value: "on" as const, label: "On" },
    { value: "off" as const, label: "Off" },
  ];
  const sandboxValue = bot && o?.sandbox === undefined ? "inherit" : view.policy.sandbox ? "on" : "off";
  const support = view.sandbox;
  const cantStart = support ? support.harnesses.filter((h) => !support.available.includes(h)).map((h) => HARNESS_NAMES[h] ?? h) : [];
  const rules = sortRules(view.rules);

  return (
    <View style={styles.root}>
      {header}
      <ScrollView contentContainerStyle={styles.body} keyboardShouldPersistTaps="handled">
        <Text style={styles.dim}>
          {bot
            ? `Settings here are for ${bot.name} only. "Default" follows the policy for all Bots.`
            : "Risky tool calls pause for a person, are allowed, or are refused. Each Bot can change these for itself."}
        </Text>
        {!canEdit ? <Text style={styles.dim}>Only an admin can change the approval policy.</Text> : null}
        {notice ? (
          <Text style={styles.good} accessibilityRole="alert">
            {notice}
          </Text>
        ) : null}
        {loadError ? <InlineError message={errorText(loadError, "Couldn't refresh the policy")} onRetry={load} /> : null}
        {error ? <InlineError message={error} /> : null}

        <View style={styles.card}>
          <Text style={styles.cardTitle} role="heading">
            Mode
          </Text>
          <Chips options={modeOptions} value={bot && o?.mode === undefined ? "inherit" : view.policy.mode} onChange={(m) => void setMode(m)} disabled={locked} />
          {view.policy.mode === "bypass" ? <Text style={styles.warn}>Bypass: Bots run everything without asking, and the actions below don't apply. Dev only.</Text> : null}
        </View>

        <View style={styles.card} accessibilityLabel="Sandbox">
          <Text style={styles.cardTitle} role="heading">
            Sandbox
          </Text>
          <Text style={styles.dim}>
            The harness's own sandbox, on top of approvals: commands write only in the workspace, temp folders, the Bot's memory, and package caches. It
            holds in Bypass too.
            {support ? ` ${support.harnesses.map((h) => HARNESS_NAMES[h] ?? h).join(" and ")} have one; other harnesses run without.` : ""}
          </Text>
          <Chips options={sandboxOptions} value={sandboxValue} onChange={(v) => void setSandbox(v)} disabled={locked} />
          {view.policy.sandbox && cantStart.length ? (
            <Text style={styles.warn}>
              {cantStart.join(" and ")}'s sandbox can't start on this server, so those runs here go without. Install bubblewrap and socat (see docs/backend.md).
            </Text>
          ) : null}
        </View>

        <View style={styles.card}>
          <Text style={styles.cardTitle} role="heading">
            Risky actions
          </Text>
          {view.classes.map((c) => {
            const options = [
              ...(bot ? [{ value: "inherit" as const, label: `Default (${ACTION_LABELS[g.classes[c.id] ?? "ask"]})` }] : []),
              ...ACTIONS.map((a) => ({ value: a, label: ACTION_LABELS[a] })),
            ];
            const value = bot ? classChoice(o, c.id) : (view.policy.classes[c.id] ?? "ask");
            return (
              <View key={c.id} style={styles.classRow} accessibilityLabel={c.label}>
                <Text style={styles.label}>{c.label}</Text>
                <Chips options={options} value={value} onChange={(a) => void setClass(c.id, c.label, a)} disabled={locked} />
              </View>
            );
          })}
        </View>

        <View style={styles.card}>
          <Text style={styles.cardTitle} role="heading">
            Time to answer
          </Text>
          <Text style={styles.dim}>
            An approval nobody answers is denied after {minutesLabel(view.policy.timeoutMinutes)}
            {bot && o?.timeoutMinutes === undefined ? " (the default)" : ""}.
          </Text>
          {canEdit ? (
            <>
              <View style={styles.row}>
                <TextInput
                  style={[styles.input, styles.minutes]}
                  value={timeout}
                  onChangeText={setTimeoutText}
                  keyboardType="number-pad"
                  editable={!busy}
                  accessibilityLabel="Minutes to wait"
                />
                <Text style={styles.dim}>minutes</Text>
                <Pressable
                  style={[styles.primaryBtn, (!!busy || !timeoutChanged) && styles.busy]}
                  disabled={!!busy || !timeoutChanged}
                  onPress={saveTimeout}
                  accessibilityRole="button"
                  accessibilityLabel="Save time to answer"
                  aria-busy={busy === "timeout"}
                >
                  <Text style={styles.primaryText}>{busy === "timeout" ? "Saving…" : "Save"}</Text>
                </Pressable>
                {bot && o?.timeoutMinutes !== undefined ? (
                  <Pressable
                    style={[styles.btn, !!busy && styles.busy]}
                    disabled={!!busy}
                    onPress={() => void patch("timeout", "Following the default time to answer.", { timeoutMinutes: null })}
                    accessibilityRole="button"
                  >
                    <Text style={styles.btnText}>Use default ({minutesLabel(g.timeoutMinutes)})</Text>
                  </Pressable>
                ) : null}
              </View>
              {"problem" in parsedTimeout && timeout ? <Text style={styles.warn}>{parsedTimeout.problem}</Text> : null}
            </>
          ) : null}
        </View>

        {bot && o && canEdit ? (
          <Pressable style={[styles.btn, styles.self, !!busy && styles.busy]} disabled={!!busy} onPress={() => void resetAll()} accessibilityRole="button">
            <Text style={styles.btnText}>Reset {bot.name} to the default policy</Text>
          </Pressable>
        ) : null}

        <View style={styles.card}>
          <Text style={styles.cardTitle} role="heading">
            Rules
          </Text>
          <Text style={styles.dim}>
            Deny rules refuse a matching call, whatever else is set. Allow rules skip asking, but never override an action set to Deny. Patterns match the
            command, path, or address: * is any text, ? one character.
          </Text>
          {rules.length ? (
            rules.map((r) => (
              <View key={r.id} style={styles.rule}>
                <View style={styles.row}>
                  <Text style={[styles.tag, r.action === "deny" ? styles.denyTag : styles.allowTag]}>{ACTION_LABELS[r.action]}</Text>
                  <Text style={styles.dim}>{toolLabel(r.tool)}</Text>
                  <Text style={[styles.faint, styles.grow]}>{r.botId ? (bot ? "This Bot" : "One Bot") : "All Bots"}</Text>
                  {canEdit ? (
                    <Pressable
                      disabled={!!busy}
                      onPress={() => void removeRule(r)}
                      accessibilityRole="button"
                      accessibilityLabel={`Delete rule ${r.pattern}`}
                      aria-busy={busy === `rule:${r.id}`}
                    >
                      <Text style={styles.dangerText}>{busy === `rule:${r.id}` ? "Deleting…" : "Delete"}</Text>
                    </Pressable>
                  ) : null}
                </View>
                <Text style={styles.pattern} selectable numberOfLines={4}>
                  {r.pattern}
                </Text>
                {r.note ? <Text style={styles.faint}>{r.note}</Text> : null}
              </View>
            ))
          ) : (
            <EmptyState
              compact
              glyph="+"
              title="No rules yet"
              message={canEdit ? "Add one below to always allow or deny calls that match it." : "Risky calls follow the actions above."}
            />
          )}
        </View>

        {canEdit ? (
          <View style={styles.card}>
            <Text style={styles.cardTitle} role="heading">
              {bot ? `Add a rule for ${bot.name}` : "Add a rule for all Bots"}
            </Text>
            <View accessibilityLabel="Rule action">
              <Chips
                options={[
                  { value: "deny" as const, label: "Deny" },
                  { value: "allow" as const, label: "Allow" },
                ]}
                value={ruleAction}
                onChange={setRuleAction}
                disabled={!!busy}
              />
            </View>
            <View accessibilityLabel="Rule tool">
              <Chips options={RULE_TOOLS} value={customTool.trim() ? "" : ruleTool} onChange={setRuleTool} disabled={!!busy} />
            </View>
            <TextInput
              style={[styles.input, styles.mono]}
              placeholder="Or an exact tool name (optional)"
              placeholderTextColor={placeholder}
              value={customTool}
              onChangeText={setCustomTool}
              autoCapitalize="none"
              autoCorrect={false}
              editable={!busy}
              accessibilityLabel="Tool name"
            />
            <TextInput
              style={[styles.input, styles.mono]}
              placeholder="Pattern, like git push origin *"
              placeholderTextColor={placeholder}
              value={pattern}
              onChangeText={setPattern}
              autoCapitalize="none"
              autoCorrect={false}
              editable={!busy}
              accessibilityLabel="Rule pattern"
            />
            <TextInput
              style={styles.input}
              placeholder="Note (optional)"
              placeholderTextColor={placeholder}
              value={note}
              onChangeText={setNote}
              editable={!busy}
              accessibilityLabel="Rule note"
            />
            {draftProblem ? <Text style={styles.warn}>{draftProblem}</Text> : null}
            <View style={styles.row}>
              <Pressable
                style={[styles.primaryBtn, (!!busy || !pattern.trim() || !!draftProblem) && styles.busy]}
                disabled={!!busy || !pattern.trim() || !!draftProblem}
                onPress={() => void addRule()}
                accessibilityRole="button"
                accessibilityLabel="Add rule"
                aria-busy={busy === "rule:add"}
              >
                <Text style={styles.primaryText}>{busy === "rule:add" ? "Adding…" : "Add rule"}</Text>
              </Pressable>
            </View>
          </View>
        ) : null}

        {canEdit && notifications ? <NotificationsCard api={notifications} bot={bot} /> : null}
      </ScrollView>
    </View>
  );
}

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    root: k.root,
    body: k.body,
    good: k.good,
    warn: k.warn,
    dim: k.dim,
    faint: k.faint,
    grow: { flex: 1 },
    card: k.card,
    cardTitle: k.cardTitle,
    classRow: { gap: t.space.sm, paddingTop: t.space.md, borderTopWidth: hairline, borderTopColor: t.c.border },
    label: k.label,
    rule: { gap: t.space.xs, paddingTop: t.space.md, borderTopWidth: hairline, borderTopColor: t.c.border },
    pattern: { ...k.mono, backgroundColor: t.c.codeBg, borderRadius: t.radius.sm, padding: t.space.sm },
    tag: { ...k.tag, fontWeight: t.font.weight.semibold },
    allowTag: k.tagGood,
    denyTag: k.tagDanger,
    mono: { fontFamily: t.font.mono },
    input: k.input,
    minutes: { width: 90 },
    row: k.actions,
    self: { alignSelf: "flex-start" },
    btn: k.btn,
    btnText: k.btnText,
    dangerText: { ...k.btnText, ...k.dangerText },
    primaryBtn: { ...k.btn, ...k.primary },
    primaryText: { ...k.btnText, ...k.primaryText },
    busy: k.disabled,
  });
});
