import React, { useCallback, useEffect, useState } from "react";
import { ActivityIndicator, Pressable, ScrollView, StyleSheet, Text, TextInput, View } from "react-native";
import type { SuperBotApi } from "../src/api";
import { confirmAsync } from "../src/dialogs";
import { ACTION_LABELS, ACTIONS, classChoice, minutesLabel, newRule, parseTimeout, ruleProblem, RULE_TOOLS, sortRules, toolLabel } from "../src/policy";
import { colors } from "../src/theme";
import type { Policy, PolicyAction, PolicyMode, PolicyPatch, PolicyRule, PolicyView } from "../src/types";
import { Chips } from "./Chips";

interface Props {
  api: Pick<SuperBotApi, "policyView" | "patchGlobalPolicy" | "patchBotPolicy" | "resetBotPolicy" | "addPolicyRule" | "deletePolicyRule">;
  /** Set to edit one Bot's policy; otherwise the global one. */
  bot?: { id: string; name: string };
  /** Admins only: the server refuses everyone else's changes (ADR 0012). */
  canEdit: boolean;
  onBack: () => void;
  /** Asks before risky changes; `confirmAsync` unless a test swaps it. */
  confirm?: (title: string, message: string, confirmLabel?: string) => Promise<boolean>;
}

type Inherit = "inherit";
const MODE_LABELS: Record<PolicyMode, string> = { ask: "Ask", bypass: "Bypass" };

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/**
 * The approval policy (ADR 0007, 0049): the mode, an action per risky class, how long an
 * approval waits, and the allow/deny rules. Global, or one Bot's on top of it.
 */
export function PolicyEditor({ api, bot, canEdit, onBack, confirm = confirmAsync }: Props) {
  const botId = bot?.id;
  const [view, setView] = useState<PolicyView | undefined>(undefined);
  /** The global policy under a Bot's, for the "Default (…)" choices. */
  const [global, setGlobal] = useState<Policy | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
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
      setError(null);
    } catch (e) {
      setError(message(e));
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
      setError(message(e));
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

  const header = (
    <View style={styles.header}>
      <Pressable onPress={onBack} accessibilityRole="button" accessibilityLabel="Back">
        <Text style={styles.back}>‹ Back</Text>
      </Pressable>
      <Text style={styles.title} numberOfLines={1}>
        {bot ? `Approvals for ${bot.name}` : "Approval policy"}
      </Text>
    </View>
  );

  if (!view) {
    return (
      <View style={styles.root}>
        {header}
        {error ? (
          <Text style={[styles.error, styles.pad]} accessibilityRole="alert">
            {error}
          </Text>
        ) : (
          <ActivityIndicator style={styles.loading} color={colors.textDim} />
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

  const parsedTimeout = parseTimeout(timeout);
  const timeoutChanged = "minutes" in parsedTimeout && parsedTimeout.minutes !== view.policy.timeoutMinutes;

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
        {error ? (
          <Text style={styles.error} accessibilityRole="alert">
            {error}
          </Text>
        ) : null}

        <View style={styles.card}>
          <Text style={styles.cardTitle}>Mode</Text>
          <Chips options={modeOptions} value={bot && o?.mode === undefined ? "inherit" : view.policy.mode} onChange={(m) => void setMode(m)} disabled={locked} />
          {view.policy.mode === "bypass" ? <Text style={styles.warn}>Bypass: Bots run everything without asking, and the actions below don't apply. Dev only.</Text> : null}
        </View>

        <View style={styles.card}>
          <Text style={styles.cardTitle}>Risky actions</Text>
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
          <Text style={styles.cardTitle}>Time to answer</Text>
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
          <Text style={styles.cardTitle}>Rules</Text>
          <Text style={styles.dim}>
            Deny rules refuse a matching call, whatever else is set. Allow rules skip asking, but never override an action set to Deny. Patterns match the
            command, path, or address: * is any text, ? one character.
          </Text>
          {rules.length ? (
            rules.map((r) => (
              <View key={r.id} style={styles.rule}>
                <View style={styles.row}>
                  <Text style={r.action === "deny" ? styles.denyTag : styles.allowTag}>{ACTION_LABELS[r.action]}</Text>
                  <Text style={styles.dim}>{toolLabel(r.tool)}</Text>
                  <Text style={[styles.faint, styles.grow]}>{r.botId ? (bot ? "This Bot" : "One Bot") : "All Bots"}</Text>
                  {canEdit ? (
                    <Pressable
                      disabled={!!busy}
                      onPress={() => void removeRule(r)}
                      accessibilityRole="button"
                      accessibilityLabel={`Delete rule ${r.pattern}`}
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
            <Text style={styles.faint}>No rules yet.</Text>
          )}
        </View>

        {canEdit ? (
          <View style={styles.card}>
            <Text style={styles.cardTitle}>{bot ? `Add a rule for ${bot.name}` : "Add a rule for all Bots"}</Text>
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
              placeholderTextColor={colors.textFaint}
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
              placeholderTextColor={colors.textFaint}
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
              placeholderTextColor={colors.textFaint}
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
              >
                <Text style={styles.primaryText}>{busy === "rule:add" ? "Adding…" : "Add rule"}</Text>
              </Pressable>
            </View>
          </View>
        ) : null}
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.bgMain },
  header: { flexDirection: "row", alignItems: "center", gap: 16, padding: 16, borderBottomWidth: 1, borderBottomColor: colors.border },
  back: { color: colors.blueDot, fontSize: 16 },
  title: { color: colors.text, fontSize: 20, fontWeight: "600", flex: 1 },
  loading: { marginTop: 32 },
  pad: { padding: 16 },
  body: { padding: 16, gap: 12, maxWidth: 640, width: "100%", alignSelf: "center" },
  good: { color: colors.accent },
  error: { color: colors.danger },
  warn: { color: colors.warning },
  dim: { color: colors.textDim },
  faint: { color: colors.textFaint, fontSize: 13 },
  grow: { flex: 1 },
  card: { backgroundColor: colors.bgSidebar, borderRadius: 14, padding: 16, gap: 10, borderWidth: 1, borderColor: colors.border },
  cardTitle: { color: colors.text, fontSize: 17, fontWeight: "600" },
  classRow: { gap: 6, paddingVertical: 4 },
  label: { color: colors.text },
  rule: { gap: 4, paddingVertical: 8, borderTopWidth: 1, borderTopColor: colors.border },
  pattern: { color: colors.text, fontFamily: "monospace", fontSize: 13, backgroundColor: "#151515", borderRadius: 8, padding: 8 },
  allowTag: { color: colors.accent, fontWeight: "600" },
  denyTag: { color: colors.danger, fontWeight: "600" },
  mono: { fontFamily: "monospace" },
  input: {
    backgroundColor: colors.bgHover,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: colors.border,
    paddingHorizontal: 12,
    paddingVertical: 10,
    color: colors.text,
  },
  minutes: { width: 90 },
  row: { flexDirection: "row", alignItems: "center", flexWrap: "wrap", gap: 8 },
  self: { alignSelf: "flex-start" },
  btn: { borderRadius: 999, borderWidth: 1, borderColor: colors.border, paddingVertical: 8, paddingHorizontal: 16 },
  btnText: { color: colors.text, fontSize: 15 },
  dangerText: { color: colors.danger, fontSize: 15 },
  primaryBtn: { backgroundColor: "#f2f2f2", borderRadius: 999, paddingVertical: 8, paddingHorizontal: 16 },
  primaryText: { color: "#111", fontSize: 15 },
  busy: { opacity: 0.6 },
});
