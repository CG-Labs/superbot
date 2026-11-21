import React, { useCallback, useEffect, useState } from "react";
import { ActivityIndicator, Pressable, StyleSheet, Text, TextInput, View } from "react-native";
import type { SuperBotApi } from "../src/api";
import { FORMAT_LABELS, MAX_DELAY_SECONDS, MAX_THROTTLE_SECONDS, parseRecipients, parseSeconds, secondsLabel, testSummary, webhookUrlProblem } from "../src/notifications";
import { colors } from "../src/theme";
import type { BotNotificationsPatch, BotNotificationsView, NotificationsPatch, NotificationsView, NotifyDetail, NotifyFormat } from "../src/types";
import { Chips } from "./Chips";

export type NotificationsApi = Pick<SuperBotApi, "notifications" | "patchNotifications" | "testNotifications" | "botNotifications" | "patchBotNotifications">;

interface Props {
  api: NotificationsApi;
  /** Set for one Bot's settings; otherwise the global ones. */
  bot?: { id: string; name: string };
}

type Inherit = "inherit";
const onOff = (on: boolean) => (on ? "On" : "Off");
const FORMATS: NotifyFormat[] = ["slack", "json"];
const ON_OFF = [
  { value: "on", label: "On" },
  { value: "off", label: "Off" },
] as const;

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/**
 * Who hears about a pending approval when no app is open (ADR 0061): email through the
 * server's SMTP settings and a webhook (Slack-compatible or signed JSON). Admins only.
 */
export function NotificationsCard({ api, bot }: Props) {
  const botId = bot?.id;
  const [view, setView] = useState<NotificationsView | undefined>(undefined);
  const [botView, setBotView] = useState<BotNotificationsView | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [to, setTo] = useState("");
  const [url, setUrl] = useState("");
  const [delay, setDelay] = useState("");
  const [throttle, setThrottle] = useState("");

  const load = useCallback(async () => {
    try {
      const [v, b] = await Promise.all([api.notifications(), botId ? api.botNotifications(botId) : Promise.resolve(undefined)]);
      setView(v);
      setBotView(b);
      setTo(v.settings.email.to.join(", "));
      setDelay(String(v.settings.delaySeconds));
      setThrottle(String(v.settings.throttleSeconds));
      setError(null);
    } catch (e) {
      setError(message(e));
    }
  }, [api, botId]);

  useEffect(() => {
    void load();
  }, [load]);

  const run = async (key: string, done: string | null, fn: () => Promise<string | void>) => {
    setBusy(key);
    setError(null);
    setNotice(null);
    try {
      const said = await fn();
      setNotice(said || done);
    } catch (e) {
      setError(message(e));
    } finally {
      setBusy(null);
    }
  };

  const patch = (key: string, done: string, p: NotificationsPatch) =>
    run(key, done, async () => {
      setView(await api.patchNotifications(p));
      if (botId) setBotView(await api.botNotifications(botId));
    });

  const patchBot = (key: string, done: string, p: BotNotificationsPatch) =>
    run(key, done, async () => {
      if (botId) setBotView(await api.patchBotNotifications(botId, p));
    });

  const test = () => run("test", null, async () => testSummary(await api.testNotifications(botId)));

  if (!view || (bot && !botView)) {
    return (
      <View style={styles.card} accessibilityLabel="Notifications">
        <Text style={styles.cardTitle}>Notifications</Text>
        {error ? <Text style={styles.error}>{error}</Text> : <ActivityIndicator color={colors.textDim} />}
      </View>
    );
  }

  const s = view.settings;
  const locked = !!busy;
  const smtp = view.email;
  const status = (
    <>
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
    </>
  );
  const urlProblem = url.trim() ? webhookUrlProblem(url) : null;
  const urlEditor = (hook: { set: boolean; host: string | null; writable: boolean }, save: (u: string | null) => void, label: string) => (
    <>
      <Text style={styles.dim}>{hook.set ? `URL set (${hook.host ?? "unknown host"}). It's kept as a secret and never shown again.` : "No URL yet."}</Text>
      {hook.writable ? (
        <>
          <TextInput
            style={[styles.input, styles.mono]}
            placeholder={hook.set ? "Replace the URL" : "https://hooks.slack.com/services/…"}
            placeholderTextColor={colors.textFaint}
            value={url}
            onChangeText={setUrl}
            autoCapitalize="none"
            autoCorrect={false}
            editable={!busy}
            accessibilityLabel={label}
          />
          {urlProblem ? <Text style={styles.warn}>{urlProblem}</Text> : null}
          <View style={styles.row}>
            <Pressable
              style={[styles.primaryBtn, (locked || !url.trim() || !!urlProblem) && styles.busy]}
              disabled={locked || !url.trim() || !!urlProblem}
              onPress={() => save(url.trim())}
              accessibilityRole="button"
              accessibilityLabel="Save webhook URL"
            >
              <Text style={styles.primaryText}>{busy === "url" ? "Saving…" : "Save URL"}</Text>
            </Pressable>
            {hook.set ? (
              <Pressable style={[styles.btn, locked && styles.busy]} disabled={locked} onPress={() => save(null)} accessibilityRole="button" accessibilityLabel="Remove webhook URL">
                <Text style={styles.dangerText}>Remove URL</Text>
              </Pressable>
            ) : null}
          </View>
        </>
      ) : (
        <Text style={styles.faint}>The server's environment sets this URL, so it changes there.</Text>
      )}
    </>
  );
  const testButton = (
    <Pressable style={[styles.btn, styles.self, locked && styles.busy]} disabled={locked} onPress={() => void test()} accessibilityRole="button" accessibilityLabel="Send a test notification">
      <Text style={styles.btnText}>{busy === "test" ? "Sending…" : "Send a test"}</Text>
    </Pressable>
  );

  if (bot && botView) {
    const o = botView.override;
    const g = botView.global;
    const emailOptions = [
      { value: "inherit" as const, label: `Default (${onOff(g.email)})` },
      { value: "on" as const, label: "On" },
      { value: "off" as const, label: "Off" },
    ];
    const hookOptions = [
      { value: "inherit" as const, label: botView.webhook.set ? "Default (its URL: On)" : `Default (${onOff(g.webhook)})` },
      { value: "on" as const, label: "On" },
      { value: "off" as const, label: "Off" },
    ];
    const formatOptions = [{ value: "inherit" as const, label: `Default (${FORMAT_LABELS[g.format]})` }, ...FORMATS.map((f) => ({ value: f, label: FORMAT_LABELS[f] }))];
    const choice = (v: boolean | undefined) => (v === undefined ? "inherit" : v ? "on" : "off");
    const toFlag = (v: "on" | "off" | Inherit) => (v === "inherit" ? null : v === "on");
    const r = botView.reaches;
    const reach = [r.email ? `email to ${r.email} address${r.email === 1 ? "" : "es"}` : null, r.webhook ? `the ${r.webhook === "own" ? "Bot's own" : "global"} webhook` : null].filter(Boolean);
    const noEmail = r.deciders.filter((d) => !d.hasEmail).map((d) => d.name);
    return (
      <View style={styles.card} accessibilityLabel="Notifications">
        <Text style={styles.cardTitle}>Notifications for {bot.name}</Text>
        <Text style={styles.dim}>{reach.length ? `Its next approval goes to ${reach.join(" and ")}.` : "Its approvals notify nobody: they wait in the app."}</Text>
        {r.deciders.length ? <Text style={styles.faint}>People who can answer: {r.deciders.map((d) => d.name).join(", ")}.</Text> : null}
        {noEmail.length && s.email.deciders ? <Text style={styles.faint}>No email address for {noEmail.join(", ")}.</Text> : null}
        {status}
        <View style={styles.field} accessibilityLabel="Email for this Bot">
          <Text style={styles.label}>Email</Text>
          <Chips
            options={emailOptions}
            value={choice(o.email)}
            onChange={(v) => void patchBot("email", v === "inherit" ? "Email follows the default." : `Email ${v}.`, { email: toFlag(v) })}
            disabled={locked || (!smtp.configured && o.email === undefined)}
          />
        </View>
        <View style={styles.field} accessibilityLabel="Webhook for this Bot">
          <Text style={styles.label}>Webhook</Text>
          <Chips
            options={hookOptions}
            value={choice(o.webhook)}
            onChange={(v) => void patchBot("webhook", v === "inherit" ? "Webhook follows the default." : `Webhook ${v}.`, { webhook: toFlag(v) })}
            disabled={locked}
          />
          {urlEditor(
            botView.webhook,
            (u) =>
              void patchBot("url", u ? "Its own webhook URL is saved." : "Its own webhook URL is removed.", { webhookUrl: u }).then(() => setUrl("")),
            "Webhook URL for this Bot",
          )}
          <Chips
            options={formatOptions}
            value={o.format ?? "inherit"}
            onChange={(f) => void patchBot("format", "Format saved.", { format: f === "inherit" ? null : f })}
            disabled={locked}
          />
        </View>
        {testButton}
      </View>
    );
  }

  const parsedTo = parseRecipients(to);
  const toChanged = "to" in parsedTo && parsedTo.to.join(",") !== s.email.to.join(",");
  const d = parseSeconds(delay, MAX_DELAY_SECONDS);
  const t = parseSeconds(throttle, MAX_THROTTLE_SECONDS);
  const timingChanged = "seconds" in d && "seconds" in t && (d.seconds !== s.delaySeconds || t.seconds !== s.throttleSeconds);

  return (
    <View style={styles.card} accessibilityLabel="Notifications">
      <Text style={styles.cardTitle}>Notifications</Text>
      <Text style={styles.dim}>
        When a Bot waits for approval, tell someone who can answer, even with no app open. Each notice links to the approval and shows what its card shows.
      </Text>
      {view.links.problem ? <Text style={styles.warn}>{view.links.problem}</Text> : null}
      {status}

      <View style={styles.field} accessibilityLabel="Email">
        <Text style={styles.label}>Email</Text>
        <Text style={styles.faint}>
          {smtp.configured ? `Sent through ${smtp.server}.` : "Not set up: set SMTP_HOST and SMTP_FROM on the server (see the deploy guide), then restart it."}
        </Text>
        <Chips
          options={ON_OFF}
          value={s.email.enabled ? "on" : "off"}
          onChange={(v) => void patch("email", `Email ${v}.`, { email: { enabled: v === "on" } })}
          disabled={locked || (!smtp.configured && !s.email.enabled)}
        />
        <TextInput
          style={styles.input}
          placeholder="ops@example.com, oncall@example.com"
          placeholderTextColor={colors.textFaint}
          value={to}
          onChangeText={setTo}
          autoCapitalize="none"
          autoCorrect={false}
          keyboardType="email-address"
          editable={!busy}
          accessibilityLabel="Email addresses"
        />
        {"problem" in parsedTo ? <Text style={styles.warn}>{parsedTo.problem}</Text> : null}
        <View style={styles.row}>
          <Pressable
            style={[styles.primaryBtn, (locked || !toChanged) && styles.busy]}
            disabled={locked || !toChanged}
            onPress={() => "to" in parsedTo && void patch("to", "Addresses saved.", { email: { to: parsedTo.to } })}
            accessibilityRole="button"
            accessibilityLabel="Save email addresses"
          >
            <Text style={styles.primaryText}>{busy === "to" ? "Saving…" : "Save addresses"}</Text>
          </Pressable>
        </View>
        <Chips
          options={[
            { value: "on", label: "Also each Bot's owner and operators" },
            { value: "off", label: "Only these addresses" },
          ]}
          value={s.email.deciders ? "on" : "off"}
          onChange={(v) =>
            void patch("deciders", v === "on" ? "Owners and operators get email too." : "Only the listed addresses get email.", { email: { deciders: v === "on" } })
          }
          disabled={locked}
        />
      </View>

      <View style={styles.field} accessibilityLabel="Webhook">
        <Text style={styles.label}>Webhook</Text>
        <Chips
          options={ON_OFF}
          value={s.webhook.enabled ? "on" : "off"}
          onChange={(v) => void patch("webhook", `Webhook ${v}.`, { webhook: { enabled: v === "on" } })}
          disabled={locked || (!view.webhook.set && !s.webhook.enabled)}
        />
        {urlEditor(view.webhook, (u) => void patch("url", u ? "Webhook URL saved." : "Webhook URL removed.", { webhook: { url: u } }).then(() => setUrl("")), "Webhook URL")}
        <Chips
          options={FORMATS.map((f) => ({ value: f, label: FORMAT_LABELS[f] }))}
          value={s.webhook.format}
          onChange={(f) => void patch("format", "Format saved.", { webhook: { format: f } })}
          disabled={locked}
        />
        {s.webhook.format === "json" && !view.signing ? <Text style={styles.faint}>Set NOTIFY_WEBHOOK_SECRET to sign JSON posts.</Text> : null}
      </View>

      <View style={styles.field} accessibilityLabel="Timing">
        <Text style={styles.label}>Timing</Text>
        <Text style={styles.faint}>
          Wait {secondsLabel(s.delaySeconds)} first, so approvals answered in the app send nothing. After a notice, a Bot's next approvals wait{" "}
          {secondsLabel(s.throttleSeconds)} and go as one digest.
        </Text>
        <View style={styles.row}>
          <Text style={styles.dim}>Wait</Text>
          <TextInput style={[styles.input, styles.seconds]} value={delay} onChangeText={setDelay} keyboardType="number-pad" editable={!busy} accessibilityLabel="Seconds to wait" />
          <Text style={styles.dim}>s, digest every</Text>
          <TextInput
            style={[styles.input, styles.seconds]}
            value={throttle}
            onChangeText={setThrottle}
            keyboardType="number-pad"
            editable={!busy}
            accessibilityLabel="Seconds between notices"
          />
          <Text style={styles.dim}>s</Text>
          <Pressable
            style={[styles.primaryBtn, (locked || !timingChanged) && styles.busy]}
            disabled={locked || !timingChanged}
            onPress={() => "seconds" in d && "seconds" in t && void patch("timing", "Timing saved.", { delaySeconds: d.seconds, throttleSeconds: t.seconds })}
            accessibilityRole="button"
            accessibilityLabel="Save timing"
          >
            <Text style={styles.primaryText}>{busy === "timing" ? "Saving…" : "Save"}</Text>
          </Pressable>
        </View>
        {"problem" in d ? <Text style={styles.warn}>{d.problem}</Text> : "problem" in t ? <Text style={styles.warn}>{t.problem}</Text> : null}
        <Chips
          options={[
            { value: "summary" as NotifyDetail, label: "Show the command (cut short)" },
            { value: "minimal" as NotifyDetail, label: "Only the Bot and the risk" },
          ]}
          value={s.detail}
          onChange={(v) => void patch("detail", "Saved.", { detail: v })}
          disabled={locked}
        />
      </View>
      {testButton}
    </View>
  );
}

const styles = StyleSheet.create({
  card: { backgroundColor: colors.bgSidebar, borderRadius: 14, padding: 16, gap: 10, borderWidth: 1, borderColor: colors.border },
  cardTitle: { color: colors.text, fontSize: 17, fontWeight: "600" },
  field: { gap: 8, paddingTop: 8, borderTopWidth: 1, borderTopColor: colors.border },
  label: { color: colors.text, fontWeight: "500" },
  good: { color: colors.accent },
  error: { color: colors.danger },
  warn: { color: colors.warning },
  dim: { color: colors.textDim },
  faint: { color: colors.textFaint, fontSize: 13 },
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
  seconds: { width: 80 },
  row: { flexDirection: "row", alignItems: "center", flexWrap: "wrap", gap: 8 },
  self: { alignSelf: "flex-start" },
  btn: { borderRadius: 999, borderWidth: 1, borderColor: colors.border, paddingVertical: 8, paddingHorizontal: 16 },
  btnText: { color: colors.text, fontSize: 15 },
  dangerText: { color: colors.danger, fontSize: 15 },
  primaryBtn: { backgroundColor: "#f2f2f2", borderRadius: 999, paddingVertical: 8, paddingHorizontal: 16 },
  primaryText: { color: "#111", fontSize: 15 },
  busy: { opacity: 0.6 },
});
