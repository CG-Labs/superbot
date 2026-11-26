import React, { useCallback, useEffect, useState } from "react";
import { Pressable, StyleSheet, Text, TextInput, View } from "react-native";
import type { SuperBotApi } from "../src/api";
import { errorText, friendlyError } from "../src/errors";
import { FORMAT_LABELS, MAX_DELAY_SECONDS, MAX_THROTTLE_SECONDS, parseRecipients, parseSeconds, secondsLabel, testSummary, webhookUrlProblem } from "../src/notifications";
import { themedStyles } from "../src/theme";
import type { BotNotificationsPatch, BotNotificationsView, NotificationsPatch, NotificationsView, NotifyDetail, NotifyFormat } from "../src/types";
import { Chips } from "./Chips";
import { InlineError } from "./ErrorState";
import { ListSkeleton } from "./Skeleton";
import { kit, usePlaceholder } from "./ui";

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

/**
 * Who hears about a pending approval when no app is open (ADR 0061): email through the
 * server's SMTP settings and a webhook (Slack-compatible or signed JSON). Admins only.
 */
export function NotificationsCard({ api, bot }: Props) {
  const styles = useStyles();
  const placeholder = usePlaceholder();
  const botId = bot?.id;
  const [view, setView] = useState<NotificationsView | undefined>(undefined);
  const [botView, setBotView] = useState<BotNotificationsView | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
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
      setLoadError(null);
    } catch (e) {
      setLoadError(errorText(e, "Couldn't load notifications"));
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
      setError(friendlyError(e));
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
        <Text style={styles.cardTitle} role="heading">
          Notifications
        </Text>
        {loadError ? <InlineError message={loadError} onRetry={load} /> : <ListSkeleton label="Loading notifications" rows={2} />}
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
      {loadError ? <InlineError message={loadError} onRetry={load} /> : null}
      {error ? <InlineError message={error} /> : null}
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
            placeholderTextColor={placeholder}
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
              aria-busy={busy === "url"}
            >
              <Text style={styles.primaryText}>{busy === "url" ? "Saving…" : "Save URL"}</Text>
            </Pressable>
            {hook.set ? (
              <Pressable style={[styles.btn, styles.dangerBtn, locked && styles.busy]} disabled={locked} onPress={() => save(null)} accessibilityRole="button" accessibilityLabel="Remove webhook URL">
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
    <Pressable
      style={[styles.btn, styles.self, locked && styles.busy]}
      disabled={locked}
      onPress={() => void test()}
      accessibilityRole="button"
      accessibilityLabel="Send a test notification"
      aria-busy={busy === "test"}
    >
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
        <Text style={styles.cardTitle} role="heading">
          Notifications for {bot.name}
        </Text>
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
      <Text style={styles.cardTitle} role="heading">
        Notifications
      </Text>
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
          placeholderTextColor={placeholder}
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
            aria-busy={busy === "to"}
          >
            <Text style={styles.primaryText}>{busy === "to" ? "Saving…" : "Save addresses"}</Text>
          </Pressable>
        </View>
        <Chips
          options={[
            { value: "on", label: "Also the people who can answer" },
            { value: "off", label: "Only these addresses" },
          ]}
          value={s.email.deciders ? "on" : "off"}
          onChange={(v) =>
            void patch("deciders", v === "on" ? "Bot owners and operators, and team owners and admins for role requests, get email too." : "Only the listed addresses get email.", { email: { deciders: v === "on" } })
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
            aria-busy={busy === "timing"}
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

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    card: k.card,
    cardTitle: k.cardTitle,
    field: k.field,
    label: k.label,
    good: k.good,
    warn: k.warn,
    dim: k.dim,
    faint: k.faint,
    mono: { fontFamily: t.font.mono },
    input: k.input,
    seconds: { width: 80 },
    row: k.actions,
    self: { alignSelf: "flex-start" },
    btn: k.btn,
    btnText: k.btnText,
    dangerBtn: k.danger,
    dangerText: { ...k.btnText, ...k.dangerText },
    primaryBtn: { ...k.btn, ...k.primary },
    primaryText: { ...k.btnText, ...k.primaryText },
    busy: k.disabled,
  });
});
