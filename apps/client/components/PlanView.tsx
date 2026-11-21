import React, { useCallback, useEffect, useRef, useState } from "react";
import { ActivityIndicator, AppState, Pressable, ScrollView, StyleSheet, Switch, Text, View } from "react-native";
import type { SuperBotApi } from "../src/api";
import { BILLING_OFF, checkoutNotice, limitSummary, openBillingPage, subscriptionLine } from "../src/billing";
import { overLimits, planUsageLines, storageWarning, usageLines } from "../src/plan";
import { colors } from "../src/theme";
import type { BillingEmails, BillingView, MyUsage } from "../src/types";

/** After a successful checkout, how often and how many times to look for Stripe's confirmation. */
export const CONFIRM_EVERY_MS = 3000;
const CONFIRM_TRIES = 20;

interface Props {
  api: Pick<SuperBotApi, "billing" | "checkout" | "billingPortal" | "myUsage" | "billingEmails" | "setUsageEmails">;
  onBack: () => void;
  /** `?checkout=` from Stripe's return link. */
  checkout?: string | string[];
  /** Opens a Stripe page; `openBillingPage` unless a test swaps it. */
  open?: (url: string) => Promise<void>;
}

/** Your model tokens and runs this billing period (ADR 0050). */
function UsageCard({ usage, warn }: { usage: MyUsage; warn?: boolean }) {
  const warning = warn ? storageWarning(usage.storage) : null;
  return (
    <View style={styles.card} accessibilityLabel="Usage this period">
      <Text style={styles.cardTitle}>Usage this period</Text>
      {usageLines(usage).map((l) => (
        <Text key={l} style={styles.line}>
          {l}
        </Text>
      ))}
      {warning ? (
        <Text style={styles.warn} accessibilityRole="alert">
          {warning}
        </Text>
      ) : null}
    </View>
  );
}

/** Whether you get usage emails, while the server sends billing emails (ADR 0091). */
function EmailsCard({ emails, busy, onChange }: { emails: BillingEmails; busy: boolean; onChange: (usage: boolean) => void }) {
  return (
    <View style={styles.card}>
      <Text style={styles.cardTitle}>Emails</Text>
      <Text style={styles.dim}>We email you when your plan, its payments or your computer change.</Text>
      <View style={styles.row}>
        <Text style={[styles.line, styles.grow]}>Also email me near my token and storage limits</Text>
        <Switch value={emails.usage} disabled={emails.canChange === false || busy} onValueChange={onChange} accessibilityLabel="Usage emails" />
      </View>
    </View>
  );
}

/** Your plan, your use of it, and Stripe's pages to buy or manage one (ADR 0042). */
export function PlanView({ api, onBack, checkout, open = openBillingPage }: Props) {
  const [view, setView] = useState<BillingView | null | undefined>(undefined);
  const [usage, setUsage] = useState<MyUsage | null>(null);
  const [emails, setEmails] = useState<BillingEmails | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const notice = checkoutNotice(checkout);
  // Bumped by each email setting save: a refresh started before one doesn't undo it.
  const saves = useRef(0);

  const load = useCallback(async () => {
    const at = saves.current;
    try {
      // Usage and emails are extra: the plan still shows if they can't load.
      const [b, u, m] = await Promise.all([api.billing(), api.myUsage().catch(() => null), api.billingEmails().catch(() => null)]);
      setView(b);
      setUsage(u);
      if (saves.current === at) setEmails(m);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [api]);

  // Back from Stripe's page in the browser: the plan may have changed.
  useEffect(() => {
    void load();
    const sub = AppState.addEventListener("change", (s) => {
      if (s === "active") void load();
    });
    return () => sub.remove();
  }, [load]);

  // Stripe can send people back before its webhook reaches the server: keep looking for a minute.
  const waiting = notice?.good === true && view != null && !view.subscription;
  useEffect(() => {
    if (!waiting) return;
    let tries = 0;
    const timer = setInterval(() => {
      if (++tries >= CONFIRM_TRIES) clearInterval(timer);
      void load();
    }, CONFIRM_EVERY_MS);
    return () => clearInterval(timer);
  }, [waiting, load]);

  const setUsageEmails = async (usage: boolean) => {
    setBusy("emails");
    setError(null);
    saves.current += 1;
    try {
      setEmails(await api.setUsageEmails(usage));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  const go = async (key: string, start: () => Promise<{ url: string }>) => {
    setBusy(key);
    setError(null);
    try {
      await open((await start()).url);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  const header = (
    <View style={styles.header}>
      <Pressable onPress={onBack} accessibilityRole="button" accessibilityLabel="Back to Bots">
        <Text style={styles.back}>‹ Bots</Text>
      </Pressable>
      <Text style={styles.title}>Plan</Text>
    </View>
  );

  if (view === undefined && !error) {
    return (
      <View style={styles.root}>
        {header}
        <ActivityIndicator style={styles.loading} color={colors.textDim} />
      </View>
    );
  }
  const shownEmails = emails ?? view?.emails;
  const emailsCard = shownEmails?.on ? (
    <EmailsCard emails={{ ...shownEmails, canChange: shownEmails.canChange ?? view?.canChange }} busy={!!busy} onChange={(v) => void setUsageEmails(v)} />
  ) : null;

  if (view === null) {
    return (
      <View style={styles.root}>
        {header}
        <Text style={[styles.dim, styles.pad]} accessibilityRole="summary">
          {BILLING_OFF}
        </Text>
        {usage || emailsCard ? (
          <ScrollView contentContainerStyle={styles.body}>
            {error ? (
              <Text style={styles.error} accessibilityRole="alert">
                {error}
              </Text>
            ) : null}
            {usage ? <UsageCard usage={usage} warn /> : null}
            {emailsCard}
          </ScrollView>
        ) : null}
      </View>
    );
  }

  const plan = view?.plan;
  // Full storage gets its own note, which says how to free it.
  const over = plan ? overLimits(plan).filter((o) => o !== "storage") : [];
  const storageNote = storageWarning(plan?.usage.storage);
  const status = view ? subscriptionLine(view.subscription) : null;
  const team = view?.teamPlan;
  const subscribed = !!view?.subscription || !!team;
  const canChange = !!view?.canChange;

  return (
    <View style={styles.root}>
      {header}
      <ScrollView contentContainerStyle={styles.body}>
        {notice ? (
          <Text style={[styles.notice, notice.good ? styles.good : styles.dim]} accessibilityRole="alert">
            {notice.text}
          </Text>
        ) : null}
        {error ? (
          <Text style={styles.error} accessibilityRole="alert">
            {error}
          </Text>
        ) : null}
        {plan ? (
          <View style={styles.card}>
            <Text style={styles.cardTitle}>{plan.label} plan</Text>
            {team ? <Text style={styles.dim}>{`${team.name ?? "Your team"} pays for this plan for everyone on it.`}</Text> : status ? <Text style={styles.dim}>{status}</Text> : null}
            {planUsageLines(plan).map((l) => (
              <Text key={l} style={styles.line}>
                {l}
              </Text>
            ))}
            {over.length ? <Text style={styles.warn}>Over this plan's limit for {over.join(", ")}: new ones are refused until you upgrade.</Text> : null}
            {storageNote ? (
              <Text style={styles.warn} accessibilityRole="alert">
                {storageNote}
              </Text>
            ) : null}
            {view?.portal && canChange ? (
              <Pressable
                style={[styles.btn, busy && styles.busy]}
                disabled={!!busy}
                onPress={() => void go("portal", () => api.billingPortal())}
                accessibilityRole="link"
                accessibilityHint="Opens Stripe's billing page"
              >
                <Text style={styles.btnText}>{busy === "portal" ? "Opening…" : "Manage billing"}</Text>
              </Pressable>
            ) : null}
          </View>
        ) : null}
        {usage ? <UsageCard usage={usage} warn={!plan} /> : null}
        {emailsCard}
        {view?.plans.length ? <Text style={styles.section}>Plans</Text> : null}
        {view?.plans.map((p) => (
          <View key={p.name} style={[styles.card, p.current && styles.currentCard]}>
            <Text style={styles.cardTitle}>{p.label}</Text>
            {limitSummary(p.limits).map((l) => (
              <Text key={l} style={styles.line}>
                {l}
              </Text>
            ))}
            {p.current ? (
              <Text style={styles.tag}>Your plan</Text>
            ) : subscribed || !canChange ? null : (
              <Pressable
                style={[styles.primaryBtn, busy && styles.busy]}
                disabled={!!busy}
                onPress={() => void go(p.name, () => api.checkout(p.name))}
                accessibilityRole="link"
                accessibilityLabel={`Upgrade to ${p.label}`}
                accessibilityHint="Opens Stripe Checkout to pay"
              >
                <Text style={styles.primaryText}>{busy === p.name ? "Opening…" : `Upgrade to ${p.label}`}</Text>
              </Pressable>
            )}
          </View>
        ))}
        {subscribed || !canChange ? (
          <Text style={styles.dim}>
            {team
              ? "Your team's owners and admins change its plan on the Team screen."
              : view?.portal && canChange
                ? "To change or cancel your plan, use Manage billing."
                : "To change your plan, ask an admin."}
          </Text>
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
  notice: { fontSize: 15 },
  good: { color: colors.accent },
  error: { color: colors.danger },
  warn: { color: colors.warning },
  dim: { color: colors.textDim },
  section: { color: colors.textDim, fontSize: 13, textTransform: "uppercase", letterSpacing: 0.5, marginTop: 8 },
  card: { backgroundColor: colors.bgSidebar, borderRadius: 14, padding: 16, gap: 6, borderWidth: 1, borderColor: colors.border },
  currentCard: { borderColor: colors.blueDot },
  cardTitle: { color: colors.text, fontSize: 17, fontWeight: "600" },
  line: { color: colors.text, fontSize: 14 },
  tag: { color: colors.blueDot, fontSize: 14, marginTop: 6 },
  btn: { alignSelf: "flex-start", borderRadius: 999, borderWidth: 1, borderColor: colors.border, paddingVertical: 8, paddingHorizontal: 16, marginTop: 8 },
  btnText: { color: colors.text, fontSize: 15 },
  primaryBtn: { alignSelf: "flex-start", backgroundColor: "#f2f2f2", borderRadius: 999, paddingVertical: 8, paddingHorizontal: 16, marginTop: 8 },
  primaryText: { color: "#111", fontSize: 15 },
  busy: { opacity: 0.6 },
  row: { flexDirection: "row", alignItems: "center", gap: 12, marginTop: 4 },
  grow: { flex: 1 },
});
