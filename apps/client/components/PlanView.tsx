import React, { useCallback, useEffect, useState } from "react";
import { ActivityIndicator, AppState, Pressable, ScrollView, StyleSheet, Text, View } from "react-native";
import type { SuperBotApi } from "../src/api";
import { checkoutNotice, limitSummary, openBillingPage, subscriptionLine } from "../src/billing";
import { overLimits, planUsageLines } from "../src/plan";
import { colors } from "../src/theme";
import type { BillingView } from "../src/types";

interface Props {
  api: Pick<SuperBotApi, "billing" | "checkout" | "billingPortal">;
  onBack: () => void;
  /** `?checkout=` from Stripe's return link. */
  checkout?: string | string[];
  /** Opens a Stripe page; `openBillingPage` unless a test swaps it. */
  open?: (url: string) => Promise<void>;
}

/** Your plan, your use of it, and Stripe's pages to buy or manage one (ADR 0041). */
export function PlanView({ api, onBack, checkout, open = openBillingPage }: Props) {
  const [view, setView] = useState<BillingView | null | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const notice = checkoutNotice(checkout);

  const load = useCallback(async () => {
    try {
      setView(await api.billing());
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
  if (view === null) {
    return (
      <View style={styles.root}>
        {header}
        <Text style={[styles.dim, styles.pad]}>Billing isn't set up on this server.</Text>
      </View>
    );
  }

  const plan = view?.plan;
  const over = plan ? overLimits(plan) : [];
  const status = view ? subscriptionLine(view.subscription) : null;
  const subscribed = !!view?.subscription;
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
            {status ? <Text style={styles.dim}>{status}</Text> : null}
            {planUsageLines(plan).map((l) => (
              <Text key={l} style={styles.line}>
                {l}
              </Text>
            ))}
            {over.length ? <Text style={styles.warn}>Over this plan's limit for {over.join(", ")}: new ones are refused until you upgrade.</Text> : null}
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
          <Text style={styles.dim}>{view?.portal && canChange ? "To change or cancel your plan, use Manage billing." : "To change your plan, ask an admin."}</Text>
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
});
