import React, { useCallback, useEffect, useState } from "react";
import { ActivityIndicator, Pressable, ScrollView, StyleSheet, Text, TextInput, View } from "react-native";
import { botAccessLabel, csvFileName, flags, groupLabel, lastLoginLabel, machineLabel, signInsLabel } from "../src/accessReview";
import { ApiError, type SuperBotApi } from "../src/api";
import { saveCsv } from "../src/saveCsv";
import { colors } from "../src/theme";
import type { AccessReview as Report, AccessReviewPerson, AccessReviewSignOff } from "../src/types";

interface Props {
  api: SuperBotApi;
  onBack: () => void;
}

const MAX_NOTES = 500;

function Person({ p }: { p: AccessReviewPerson }) {
  const marks = flags(p);
  return (
    <View style={styles.person} accessibilityLabel={`Access of ${p.name}`}>
      <View style={styles.rowTop}>
        <Text style={styles.name} numberOfLines={1}>
          {p.name}
        </Text>
        <Text style={styles.dim}>{p.role}</Text>
        {p.team ? <Text style={styles.dim}>· team {p.team.role}</Text> : null}
      </View>
      {p.email ? <Text style={styles.faint}>{p.email}</Text> : null}
      {marks.length ? (
        <View style={styles.tags}>
          {marks.map((m) => (
            <Text key={m} style={styles.tag}>
              {m}
            </Text>
          ))}
        </View>
      ) : null}
      <Text style={styles.line}>Last sign-in: {lastLoginLabel(p)}</Text>
      <Text style={styles.line}>Second factor: {p.mfa.enabled ? "on" : "off"}</Text>
      <Text style={styles.line}>Bots: {botAccessLabel(p)}</Text>
      <Text style={styles.line}>Signed in: {signInsLabel(p)}</Text>
      <Text style={styles.line}>Machine: {machineLabel(p)}</Text>
    </View>
  );
}

function SignOff({ r }: { r: AccessReviewSignOff }) {
  const who = r.reviewer.name || r.reviewer.email || r.reviewer.id || "Unknown";
  return (
    <View style={styles.review}>
      <Text style={styles.line}>
        {new Date(r.at).toLocaleString()} · {who}
        {r.summary ? <Text style={styles.dim}> · {r.summary.people} people</Text> : null}
      </Text>
      {r.notes ? <Text style={styles.faint}>{r.notes}</Text> : null}
    </View>
  );
}

/** Who has access, for an admin to review and sign off (SOC 2 CC6.3, ADR 0099). The server refuses it to everyone else. */
export function AccessReview({ api, onBack }: Props) {
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notes, setNotes] = useState("");
  const [saving, setSaving] = useState(false);
  const [signError, setSignError] = useState<string | null>(null);
  const [signed, setSigned] = useState<AccessReviewSignOff | null>(null);
  const [exporting, setExporting] = useState(false);

  const load = useCallback(async () => {
    setError(null);
    setSignError(null);
    try {
      setReport(await api.accessReview());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Couldn't load the access review");
    }
  }, [api]);

  useEffect(() => {
    void load();
  }, [load]);

  const exportCsv = async () => {
    if (!report) return;
    setExporting(true);
    setError(null);
    try {
      const { csv, fileName } = await api.accessReviewCsv(report.digest);
      // The server builds the CSV from a fresh report, so name it by that report's time, not the one on screen.
      await saveCsv(fileName ?? csvFileName(Date.now()), csv, "Export access review");
    } catch (err) {
      const stale = err instanceof ApiError && err.status === 409;
      setError(stale ? "Access changed since this report loaded. Reload it before exporting." : err instanceof Error ? err.message : "Export failed");
    } finally {
      setExporting(false);
    }
  };

  const signOff = async () => {
    if (!report) return;
    setSaving(true);
    setSignError(null);
    try {
      const r = await api.completeAccessReview(report.digest, notes);
      setSigned(r);
      setNotes("");
      setReport({ ...report, reviews: [r, ...report.reviews] });
    } catch (err) {
      const stale = err instanceof ApiError && err.status === 409;
      setSignError(stale ? "Access changed since this report loaded. Reload it and review it again." : err instanceof Error ? err.message : "Couldn't sign off");
    } finally {
      setSaving(false);
    }
  };

  const s = report?.summary;
  return (
    <View style={styles.root}>
      <View style={styles.header}>
        <Pressable onPress={onBack} accessibilityRole="button" accessibilityLabel="Back to Bots">
          <Text style={styles.back}>‹ Bots</Text>
        </Pressable>
        <Text style={styles.title}>Access review</Text>
        <Pressable
          style={[styles.primaryBtn, (exporting || !report) && styles.busy]}
          onPress={() => void exportCsv()}
          disabled={exporting || !report}
          accessibilityRole="button"
          accessibilityState={{ disabled: exporting || !report, busy: exporting }}
        >
          <Text style={styles.primaryText}>{exporting ? "Exporting…" : "Export CSV"}</Text>
        </Pressable>
      </View>
      {error ? <Text style={styles.error}>{error}</Text> : null}
      {!report ? (
        error ? (
          <Pressable onPress={() => void load()} accessibilityRole="button" style={styles.retry}>
            <Text style={styles.link}>Retry</Text>
          </Pressable>
        ) : (
          <ActivityIndicator color={colors.textDim} style={{ marginTop: 20 }} />
        )
      ) : (
        <ScrollView contentContainerStyle={styles.body} testID="access-review">
          <Text style={styles.faint}>Generated {new Date(report.generatedAt).toLocaleString()}</Text>
          {s ? (
            <Text style={styles.line}>
              {s.people} people: {s.active} active, {s.disabled} disabled, {s.admins} admins, {s.activeWithoutMfa} active without a second factor,{" "}
              {s.scimManaged} from SCIM, {s.apiAccess} API tokens, {s.machines} machines.
            </Text>
          ) : null}
          <View style={styles.card}>
            <Text style={styles.section}>Sign off</Text>
            <Text style={styles.faint}>Recorded in the audit log as access_review.completed, with you as the reviewer and this report&apos;s digest.</Text>
            <TextInput
              style={styles.input}
              accessibilityLabel="Review notes"
              placeholder="Notes, e.g. what you changed (optional)"
              placeholderTextColor={colors.textFaint}
              value={notes}
              onChangeText={(t) => setNotes(t.slice(0, MAX_NOTES))}
              multiline
            />
            <View style={styles.rowTop}>
              <Pressable
                style={[styles.primaryBtn, saving && styles.busy]}
                onPress={() => void signOff()}
                disabled={saving}
                accessibilityRole="button"
                accessibilityState={{ disabled: saving, busy: saving }}
              >
                <Text style={styles.primaryText}>{saving ? "Signing off…" : "Mark as reviewed"}</Text>
              </Pressable>
              <Pressable onPress={() => void load()} accessibilityRole="button">
                <Text style={styles.link}>Reload</Text>
              </Pressable>
            </View>
            {signed && signed.digest === report.digest ? <Text style={styles.ok}>Signed off at {new Date(signed.at).toLocaleString()}.</Text> : null}
            {signError ? <Text style={styles.error}>{signError}</Text> : null}
          </View>
          {report.groups.map((g) => (
            <View key={`${g.tenant ?? ""}/${g.team?.id ?? ""}`} style={styles.group}>
              <Text style={styles.section}>
                {groupLabel(g)} <Text style={styles.dim}>({g.people.length})</Text>
              </Text>
              {g.people.map((p) => (
                <Person key={p.id} p={p} />
              ))}
            </View>
          ))}
          <View style={styles.group}>
            <Text style={styles.section}>Past sign-offs</Text>
            {report.reviews.length ? report.reviews.map((r) => <SignOff key={r.eventId} r={r} />) : <Text style={styles.faint}>None yet.</Text>}
          </View>
        </ScrollView>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.bgMain },
  header: { flexDirection: "row", alignItems: "center", gap: 16, padding: 16, borderBottomWidth: 1, borderBottomColor: colors.border },
  back: { color: colors.blueDot, fontSize: 16 },
  title: { color: colors.text, fontSize: 20, fontWeight: "600", flex: 1 },
  primaryBtn: { backgroundColor: "#f2f2f2", borderRadius: 999, paddingVertical: 8, paddingHorizontal: 16 },
  primaryText: { color: "#111", fontSize: 15 },
  busy: { opacity: 0.6 },
  body: { padding: 16, gap: 14 },
  card: { gap: 8, padding: 14, borderRadius: 14, borderWidth: 1, borderColor: colors.border },
  group: { gap: 6 },
  section: { color: colors.text, fontSize: 16, fontWeight: "600" },
  person: { padding: 12, borderRadius: 14, gap: 3, backgroundColor: colors.bgSidebar },
  review: { paddingVertical: 4, gap: 2 },
  rowTop: { flexDirection: "row", alignItems: "center", gap: 8 },
  name: { color: colors.text, fontSize: 15, fontWeight: "600", flexShrink: 1 },
  line: { color: colors.text },
  dim: { color: colors.textDim },
  faint: { color: colors.textFaint, fontSize: 12 },
  tags: { flexDirection: "row", flexWrap: "wrap", gap: 6 },
  tag: { color: colors.textDim, fontSize: 12, borderWidth: 1, borderColor: colors.border, borderRadius: 999, paddingHorizontal: 8, paddingVertical: 1 },
  input: {
    backgroundColor: colors.bgHover,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: colors.border,
    paddingHorizontal: 12,
    paddingVertical: 10,
    color: colors.text,
    minHeight: 60,
  },
  link: { color: colors.blueDot },
  retry: { paddingHorizontal: 16, paddingVertical: 8 },
  ok: { color: colors.text },
  error: { color: colors.danger, paddingHorizontal: 16, paddingVertical: 8 },
});
