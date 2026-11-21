import React, { useEffect, useRef, useState } from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";
import { decisionSummary, detailsPretty, eventFields, eventText, pivotsFor, signInLabel, type AuditFilters } from "../src/audit";
import { copyText, COPY_LABEL } from "../src/clipboard";
import { colors } from "../src/theme";
import type { AuditEvent } from "../src/types";

interface Props {
  e: AuditEvent;
  botName?: (id: string) => string | undefined;
  nameOf: (userId: string) => string;
  /** Shows the log with these filters instead. */
  onPivot: (filters: AuditFilters) => void;
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <View style={styles.field}>
      <Text style={styles.label}>{label}</Text>
      <Text style={styles.value} selectable>
        {value}
      </Text>
    </View>
  );
}

/** One audit event in full: every field, an approval's decision, its details, and "show everything like this". */
export function AuditEventDetail({ e, botName, nameOf, onPivot }: Props) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => {
    if (timer.current) clearTimeout(timer.current);
  }, []);
  const decision = decisionSummary(e);
  const details = detailsPretty(e);
  const how = signInLabel(e, nameOf);

  const copy = async () => {
    if (!(await copyText(eventText(e)))) return;
    setCopied(true);
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setCopied(false), 2000);
  };

  return (
    <View style={styles.root} testID="audit-event-detail">
      <View style={styles.top}>
        <Text style={styles.action} selectable>
          {e.action}
        </Text>
        <Text style={[styles.tag, e.outcome === "success" ? styles.okTag : styles.badTag]}>{e.outcome}</Text>
      </View>
      {how ? <Text style={styles.dim}>{how}</Text> : null}

      {decision ? (
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Decision</Text>
          <Text style={[styles.verdict, e.action !== "approval.approved" && styles.verdictBad]}>{decision.verdict}</Text>
          {decision.lines.map(([label, value]) => (
            <Row key={label} label={label} value={value} />
          ))}
        </View>
      ) : null}

      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Event</Text>
        {eventFields(e, { nameOf, botName }).map(([label, value]) => (
          <Row key={label} label={label} value={value} />
        ))}
      </View>

      {details ? (
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Details</Text>
          <Text style={styles.code} selectable>
            {details}
          </Text>
        </View>
      ) : null}

      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Show</Text>
        {pivotsFor(e, { nameOf, botName }).map((p) => (
          <Pressable key={p.label} onPress={() => onPivot(p.filters)} accessibilityRole="button" style={styles.pivot}>
            <Text style={styles.link}>{p.label} ›</Text>
          </Pressable>
        ))}
      </View>

      <Pressable style={styles.copyBtn} onPress={() => void copy()} accessibilityRole="button" accessibilityLabel={`${COPY_LABEL} event`}>
        <Text style={styles.copyText}>{copied ? "Copied" : `${COPY_LABEL} event`}</Text>
      </Pressable>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { gap: 14 },
  top: { flexDirection: "row", alignItems: "center", gap: 8, flexWrap: "wrap" },
  action: { color: colors.text, fontFamily: "monospace", fontSize: 16, lineHeight: 22, flexShrink: 1 },
  tag: { fontSize: 12, borderWidth: 1, borderRadius: 999, paddingHorizontal: 8, paddingVertical: 1 },
  okTag: { color: colors.accent, borderColor: "#2a4a33" },
  badTag: { color: colors.danger, borderColor: "#5a2a2c" },
  dim: { color: colors.textDim },
  section: { gap: 6 },
  sectionTitle: { color: colors.textFaint, fontSize: 12, fontWeight: "600", textTransform: "uppercase", letterSpacing: 0.5 },
  verdict: { color: colors.accent, fontSize: 15, fontWeight: "600" },
  verdictBad: { color: colors.danger },
  field: { flexDirection: "row", gap: 12 },
  label: { color: colors.textDim, width: 110, fontSize: 13 },
  value: { color: colors.text, flex: 1, fontSize: 13 },
  code: {
    color: colors.textDim,
    fontFamily: "monospace",
    fontSize: 12,
    lineHeight: 18,
    backgroundColor: colors.bgSidebar,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: colors.border,
    padding: 12,
  },
  pivot: { paddingVertical: 4 },
  link: { color: colors.blueDot },
  copyBtn: { alignSelf: "flex-start", borderWidth: 1, borderColor: colors.border, borderRadius: 999, paddingVertical: 8, paddingHorizontal: 16 },
  copyText: { color: colors.text },
});
