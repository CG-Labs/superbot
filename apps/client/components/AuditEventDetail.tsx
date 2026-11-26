import React, { useEffect, useRef, useState } from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";
import { decisionSummary, detailsPretty, eventFields, eventText, pivotsFor, signInLabel, type AuditFilters } from "../src/audit";
import { copyText, COPY_LABEL } from "../src/clipboard";
import { hairline, themedStyles, type } from "../src/theme";
import { kit } from "./ui";
import type { AuditEvent } from "../src/types";

interface Props {
  e: AuditEvent;
  botName?: (id: string) => string | undefined;
  nameOf: (userId: string) => string;
  /** Shows the log with these filters instead. */
  onPivot: (filters: AuditFilters) => void;
}

function Row({ label, value, first }: { label: string; value: string; first?: boolean }) {
  const styles = useStyles();
  return (
    <View style={[styles.field, first && styles.fieldFirst]}>
      <Text style={styles.label}>{label}</Text>
      <Text style={styles.value} selectable>
        {value}
      </Text>
    </View>
  );
}

/** One audit event in full: every field, an approval's decision, its details, and "show everything like this". */
export function AuditEventDetail({ e, botName, nameOf, onPivot }: Props) {
  const styles = useStyles();
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
        <Text style={styles.action} role="heading" selectable>
          {e.action}
        </Text>
        <Text style={[styles.tag, e.outcome === "success" ? styles.okTag : styles.badTag]}>{e.outcome}</Text>
      </View>
      {how ? <Text style={styles.dim}>{how}</Text> : null}

      {decision ? (
        <View style={styles.section}>
          <Text style={styles.sectionTitle} role="heading">
            Decision
          </Text>
          <View style={styles.group}>
            <Text style={[styles.verdict, e.action !== "approval.approved" && styles.verdictBad]}>{decision.verdict}</Text>
            {decision.lines.map(([label, value]) => (
              <Row key={label} label={label} value={value} />
            ))}
          </View>
        </View>
      ) : null}

      <View style={styles.section}>
        <Text style={styles.sectionTitle} role="heading">
          Event
        </Text>
        <View style={styles.group}>
          {eventFields(e, { nameOf, botName }).map(([label, value], i) => (
            <Row key={label} label={label} value={value} first={i === 0} />
          ))}
        </View>
      </View>

      {details ? (
        <View style={styles.section}>
          <Text style={styles.sectionTitle} role="heading">
            Details
          </Text>
          <Text style={styles.code} selectable>
            {details}
          </Text>
        </View>
      ) : null}

      <View style={styles.section}>
        <Text style={styles.sectionTitle} role="heading">
          Show
        </Text>
        <View style={styles.group}>
          {pivotsFor(e, { nameOf, botName }).map((p, i) => (
            <Pressable
              key={p.label}
              onPress={() => onPivot(p.filters)}
              accessibilityRole="button"
              accessibilityLabel={p.label}
              style={({ pressed }) => [styles.pivot, i === 0 && styles.fieldFirst, pressed && styles.pivotPressed]}
            >
              <Text style={styles.link}>{p.label} ›</Text>
            </Pressable>
          ))}
        </View>
      </View>

      <Pressable style={({ pressed }) => [styles.copyBtn, pressed && styles.copyPressed]} onPress={() => void copy()} accessibilityRole="button" accessibilityLabel={`${COPY_LABEL} event`}>
        <Text style={styles.copyText}>{copied ? "Copied" : `${COPY_LABEL} event`}</Text>
      </Pressable>
    </View>
  );
}

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    root: { gap: t.space.lg },
    top: { flexDirection: "row", alignItems: "center", gap: t.space.sm, flexWrap: "wrap" },
    action: { color: t.c.text, fontFamily: t.font.mono, ...type(t, "md"), fontWeight: t.font.weight.semibold, flexShrink: 1 },
    tag: k.tag,
    okTag: k.tagGood,
    badTag: k.tagDanger,
    dim: k.dim,
    section: { gap: t.space.sm },
    sectionTitle: { ...k.section, marginTop: 0, marginBottom: 0 },
    group: { ...k.card, gap: 0, paddingVertical: t.space.xs, paddingHorizontal: t.space.lg },
    verdict: { color: t.c.success, ...type(t, "md"), fontWeight: t.font.weight.semibold, paddingVertical: t.space.sm },
    verdictBad: { color: t.c.danger },
    field: { flexDirection: "row", gap: t.space.md, paddingVertical: t.space.sm, borderTopWidth: hairline, borderTopColor: t.c.border },
    fieldFirst: { borderTopWidth: 0 },
    label: { ...k.dim, width: 110 },
    value: { color: t.c.text, ...type(t, "sm"), flex: 1 },
    code: { ...k.inset, color: t.c.textMuted, fontFamily: t.font.mono, ...type(t, "xs") },
    pivot: { paddingVertical: t.space.sm, borderTopWidth: hairline, borderTopColor: t.c.border },
    pivotPressed: { opacity: 0.7 },
    link: { ...k.link, ...type(t, "sm") },
    copyBtn: { ...k.btn, alignSelf: "flex-start" },
    copyPressed: k.btnPressed,
    copyText: k.btnText,
  });
});
