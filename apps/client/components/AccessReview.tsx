import React, { useCallback, useEffect, useState } from "react";
import { Pressable, ScrollView, StyleSheet, Text, TextInput, View } from "react-native";
import {
  botAccessLabel,
  csvFileName,
  effectiveLabel,
  flags,
  groupLabel,
  lastLoginLabel,
  machineLabel,
  ownerLabel,
  serviceFlags,
  serviceRoleLabel,
  serviceTokenLabel,
  signInsLabel,
} from "../src/accessReview";
import { ApiError, type SuperBotApi } from "../src/api";
import { friendlyError } from "../src/errors";
import { saveCsv } from "../src/saveCsv";
import { hairline, themedStyles, type } from "../src/theme";
import type { AccessReview as Report, AccessReviewPerson, AccessReviewServiceAccount, AccessReviewSignOff } from "../src/types";
import { EmptyState } from "./EmptyState";
import { ErrorState, InlineError } from "./ErrorState";
import { PageSkeleton } from "./Skeleton";
import { kit, PageHeader, usePlaceholder } from "./ui";

interface Props {
  api: SuperBotApi;
  onBack: () => void;
}

const MAX_NOTES = 500;

function Person({ p, first }: { p: AccessReviewPerson; first: boolean }) {
  const styles = useStyles();
  const marks = flags(p);
  return (
    <View style={[styles.person, first && styles.personFirst]} accessibilityLabel={`Access of ${p.name}`}>
      <View style={styles.rowTop}>
        <Text style={styles.name} numberOfLines={1}>
          {p.name}
        </Text>
        <Text style={styles.dim}>{p.role}</Text>
        {p.team ? <Text style={styles.dim}>· team {p.team.role}</Text> : null}
      </View>
      {p.email ? <Text style={styles.faint}>{p.email}</Text> : null}
      <Tags marks={marks} />
      <Text style={styles.line}>Last sign-in: {lastLoginLabel(p)}</Text>
      <Text style={styles.line}>Second factor: {p.mfa.enabled ? "on" : "off"}</Text>
      <Text style={styles.line}>Bots: {botAccessLabel(p)}</Text>
      <Text style={styles.line}>Signed in: {signInsLabel(p)}</Text>
      <Text style={styles.line}>Machine: {machineLabel(p)}</Text>
    </View>
  );
}

function Tags({ marks }: { marks: string[] }) {
  const styles = useStyles();
  if (!marks.length) return null;
  return (
    <View style={styles.tags}>
      {marks.map((m) => (
        <Text key={m} style={styles.tag}>
          {m}
        </Text>
      ))}
    </View>
  );
}

/** A service account (ADR 0165): who owns it, what it can use today, its Bots and live tokens. */
function ServiceAccount({ s, first }: { s: AccessReviewServiceAccount; first: boolean }) {
  const styles = useStyles();
  return (
    <View style={[styles.person, first && styles.personFirst]} accessibilityLabel={`Access of service account ${s.name}`}>
      <View style={styles.rowTop}>
        <Text style={styles.name} numberOfLines={1}>
          {s.name}
        </Text>
        <Text style={styles.dim}>{serviceRoleLabel(s)}</Text>
      </View>
      {s.description ? <Text style={styles.faint}>{s.description}</Text> : null}
      <Tags marks={serviceFlags(s)} />
      <Text style={styles.line}>Owner: {ownerLabel(s)}</Text>
      <Text style={styles.line}>Can use today: {effectiveLabel(s)}</Text>
      <Text style={styles.line}>Bots: {botAccessLabel(s)}</Text>
      {s.tokens.length ? (
        s.tokens.map((t) => (
          <Text key={t.id} style={styles.line}>
            Token: {serviceTokenLabel(t)}
          </Text>
        ))
      ) : (
        <Text style={styles.line}>Tokens: none live</Text>
      )}
    </View>
  );
}

function SignOff({ r, first }: { r: AccessReviewSignOff; first: boolean }) {
  const styles = useStyles();
  const who = r.reviewer.name || r.reviewer.email || r.reviewer.id || "Unknown";
  return (
    <View style={[styles.review, first && styles.personFirst]}>
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
  const styles = useStyles();
  const placeholder = usePlaceholder();
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);
  /** Why the report didn't load, in plain words; kept apart from export failures so it can offer a retry. */
  const [loadError, setLoadError] = useState<string | null>(null);
  const [notes, setNotes] = useState("");
  const [saving, setSaving] = useState(false);
  const [signError, setSignError] = useState<string | null>(null);
  const [signed, setSigned] = useState<AccessReviewSignOff | null>(null);
  const [exporting, setExporting] = useState(false);

  const load = useCallback(async () => {
    setLoadError(null);
    setError(null);
    setSignError(null);
    try {
      setReport(await api.accessReview());
    } catch (err) {
      setLoadError(friendlyError(err));
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
      setError(stale ? "Access changed since this report loaded. Reload it before exporting." : friendlyError(err, "Export failed. Try again."));
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
      setSignError(stale ? "Access changed since this report loaded. Reload it and review it again." : friendlyError(err, "Couldn't sign off. Try again."));
    } finally {
      setSaving(false);
    }
  };

  const s = report?.summary;
  return (
    <View style={styles.root}>
      <PageHeader
        title="Access review"
        onBack={onBack}
        right={
          <Pressable
            style={[styles.headerBtn, (exporting || !report) && styles.busy]}
            onPress={() => void exportCsv()}
            disabled={exporting || !report}
            accessibilityRole="button"
            accessibilityState={{ disabled: exporting || !report, busy: exporting }}
          >
            <Text style={styles.primaryText}>{exporting ? "Exporting…" : "Export CSV"}</Text>
          </Pressable>
        }
      />
      {error || (report && loadError) ? (
        <View style={styles.notices}>
          {report && loadError ? <InlineError message={`Couldn't load the access review. ${loadError}`} onRetry={load} /> : null}
          {error ? <InlineError message={error} /> : null}
        </View>
      ) : null}
      {!report ? (
        loadError ? (
          <ErrorState title="Couldn't load the access review" message={loadError} onRetry={load} />
        ) : (
          <PageSkeleton label="Loading the access review" />
        )
      ) : (
        <ScrollView contentContainerStyle={styles.body} testID="access-review">
          <Text style={styles.faint}>Generated {new Date(report.generatedAt).toLocaleString()}</Text>
          {s ? (
            <Text style={styles.summary}>
              {s.people} people: {s.active} active, {s.disabled} disabled, {s.admins} admins, {s.activeWithoutMfa} active without a second factor,{" "}
              {s.scimManaged} from SCIM, {s.apiAccess} API tokens, {s.machines} machines.
              {s.serviceAccounts ? ` ${s.serviceAccounts} service accounts with ${s.serviceApiAccess ?? 0} live tokens.` : ""}
            </Text>
          ) : null}
          <View style={styles.card}>
            <Text style={styles.cardTitle} role="heading">
              Sign off
            </Text>
            <Text style={styles.faint}>Recorded in the audit log as access_review.completed, with you as the reviewer and this report&apos;s digest.</Text>
            <TextInput
              style={styles.input}
              accessibilityLabel="Review notes"
              placeholder="Notes, e.g. what you changed (optional)"
              placeholderTextColor={placeholder}
              value={notes}
              onChangeText={(t) => setNotes(t.slice(0, MAX_NOTES))}
              multiline
            />
            <View style={styles.actions}>
              <Pressable
                style={[styles.primaryBtn, saving && styles.busy]}
                onPress={() => void signOff()}
                disabled={saving}
                accessibilityRole="button"
                accessibilityState={{ disabled: saving, busy: saving }}
              >
                <Text style={styles.primaryText}>{saving ? "Signing off…" : "Mark as reviewed"}</Text>
              </Pressable>
              <Pressable onPress={() => void load()} accessibilityRole="button" style={({ pressed }) => [styles.btn, pressed && styles.btnPressed]}>
                <Text style={styles.btnText}>Reload</Text>
              </Pressable>
            </View>
            {signed && signed.digest === report.digest ? <Text style={styles.ok}>Signed off at {new Date(signed.at).toLocaleString()}.</Text> : null}
            {signError ? <InlineError message={signError} /> : null}
          </View>
          {report.groups.map((g) => (
            <View key={`${g.tenant ?? ""}/${g.team?.id ?? ""}`} style={styles.group}>
              <Text style={styles.section} role="heading">
                {groupLabel(g)} <Text style={styles.count}>({g.people.length})</Text>
              </Text>
              <View style={styles.list}>
                {g.people.map((p, i) => (
                  <Person key={p.id} p={p} first={i === 0} />
                ))}
              </View>
            </View>
          ))}
          {report.serviceAccounts?.length ? (
            <View style={styles.group}>
              <Text style={styles.section} role="heading">
                Service accounts <Text style={styles.count}>({report.serviceAccounts.length})</Text>
              </Text>
              <View style={styles.list}>
                {report.serviceAccounts.map((sa, i) => (
                  <ServiceAccount key={sa.id} s={sa} first={i === 0} />
                ))}
              </View>
            </View>
          ) : null}
          <View style={styles.group}>
            <Text style={styles.section} role="heading">
              Past sign-offs
            </Text>
            <View style={styles.list}>
              {report.reviews.length ? (
                report.reviews.map((r, i) => <SignOff key={r.eventId} r={r} first={i === 0} />)
              ) : (
                <EmptyState compact glyph="+" title="No sign-offs yet" message="Mark this report as reviewed to record the first one." />
              )}
            </View>
          </View>
        </ScrollView>
      )}
    </View>
  );
}

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    root: k.root,
    headerBtn: { ...k.btn, ...k.btnSmall, ...k.primary },
    primaryBtn: { ...k.btn, ...k.primary },
    primaryText: { ...k.btnText, ...k.primaryText },
    btn: k.btn,
    btnPressed: k.btnPressed,
    btnText: k.btnText,
    busy: k.disabled,
    body: k.body,
    summary: k.dim,
    card: k.card,
    cardTitle: k.cardTitle,
    group: { gap: t.space.sm },
    section: { ...k.section, marginBottom: 0 },
    count: { fontWeight: t.font.weight.regular },
    list: { ...k.card, gap: 0, paddingVertical: t.space.xs },
    person: { paddingVertical: t.space.md, gap: t.space.xxs, borderTopWidth: hairline, borderTopColor: t.c.border },
    personFirst: { borderTopWidth: 0 },
    review: { paddingVertical: t.space.sm, gap: t.space.xxs, borderTopWidth: hairline, borderTopColor: t.c.border },
    rowTop: { flexDirection: "row", alignItems: "center", gap: t.space.sm },
    actions: k.actions,
    name: { ...k.strong, flexShrink: 1 },
    line: { color: t.c.text, ...type(t, "sm") },
    dim: k.dim,
    faint: k.faint,
    tags: { ...k.tags, marginVertical: t.space.xxs },
    tag: k.tag,
    input: { ...k.input, ...k.inputMultiline },
    ok: k.good,
    notices: { gap: t.space.sm, paddingHorizontal: t.space.lg, paddingVertical: t.space.sm },
  });
});
