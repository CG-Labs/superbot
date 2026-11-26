import React, { useCallback, useEffect, useRef, useState } from "react";
import { FlatList, Modal, Pressable, ScrollView, StyleSheet, Text, TextInput, useWindowDimensions, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import type { SuperBotApi } from "../src/api";
import {
  ACTORS,
  actorLabel,
  auditQuery,
  csvFileName,
  detailsText,
  KINDS,
  METHODS,
  nameFrom,
  NO_FILTERS,
  OUTCOMES,
  signInLabel,
  targetLabel,
  type AuditFilters,
} from "../src/audit";
import { saveCsv } from "../src/saveCsv";
import { hairline, themedStyles, type } from "../src/theme";
import type { AuditEvent } from "../src/types";
import { AuditChainPanel } from "./AuditChainPanel";
import { AuditEventDetail } from "./AuditEventDetail";
import { Chips } from "./Chips";
import { kit, PageHeader, Spinner, usePlaceholder } from "./ui";

interface Props {
  api: SuperBotApi;
  onBack: () => void;
  /** Names Bots the log only has an id for. */
  botName?: (id: string) => string | undefined;
  /** The Bots to offer as a filter. */
  bots?: readonly { id: string; name: string }[];
  /** Filters to open with, e.g. from `/audit?bot=<id>`. */
  initial?: Partial<AuditFilters>;
}

/** Typing waits this long before asking the server again. */
const DEBOUNCE_MS = 300;

function Field({ label, value, onChange, placeholder, width }: { label: string; value: string; onChange: (v: string) => void; placeholder: string; width?: number }) {
  const styles = useStyles();
  const placeholderColor = usePlaceholder();
  return (
    <TextInput
      style={[styles.input, width ? { width } : styles.grow]}
      accessibilityLabel={label}
      placeholder={placeholder}
      placeholderTextColor={placeholderColor}
      value={value}
      onChangeText={onChange}
      autoCapitalize="none"
      autoCorrect={false}
      spellCheck={false}
    />
  );
}

function EventRow({
  e,
  selected,
  first,
  last,
  onPress,
  botName,
  nameOf,
}: {
  e: AuditEvent;
  selected: boolean;
  first: boolean;
  last: boolean;
  onPress: () => void;
  botName?: Props["botName"];
  nameOf: (id: string) => string;
}) {
  const styles = useStyles();
  const how = signInLabel(e, nameOf);
  const target = targetLabel(e);
  const details = detailsText(e);
  return (
    <Pressable
      style={({ pressed }) => [
        styles.row,
        first && styles.rowFirst,
        last && styles.rowLast,
        e.outcome !== "success" && styles.rowBad,
        pressed && styles.rowPressed,
        selected && styles.rowOpen,
      ]}
      onPress={onPress}
      accessibilityRole="button"
      accessibilityLabel={`Audit event ${e.id}: ${e.action}`}
      accessibilityState={{ selected }}
    >
      <View style={styles.rowTop}>
        <Text style={styles.action} numberOfLines={1}>
          {e.action}
        </Text>
        {e.outcome !== "success" ? <Text style={[styles.tag, styles.badTag]}>{e.outcome}</Text> : null}
        <Text style={styles.time}>{new Date(e.at).toLocaleString()}</Text>
      </View>
      <Text style={styles.who} numberOfLines={1}>
        {actorLabel(e, botName)}
        {how ? <Text style={styles.dim}> · {how}</Text> : null}
      </Text>
      {target || e.ip ? (
        <Text style={styles.faint} numberOfLines={1}>
          {[target, e.ip].filter(Boolean).join(" · ")}
        </Text>
      ) : null}
      {details ? (
        <Text style={styles.details} numberOfLines={1}>
          {details}
        </Text>
      ) : null}
    </Pressable>
  );
}

/** The audit log for admins: filters, paging, event detail, CSV export, and the hash chain's state (ADR 0009, 0019, 0028, 0060, 0149). The server refuses it to everyone else. */
export function AuditLog({ api, onBack, botName, bots = [], initial }: Props) {
  const styles = useStyles();
  const { width } = useWindowDimensions();
  const wide = width >= 900;
  const [filters, setFilters] = useState<AuditFilters>(() => ({ ...NO_FILTERS, ...initial }));
  const [showFilters, setShowFilters] = useState(() => Object.values(initial ?? {}).some(Boolean));
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [next, setNext] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<AuditEvent | null>(null);
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const [showChain, setShowChain] = useState(false);
  const seq = useRef(0);
  /** The filter the rows on screen came from: Load more and Export use it, not what's half-typed. */
  const shown = useRef("");
  const first = useRef(true);

  let query = "";
  let filterError: string | null = null;
  try {
    query = auditQuery(filters);
  } catch (err) {
    filterError = err instanceof Error ? err.message : "Invalid filter";
  }

  const load = useCallback(
    async (q: string, before?: number) => {
      const n = ++seq.current;
      if (before == null) setLoading(true);
      setLoadingMore(before != null);
      try {
        const page = await api.audit(q, before);
        if (n !== seq.current) return;
        shown.current = q;
        setEvents((prev) => (before != null && prev ? [...prev, ...page.events] : page.events));
        setNext(page.nextBefore);
        setError(null);
      } catch (err) {
        if (n !== seq.current) return;
        setError(err instanceof Error ? err.message : "Couldn't load the audit log");
        if (before == null) {
          shown.current = q;
          setEvents([]);
          setNext(null);
        }
      } finally {
        if (n === seq.current) {
          setLoading(false);
          setLoadingMore(false);
        }
      }
    },
    [api],
  );

  useEffect(() => {
    if (filterError) return;
    const delay = first.current ? 0 : DEBOUNCE_MS;
    first.current = false;
    const t = setTimeout(() => void load(query), delay);
    return () => clearTimeout(t);
  }, [query, filterError, load]);

  // Reloads what the controls show, so it never brings back a filter that a newer load is replacing.
  const refresh = async () => {
    setRefreshing(true);
    try {
      await load(filterError ? shown.current : query);
    } finally {
      setRefreshing(false);
    }
  };

  const set = <K extends keyof AuditFilters>(k: K) => (v: AuditFilters[K]) => setFilters((f) => ({ ...f, [k]: v }));
  const active = Object.values(filters).filter(Boolean).length;

  const exportCsv = async () => {
    setExporting(true);
    setExportError(null);
    try {
      await saveCsv(csvFileName(), await api.auditCsv(shown.current));
    } catch (err) {
      setExportError(err instanceof Error ? err.message : "Export failed");
    } finally {
      setExporting(false);
    }
  };

  const pivot = (f: AuditFilters) => {
    setFilters(f);
    if (!wide) {
      setSelected(null);
      setShowFilters(true);
    }
  };

  const nameOf = nameFrom(events ?? []);
  const botOptions = [
    { value: "", label: "Any Bot" },
    ...[...bots].sort((a, b) => a.name.localeCompare(b.name)).map((b) => ({ value: b.id, label: b.name })),
  ];
  if (filters.bot && !botOptions.some((o) => o.value === filters.bot)) botOptions.push({ value: filters.bot, label: botName?.(filters.bot) ?? filters.bot });

  const filterFields = (
    <>
      <View style={styles.inputs}>
        <Field label="Action" value={filters.action} onChange={set("action")} placeholder="Action, e.g. bot.* or auth.login_failed" />
      </View>
      <Chips options={KINDS} value={filters.action.trim()} onChange={set("action")} />
      <View style={styles.inputs}>
        <Field label="Person" value={filters.person} onChange={set("person")} placeholder="Person: email or id" />
        <Field label="On behalf of" value={filters.onBehalfOf} onChange={set("onBehalfOf")} placeholder="Done for: email or id" />
        <Field label="Session" value={filters.session} onChange={set("session")} placeholder="Session id" />
      </View>
      <Chips options={ACTORS} value={filters.actor} onChange={set("actor")} disabled={!!filters.person.trim()} />
      {botOptions.length > 1 ? <Chips options={botOptions} value={filters.bot} onChange={set("bot")} /> : null}
      <Chips options={METHODS} value={filters.method} onChange={set("method")} />
      <Chips options={OUTCOMES} value={filters.outcome} onChange={set("outcome")} />
      <View style={styles.inputs}>
        <Field label="From" value={filters.from} onChange={set("from")} placeholder="From YYYY-MM-DD" width={170} />
        <Field label="To" value={filters.to} onChange={set("to")} placeholder="To YYYY-MM-DD" width={170} />
        {active ? (
          <Pressable onPress={() => setFilters(NO_FILTERS)} accessibilityRole="button" style={styles.clear}>
            <Text style={styles.link}>Clear filters</Text>
          </Pressable>
        ) : null}
      </View>
      {filterError ? <Text style={styles.error}>{filterError}</Text> : null}
    </>
  );
  // Phones scroll the filters, so the list keeps some of the screen.
  const filterPanel = wide ? (
    <View style={styles.filters} testID="audit-filters">
      {filterFields}
    </View>
  ) : (
    <ScrollView style={styles.filtersNarrow} contentContainerStyle={styles.filters} testID="audit-filters" keyboardShouldPersistTaps="handled">
      {filterFields}
    </ScrollView>
  );

  const detail = selected ? <AuditEventDetail key={selected.id} e={selected} botName={botName} nameOf={nameOf} onPivot={pivot} /> : null;

  const list = (
    <FlatList
      style={styles.list}
      data={events ?? []}
      extraData={selected?.id}
      keyExtractor={(e) => String(e.id)}
      contentContainerStyle={styles.listContent}
      refreshing={refreshing}
      onRefresh={() => void refresh()}
      testID="audit-list"
      renderItem={({ item, index }) => (
        <EventRow
          e={item}
          selected={selected?.id === item.id}
          first={index === 0}
          last={index === (events?.length ?? 0) - 1}
          onPress={() => setSelected(item)}
          botName={botName}
          nameOf={nameOf}
        />
      )}
      ListEmptyComponent={
        loading ? (
          <Spinner style={styles.spinner} />
        ) : (
          <Text style={error ? styles.error : styles.empty}>{error ?? "No events match."}</Text>
        )
      }
      ListFooterComponent={
        <View style={styles.footer}>
          {events?.length && error ? <Text style={styles.error}>{error}</Text> : null}
          {next != null && !loading ? (
            <Pressable
              style={[styles.moreBtn, loadingMore && styles.busy]}
              onPress={() => void load(shown.current, next)}
              disabled={loadingMore}
              accessibilityRole="button"
              accessibilityState={{ disabled: loadingMore, busy: loadingMore }}
            >
              <Text style={styles.moreText}>{loadingMore ? "Loading…" : "Load more"}</Text>
            </Pressable>
          ) : null}
          <Text style={styles.faint}>Append-only. Export uses the filters the list shows.</Text>
        </View>
      }
    />
  );

  return (
    <View style={styles.root}>
      <PageHeader
        title="Audit log"
        onBack={onBack}
        right={
          <View style={styles.headerActions}>
            <Pressable
              onPress={() => setShowChain((s) => !s)}
              accessibilityRole="button"
              accessibilityState={{ expanded: showChain }}
              accessibilityLabel="The hash chain's state"
              style={({ pressed }) => [styles.btn, showChain && styles.btnOn, pressed && styles.btnPressed]}
            >
              <Text style={styles.btnText}>{showChain ? "Hide chain" : "Chain"}</Text>
            </Pressable>
            <Pressable
              style={[styles.primaryBtn, exporting && styles.busy]}
              onPress={() => void exportCsv()}
              disabled={exporting}
              accessibilityRole="button"
              accessibilityState={{ disabled: exporting, busy: exporting }}
            >
              <Text style={styles.primaryText}>{exporting ? "Exporting…" : "Export CSV"}</Text>
            </Pressable>
          </View>
        }
      />
      {showChain ? <AuditChainPanel api={api} /> : null}
      {wide ? (
        filterPanel
      ) : (
        <>
          <Pressable style={styles.filterToggle} onPress={() => setShowFilters((s) => !s)} accessibilityRole="button" accessibilityState={{ expanded: showFilters }}>
            <Text style={styles.link}>
              {showFilters ? "Hide filters" : "Filters"}
              {active ? ` · ${active}` : ""}
            </Text>
          </Pressable>
          {showFilters ? filterPanel : null}
        </>
      )}
      {exportError ? <Text style={styles.error}>{exportError}</Text> : null}
      {wide ? (
        <View style={styles.body}>
          {list}
          <ScrollView style={styles.detailPane} contentContainerStyle={styles.detailBody}>
            {detail ?? <Text style={styles.empty}>Pick an event to see all of it.</Text>}
          </ScrollView>
        </View>
      ) : (
        <>
          {list}
          <Modal visible={!!selected} animationType="slide" onRequestClose={() => setSelected(null)}>
            <SafeAreaView style={styles.modalRoot}>
              <Pressable style={styles.modalHeader} onPress={() => setSelected(null)} accessibilityRole="button" accessibilityLabel="Back to the audit log">
                <Text style={styles.back}>‹ Audit log</Text>
              </Pressable>
              <ScrollView contentContainerStyle={styles.modalBody}>{detail}</ScrollView>
            </SafeAreaView>
          </Modal>
        </>
      )}
    </View>
  );
}

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    root: k.root,
    back: k.backText,
    headerActions: { flexDirection: "row", alignItems: "center", gap: t.space.sm },
    btn: { ...k.btn, ...k.btnSmall },
    btnOn: { backgroundColor: t.c.selected },
    btnPressed: k.btnPressed,
    btnText: k.btnText,
    primaryBtn: { ...k.btn, ...k.btnSmall, ...k.primary },
    primaryText: { ...k.btnText, ...k.primaryText },
    busy: k.disabled,
    filterToggle: { paddingHorizontal: t.space.lg, paddingVertical: t.space.md, borderBottomWidth: hairline, borderBottomColor: t.c.border },
    filtersNarrow: { maxHeight: "55%", flexGrow: 0 },
    filters: { gap: t.space.sm, paddingHorizontal: t.space.lg, paddingVertical: t.space.md, borderBottomWidth: hairline, borderBottomColor: t.c.border },
    inputs: { flexDirection: "row", flexWrap: "wrap", gap: t.space.sm, alignItems: "center" },
    input: { ...k.search, ...type(t, "sm") },
    grow: { flexGrow: 1, flexBasis: 200 },
    clear: { paddingHorizontal: t.space.sm, paddingVertical: t.space.sm },
    link: k.link,
    body: { flex: 1, flexDirection: "row" },
    list: { flex: 1 },
    listContent: { padding: t.space.lg, paddingBottom: t.space.xl },
    spinner: { marginTop: t.space.xl },
    detailPane: { width: 440, flexGrow: 0, backgroundColor: t.c.surface, borderLeftWidth: hairline, borderLeftColor: t.c.border },
    detailBody: { padding: t.space.xl },
    modalRoot: { flex: 1, backgroundColor: t.c.bg },
    modalHeader: { ...k.header, minHeight: 0 },
    modalBody: { padding: t.space.lg },
    // The rows together make one card: hairlines between them, the card's corners on the first and last.
    row: {
      paddingVertical: t.space.md,
      paddingHorizontal: t.space.lg,
      gap: t.space.xxs,
      backgroundColor: t.c.raised,
      borderColor: t.c.border,
      borderTopWidth: hairline,
      borderLeftWidth: hairline,
      borderRightWidth: hairline,
    },
    rowFirst: { borderTopLeftRadius: t.radius.lg, borderTopRightRadius: t.radius.lg },
    rowLast: { borderBottomWidth: hairline, borderBottomLeftRadius: t.radius.lg, borderBottomRightRadius: t.radius.lg },
    rowBad: { borderLeftWidth: t.space.xxs, borderLeftColor: t.c.danger },
    rowPressed: { backgroundColor: t.c.hover },
    rowOpen: { backgroundColor: t.c.selected },
    rowTop: { flexDirection: "row", alignItems: "center", gap: t.space.sm },
    // One clipped line: without the extra line height, web cuts off the underscores.
    action: { color: t.c.text, fontFamily: t.font.mono, ...type(t, "sm"), fontWeight: t.font.weight.medium, flexShrink: 1 },
    time: { ...k.faint, marginLeft: "auto" },
    who: { color: t.c.text, ...type(t, "sm") },
    dim: { color: t.c.textMuted },
    faint: k.faint,
    details: { color: t.c.textMuted, fontFamily: t.font.mono, ...type(t, "xs") },
    tag: k.tag,
    badTag: k.tagDanger,
    empty: k.empty,
    error: { ...k.error, paddingHorizontal: t.space.lg, paddingVertical: t.space.sm },
    footer: { alignItems: "center", gap: t.space.md, paddingVertical: t.space.lg },
    moreBtn: k.btn,
    moreText: k.btnText,
  });
});
