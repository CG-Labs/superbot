import React, { useMemo, type ReactNode } from "react";
import { Linking, ScrollView, StyleSheet, Text, View } from "react-native";
import { decodeEntities, parseMarkdown, safeHref, type Token, type Tokens } from "../src/markdown";
import { hairline, themedStyles, type Theme } from "../src/theme";

/**
 * Renders a message's Markdown as native views, on iOS, Android and web alike. Raw HTML is shown as
 * the text it is, never interpreted; links open only when `safeHref` allows them; images show as a
 * link to the image rather than loading it, so a message can't make the app fetch a tracking pixel.
 */
export function Markdown({ children }: { children: string }) {
  const styles = useStyles();
  const tokens = useMemo(() => parseMarkdown(children), [children]);
  return <View style={styles.root}>{blocks(styles, tokens, "b")}</View>;
}

type Styles = ReturnType<typeof makeStyles>;

function open(url: string) {
  void Linking.openURL(url).catch(() => {});
}

function blocks(styles: Styles, tokens: Token[], key: string): ReactNode[] {
  const out: ReactNode[] = [];
  tokens.forEach((t, i) => {
    const node = block(styles, t as Tokens.Generic, `${key}.${i}`);
    if (node !== null) out.push(node);
  });
  return out;
}

function block(styles: Styles, t: Tokens.Generic, key: string): ReactNode {
  switch (t.type) {
    case "space":
    case "def":
    case "checkbox":
      return null;
    case "paragraph":
    case "text":
      return (
        <Text key={key} style={styles.body}>
          {t.tokens ? inline(styles, t.tokens, key) : decodeEntities(t.text)}
        </Text>
      );
    case "heading":
      return (
        <Text key={key} role="heading" style={[styles.body, styles.heading, headingSize(t.depth)]}>
          {inline(styles, t.tokens ?? [], key)}
        </Text>
      );
    case "code":
      return (
        <ScrollView key={key} horizontal style={styles.fence} contentContainerStyle={styles.fenceInner}>
          <Text selectable style={styles.codeBlock}>
            {t.text}
          </Text>
        </ScrollView>
      );
    case "blockquote":
      return (
        <View key={key} style={styles.quote}>
          {blocks(styles, t.tokens ?? [], key)}
        </View>
      );
    case "list":
      return list(styles, t as Tokens.List, key);
    case "table":
      return table(styles, t as Tokens.Table, key);
    case "hr":
      return <View key={key} style={styles.hr} />;
    case "html":
      return t.text.trim() ? (
        <Text key={key} style={styles.body}>
          {t.text.replace(/\n+$/, "")}
        </Text>
      ) : null;
    default:
      return t.raw ? (
        <Text key={key} style={styles.body}>
          {t.raw}
        </Text>
      ) : null;
  }
}

function list(styles: Styles, t: Tokens.List, key: string): ReactNode {
  const start = typeof t.start === "number" ? t.start : 1;
  return (
    <View key={key} style={styles.list}>
      {t.items.map((item, i) => {
        const marker = item.task ? (item.checked ? "\u2611" : "\u2610") : t.ordered ? `${start + i}.` : "\u2022";
        return (
          <View key={`${key}.${i}`} style={styles.item}>
            <Text style={[styles.body, styles.marker]}>{marker}</Text>
            <View style={styles.itemBody}>{blocks(styles, item.tokens, `${key}.${i}`)}</View>
          </View>
        );
      })}
    </View>
  );
}

function table(styles: Styles, t: Tokens.Table, key: string): ReactNode {
  const cell = (c: Tokens.TableCell, k: string, header: boolean) => (
    <View key={k} style={[styles.cell, header && styles.headerCell]}>
      <Text style={[styles.body, header && styles.strong, { textAlign: c.align ?? "left" }]}>{inline(styles, c.tokens, k)}</Text>
    </View>
  );
  return (
    <ScrollView key={key} horizontal style={styles.tableScroll}>
      <View role="table" style={styles.table}>
        <View role="row" style={styles.tr}>
          {t.header.map((c, j) => cell(c, `${key}.h${j}`, true))}
        </View>
        {t.rows.map((row, i) => (
          <View key={`${key}.r${i}`} role="row" style={styles.tr}>
            {row.map((c, j) => cell(c, `${key}.r${i}.${j}`, false))}
          </View>
        ))}
      </View>
    </ScrollView>
  );
}

function inline(styles: Styles, tokens: Token[], key: string): ReactNode[] {
  return tokens.map((tok, i) => {
    const t = tok as Tokens.Generic;
    const k = `${key}.${i}`;
    switch (t.type) {
      case "text":
        return t.tokens ? <React.Fragment key={k}>{inline(styles, t.tokens, k)}</React.Fragment> : decodeEntities(t.text);
      case "escape":
        return t.text;
      case "strong":
        return (
          <Text key={k} style={styles.strong}>
            {inline(styles, t.tokens ?? [], k)}
          </Text>
        );
      case "em":
        return (
          <Text key={k} style={styles.em}>
            {inline(styles, t.tokens ?? [], k)}
          </Text>
        );
      case "del":
        return (
          <Text key={k} style={styles.del}>
            {inline(styles, t.tokens ?? [], k)}
          </Text>
        );
      case "codespan":
        return (
          <Text key={k} style={styles.codeInline}>
            {t.text}
          </Text>
        );
      case "br":
        return "\n";
      case "link":
        return link(styles, t.href, inline(styles, t.tokens ?? [], k), k);
      case "image":
        return link(styles, t.href, decodeEntities(t.text) || "image", k);
      case "html":
        return t.text;
      default:
        return t.raw;
    }
  });
}

function link(styles: Styles, href: string, label: ReactNode, key: string): ReactNode {
  const url = safeHref(href);
  if (!url) return <React.Fragment key={key}>{label}</React.Fragment>;
  return (
    <Text key={key} role="link" style={styles.link} onPress={() => open(url)}>
      {label}
    </Text>
  );
}

function headingSize(depth: number) {
  const fontSize = [24, 21, 18, 16, 15, 15][Math.min(Math.max(depth, 1), 6) - 1];
  return { fontSize, lineHeight: Math.round(fontSize * 1.35) };
}

function makeStyles(t: Theme) {
  return StyleSheet.create({
    root: { gap: t.space.sm + 2 },
    body: { color: t.c.text, fontSize: t.font.size.md, lineHeight: 23 },
    heading: { fontWeight: t.font.weight.bold },
    strong: { fontWeight: t.font.weight.bold },
    em: { fontStyle: "italic" },
    del: { textDecorationLine: "line-through" },
    link: { color: t.c.accentText, textDecorationLine: "underline" },
    codeInline: { fontFamily: t.font.mono, backgroundColor: t.c.codeBg, borderRadius: 4, fontSize: t.font.size.sm },
    fence: { backgroundColor: t.c.codeBg, borderRadius: t.radius.md, borderWidth: hairline, borderColor: t.c.border },
    fenceInner: { padding: t.space.md },
    codeBlock: { color: t.c.text, fontFamily: t.font.mono, fontSize: t.font.size.sm, lineHeight: 19 },
    quote: { borderLeftWidth: 3, borderLeftColor: t.c.borderStrong, paddingLeft: t.space.md, gap: t.space.sm },
    list: { gap: t.space.xs },
    item: { flexDirection: "row", gap: 6 },
    marker: { minWidth: 18, color: t.c.textMuted },
    itemBody: { flex: 1, gap: t.space.xs },
    hr: { height: hairline, backgroundColor: t.c.border, marginVertical: t.space.xs },
    tableScroll: { flexGrow: 0 },
    table: { borderWidth: 1, borderColor: t.c.border, borderRadius: t.radius.sm, overflow: "hidden" },
    tr: { flexDirection: "row" },
    cell: { width: 140, paddingHorizontal: t.space.sm, paddingVertical: t.space.xs, borderColor: t.c.border, borderTopWidth: 1 },
    headerCell: { borderTopWidth: 0, backgroundColor: t.c.surface },
  });
}

const useStyles = themedStyles(makeStyles);
