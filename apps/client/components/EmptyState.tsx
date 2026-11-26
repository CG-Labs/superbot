import React from "react";
import { StyleSheet, Text, View } from "react-native";
import { themedStyles, type } from "../src/theme";
import { PillButton } from "./ui";

export interface StateAction {
  label: string;
  onPress: () => void;
  hint?: string;
}

interface Props {
  title: string;
  message?: string;
  /** Art above the title, such as a Bot's avatar; otherwise `glyph` in a soft circle. */
  art?: React.ReactNode;
  glyph?: string;
  /** The one next step, as a primary button. */
  action?: StateAction;
  secondaryAction?: StateAction;
  /** Smaller, for a list that's empty inside a panel or the sidebar. */
  compact?: boolean;
}

/** A friendly word where there's nothing to show yet, with what to do next. */
export function EmptyState({ title, message, art, glyph, action, secondaryAction, compact }: Props) {
  const styles = useStyles();
  return (
    <View style={[styles.root, compact && styles.rootCompact]} testID="empty-state">
      {art ??
        (glyph ? (
          <View style={[styles.circle, compact && styles.circleCompact]} importantForAccessibility="no-hide-descendants" accessibilityElementsHidden>
            <Text style={compact ? styles.glyphCompact : styles.glyph} maxFontSizeMultiplier={1.2}>
              {glyph}
            </Text>
          </View>
        ) : null)}
      <Text role="heading" style={compact ? styles.titleCompact : styles.title}>
        {title}
      </Text>
      {message ? <Text style={compact ? styles.messageCompact : styles.message}>{message}</Text> : null}
      {action || secondaryAction ? (
        <View style={styles.actions}>
          {action ? <PillButton tone="primary" small={compact} label={action.label} hint={action.hint} onPress={action.onPress} /> : null}
          {secondaryAction ? (
            <PillButton small={compact} label={secondaryAction.label} hint={secondaryAction.hint} onPress={secondaryAction.onPress} />
          ) : null}
        </View>
      ) : null}
    </View>
  );
}

const useStyles = themedStyles((t) =>
  StyleSheet.create({
    root: { alignItems: "center", justifyContent: "center", gap: t.space.sm, paddingVertical: t.space.xxxl, paddingHorizontal: t.space.xl },
    rootCompact: { paddingVertical: t.space.xl, paddingHorizontal: t.space.md, gap: t.space.xs },
    circle: {
      width: 64,
      height: 64,
      borderRadius: t.radius.pill,
      backgroundColor: t.c.accentSoft,
      alignItems: "center",
      justifyContent: "center",
      marginBottom: t.space.xs,
    },
    circleCompact: { width: 40, height: 40, marginBottom: t.space.xxs },
    glyph: { color: t.c.accentText, fontSize: 28, lineHeight: 34 },
    glyphCompact: { color: t.c.accentText, fontSize: 18, lineHeight: 22 },
    title: { color: t.c.text, ...type(t, "xl"), fontWeight: t.font.weight.semibold, textAlign: "center", marginTop: t.space.xs },
    titleCompact: { color: t.c.text, ...type(t, "md"), fontWeight: t.font.weight.semibold, textAlign: "center" },
    message: { color: t.c.textMuted, ...type(t, "md"), textAlign: "center", maxWidth: 380 },
    messageCompact: { color: t.c.textMuted, ...type(t, "sm"), textAlign: "center", maxWidth: 280 },
    actions: { flexDirection: "row", flexWrap: "wrap", justifyContent: "center", gap: t.space.sm, marginTop: t.space.md },
  }),
);
