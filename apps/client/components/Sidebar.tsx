import React from "react";
import { Pressable, ScrollView, StyleSheet, Text, TextInput, View } from "react-native";
import { isAdmin } from "../src/admin";
import { workingLabel } from "../src/runQueue";
import { canSeeServiceAccounts } from "../src/serviceAccounts";
import { useSuperBot } from "../src/SuperBotContext";
import { hairline, themedStyles, type, useTheme } from "../src/theme";
import { BotAvatar } from "./BotAvatar";

interface Props {
  onSelectBot: (id: string) => void;
  onNewBot: () => void;
  onLogout: () => void;
  onOpenApprovals: () => void;
  /** Everyone's own plan and billing; set only when the server sells plans (ADR 0042). */
  onOpenPlan?: () => void;
  /** Everyone's own secrets for their Bots (ADR 0044). */
  onOpenSecrets?: () => void;
  /** Your team (ADR 0088); set when you're on one or have been invited. */
  onOpenTeam?: () => void;
  /** This device's settings, like App lock (ADR 0078). */
  onOpenSettings?: () => void;
  /** These three are shown to admins only; the server refuses the admin API and console to everyone else. */
  onOpenUsers?: () => void;
  onOpenAudit?: () => void;
  /** Admins: who has access, to review and sign off (ADR 0099). */
  onOpenAccessReview?: () => void;
  onOpenRoles?: () => void;
  /** Scripts' and integrations' own identities and tokens (ADR 0143, 0152): admins, delegates with users.manage for their own (ADR 0182), and any owner (ADR 0239). */
  onOpenServiceAccounts?: () => void;
  /** The server's admin console (ADR 0027), in a new tab or the system browser. */
  onOpenConsole?: () => void;
  /** Set while the server's setup wizard waits for an admin (ADR 0034); opens it in the console. */
  onOpenSetup?: () => void;
  compact?: boolean;
}

export function Sidebar({ onSelectBot, onNewBot, onLogout, onOpenApprovals, onOpenPlan, onOpenSecrets, onOpenTeam, onOpenSettings, onOpenUsers, onOpenAudit, onOpenAccessReview, onOpenRoles, onOpenServiceAccounts, onOpenConsole, onOpenSetup, compact }: Props) {
  const {
    bots,
    activeId,
    filter,
    setFilter,
    showHidden,
    setShowHidden,
    me,
    handoffs,
    approvals,
    canWrite,
  } = useSuperBot();

  const t = useTheme();
  const styles = useStyles();
  const edge = t.scheme === "light" ? t.c.borderStrong : undefined;
  const primary = bots.find((b) => b.primary);
  const q = filter.toLowerCase();
  const list = bots
    .filter((b) => !b.primary && b.hidden === showHidden)
    .filter((b) => !q || b.name.toLowerCase().includes(q) || (b.preview || "").toLowerCase().includes(q));

  const nav = (
    label: string,
    onPress: () => void,
    opts: { role?: "button" | "link"; a11yLabel?: string; hint?: string; strong?: boolean; trailing?: React.ReactNode } = {},
  ) => (
    <Pressable
      style={({ pressed }) => [styles.navRow, pressed && styles.navPressed]}
      onPress={onPress}
      accessibilityRole={opts.role ?? "button"}
      accessibilityLabel={opts.a11yLabel}
      accessibilityHint={opts.hint}
    >
      <Text style={opts.strong ? styles.navStrong : styles.navText}>{label}</Text>
      {opts.trailing}
    </Pressable>
  );

  return (
    <View style={[styles.sidebar, compact && styles.sidebarCompact]}>
      <View style={styles.topRow}>
        <Text style={styles.brand} accessibilityRole="header">
          SuperBot
        </Text>
        {canWrite ? (
          <Pressable style={({ pressed }) => [styles.iconBtn, pressed && styles.navPressed]} onPress={onNewBot} accessibilityRole="button" accessibilityLabel="New Bot">
            <Text style={styles.iconText}>+</Text>
          </Pressable>
        ) : null}
        <Pressable style={({ pressed }) => [styles.iconBtn, pressed && styles.navPressed]} onPress={onLogout} accessibilityRole="button" accessibilityLabel="Sign out">
          <Text style={styles.iconText}>⎋</Text>
        </Pressable>
      </View>
      <TextInput
        style={styles.search}
        placeholder="Search bots"
        placeholderTextColor={t.c.textFaint}
        value={filter}
        onChangeText={setFilter}
        accessibilityLabel="Search bots"
      />
      <ScrollView style={styles.scroll} contentContainerStyle={styles.scrollInner}>
        {primary ? (
          <Pressable
            style={({ pressed }) => [styles.primary, activeId === primary.id && styles.primaryActive, pressed && styles.navPressed]}
            onPress={() => onSelectBot(primary.id)}
          >
            <BotAvatar color={primary.color} shape={primary.shape} size={56} outline={edge} />
            <View style={styles.meta}>
              <Text style={styles.primaryName} numberOfLines={1}>
                {primary.name}
              </Text>
              {handoffs[primary.id] ? <Text style={styles.needsYou}>Needs you</Text> : null}
            </View>
            {primary.unread && activeId !== primary.id ? <View style={styles.dot} /> : null}
          </Pressable>
        ) : null}
        <View style={styles.list}>
          {list.map((b) => (
            <Pressable
              key={b.id}
              style={({ pressed }) => [styles.row, activeId === b.id && styles.active, pressed && styles.navPressed]}
              onPress={() => onSelectBot(b.id)}
            >
              <BotAvatar color={b.color} shape={b.shape} size={40} outline={edge} />
              <View style={styles.meta}>
                <Text style={[styles.name, b.unread && activeId !== b.id && styles.nameUnread]} numberOfLines={1}>
                  {b.name}
                </Text>
                {handoffs[b.id] ? (
                  <Text style={styles.needsYou} numberOfLines={1}>
                    Needs you on its screen
                  </Text>
                ) : (
                  <Text style={styles.preview} numberOfLines={1}>
                    {b.working ? `${workingLabel(b)}…` : b.preview || ""}
                  </Text>
                )}
              </View>
              {b.unread && activeId !== b.id ? <View style={styles.dot} /> : null}
            </Pressable>
          ))}
          {!list.length ? (
            <Text style={styles.empty}>{showHidden ? "No hidden bots" : "No bots yet"}</Text>
          ) : null}
        </View>
        <View style={styles.divider} />
        {nav(showHidden ? "Back to bots" : "Hidden bots", () => setShowHidden(!showHidden))}
        {nav("Approvals", onOpenApprovals, {
          strong: approvals.length > 0,
          trailing: approvals.length ? (
            <View style={styles.badge}>
              <Text style={styles.badgeText}>{approvals.length}</Text>
            </View>
          ) : null,
        })}
        {onOpenPlan ? nav("Plan", onOpenPlan) : null}
        {onOpenSecrets ? nav("Your secrets", onOpenSecrets) : null}
        {onOpenTeam ? nav("Team", onOpenTeam) : null}
        {onOpenSettings ? nav("Settings", onOpenSettings) : null}
        {isAdmin(me) ? (
          <>
            <Text style={styles.section}>Admin</Text>
            {onOpenSetup
              ? nav("Finish server setup ↗", onOpenSetup, {
                  role: "link",
                  a11yLabel: "Finish server setup",
                  hint: "Opens the setup wizard in the server's admin console",
                  strong: true,
                })
              : null}
            {onOpenUsers ? nav("Users", onOpenUsers) : null}
            {onOpenRoles ? nav("Roles", onOpenRoles) : null}
            {onOpenServiceAccounts ? nav("Service accounts", onOpenServiceAccounts) : null}
            {onOpenAudit ? nav("Audit log", onOpenAudit) : null}
            {onOpenAccessReview ? nav("Access review", onOpenAccessReview) : null}
            {onOpenConsole
              ? nav("Admin console ↗", onOpenConsole, {
                  role: "link",
                  a11yLabel: "Admin console",
                  hint: "Opens the server's admin console in the browser",
                })
              : null}
          </>
        ) : onOpenServiceAccounts && canSeeServiceAccounts(me) ? (
          nav("Your service accounts", onOpenServiceAccounts)
        ) : null}
      </ScrollView>
      <View style={styles.meRow}>
        <View style={styles.meAvatar}>
          <Text style={styles.meInitial}>{(me.name || "?")[0]?.toUpperCase()}</Text>
        </View>
        <Text style={styles.meName} numberOfLines={1}>
          {me.name || "You"}
        </Text>
      </View>
    </View>
  );
}

const useStyles = themedStyles((t) =>
  StyleSheet.create({
    sidebar: {
      width: t.layout.sidebar,
      maxWidth: "100%",
      backgroundColor: t.c.surface,
      borderRightWidth: hairline,
      borderRightColor: t.c.border,
      paddingHorizontal: t.space.md,
      paddingTop: t.space.md,
      flexShrink: 0,
    },
    sidebarCompact: { flex: 1, width: "100%", borderRightWidth: 0, backgroundColor: t.c.bg },
    topRow: { flexDirection: "row", alignItems: "center", gap: t.space.xs, paddingLeft: t.space.sm },
    brand: { flex: 1, color: t.c.text, ...type(t, "lg"), fontWeight: t.font.weight.semibold, letterSpacing: -0.2 },
    iconBtn: {
      width: 36,
      height: 36,
      borderRadius: t.radius.pill,
      alignItems: "center",
      justifyContent: "center",
    },
    iconText: { color: t.c.textMuted, fontSize: 20, lineHeight: 22 },
    search: {
      marginTop: t.space.md,
      marginBottom: t.space.sm,
      backgroundColor: t.c.raised,
      borderRadius: t.radius.pill,
      borderWidth: 1,
      borderColor: t.c.border,
      paddingHorizontal: t.space.lg,
      paddingVertical: t.space.sm,
      color: t.c.text,
      ...type(t, "md"),
    },
    scroll: { flex: 1, marginHorizontal: -t.space.xs },
    scrollInner: { paddingHorizontal: t.space.xs, paddingBottom: t.space.lg },
    primary: {
      flexDirection: "row",
      alignItems: "center",
      gap: t.space.md,
      marginTop: t.space.sm,
      marginBottom: t.space.md,
      padding: t.space.md,
      borderRadius: t.radius.lg,
      backgroundColor: t.c.raised,
      borderWidth: 1,
      borderColor: t.c.border,
      boxShadow: t.shadow.card,
    },
    primaryActive: { borderColor: t.c.accentBorder },
    primaryName: { color: t.c.text, ...type(t, "lg"), fontWeight: t.font.weight.semibold },
    list: { gap: t.space.xxs },
    row: {
      flexDirection: "row",
      alignItems: "center",
      gap: t.space.md,
      paddingHorizontal: t.space.sm,
      paddingVertical: t.space.sm,
      borderRadius: t.radius.md,
    },
    active: { backgroundColor: t.c.selected },
    meta: { flex: 1, minWidth: 0 },
    name: { color: t.c.text, ...type(t, "md"), fontWeight: t.font.weight.medium },
    nameUnread: { fontWeight: t.font.weight.bold },
    preview: { color: t.c.textMuted, ...type(t, "sm") },
    needsYou: { color: t.c.accentText, ...type(t, "sm"), fontWeight: t.font.weight.semibold },
    dot: {
      width: 8,
      height: 8,
      borderRadius: 4,
      backgroundColor: t.c.accent,
    },
    empty: { color: t.c.textFaint, padding: t.space.md, textAlign: "center", ...type(t, "sm") },
    divider: { height: hairline, backgroundColor: t.c.border, marginVertical: t.space.md, marginHorizontal: t.space.sm },
    section: {
      color: t.c.textFaint,
      ...type(t, "xs"),
      fontWeight: t.font.weight.semibold,
      textTransform: "uppercase",
      letterSpacing: 0.6,
      paddingHorizontal: t.space.sm,
      marginTop: t.space.md,
      marginBottom: t.space.xs,
    },
    navRow: {
      flexDirection: "row",
      alignItems: "center",
      justifyContent: "space-between",
      paddingHorizontal: t.space.sm,
      paddingVertical: t.space.sm,
      borderRadius: t.radius.sm,
    },
    navPressed: { backgroundColor: t.c.hover },
    navText: { color: t.c.textMuted, ...type(t, "md") },
    navStrong: { color: t.c.text, ...type(t, "md"), fontWeight: t.font.weight.medium },
    badge: {
      backgroundColor: t.c.accent,
      borderRadius: t.radius.pill,
      minWidth: 22,
      paddingHorizontal: 7,
      alignItems: "center",
    },
    badgeText: { color: t.c.onAccent, ...type(t, "xs"), lineHeight: 20, fontWeight: t.font.weight.semibold },
    meRow: {
      flexDirection: "row",
      alignItems: "center",
      gap: t.space.md,
      paddingVertical: t.space.md,
      paddingHorizontal: t.space.sm,
      borderTopWidth: hairline,
      borderTopColor: t.c.border,
    },
    meAvatar: {
      width: 32,
      height: 32,
      borderRadius: 16,
      backgroundColor: t.c.accentSoft,
      alignItems: "center",
      justifyContent: "center",
    },
    meInitial: { color: t.c.accentText, fontWeight: t.font.weight.semibold },
    meName: { flex: 1, color: t.c.text, ...type(t, "md"), fontWeight: t.font.weight.medium },
  }),
);
