import React from "react";
import { Pressable, ScrollView, StyleSheet, Text, TextInput, View } from "react-native";
import { useSuperBot } from "../src/SuperBotContext";
import { colors } from "../src/theme";
import { BotAvatar } from "./BotAvatar";

interface Props {
  onSelectBot: (id: string) => void;
  onNewBot: () => void;
  onLogout: () => void;
  onOpenApprovals: () => void;
  /** Shown to admins only; the server refuses the users API to everyone else. */
  onOpenUsers?: () => void;
  compact?: boolean;
}

export function Sidebar({ onSelectBot, onNewBot, onLogout, onOpenApprovals, onOpenUsers, compact }: Props) {
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

  const primary = bots.find((b) => b.primary);
  const q = filter.toLowerCase();
  const list = bots
    .filter((b) => !b.primary && b.hidden === showHidden)
  .filter((b) => !q || b.name.toLowerCase().includes(q) || (b.preview || "").toLowerCase().includes(q));

  return (
    <View style={[styles.sidebar, compact && styles.sidebarCompact]}>
      <View style={styles.topRow}>
        {canWrite ? (
          <Pressable style={styles.iconBtn} onPress={onNewBot}>
            <Text style={styles.iconText}>+</Text>
          </Pressable>
        ) : null}
        <Pressable style={styles.iconBtn} onPress={onLogout}>
          <Text style={styles.iconText}>⎋</Text>
        </Pressable>
      </View>
      <TextInput
        style={styles.search}
        placeholder="Search bots"
        placeholderTextColor={colors.textFaint}
        value={filter}
        onChangeText={setFilter}
      />
      {primary ? (
        <Pressable
          style={[styles.primary, activeId === primary.id && styles.active]}
          onPress={() => onSelectBot(primary.id)}
        >
          <BotAvatar color={primary.color} shape={primary.shape} size={72} />
          <Text style={styles.primaryName}>{primary.name}</Text>
          {handoffs[primary.id] ? <Text style={styles.needsYou}>Needs you</Text> : null}
          {primary.unread && activeId !== primary.id ? <View style={styles.dot} /> : null}
        </Pressable>
      ) : null}
      <ScrollView style={styles.list} contentContainerStyle={{ gap: 2 }}>
        {list.map((b) => (
          <Pressable
            key={b.id}
            style={[styles.row, activeId === b.id && styles.active]}
            onPress={() => onSelectBot(b.id)}
          >
            <BotAvatar color={b.color} shape={b.shape} size={44} />
            <View style={styles.meta}>
              <Text style={styles.name} numberOfLines={1}>
                {b.name}
              </Text>
              {handoffs[b.id] ? (
                <Text style={styles.needsYou} numberOfLines={1}>
                  Needs you on its screen
                </Text>
              ) : (
                <Text style={styles.preview} numberOfLines={1}>
                  {b.working ? `${b.status || "Working"}…` : b.preview || ""}
                </Text>
              )}
            </View>
            {b.unread && activeId !== b.id ? <View style={styles.dot} /> : null}
          </Pressable>
        ))}
        {!list.length ? (
          <Text style={styles.empty}>{showHidden ? "No hidden bots" : "No bots yet"}</Text>
        ) : null}
      </ScrollView>
      <Pressable style={styles.hiddenBtn} onPress={() => setShowHidden(!showHidden)}>
        <Text style={styles.hiddenText}>{showHidden ? "Back to bots" : "Hidden bots"}</Text>
      </Pressable>
      <Pressable style={styles.approvalsBtn} onPress={onOpenApprovals}>
        <Text style={approvals.length ? styles.approvalsWaiting : styles.hiddenText}>Approvals</Text>
        {approvals.length ? (
          <View style={styles.badge}>
            <Text style={styles.badgeText}>{approvals.length}</Text>
          </View>
        ) : null}
      </Pressable>
      {onOpenUsers && me.permissions?.includes("admin") ? (
        <Pressable style={styles.approvalsBtn} onPress={onOpenUsers} accessibilityRole="button">
          <Text style={styles.hiddenText}>Users</Text>
        </Pressable>
      ) : null}
      <View style={styles.meRow}>
        <View style={styles.meAvatar}>
          <Text style={styles.meInitial}>{(me.name || "?")[0]?.toUpperCase()}</Text>
        </View>
        <Text style={styles.meName}>{me.name || "You"}</Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  sidebar: {
    width: 320,
    maxWidth: "100%",
    backgroundColor: colors.bgSidebar,
    borderRightWidth: 1,
    borderRightColor: colors.border,
    padding: 12,
    flex: 1,
  },
  sidebarCompact: { width: "100%", borderRightWidth: 0 },
  topRow: { flexDirection: "row", justifyContent: "flex-end", gap: 8 },
  iconBtn: {
    width: 40,
    height: 40,
    borderRadius: 20,
    backgroundColor: colors.bgHover,
    alignItems: "center",
    justifyContent: "center",
  },
  iconText: { color: colors.text, fontSize: 22, lineHeight: 24 },
  search: {
    marginTop: 10,
    backgroundColor: colors.bgHover,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: colors.border,
    paddingHorizontal: 12,
    paddingVertical: 10,
    color: colors.text,
  },
  primary: {
    alignItems: "center",
    marginVertical: 16,
    padding: 8,
    borderRadius: 14,
  },
  primaryName: { color: colors.text, marginTop: 8, fontSize: 15 },
  list: { flex: 1 },
  row: {
    flexDirection: "row",
    alignItems: "center",
    gap: 10,
    padding: 10,
    borderRadius: 14,
  },
  active: { backgroundColor: colors.bgActive },
  meta: { flex: 1, minWidth: 0 },
  name: { color: "#f0f0f0", fontSize: 16 },
  preview: { color: colors.textDim, fontSize: 14 },
  needsYou: { color: colors.blueDot, fontSize: 14, fontWeight: "600" },
  dot: {
    width: 9,
    height: 9,
    borderRadius: 5,
    backgroundColor: colors.blueDot,
  },
  empty: { color: colors.textFaint, padding: 12, textAlign: "center" },
  hiddenBtn: { paddingVertical: 10 },
  hiddenText: { color: colors.textDim },
  approvalsBtn: { flexDirection: "row", alignItems: "center", justifyContent: "space-between", paddingVertical: 10 },
  approvalsWaiting: { color: colors.text },
  badge: { backgroundColor: colors.danger, borderRadius: 999, minWidth: 22, paddingHorizontal: 7, alignItems: "center" },
  badgeText: { color: "#fff", fontSize: 13, lineHeight: 22 },
  meRow: { flexDirection: "row", alignItems: "center", gap: 10, paddingTop: 8 },
  meAvatar: {
    width: 36,
    height: 36,
    borderRadius: 18,
    backgroundColor: colors.bgActive,
    alignItems: "center",
    justifyContent: "center",
  },
  meInitial: { color: colors.text, fontWeight: "600" },
  meName: { color: colors.textDim },
});