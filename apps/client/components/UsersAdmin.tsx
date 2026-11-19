import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  ActivityIndicator,
  Modal,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  useWindowDimensions,
  View,
} from "react-native";
import type { SuperBotApi } from "../src/api";
import { relativeTime, ROLES, signInMethod } from "../src/invite";
import { fetchSsoProviders, type SsoProvider } from "../src/sso";
import { colors } from "../src/theme";
import type { AdminUser } from "../src/types";
import { InviteUserForm } from "./InviteUserForm";
import { SignupRequests } from "./SignupRequests";
import { UserDetail } from "./UserDetail";

interface Props {
  api: SuperBotApi;
  meId?: string | null;
  onBack: () => void;
}

const ROLE_LABEL = Object.fromEntries(ROLES.map((r) => [r.role, r.label]));

export function matchesUser(u: AdminUser, q: string): boolean {
  const s = q.trim().toLowerCase();
  return !s || [u.name, u.email ?? "", u.role, u.status, ...(u.identities ?? []).map((i) => i.provider)].some((v) => v.toLowerCase().includes(s));
}

function UserRow({ u, providers, selected, onPress }: { u: AdminUser; providers: SsoProvider[]; selected: boolean; onPress: () => void }) {
  const label = (id: string) => providers.find((p) => p.id === id)?.label ?? id;
  return (
    <Pressable style={[styles.row, selected && styles.selected]} onPress={onPress} accessibilityRole="button" accessibilityLabel={`User ${u.name}`}>
      <View style={styles.rowMain}>
        <Text style={styles.name} numberOfLines={1}>
          {u.name}
          {u.breakGlass ? <Text style={styles.faint}> · owner</Text> : null}
        </Text>
        <Text style={styles.dim} numberOfLines={1}>
          {u.email ?? "No email"}
        </Text>
        <View style={styles.tags}>
          <Text style={[styles.tag, u.role === "admin" && styles.adminTag]}>{ROLE_LABEL[u.role] ?? u.role}</Text>
          {u.status === "disabled" ? <Text style={[styles.tag, styles.disabledTag]}>Disabled</Text> : null}
          {(u.identities ?? []).map((i) => (
            <Text key={i.id} style={styles.tag}>
              {label(i.provider)}
            </Text>
          ))}
          {u.pendingCodes ? <Text style={[styles.tag, styles.codeTag]}>Code waiting</Text> : null}
        </View>
      </View>
      <View style={styles.rowSide}>
        <Text style={styles.faint}>Last sign-in</Text>
        <Text style={styles.dim}>{relativeTime(u.lastLoginAt)}</Text>
        {u.lastLogin?.authMethod ? <Text style={styles.faint}>with {signInMethod(u.lastLogin.authMethod, u.lastLogin.idpProvider && label(u.lastLogin.idpProvider))}</Text> : null}
        <Text style={styles.faint}>Added {new Date(u.createdAt).toLocaleDateString()}</Text>
      </View>
    </Pressable>
  );
}

/** The admin portal: requests for access, people, their roles, sign-in codes, sessions, SSO links, and Bot access (ADR 0021, 0022). */
export function UsersAdmin({ api, meId, onBack }: Props) {
  const { width } = useWindowDimensions();
  const wide = width >= 900;
  const [users, setUsers] = useState<AdminUser[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [inviting, setInviting] = useState(false);
  // Selected once the invite closes, so the user's panel never covers the one-time code.
  const created = useRef<string | null>(null);
  const [providers, setProviders] = useState<SsoProvider[]>([]);

  const load = useCallback(async () => {
    try {
      setUsers(await api.users());
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Couldn't load users");
    }
  }, [api]);

  // Every way out (Done, Cancel, Android Back) takes the new user, so it isn't opened later.
  const closeInvite = () => {
    setInviting(false);
    if (created.current) setSelectedId(created.current);
    created.current = null;
    void load();
  };

  useEffect(() => {
    void load();
    void fetchSsoProviders(api.baseUrl).then(setProviders);
  }, [api, load]);

  const selected = users?.find((u) => u.id === selectedId) ?? null;
  const list = (users ?? []).filter((u) => matchesUser(u, query));
  const detail = selected ? (
    <UserDetail key={selected.id} api={api} user={selected} meId={meId} providers={providers} onChanged={load} />
  ) : null;

  return (
    <View style={styles.root}>
      <View style={styles.header}>
        <Pressable onPress={onBack} accessibilityRole="button" accessibilityLabel="Back to Bots">
          <Text style={styles.back}>‹ Bots</Text>
        </Pressable>
        <Text style={styles.title}>Users</Text>
        <Pressable style={styles.primaryBtn} onPress={() => setInviting(true)} accessibilityRole="button">
          <Text style={styles.primaryText}>Add user</Text>
        </Pressable>
      </View>
      <View style={styles.body}>
        <View style={wide ? styles.listPaneWide : styles.listPane}>
          <TextInput
            style={styles.search}
            placeholder="Search people"
            placeholderTextColor={colors.textFaint}
            value={query}
            onChangeText={setQuery}
          />
          {error ? <Text style={styles.error}>{error}</Text> : null}
          {users == null && !error ? <ActivityIndicator color={colors.textDim} style={{ marginTop: 20 }} /> : null}
          <ScrollView contentContainerStyle={{ gap: 4, paddingBottom: 24 }}>
            <SignupRequests
              api={api}
              onApproved={(id) => {
                setSelectedId(id);
                void load();
              }}
            />
            {list.map((u) => (
              <UserRow key={u.id} u={u} providers={providers} selected={u.id === selectedId} onPress={() => setSelectedId(u.id)} />
            ))}
            {users && !list.length ? <Text style={styles.empty}>{query ? "Nobody matches." : "No users yet."}</Text> : null}
          </ScrollView>
        </View>
        {wide ? (
          <ScrollView style={styles.detailPane} contentContainerStyle={{ padding: 20 }}>
            {detail ?? <Text style={styles.empty}>Pick someone to manage their role, sign-ins, and access.</Text>}
          </ScrollView>
        ) : null}
      </View>
      {!wide ? (
        <Modal visible={!!selected} animationType="slide" onRequestClose={() => setSelectedId(null)}>
          <View style={styles.modalRoot}>
            <Pressable style={styles.modalHeader} onPress={() => setSelectedId(null)} accessibilityRole="button">
              <Text style={styles.back}>‹ Users</Text>
            </Pressable>
            <ScrollView contentContainerStyle={{ padding: 16, paddingRight: 20 }}>{detail}</ScrollView>
          </View>
        </Modal>
      ) : null}
      <Modal visible={inviting} animationType="slide" transparent onRequestClose={closeInvite} testID="invite-modal">
        <View style={styles.backdrop}>
          <ScrollView style={styles.sheet} contentContainerStyle={{ padding: 20, gap: 8 }}>
            <Text style={styles.title}>Add user</Text>
            {inviting ? (
              <InviteUserForm
                api={api}
                onCreated={(u) => {
                  created.current = u.id;
                  void load();
                }}
                onClose={closeInvite}
              />
            ) : null}
          </ScrollView>
        </View>
      </Modal>
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
  body: { flex: 1, flexDirection: "row" },
  listPane: { flex: 1, padding: 12 },
  listPaneWide: { width: 460, padding: 12, borderRightWidth: 1, borderRightColor: colors.border },
  detailPane: { flex: 1 },
  search: {
    backgroundColor: colors.bgHover,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: colors.border,
    paddingHorizontal: 12,
    paddingVertical: 10,
    color: colors.text,
    marginBottom: 8,
  },
  row: { flexDirection: "row", gap: 12, padding: 12, borderRadius: 14 },
  selected: { backgroundColor: colors.bgActive },
  rowMain: { flex: 1, minWidth: 0, gap: 2 },
  rowSide: { alignItems: "flex-end", gap: 2 },
  name: { color: colors.text, fontSize: 16 },
  dim: { color: colors.textDim },
  faint: { color: colors.textFaint, fontSize: 12 },
  tags: { flexDirection: "row", flexWrap: "wrap", gap: 6, marginTop: 4 },
  tag: { color: colors.textDim, fontSize: 12, borderWidth: 1, borderColor: colors.border, borderRadius: 999, paddingHorizontal: 8, paddingVertical: 2 },
  adminTag: { color: colors.blueDot, borderColor: "#24406e" },
  disabledTag: { color: colors.danger, borderColor: "#5a2a2c" },
  codeTag: { color: colors.warning, borderColor: "#5a4520" },
  empty: { color: colors.textFaint, padding: 12, textAlign: "center" },
  error: { color: colors.danger, padding: 8 },
  modalRoot: { flex: 1, backgroundColor: colors.bgMain, paddingTop: 32 },
  modalHeader: { padding: 16, borderBottomWidth: 1, borderBottomColor: colors.border, backgroundColor: colors.bgMain },
  backdrop: { flex: 1, backgroundColor: "rgba(0,0,0,0.5)", justifyContent: "center", padding: 16 },
  sheet: { flexGrow: 0, maxHeight: "90%", width: "100%", maxWidth: 560, alignSelf: "center", backgroundColor: colors.bgSidebar, borderRadius: 16 },
});
