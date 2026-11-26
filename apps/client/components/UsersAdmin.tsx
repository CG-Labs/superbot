import React, { useCallback, useEffect, useRef, useState } from "react";
import {
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
import { errorText } from "../src/errors";
import { EmptyState } from "./EmptyState";
import { InlineError } from "./ErrorState";
import { ListSkeleton } from "./Skeleton";
import { relativeTime, ROLES, signInMethod } from "../src/invite";
import { fetchSsoProviders, type SsoProvider } from "../src/sso";
import { endsLabel } from "../src/roles";
import { hairline, themedStyles, useTheme } from "../src/theme";
import type { AdminUser, CustomRole } from "../src/types";
import { InviteUserForm } from "./InviteUserForm";
import { SignupRequests } from "./SignupRequests";
import { UserDetail } from "./UserDetail";
import { DetailSheet, PaneTransition, useModalAnimation } from "./Shell";
import { kit, PageHeader } from "./ui";

interface Props {
  api: SuperBotApi;
  meId?: string | null;
  onBack: () => void;
}

const ROLE_LABEL = Object.fromEntries(ROLES.map((r) => [r.role, r.label]));

export function matchesUser(u: AdminUser, q: string): boolean {
  const s = q.trim().toLowerCase();
  return !s || [u.name, u.email ?? "", u.role, u.status, u.customRole?.name ?? "", ...(u.identities ?? []).map((i) => i.provider)].some((v) => v.toLowerCase().includes(s));
}

function UserRow({ u, providers, selected, onPress }: { u: AdminUser; providers: SsoProvider[]; selected: boolean; onPress: () => void }) {
  const styles = useStyles();
  const label = (id: string) => providers.find((p) => p.id === id)?.label ?? id;
  return (
    <Pressable
      style={[styles.row, selected && styles.selected]}
      onPress={onPress}
      accessibilityRole="button"
      accessibilityLabel={`User ${u.name}`}
      accessibilityState={{ selected }}
    >
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
          {u.customRole ? (
            <Text style={styles.tag}>
              {u.customRole.name}
              {u.customRole.expiresAt ? ` · ${endsLabel(u.customRole.expiresAt, Date.now())}` : ""}
            </Text>
          ) : null}
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
  const styles = useStyles();
  const t = useTheme();
  const { width } = useWindowDimensions();
  const wide = width >= 900;
  const modalAnimation = useModalAnimation();
  const [users, setUsers] = useState<AdminUser[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [inviting, setInviting] = useState(false);
  // Selected once the invite closes, so the user's panel never covers the one-time code.
  const created = useRef<string | null>(null);
  const inviteBusy = useRef(false);
  const setInviteBusy = useCallback((b: boolean) => {
    inviteBusy.current = b;
  }, []);
  const [providers, setProviders] = useState<SsoProvider[]>([]);
  const [roles, setRoles] = useState<CustomRole[]>([]);

  const load = useCallback(async () => {
    try {
      setUsers(await api.users());
      setError(null);
    } catch (err) {
      setError(errorText(err, "Couldn't load users"));
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
    api.roles().then(
      (v) => setRoles(v.roles),
      () => setRoles([]),
    );
  }, [api, load]);

  const selected = users?.find((u) => u.id === selectedId) ?? null;
  const list = (users ?? []).filter((u) => matchesUser(u, query));
  const detail = selected ? (
    <UserDetail key={selected.id} api={api} user={selected} meId={meId} providers={providers} roles={roles} onChanged={load} />
  ) : null;

  return (
    <View style={styles.root}>
      <PageHeader
        title="Users"
        onBack={onBack}
        right={
          <Pressable style={styles.primaryBtn} onPress={() => setInviting(true)} accessibilityRole="button">
            <Text style={styles.primaryText}>Add user</Text>
          </Pressable>
        }
      />
      <View style={styles.body}>
        <View style={wide ? styles.listPaneWide : styles.listPane}>
          <TextInput
            style={styles.search}
            placeholder="Search people"
            placeholderTextColor={t.c.textFaint}
            value={query}
            onChangeText={setQuery}
            accessibilityLabel="Search people"
          />
          {error ? <InlineError message={error} onRetry={load} /> : null}
          {users == null && !error ? <ListSkeleton label="Loading users" rows={4} /> : null}
          <ScrollView contentContainerStyle={styles.list}>
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
            {users && !list.length ? (
              query ? (
                <EmptyState compact glyph="⌕" title="Nobody matches" message="Try a name, email, role, or sign-in provider." />
              ) : (
                <EmptyState compact glyph="+" title="No users yet" message="Add someone with Add user, or approve a request above." />
              )
            ) : null}
          </ScrollView>
        </View>
        {wide ? (
          <ScrollView style={styles.detailPane} contentContainerStyle={styles.detailBody}>
            <PaneTransition paneKey={selected?.id ?? ""}>
              {detail ?? <Text style={styles.empty}>Pick someone to manage their role, sign-ins, and access.</Text>}
            </PaneTransition>
          </ScrollView>
        ) : null}
      </View>
      {!wide ? (
        <DetailSheet visible={!!selected} onClose={() => setSelectedId(null)} backText="‹ Users" backLabel="Back to users">
          {detail}
        </DetailSheet>
      ) : null}
      <Modal
        visible={inviting}
        animationType={modalAnimation}
        transparent
        onRequestClose={() => {
          if (!inviteBusy.current) closeInvite();
        }}
        testID="invite-modal"
      >
        <View style={styles.backdrop}>
          <ScrollView style={styles.sheet} contentContainerStyle={styles.sheetBody}>
            <Text style={styles.sheetTitle} role="heading">
              Add user
            </Text>
            {inviting ? (
              <InviteUserForm
                api={api}
                onCreated={(u) => {
                  created.current = u.id;
                  void load();
                }}
                onClose={closeInvite}
                onBusy={setInviteBusy}
              />
            ) : null}
          </ScrollView>
        </View>
      </Modal>
    </View>
  );
}

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    root: k.root,
    primaryBtn: { ...k.btn, ...k.btnSmall, ...k.primary },
    primaryText: { ...k.btnText, ...k.primaryText },
    body: { flex: 1, flexDirection: "row" },
    listPane: { flex: 1, padding: t.space.md },
    listPaneWide: { width: 440, padding: t.space.md, backgroundColor: t.c.surface, borderRightWidth: hairline, borderRightColor: t.c.border },
    detailPane: { flex: 1 },
    detailBody: { padding: t.space.xl, width: "100%", maxWidth: 760, alignSelf: "center" },
    list: { gap: t.space.xxs, paddingBottom: t.space.xl },
    search: { ...k.search, marginBottom: t.space.sm },
    row: { flexDirection: "row", gap: t.space.md, padding: t.space.md, borderRadius: t.radius.md },
    selected: { backgroundColor: t.c.selected },
    rowMain: { flex: 1, minWidth: 0, gap: t.space.xxs },
    rowSide: { alignItems: "flex-end", gap: t.space.xxs },
    name: { ...k.text, fontWeight: t.font.weight.medium },
    dim: k.dim,
    faint: k.faint,
    tags: { ...k.tags, marginTop: t.space.xs },
    tag: k.tag,
    adminTag: k.tagAccent,
    disabledTag: k.tagDanger,
    codeTag: k.tagWarn,
    empty: k.empty,
    error: { ...k.error, padding: t.space.sm },
    backdrop: k.backdrop,
    sheet: k.sheet,
    sheetBody: k.sheetBody,
    sheetTitle: { ...k.title, flex: 0 },
  });
});
