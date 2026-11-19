import React, { useCallback, useEffect, useRef, useState } from "react";
import { ActivityIndicator, Modal, Pressable, ScrollView, StyleSheet, Text, TextInput, View } from "react-native";
import { ApiError, type SuperBotApi } from "../src/api";
import { confirmAsync } from "../src/dialogs";
import { APPROVAL_TTLS, relativeTime, ROLES, SIGN_IN_CHOICES } from "../src/invite";
import { colors } from "../src/theme";
import type { Role, SignupApproval, SignupRequest } from "../src/types";
import { Chips } from "./Chips";
import { CodeReveal } from "./CodeReveal";

interface Props {
  api: SuperBotApi;
  /** Called with the new user once the approval's code is closed. */
  onApproved: (userId: string) => void;
}

function Review({
  api,
  request,
  onApproved,
  onClose,
  onBusy,
}: {
  api: SuperBotApi;
  request: SignupRequest;
  onApproved: (a: SignupApproval) => void;
  onClose: () => void;
  /** While approving or rejecting: the sheet must stay open, or the new code is lost. */
  onBusy: (busy: boolean) => void;
}) {
  const [role, setRole] = useState<Role>("member");
  const [ttl, setTtl] = useState<number>(APPROVAL_TTLS[1].minutes);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [made, setMade] = useState<SignupApproval | null>(null);
  useEffect(() => onBusy(busy), [busy, onBusy]);

  const run = async (f: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await f();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed");
    } finally {
      setBusy(false);
    }
  };

  const approve = () =>
    run(async () => {
      const a = await api.approveSignup(request.id, { role, ttlMinutes: ttl });
      onApproved(a);
      setMade(a);
    });

  const reject = async () => {
    if (!(await confirmAsync(`Reject ${request.name}'s request?`, "Nobody is told. You can still add them later.", "Reject"))) return;
    void run(async () => {
      await api.rejectSignup(request.id, reason.trim());
      onClose();
    });
  };

  if (made) {
    return (
      <View style={styles.form}>
        <CodeReveal code={made} name={made.user.name} serverUrl={api.baseUrl} onDone={onClose} />
        {made.sso.length ? (
          <Text style={styles.hint}>
            To skip codes, link their {made.sso.map((p) => p.label).join(" or ")} account from their page once they tell you their id there.
          </Text>
        ) : null}
      </View>
    );
  }

  const roleHint = ROLES.find((r) => r.role === role)?.hint;
  return (
    <View style={styles.form}>
      <Text style={styles.name}>{request.name}</Text>
      <Text style={styles.dim} selectable>
        {request.email}
      </Text>
      <Text style={styles.dim}>
        {request.company} · {request.teamSize} people · prefers {SIGN_IN_CHOICES[request.signIn] ?? request.signIn}
      </Text>
      <Text style={styles.useCase} selectable>
        {request.useCase}
      </Text>
      <Text style={styles.faint}>Asked {relativeTime(request.createdAt)}</Text>
      {request.existingUser ? (
        <Text style={styles.warn}>A user with this email exists already. Reject this request, or make them a code from their page.</Text>
      ) : (
        <>
          <Text style={styles.label}>Role</Text>
          <Chips options={ROLES.map((r) => ({ value: r.role, label: r.label }))} value={role} onChange={setRole} disabled={busy} />
          {roleHint ? <Text style={styles.hint}>{roleHint}</Text> : null}
          <Text style={styles.label}>Code expires after</Text>
          <Chips options={APPROVAL_TTLS.map((t) => ({ value: t.minutes, label: t.label }))} value={ttl} onChange={setTtl} disabled={busy} />
          <Text style={styles.hint}>No email is sent: you hand them the code or invite.</Text>
        </>
      )}
      <Text style={styles.label}>Reason, if you reject</Text>
      <TextInput
        style={styles.input}
        placeholder="Only admins see it (optional)"
        placeholderTextColor={colors.textFaint}
        value={reason}
        onChangeText={setReason}
        maxLength={500}
        accessibilityLabel="Reason"
      />
      {error ? <Text style={styles.error}>{error}</Text> : null}
      <View style={styles.actions}>
        <Pressable style={[styles.btn, busy && styles.disabled]} disabled={busy} onPress={onClose} accessibilityRole="button">
          <Text style={styles.btnText}>Cancel</Text>
        </Pressable>
        <Pressable style={[styles.btn, busy && styles.disabled]} disabled={busy} onPress={() => void reject()} accessibilityRole="button">
          <Text style={[styles.btnText, styles.danger]}>Reject</Text>
        </Pressable>
        {request.existingUser ? null : (
          <Pressable style={[styles.btn, styles.primary, busy && styles.disabled]} disabled={busy} onPress={() => void approve()} accessibilityRole="button">
            {busy ? <ActivityIndicator color="#111" /> : <Text style={[styles.btnText, styles.primaryText]}>Approve</Text>}
          </Pressable>
        )}
      </View>
    </View>
  );
}

/**
 * Pending requests for access from the landing page (ADR 0022), above the people in the
 * admin portal. Approving makes the user and their one-time code; nothing shows when
 * there are none, or the server is older than sign-ups.
 */
export function SignupRequests({ api, onApproved }: Props) {
  const [list, setList] = useState<SignupRequest[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<SignupRequest | null>(null);
  // Opened once the code closes, so the user's panel never covers it.
  const approved = useRef<string | null>(null);
  const busy = useRef(false);
  const setBusy = useCallback((b: boolean) => {
    busy.current = b;
  }, []);

  const load = useCallback(async () => {
    try {
      setList(await api.signups("pending"));
      setError(null);
    } catch (err) {
      setList([]);
      setError(err instanceof ApiError && err.status === 404 ? null : err instanceof Error ? err.message : "Couldn't load requests");
    }
  }, [api]);

  useEffect(() => {
    void load();
  }, [load]);

  const close = () => {
    setOpen(null);
    if (approved.current) onApproved(approved.current);
    approved.current = null;
    void load();
  };

  return (
    <>
      {list.length || error ? (
        <View style={styles.section} testID="signup-requests">
          <Text style={styles.heading}>Requests{list.length ? ` · ${list.length}` : ""}</Text>
          {error ? <Text style={styles.error}>{error}</Text> : null}
          {list.map((r) => (
            <Pressable key={r.id} style={styles.row} onPress={() => setOpen(r)} accessibilityRole="button" accessibilityLabel={`Request from ${r.name}`}>
              <View style={styles.rowMain}>
                <Text style={styles.rowName} numberOfLines={1}>
                  {r.name} <Text style={styles.faint}>· {r.company}</Text>
                </Text>
                <Text style={styles.dim} numberOfLines={1}>
                  {r.email}
                </Text>
              </View>
              <View style={styles.rowSide}>
                <Text style={styles.faint}>{relativeTime(r.createdAt)}</Text>
                {r.existingUser ? <Text style={[styles.tag, styles.warnTag]}>Has an account</Text> : null}
              </View>
            </Pressable>
          ))}
        </View>
      ) : null}
      <Modal
        visible={!!open}
        animationType="slide"
        transparent
        onRequestClose={() => {
          if (!busy.current) close();
        }}
        testID="signup-modal"
      >
        <View style={styles.backdrop}>
          <ScrollView style={styles.sheet} contentContainerStyle={{ padding: 20, gap: 8 }}>
            <Text style={styles.title}>Request for access</Text>
            {open ? (
              <Review
                api={api}
                request={open}
                onApproved={(a) => {
                  approved.current = a.user.id;
                  void load();
                }}
                onClose={close}
                onBusy={setBusy}
              />
            ) : null}
          </ScrollView>
        </View>
      </Modal>
    </>
  );
}

const styles = StyleSheet.create({
  section: { gap: 4, marginBottom: 12, paddingBottom: 8, borderBottomWidth: 1, borderBottomColor: colors.border },
  heading: { color: colors.textDim, fontSize: 13, fontWeight: "600", paddingHorizontal: 12, paddingTop: 4 },
  row: { flexDirection: "row", gap: 12, padding: 12, borderRadius: 14, backgroundColor: colors.bgHover },
  rowMain: { flex: 1, minWidth: 0, gap: 2 },
  rowSide: { alignItems: "flex-end", gap: 4 },
  rowName: { color: colors.text, fontSize: 16 },
  tag: { fontSize: 12, borderWidth: 1, borderRadius: 999, paddingHorizontal: 8, paddingVertical: 2 },
  warnTag: { color: colors.warning, borderColor: "#5a4520" },
  title: { color: colors.text, fontSize: 20, fontWeight: "600" },
  form: { gap: 8 },
  name: { color: colors.text, fontSize: 18, fontWeight: "600" },
  dim: { color: colors.textDim },
  faint: { color: colors.textFaint, fontSize: 12 },
  useCase: { color: colors.text, backgroundColor: colors.bgBubble, borderRadius: 10, padding: 10, lineHeight: 19 },
  label: { color: colors.textDim, fontSize: 14, marginTop: 6 },
  hint: { color: colors.textFaint, fontSize: 13 },
  warn: { color: colors.warning },
  input: {
    backgroundColor: colors.bgBubble,
    borderColor: colors.border,
    borderWidth: 1,
    borderRadius: 12,
    paddingHorizontal: 14,
    paddingVertical: 10,
    color: colors.text,
    fontSize: 16,
  },
  error: { color: colors.danger, padding: 4 },
  actions: { flexDirection: "row", justifyContent: "flex-end", gap: 10, marginTop: 12 },
  btn: { paddingVertical: 9, paddingHorizontal: 18, borderRadius: 999, borderWidth: 1, borderColor: "#3a3a3a", minWidth: 90, alignItems: "center" },
  btnText: { color: colors.text, fontSize: 15 },
  danger: { color: colors.danger },
  primary: { backgroundColor: "#f2f2f2", borderColor: "#f2f2f2" },
  primaryText: { color: "#111" },
  disabled: { opacity: 0.5 },
  backdrop: { flex: 1, backgroundColor: "rgba(0,0,0,0.5)", justifyContent: "center", padding: 16 },
  sheet: { flexGrow: 0, maxHeight: "90%", width: "100%", maxWidth: 560, alignSelf: "center", backgroundColor: colors.bgSidebar, borderRadius: 16 },
});
