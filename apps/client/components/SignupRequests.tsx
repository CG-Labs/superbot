import React, { useCallback, useEffect, useRef, useState } from "react";
import { ActivityIndicator, Modal, Pressable, ScrollView, StyleSheet, Text, TextInput, View } from "react-native";
import { ApiError, type SuperBotApi } from "../src/api";
import { confirmAsync } from "../src/dialogs";
import { APPROVAL_TTLS, relativeTime, ROLES, SIGN_IN_CHOICES } from "../src/invite";
import { themedStyles, type, useTheme } from "../src/theme";
import type { Role, SignupApproval, SignupRequest } from "../src/types";
import { Chips } from "./Chips";
import { CodeReveal } from "./CodeReveal";
import { kit, usePlaceholder } from "./ui";

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
  const styles = useStyles();
  const t = useTheme();
  const placeholder = usePlaceholder();
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
        placeholderTextColor={placeholder}
        value={reason}
        onChangeText={setReason}
        maxLength={500}
        accessibilityLabel="Reason"
      />
      {error ? <Text style={styles.error}>{error}</Text> : null}
      <View style={styles.actions}>
        <Pressable style={({ pressed }) => [styles.btn, pressed && styles.pressed, busy && styles.disabled]} disabled={busy} onPress={onClose} accessibilityRole="button">
          <Text style={styles.btnText}>Cancel</Text>
        </Pressable>
        <Pressable style={[styles.btn, styles.dangerBtn, busy && styles.disabled]} disabled={busy} onPress={() => void reject()} accessibilityRole="button">
          <Text style={[styles.btnText, styles.danger]}>Reject</Text>
        </Pressable>
        {request.existingUser ? null : (
          <Pressable style={[styles.btn, styles.primary, busy && styles.disabled]} disabled={busy} onPress={() => void approve()} accessibilityRole="button">
            {busy ? <ActivityIndicator color={t.c.onAccent} /> : <Text style={[styles.btnText, styles.primaryText]}>Approve</Text>}
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
  const styles = useStyles();
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
          {list.map((r, i) => (
            <Pressable key={r.id} style={[styles.row, i === 0 && styles.rowFirst]} onPress={() => setOpen(r)} accessibilityRole="button" accessibilityLabel={`Request from ${r.name}`}>
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
          <ScrollView style={styles.sheet} contentContainerStyle={styles.sheetBody}>
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

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    section: { ...k.card, gap: 0, marginBottom: t.space.md },
    heading: { ...k.cardTitle, marginBottom: t.space.xs },
    row: { ...k.row, alignItems: "flex-start", paddingVertical: t.space.sm },
    rowMain: { flex: 1, minWidth: 0, gap: t.space.xxs },
    rowFirst: k.rowFirst,
    rowSide: { alignItems: "flex-end", gap: t.space.xs },
    rowName: { ...k.text, fontWeight: t.font.weight.medium },
    tag: k.tag,
    warnTag: k.tagWarn,
    title: { ...k.title, flex: 0 },
    form: { gap: t.space.sm },
    name: { ...k.strong, ...type(t, "lg") },
    dim: k.dim,
    faint: k.faint,
    useCase: { ...k.inset, ...k.text },
    label: { ...k.label, marginTop: t.space.xs },
    hint: k.faint,
    warn: k.warn,
    input: k.input,
    error: { ...k.error, padding: t.space.xs },
    actions: { ...k.actions, justifyContent: "flex-end", marginTop: t.space.md },
    btn: { ...k.btn, minWidth: 90 },
    btnText: k.btnText,
    pressed: k.btnPressed,
    dangerBtn: k.danger,
    danger: k.dangerText,
    primary: k.primary,
    primaryText: k.primaryText,
    disabled: k.disabled,
    backdrop: k.backdrop,
    sheet: k.sheet,
    sheetBody: k.sheetBody,
  });
});
