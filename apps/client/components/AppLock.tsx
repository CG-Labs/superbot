import React, { createContext, useCallback, useContext, useEffect, useReducer, useRef, useState } from "react";
import { AppState, Image, Modal, Platform, Pressable, StyleSheet, Text, View } from "react-native";
import {
  availabilityFrom,
  availabilityProblem,
  DEFAULT_LOCK_SETTINGS,
  LOCK_SETTINGS_KEY,
  lockReducer,
  parseLockSettings,
  serializeLockSettings,
  STUCK_MESSAGE,
  stuckBeforePrompt,
  unlockOutcome,
  UNLOCKED,
  type Availability,
  type LockAfter,
  type LockSettings,
} from "../src/appLock";
import { storeDelete, storeGet, storeSet } from "../src/auth";
import { localAuth as deviceAuth, type LocalAuth } from "../src/localAuth";
import { useSuperBot } from "../src/SuperBotContext";
import { colors } from "../src/theme";

export interface LockStore {
  get(): Promise<string | null>;
  set(value: string): Promise<void>;
  clear(): Promise<void>;
}

const deviceStore: LockStore = {
  get: () => storeGet(LOCK_SETTINGS_KEY),
  set: (v) => storeSet(LOCK_SETTINGS_KEY, v),
  clear: () => storeDelete(LOCK_SETTINGS_KEY),
};

interface AppLockValue {
  settings: LockSettings;
  /** Null while the device is being checked. */
  availability: Availability | null;
  /** Asks for biometrics once, so nobody turns on a lock they can't open. Returns a problem, or null. */
  enable(): Promise<string | null>;
  disable(): Promise<void>;
  setLockAfter(v: LockAfter): Promise<void>;
}

const AppLockContext = createContext<AppLockValue | null>(null);

export function useAppLock(): AppLockValue {
  const v = useContext(AppLockContext);
  if (!v) throw new Error("useAppLock must be used within AppLockProvider");
  return v;
}

interface Props {
  children: React.ReactNode;
  /** Swapped in tests. */
  auth?: LocalAuth;
  store?: LockStore;
  os?: string;
  now?: () => number;
}

/**
 * App lock (ADR 0078). Off by default. When on, a signed-in app asks for biometrics (or the
 * device passcode) on cold start and after a set time in the background, and hides its
 * content while inactive so the app switcher shows no chats. The screens stay mounted under
 * the lock, so drafts survive it.
 */
export function AppLockProvider({ children, auth = deviceAuth, store = deviceStore, os = Platform.OS, now = Date.now }: Props) {
  const { api, logout } = useSuperBot();
  const supported = os !== "web";
  const [settings, setSettings] = useState<LockSettings>(DEFAULT_LOCK_SETTINGS);
  const [loaded, setLoaded] = useState(!supported);
  const [availability, setAvailability] = useState<Availability | null>(supported ? null : { kind: "unsupported" });
  const [state, dispatch] = useReducer(lockReducer, UNLOCKED);
  const [message, setMessage] = useState<string | null>(null);
  const [stuck, setStuck] = useState(false);
  const [busy, setBusy] = useState(false);
  const settingsRef = useRef(settings);
  settingsRef.current = settings;
  /** A system prompt (Face ID, or Android's passcode screen) moves the app out of the foreground; that is not leaving. */
  const prompting = useRef(false);
  const autoPrompted = useRef(false);

  const probe = useCallback(async () => {
    if (!supported) return null;
    try {
      return await auth.probe();
    } catch {
      return null;
    }
  }, [auth, supported]);

  const refreshAvailability = useCallback(async () => {
    if (!supported) return;
    setAvailability(availabilityFrom(os, await probe()));
  }, [os, probe, supported]);

  useEffect(() => {
    if (!supported) return;
    let live = true;
    void (async () => {
      let s = DEFAULT_LOCK_SETTINGS;
      try {
        s = parseLockSettings(await store.get());
      } catch {
        // Unreadable storage means off, never a lock nobody can open.
      }
      if (!live) return;
      setSettings(s);
      dispatch({ type: "start", settings: s });
      setLoaded(true);
    })();
    void refreshAvailability();
    return () => {
      live = false;
    };
  }, [refreshAvailability, store, supported]);

  useEffect(() => {
    if (!supported) return;
    const sub = AppState.addEventListener("change", (s) => {
      if (prompting.current) return;
      dispatch({ type: "appState", state: s, now: now(), settings: settingsRef.current });
      if (s === "active") void refreshAvailability();
    });
    return () => sub.remove();
  }, [now, refreshAvailability, supported]);

  // Storage first, so the screen never shows a setting the next launch won't have.
  const save = useCallback(
    async (s: LockSettings) => {
      if (s.enabled) await store.set(serializeLockSettings(s));
      else await store.clear();
      setSettings(s);
    },
    [store],
  );

  // Signing out, here or anywhere, turns the lock off: it guards a session, and a device
  // that can no longer unlock must not lock the next sign-in too.
  const hadApi = useRef(false);
  useEffect(() => {
    if (api) {
      hadApi.current = true;
      return;
    }
    if (!hadApi.current) return;
    hadApi.current = false;
    dispatch({ type: "unlocked" });
    setMessage(null);
    setStuck(false);
    if (!settingsRef.current.enabled) return;
    setSettings({ ...settingsRef.current, enabled: false });
    void store.clear().catch(() => {});
  }, [api, store]);

  const unlock = useCallback(async () => {
    if (prompting.current) return;
    prompting.current = true;
    setMessage(null);
    setBusy(true);
    try {
      if (stuckBeforePrompt(await probe())) {
        setStuck(true);
        setMessage(STUCK_MESSAGE);
        return;
      }
      const r = await auth.authenticate("Unlock SuperBot");
      if (r.success) {
        setStuck(false);
        dispatch({ type: "unlocked" });
      } else {
        const o = unlockOutcome(r.error);
        setStuck(o.stuck);
        setMessage(o.message);
      }
    } catch (e) {
      setMessage(e instanceof Error ? e.message : "Couldn't unlock. Try again.");
    } finally {
      prompting.current = false;
      setBusy(false);
    }
  }, [auth, probe]);

  const showLock = supported && !!api && loaded && state.locked;
  // Prompt once each time the lock comes to the front; after a cancel, the button asks again.
  useEffect(() => {
    if (!showLock || state.covered) {
      autoPrompted.current = false;
      return;
    }
    if (autoPrompted.current || AppState.currentState !== "active") return;
    autoPrompted.current = true;
    void unlock();
  }, [showLock, state.covered, unlock]);

  const enable = useCallback(async () => {
    if (prompting.current) return "Finish the check that's already open.";
    prompting.current = true;
    try {
      const a = availabilityFrom(os, await probe());
      setAvailability(a);
      const problem = availabilityProblem(a);
      if (problem) return problem;
      const r = await auth.authenticate("Turn on App lock");
      if (!r.success) return unlockOutcome(r.error).message ?? "App lock stays off.";
    } catch (e) {
      return e instanceof Error ? e.message : "Couldn't check it's you.";
    } finally {
      prompting.current = false;
    }
    await save({ ...settingsRef.current, enabled: true });
    return null;
  }, [auth, os, probe, save]);

  const disable = useCallback(() => save({ ...settingsRef.current, enabled: false }), [save]);
  const setLockAfter = useCallback((v: LockAfter) => save({ ...settingsRef.current, lockAfter: v }), [save]);

  const signOut = async () => {
    setBusy(true);
    try {
      await save({ ...settingsRef.current, enabled: false }).catch(() => {});
      await logout();
    } finally {
      setBusy(false);
    }
  };

  // Until the setting is read, a signed-in app shows nothing: it may turn out to be locked.
  const cover = supported && !!api && (!loaded || state.covered);
  const value: AppLockValue = { settings, availability, enable, disable, setLockAfter };
  return (
    <AppLockContext.Provider value={value}>
      <View style={styles.fill} importantForAccessibility={showLock || cover ? "no-hide-descendants" : "auto"} accessibilityElementsHidden={showLock || cover}>
        {children}
      </View>
      {/* A native modal, so it also covers the screens' own modals (approvals, the screen viewer). */}
      <Modal visible={showLock || cover} animationType="none" statusBarTranslucent navigationBarTranslucent onRequestClose={() => {}}>
        {showLock ? (
          <LockScreen label={availability?.kind === "available" || availability?.kind === "not-enrolled" ? availability.label : null} message={message} stuck={stuck} busy={busy} onUnlock={() => void unlock()} onSignOut={() => void signOut()} />
        ) : (
          <View style={[styles.fill, styles.cover]} testID="app-lock-cover" />
        )}
      </Modal>
    </AppLockContext.Provider>
  );
}

interface LockScreenProps {
  label: string | null;
  message: string | null;
  stuck: boolean;
  busy: boolean;
  onUnlock: () => void;
  onSignOut: () => void;
}

function LockScreen({ label, message, stuck, busy, onUnlock, onSignOut }: LockScreenProps) {
  return (
    <View style={[styles.fill, styles.lock]} accessibilityViewIsModal accessibilityLabel="SuperBot is locked">
      <View style={styles.card}>
        <Image source={require("../assets/images/icon.png")} style={styles.mark} accessibilityIgnoresInvertColors />
        <Text style={styles.title}>SuperBot is locked</Text>
        {message ? (
          <Text style={stuck ? styles.error : styles.sub} accessibilityRole="alert">
            {message}
          </Text>
        ) : (
          <Text style={styles.sub}>{label ? `Use ${label} or your passcode to open it.` : "Use your passcode to open it."}</Text>
        )}
        {stuck ? null : (
          <Pressable style={[styles.btn, busy && styles.busy]} disabled={busy} onPress={onUnlock} accessibilityRole="button" accessibilityLabel="Unlock">
            <Text style={styles.btnText}>Unlock</Text>
          </Pressable>
        )}
        <Pressable style={[stuck ? styles.btn : styles.secondary, busy && styles.busy]} disabled={busy} onPress={onSignOut} accessibilityRole="button" accessibilityLabel="Sign out">
          <Text style={stuck ? styles.btnText : styles.secondaryText}>Sign out</Text>
        </Pressable>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  fill: { flex: 1 },
  cover: { backgroundColor: colors.bgMain },
  lock: { backgroundColor: colors.bgMain, justifyContent: "center", padding: 24 },
  card: { maxWidth: 440, width: "100%", alignSelf: "center", alignItems: "center", gap: 12 },
  mark: { width: 88, height: 88, borderRadius: 20, marginBottom: 8 },
  title: { fontSize: 24, fontWeight: "700", color: colors.text },
  sub: { color: colors.textDim, textAlign: "center" },
  error: { color: colors.danger, textAlign: "center" },
  btn: { marginTop: 8, backgroundColor: colors.blue, borderRadius: 12, paddingVertical: 14, alignItems: "center", alignSelf: "stretch" },
  btnText: { color: "#fff", fontWeight: "600", fontSize: 16 },
  secondary: { paddingVertical: 12, alignItems: "center", alignSelf: "stretch" },
  secondaryText: { color: colors.textDim, fontSize: 15 },
  busy: { opacity: 0.6 },
});
