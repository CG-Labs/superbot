import React, { useCallback, useEffect, useRef, useState } from "react";
import { StyleSheet, Text, View } from "react-native";
import type { SuperBotApi } from "../src/api";
import { errorText, friendlyError } from "../src/errors";
import { BLOCKED, projectProblem, pushUnavailable } from "../src/push";
import { pushDevice, type PushDevice } from "../src/pushDevice";
import { themedStyles } from "../src/theme";
import type { PushView } from "../src/types";
import { Chips } from "./Chips";
import { InlineError } from "./ErrorState";
import { ListSkeleton } from "./Skeleton";
import { kit } from "./ui";

export type PushApi = Pick<SuperBotApi, "pushDevice" | "registerPush" | "unregisterPush">;

interface Props {
  api: PushApi;
  device?: PushDevice;
}

const ON_OFF = [
  { value: "on", label: "On" },
  { value: "off", label: "Off" },
] as const;

/**
 * Push notifications on this phone (ADR 0080): off until you turn them on, and only
 * where the server sends them. Each push says only which Bot needs you.
 */
export function PushCard({ api, device = pushDevice }: Props) {
  const styles = useStyles();
  const [view, setView] = useState<PushView | undefined>(undefined);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const supported = device.platform !== null;
  const live = useRef(true);

  const load = useCallback(async () => {
    try {
      const v = await api.pushDevice();
      if (!live.current) return;
      setView(v);
      setLoadError(null);
    } catch (e) {
      if (live.current) setLoadError(errorText(e, "Couldn't load push notifications"));
    }
  }, [api]);

  useEffect(() => {
    live.current = true;
    if (supported) void load();
    return () => {
      live.current = false;
    };
  }, [load, supported]);

  const run = async (fn: () => Promise<string | null>) => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      setNotice(await fn());
    } catch (e) {
      setError(friendlyError(e));
    } finally {
      setBusy(false);
    }
  };

  const register = async (kinds: { approvals: boolean; routines: boolean }) => {
    const problem = projectProblem(device.projectId);
    if (problem) throw new Error(problem);
    let permission = await device.permission();
    if (permission === "undetermined") permission = await device.requestPermission();
    if (permission !== "granted") throw new Error(BLOCKED);
    const token = await device.token();
    setView(await api.registerPush({ token, platform: device.platform as "ios" | "android", ...kinds }));
  };

  const on = () =>
    run(async () => {
      await register({ approvals: true, routines: true });
      return "Push notifications are on for this phone.";
    });
  const off = () =>
    run(async () => {
      setView(await api.unregisterPush());
      return "Push notifications are off for this phone.";
    });
  const kind = (k: "approvals" | "routines", want: boolean) =>
    run(async () => {
      const d = view?.device;
      if (!d) return null;
      await register({ approvals: d.approvals, routines: d.routines, [k]: want });
      return null;
    });

  const unavailable = pushUnavailable(view, supported);
  const body = () => {
    if (!supported) return <Text style={styles.dim}>{unavailable}</Text>;
    if (!view) return loadError ? null : <ListSkeleton label="Loading push notifications" rows={2} />;
    const d = view.device;
    // With push paused on the server, a saved phone can still be removed, not added.
    if (!view.available && !d) return <Text style={styles.dim}>{unavailable}</Text>;
    return (
      <>
        {unavailable ? <Text style={styles.dim}>{`${unavailable} This phone is still saved, and would get them again if it's turned back on.`}</Text> : null}
        <View style={styles.field} accessibilityLabel="Push notifications on or off">
          <Text style={styles.label}>On this phone</Text>
          <Chips
            options={ON_OFF}
            value={d ? "on" : "off"}
            onChange={(v) => {
              if (v === "on" && !d) void on();
              if (v === "off" && d) void off();
            }}
            disabled={busy}
          />
        </View>
        {d && view.available ? (
          <>
            <View style={styles.field} accessibilityLabel="Approvals">
              <Text style={styles.label}>An approval or request is waiting for you, or yours is decided</Text>
              <Chips
                options={ON_OFF}
                value={d.approvals ? "on" : "off"}
                onChange={(v) => {
                  if ((v === "on") !== d.approvals) void kind("approvals", v === "on");
                }}
                disabled={busy}
              />
            </View>
            <View style={styles.field} accessibilityLabel="Routines">
              <Text style={styles.label}>A routine you set up finished</Text>
              <Chips
                options={ON_OFF}
                value={d.routines ? "on" : "off"}
                onChange={(v) => {
                  if ((v === "on") !== d.routines) void kind("routines", v === "on");
                }}
                disabled={busy}
              />
            </View>
          </>
        ) : null}
      </>
    );
  };

  return (
    <View style={styles.card} accessibilityLabel="Push notifications">
      <Text style={styles.cardTitle} role="heading">
        Push notifications
      </Text>
      <Text style={styles.dim}>
        Hear about waiting approvals, requests for roles and finished routines when SuperBot is closed. A notification names the Bot and nothing it asked, and no role; tap it to see the details here. Signing out turns it off.
      </Text>
      {notice ? (
        <Text style={styles.good} accessibilityRole="alert">
          {notice}
        </Text>
      ) : null}
      {loadError ? <InlineError message={loadError} onRetry={load} /> : null}
      {error ? <InlineError message={error} /> : null}
      {body()}
    </View>
  );
}

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    card: k.card,
    cardTitle: k.cardTitle,
    field: k.field,
    label: k.label,
    good: k.good,
    dim: k.dim,
  });
});
