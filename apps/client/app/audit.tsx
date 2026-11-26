import React from "react";
import { Redirect, useLocalSearchParams } from "expo-router";
import { StyleSheet, View } from "react-native";
import { AuditLog } from "../components/AuditLog";
import { RouteNotice, RouteScreen, useGoBack } from "../components/Shell";
import { kit, Spinner } from "../components/ui";
import { isAdmin } from "../src/admin";
import { linkedFilters } from "../src/audit";
import { useSuperBot } from "../src/SuperBotContext";
import { themedStyles } from "../src/theme";

/**
 * Admins only. The server refuses the audit log to anyone else; this just says so.
 * `/audit?bot=<id>` (or `person`, `session`, `onBehalfOf`, `action`) opens it filtered.
 */
export default function AuditScreen() {
  const styles = useStyles();
  const back = useGoBack();
  const { ready, api, me, bots } = useSuperBot();
  const params = useLocalSearchParams<Record<string, string>>();
  // A link or reload lands here before the saved session is restored: wait, don't bounce to /home.
  if (!ready) {
    return (
      <View style={styles.loading}>
        <Spinner />
      </View>
    );
  }
  if (!api) return <Redirect href="/" />;
  const botName = (id: string) => bots.find((b) => b.id === id)?.name;
  const initial = linkedFilters(params);
  return (
    <RouteScreen>
      {isAdmin(me) ? (
        <AuditLog key={JSON.stringify(initial)} api={api} onBack={back} botName={botName} bots={bots} initial={initial} />
      ) : (
        <RouteNotice title="Audit log" message="Only admins can see the audit log." onBack={back} />
      )}
    </RouteScreen>
  );
}

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    loading: k.center,
  });
});
