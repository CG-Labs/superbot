import React from "react";
import { Redirect } from "expo-router";
import { StyleSheet, View } from "react-native";
import { SettingsView } from "../components/SettingsView";
import { RouteScreen, useGoBack } from "../components/Shell";
import { kit, Spinner } from "../components/ui";
import { useSuperBot } from "../src/SuperBotContext";
import { themedStyles } from "../src/theme";

/** This device's settings: App lock (ADR 0078) and push notifications (ADR 0080); your two-factor authentication (ADR 0094) and your data's residency pin (ADR 0168). */
export default function SettingsScreen() {
  const styles = useStyles();
  const back = useGoBack();
  const { ready, api, can } = useSuperBot();
  if (!ready) {
    return (
      <View style={styles.loading}>
        <Spinner />
      </View>
    );
  }
  if (!api) return <Redirect href="/" />;
  return (
    <RouteScreen>
      <SettingsView onBack={back} api={api} admin={can("admin")} />
    </RouteScreen>
  );
}

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    loading: k.center,
  });
});
