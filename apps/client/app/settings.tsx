import React from "react";
import { Redirect, router } from "expo-router";
import { StyleSheet, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { SettingsView } from "../components/SettingsView";
import { kit, Spinner } from "../components/ui";
import { useSuperBot } from "../src/SuperBotContext";
import { themedStyles } from "../src/theme";

/** This device's settings: App lock (ADR 0078) and push notifications (ADR 0080); your two-factor authentication (ADR 0094) and your data's residency pin (ADR 0168). */
export default function SettingsScreen() {
  const styles = useStyles();
  const { ready, api, can } = useSuperBot();
  if (!ready) {
    return (
      <View style={styles.loading}>
        <Spinner />
      </View>
    );
  }
  if (!api) return <Redirect href="/" />;
  const back = () => (router.canGoBack() ? router.back() : router.replace("/home"));
  return (
    <SafeAreaView style={styles.root} edges={["top", "left", "right"]}>
      <SettingsView onBack={back} api={api} admin={can("admin")} />
    </SafeAreaView>
  );
}

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    root: k.root,
    loading: k.center,
  });
});
