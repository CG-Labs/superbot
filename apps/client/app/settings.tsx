import React from "react";
import { Redirect, router } from "expo-router";
import { ActivityIndicator, StyleSheet, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { SettingsView } from "../components/SettingsView";
import { useSuperBot } from "../src/SuperBotContext";
import { colors } from "../src/theme";

/** This device's settings: App lock (ADR 0078) and push notifications (ADR 0080). */
export default function SettingsScreen() {
  const { ready, api } = useSuperBot();
  if (!ready) {
    return (
      <View style={styles.loading}>
        <ActivityIndicator color={colors.textDim} />
      </View>
    );
  }
  if (!api) return <Redirect href="/" />;
  const back = () => (router.canGoBack() ? router.back() : router.replace("/home"));
  return (
    <SafeAreaView style={styles.root} edges={["top", "left", "right"]}>
      <SettingsView onBack={back} api={api} />
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.bgMain },
  loading: { flex: 1, justifyContent: "center", backgroundColor: colors.bgMain },
});
