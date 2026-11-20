import React from "react";
import { Redirect, router } from "expo-router";
import { ActivityIndicator, StyleSheet, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { SecretsView } from "../components/SecretsView";
import { useSuperBot } from "../src/SuperBotContext";
import { colors } from "../src/theme";

/** Your own secrets, for your Bots only (ADR 0044). Everyone signed in has this screen. */
export default function SecretsScreen() {
  const { ready, api, canWrite } = useSuperBot();
  // A link or reload lands here before the saved session is restored: wait, don't bounce to /home.
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
      <SecretsView api={api} onBack={back} canWrite={canWrite} />
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.bgMain },
  loading: { flex: 1, justifyContent: "center", backgroundColor: colors.bgMain },
});
