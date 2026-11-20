import React from "react";
import { Redirect, router, useLocalSearchParams } from "expo-router";
import { ActivityIndicator, StyleSheet, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { PlanView } from "../components/PlanView";
import { useSuperBot } from "../src/SuperBotContext";
import { colors } from "../src/theme";

/** Your plan, and Stripe's pages to buy or manage it (ADR 0041). Stripe sends people back here. */
export default function PlanScreen() {
  const { ready, api } = useSuperBot();
  const { checkout } = useLocalSearchParams<{ checkout?: string }>();
  // Coming back from Stripe is a fresh page load: wait for the saved session.
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
      <PlanView api={api} onBack={back} checkout={checkout} />
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.bgMain },
  loading: { flex: 1, justifyContent: "center", backgroundColor: colors.bgMain },
});
