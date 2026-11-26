import React from "react";
import { Redirect, router, useLocalSearchParams } from "expo-router";
import { StyleSheet, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { PlanView } from "../components/PlanView";
import { kit, Spinner } from "../components/ui";
import { useSuperBot } from "../src/SuperBotContext";
import { themedStyles } from "../src/theme";

/** Your plan, and Stripe's pages to buy or manage it (ADR 0042). Stripe sends people back here. */
export default function PlanScreen() {
  const styles = useStyles();
  const { ready, api } = useSuperBot();
  const { checkout } = useLocalSearchParams<{ checkout?: string }>();
  // Coming back from Stripe is a fresh page load: wait for the saved session.
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
      <PlanView api={api} onBack={back} checkout={checkout} />
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
