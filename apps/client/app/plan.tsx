import React from "react";
import { Redirect, useLocalSearchParams } from "expo-router";
import { StyleSheet, View } from "react-native";
import { PlanView } from "../components/PlanView";
import { RouteScreen, useGoBack } from "../components/Shell";
import { PageSkeleton } from "../components/Skeleton";
import { kit } from "../components/ui";
import { useSuperBot } from "../src/SuperBotContext";
import { themedStyles } from "../src/theme";

/** Your plan, and Stripe's pages to buy or manage it (ADR 0042). Stripe sends people back here. */
export default function PlanScreen() {
  const styles = useStyles();
  const back = useGoBack();
  const { ready, api } = useSuperBot();
  const { checkout } = useLocalSearchParams<{ checkout?: string }>();
  // Coming back from Stripe is a fresh page load: wait for the saved session.
  if (!ready) {
    return (
      <View style={styles.loading}>
        <PageSkeleton />
      </View>
    );
  }
  if (!api) return <Redirect href="/" />;
  return (
    <RouteScreen>
      <PlanView api={api} onBack={back} checkout={checkout} />
    </RouteScreen>
  );
}

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    loading: k.center,
  });
});
