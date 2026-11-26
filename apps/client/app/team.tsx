import React from "react";
import { Redirect, useLocalSearchParams } from "expo-router";
import { StyleSheet, View } from "react-native";
import { TeamView } from "../components/TeamView";
import { RouteScreen, useGoBack } from "../components/Shell";
import { PageSkeleton } from "../components/Skeleton";
import { kit } from "../components/ui";
import { useSuperBot } from "../src/SuperBotContext";
import { themedStyles } from "../src/theme";

/** Your team (ADR 0087, 0088, 0093). Everyone on one sees it; its owners and admins manage it and its plan. Stripe sends them back here. */
export default function TeamScreen() {
  const styles = useStyles();
  const back = useGoBack();
  const { ready, api, me, canWrite } = useSuperBot();
  const { checkout } = useLocalSearchParams<{ checkout?: string }>();
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
      <TeamView api={api} meId={me.id} canWrite={canWrite} onBack={back} checkout={checkout} />
    </RouteScreen>
  );
}

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    loading: k.center,
  });
});
