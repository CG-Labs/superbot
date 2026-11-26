import React from "react";
import { Redirect } from "expo-router";
import { StyleSheet, View } from "react-native";
import { SecretsView } from "../components/SecretsView";
import { RouteScreen, useGoBack } from "../components/Shell";
import { PageSkeleton } from "../components/Skeleton";
import { kit } from "../components/ui";
import { useSuperBot } from "../src/SuperBotContext";
import { themedStyles } from "../src/theme";

/** Your own secrets, for your Bots only (ADR 0044). Everyone signed in has this screen. */
export default function SecretsScreen() {
  const styles = useStyles();
  const back = useGoBack();
  const { ready, api, canWrite } = useSuperBot();
  // A link or reload lands here before the saved session is restored: wait, don't bounce to /home.
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
      <SecretsView api={api} onBack={back} canWrite={canWrite} />
    </RouteScreen>
  );
}

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    loading: k.center,
  });
});
