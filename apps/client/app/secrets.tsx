import React from "react";
import { Redirect, router } from "expo-router";
import { StyleSheet, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { SecretsView } from "../components/SecretsView";
import { kit, Spinner } from "../components/ui";
import { useSuperBot } from "../src/SuperBotContext";
import { themedStyles } from "../src/theme";

/** Your own secrets, for your Bots only (ADR 0044). Everyone signed in has this screen. */
export default function SecretsScreen() {
  const styles = useStyles();
  const { ready, api, canWrite } = useSuperBot();
  // A link or reload lands here before the saved session is restored: wait, don't bounce to /home.
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
      <SecretsView api={api} onBack={back} canWrite={canWrite} />
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
