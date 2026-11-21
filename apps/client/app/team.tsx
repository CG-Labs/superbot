import React from "react";
import { Redirect, router, useLocalSearchParams } from "expo-router";
import { ActivityIndicator, StyleSheet, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { TeamView } from "../components/TeamView";
import { useSuperBot } from "../src/SuperBotContext";
import { colors } from "../src/theme";

/** Your team (ADR 0087, 0088, 0093). Everyone on one sees it; its owners and admins manage it and its plan. Stripe sends them back here. */
export default function TeamScreen() {
  const { ready, api, me, canWrite } = useSuperBot();
  const { checkout } = useLocalSearchParams<{ checkout?: string }>();
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
      <TeamView api={api} meId={me.id} canWrite={canWrite} onBack={back} checkout={checkout} />
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.bgMain },
  loading: { flex: 1, justifyContent: "center", backgroundColor: colors.bgMain },
});
