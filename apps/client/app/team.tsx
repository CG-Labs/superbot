import React from "react";
import { Redirect, router } from "expo-router";
import { ActivityIndicator, StyleSheet, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { TeamView } from "../components/TeamView";
import { useSuperBot } from "../src/SuperBotContext";
import { colors } from "../src/theme";

/** Your team (ADR 0087, 0088). Everyone on one sees it; its owners and admins manage it. */
export default function TeamScreen() {
  const { ready, api, me, canWrite } = useSuperBot();
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
      <TeamView api={api} meId={me.id} canWrite={canWrite} onBack={back} />
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.bgMain },
  loading: { flex: 1, justifyContent: "center", backgroundColor: colors.bgMain },
});
