import React from "react";
import { Redirect, router } from "expo-router";
import { ActivityIndicator, StyleSheet, Text, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { AccessReview } from "../components/AccessReview";
import { isAdmin } from "../src/admin";
import { useSuperBot } from "../src/SuperBotContext";
import { colors } from "../src/theme";

/** Admins only (ADR 0099). The server refuses the report to anyone else; this just says so. */
export default function AccessReviewScreen() {
  const { ready, api, me } = useSuperBot();
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
      {isAdmin(me) ? (
        <AccessReview api={api} onBack={back} />
      ) : (
        <View style={styles.denied}>
          <Text style={styles.text}>Only admins can review access.</Text>
          <Text style={styles.link} onPress={back}>
            Back to Bots
          </Text>
        </View>
      )}
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.bgMain },
  loading: { flex: 1, justifyContent: "center", backgroundColor: colors.bgMain },
  denied: { flex: 1, alignItems: "center", justifyContent: "center", gap: 12 },
  text: { color: colors.text, fontSize: 16 },
  link: { color: colors.blueDot },
});
