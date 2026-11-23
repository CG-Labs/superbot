import React from "react";
import { Redirect, router } from "expo-router";
import { ActivityIndicator, StyleSheet, Text, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { ServiceAccountsAdmin } from "../components/ServiceAccountsAdmin";
import { isAdmin } from "../src/admin";
import { useSuperBot } from "../src/SuperBotContext";
import { colors } from "../src/theme";

/** Admins only (ADR 0143, 0152). The server refuses service accounts to people without users.manage; this just says so. */
export default function ServiceAccountsScreen() {
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
        <ServiceAccountsAdmin api={api} onBack={back} />
      ) : (
        <View style={styles.denied}>
          <Text style={styles.text}>Only admins can manage service accounts.</Text>
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
