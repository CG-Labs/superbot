import React from "react";
import { Redirect, router, useLocalSearchParams } from "expo-router";
import { ActivityIndicator, StyleSheet, Text, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { AuditLog } from "../components/AuditLog";
import { isAdmin } from "../src/admin";
import { linkedFilters } from "../src/audit";
import { useSuperBot } from "../src/SuperBotContext";
import { colors } from "../src/theme";

/**
 * Admins only. The server refuses the audit log to anyone else; this just says so.
 * `/audit?bot=<id>` (or `person`, `session`, `onBehalfOf`, `action`) opens it filtered.
 */
export default function AuditScreen() {
  const { ready, api, me, bots } = useSuperBot();
  const params = useLocalSearchParams<Record<string, string>>();
  // A link or reload lands here before the saved session is restored: wait, don't bounce to /home.
  if (!ready) {
    return (
      <View style={styles.loading}>
        <ActivityIndicator color={colors.textDim} />
      </View>
    );
  }
  if (!api) return <Redirect href="/" />;
  const back = () => (router.canGoBack() ? router.back() : router.replace("/home"));
  const botName = (id: string) => bots.find((b) => b.id === id)?.name;
  const initial = linkedFilters(params);
  return (
    <SafeAreaView style={styles.root} edges={["top", "left", "right"]}>
      {isAdmin(me) ? (
        <AuditLog key={JSON.stringify(initial)} api={api} onBack={back} botName={botName} bots={bots} initial={initial} />
      ) : (
        <View style={styles.denied}>
          <Text style={styles.text}>Only admins can see the audit log.</Text>
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
