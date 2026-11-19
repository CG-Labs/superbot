import React from "react";
import { Redirect, router } from "expo-router";
import { StyleSheet, Text, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { AuditLog } from "../components/AuditLog";
import { isAdmin } from "../src/admin";
import { useSuperBot } from "../src/SuperBotContext";
import { colors } from "../src/theme";

/** Admins only. The server refuses the audit log to anyone else; this just says so. */
export default function AuditScreen() {
  const { api, me, bots } = useSuperBot();
  if (!api) return <Redirect href="/" />;
  const back = () => (router.canGoBack() ? router.back() : router.replace("/home"));
  const botName = (id: string) => bots.find((b) => b.id === id)?.name;
  return (
    <SafeAreaView style={styles.root} edges={["top", "left", "right"]}>
      {isAdmin(me) ? (
        <AuditLog api={api} onBack={back} botName={botName} />
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
  denied: { flex: 1, alignItems: "center", justifyContent: "center", gap: 12 },
  text: { color: colors.text, fontSize: 16 },
  link: { color: colors.blueDot },
});
