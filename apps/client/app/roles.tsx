import React from "react";
import { Redirect, router } from "expo-router";
import { StyleSheet, Text, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { RolesAdmin } from "../components/RolesAdmin";
import { kit, Spinner } from "../components/ui";
import { isAdmin } from "../src/admin";
import { useSuperBot } from "../src/SuperBotContext";
import { themedStyles } from "../src/theme";

/** Admins only (ADR 0123, 0132). The server refuses roles to anyone else; this just says so. */
export default function RolesScreen() {
  const styles = useStyles();
  const { ready, api, me } = useSuperBot();
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
      {isAdmin(me) ? (
        <RolesAdmin api={api} meId={me.id} onBack={back} />
      ) : (
        <View style={styles.denied}>
          <Text style={styles.text}>Only admins can manage roles.</Text>
          <Text style={styles.link} onPress={back}>
            Back to Bots
          </Text>
        </View>
      )}
    </SafeAreaView>
  );
}

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    root: k.root,
    loading: k.center,
    denied: k.center,
    text: k.text,
    link: k.link,
  });
});
