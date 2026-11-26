import React from "react";
import { Redirect, router } from "expo-router";
import { StyleSheet, Text, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { UsersAdmin } from "../components/UsersAdmin";
import { kit } from "../components/ui";
import { useSuperBot } from "../src/SuperBotContext";
import { themedStyles } from "../src/theme";

/** Admins only. The server refuses everything here to anyone else; this just says so. */
export default function UsersScreen() {
  const styles = useStyles();
  const { api, me } = useSuperBot();
  if (!api) return <Redirect href="/" />;
  const back = () => (router.canGoBack() ? router.back() : router.replace("/home"));
  return (
    <SafeAreaView style={styles.root} edges={["top", "left", "right"]}>
      {me.permissions?.includes("admin") ? (
        <UsersAdmin api={api} meId={me.id} onBack={back} />
      ) : (
        <View style={styles.denied}>
          <Text style={styles.text}>Only admins can manage users.</Text>
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
    denied: k.center,
    text: k.text,
    link: k.link,
  });
});
