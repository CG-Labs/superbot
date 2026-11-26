import React from "react";
import { Redirect } from "expo-router";
import { StyleSheet, View } from "react-native";
import { RolesAdmin } from "../components/RolesAdmin";
import { RouteNotice, RouteScreen, useGoBack } from "../components/Shell";
import { kit, Spinner } from "../components/ui";
import { isAdmin } from "../src/admin";
import { useSuperBot } from "../src/SuperBotContext";
import { themedStyles } from "../src/theme";

/** Admins only (ADR 0123, 0132). The server refuses roles to anyone else; this just says so. */
export default function RolesScreen() {
  const styles = useStyles();
  const back = useGoBack();
  const { ready, api, me } = useSuperBot();
  if (!ready) {
    return (
      <View style={styles.loading}>
        <Spinner />
      </View>
    );
  }
  if (!api) return <Redirect href="/" />;
  return (
    <RouteScreen>
      {isAdmin(me) ? (
        <RolesAdmin api={api} meId={me.id} onBack={back} />
      ) : (
        <RouteNotice title="Roles" message="Only admins can manage roles." onBack={back} />
      )}
    </RouteScreen>
  );
}

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    loading: k.center,
  });
});
