import React from "react";
import { Redirect } from "expo-router";
import { StyleSheet, View } from "react-native";
import { ServiceAccountsAdmin } from "../components/ServiceAccountsAdmin";
import { RouteNotice, RouteScreen, useGoBack } from "../components/Shell";
import { kit, Spinner } from "../components/ui";
import { isAdmin } from "../src/admin";
import { canSeeServiceAccounts } from "../src/serviceAccounts";
import { useSuperBot } from "../src/SuperBotContext";
import { themedStyles } from "../src/theme";

/**
 * Admins manage every service account; anyone whose role holds users.manage, the ones they
 * own (ADR 0143, 0152, 0182); any other owner sees theirs, revokes tokens and disables them
 * (ADR 0239). The server checks it all; this just says so to everyone else.
 */
export default function ServiceAccountsScreen() {
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
      {canSeeServiceAccounts(me) ? (
        <ServiceAccountsAdmin api={api} onBack={back} admin={isAdmin(me)} />
      ) : (
        <RouteNotice title="Service accounts" message="You own no service accounts. Admins, and people whose role lets them manage users, make them." onBack={back} />
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
