import React from "react";
import { Redirect } from "expo-router";
import { StyleSheet, View } from "react-native";
import { AccessReview } from "../components/AccessReview";
import { RouteNotice, RouteScreen, useGoBack } from "../components/Shell";
import { PageSkeleton } from "../components/Skeleton";
import { kit } from "../components/ui";
import { isAdmin } from "../src/admin";
import { useSuperBot } from "../src/SuperBotContext";
import { themedStyles } from "../src/theme";

/** Admins only (ADR 0099). The server refuses the report to anyone else; this just says so. */
export default function AccessReviewScreen() {
  const styles = useStyles();
  const back = useGoBack();
  const { ready, api, me } = useSuperBot();
  if (!ready) {
    return (
      <View style={styles.loading}>
        <PageSkeleton />
      </View>
    );
  }
  if (!api) return <Redirect href="/" />;
  return (
    <RouteScreen>
      {isAdmin(me) ? (
        <AccessReview api={api} onBack={back} />
      ) : (
        <RouteNotice title="Access review" message="Only admins can review access." onBack={back} />
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
