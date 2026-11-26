import React from "react";
import { Redirect, useLocalSearchParams } from "expo-router";
import { StyleSheet, View } from "react-native";
import { PolicyEditor } from "../components/PolicyEditor";
import { RouteScreen, useGoBack } from "../components/Shell";
import { PageSkeleton } from "../components/Skeleton";
import { kit } from "../components/ui";
import { useSuperBot } from "../src/SuperBotContext";
import { themedStyles } from "../src/theme";

/** The approval policy (ADR 0049): `/policy` for all Bots, `/policy?bot=<id>` for one. */
export default function PolicyScreen() {
  const styles = useStyles();
  const back = useGoBack();
  const { ready, api, bots, can } = useSuperBot();
  const { bot: botId } = useLocalSearchParams<{ bot?: string }>();
  if (!ready) {
    return (
      <View style={styles.loading}>
        <PageSkeleton />
      </View>
    );
  }
  if (!api) return <Redirect href="/" />;
  const found = botId ? bots.find((b) => b.id === botId) : undefined;
  const bot = botId ? { id: botId, name: found?.name ?? "this Bot" } : undefined;
  return (
    <RouteScreen>
      <PolicyEditor key={botId ?? "global"} api={api} bot={bot} canEdit={can("admin")} notifications={api} onBack={back} />
    </RouteScreen>
  );
}

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    loading: k.center,
  });
});
