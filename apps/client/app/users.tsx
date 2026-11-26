import React from "react";
import { Redirect } from "expo-router";
import { UsersAdmin } from "../components/UsersAdmin";
import { RouteNotice, RouteScreen, useGoBack } from "../components/Shell";
import { useSuperBot } from "../src/SuperBotContext";

/** Admins only. The server refuses everything here to anyone else; this just says so. */
export default function UsersScreen() {
  const back = useGoBack();
  const { api, me } = useSuperBot();
  if (!api) return <Redirect href="/" />;
  return (
    <RouteScreen>
      {me.permissions?.includes("admin") ? (
        <UsersAdmin api={api} meId={me.id} onBack={back} />
      ) : (
        <RouteNotice title="Users" message="Only admins can manage users." onBack={back} />
      )}
    </RouteScreen>
  );
}
