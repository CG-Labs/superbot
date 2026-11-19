import { useEffect } from "react";
import { Redirect, router, useLocalSearchParams } from "expo-router";
import { ActivityIndicator, View } from "react-native";
import { LoginScreen } from "../components/LoginScreen";
import { codeFromHash } from "../src/invite";
import { useSuperBot } from "../src/SuperBotContext";
import { colors } from "../src/theme";

export default function Index() {
  const { ready, api, inviteCode, offerInviteCode } = useSuperBot();
  // An invite link's `#code=` (ADR 0021): the router keeps the fragment as a param and
  // writes it back to the address bar, so it is taken here and the URL replaced without it.
  const hash = useLocalSearchParams<{ "#"?: string }>()["#"];
  useEffect(() => {
    if (!hash?.includes("code=")) return;
    const code = codeFromHash(hash);
    if (code) offerInviteCode(code);
    router.replace("/");
  }, [hash, offerInviteCode]);

  if (!ready) {
    return (
      <View style={{ flex: 1, justifyContent: "center", backgroundColor: colors.bgMain }}>
        <ActivityIndicator color={colors.textDim} />
      </View>
    );
  }

  if (!api) {
    return <LoginScreen key={inviteCode ?? ""} inviteCode={inviteCode} />;
  }

  return <Redirect href="/home" />;
}
