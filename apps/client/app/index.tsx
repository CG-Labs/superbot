import { useEffect } from "react";
import { Redirect, router, useLocalSearchParams } from "expo-router";
import { LoginScreen } from "../components/LoginScreen";
import { AppSkeleton } from "../components/Skeleton";
import { codeFromHash } from "../src/invite";
import { approvalParam } from "../src/notifications";
import { botParam } from "../src/push";
import { useSuperBot } from "../src/SuperBotContext";

export default function Index() {
  const { ready, api, inviteCode, offerInviteCode } = useSuperBot();
  // An invite link's `#code=` (ADR 0021): the router keeps the fragment as a param and
  // writes it back to the address bar, so it is taken here and the URL replaced without it.
  const params = useLocalSearchParams<{ "#"?: string; approval?: string; bot?: string }>();
  const hash = params["#"];
  // A notification's link to an approval (ADR 0061) or a Bot (ADR 0080), kept through sign-in.
  const approval = approvalParam(params.approval);
  const bot = botParam(params.bot);
  useEffect(() => {
    if (!hash?.includes("code=")) return;
    const code = codeFromHash(hash);
    if (code) offerInviteCode(code);
    router.replace("/");
  }, [hash, offerInviteCode]);

  if (!ready) return <AppSkeleton />;

  if (!api) {
    return <LoginScreen key={inviteCode ?? ""} inviteCode={inviteCode} />;
  }

  return <Redirect href={approval ? { pathname: "/home", params: { approval } } : bot ? { pathname: "/home", params: { bot } } : "/home"} />;
}
