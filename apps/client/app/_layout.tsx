import { Stack } from "expo-router";
import { SuperBotProvider } from "../src/SuperBotContext";
import { StatusBar } from "expo-status-bar";
import { AppLockProvider } from "../components/AppLock";
import { stackOptions, statusBarStyle } from "../components/Shell";
import { useReducedMotion } from "../src/motion";
import { useTheme } from "../src/theme";
import { usePushTaps } from "../src/pushTaps";

export default function RootLayout() {
  usePushTaps();
  const t = useTheme();
  const reduceMotion = useReducedMotion();
  return (
    <SuperBotProvider>
      <StatusBar style={statusBarStyle(t.scheme)} />
      <AppLockProvider>
        <Stack screenOptions={stackOptions(t, reduceMotion)} />
      </AppLockProvider>
    </SuperBotProvider>
  );
}
