import { Stack } from "expo-router";
import { SuperBotProvider } from "../src/SuperBotContext";
import { StatusBar } from "expo-status-bar";
import { AppLockProvider } from "../components/AppLock";
import { stackOptions, statusBarStyle, useMotion } from "../components/Shell";
import { ToastProvider } from "../components/Toast";
import { useTheme } from "../src/theme";
import { usePushTaps } from "../src/pushTaps";
import { installWebA11y } from "../src/webA11y";

installWebA11y();

export default function RootLayout() {
  usePushTaps();
  const t = useTheme();
  const { reduced } = useMotion();
  return (
    <SuperBotProvider>
      <StatusBar style={statusBarStyle(t.scheme)} />
      <AppLockProvider>
        <ToastProvider>
          <Stack screenOptions={stackOptions(t, reduced)} />
        </ToastProvider>
      </AppLockProvider>
    </SuperBotProvider>
  );
}
