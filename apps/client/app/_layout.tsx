import { Stack } from "expo-router";
import { SuperBotProvider } from "../src/SuperBotContext";
import { StatusBar } from "expo-status-bar";
import { AppLockProvider } from "../components/AppLock";
import { ToastProvider } from "../components/Toast";
import { colors } from "../src/theme";
import { usePushTaps } from "../src/pushTaps";
import { installWebA11y } from "../src/webA11y";

installWebA11y();

export default function RootLayout() {
  usePushTaps();
  return (
    <SuperBotProvider>
      <StatusBar style="light" />
      <AppLockProvider>
        <ToastProvider>
          <Stack
            screenOptions={{
              headerShown: false,
              contentStyle: { backgroundColor: colors.bgMain },
            }}
          />
        </ToastProvider>
      </AppLockProvider>
    </SuperBotProvider>
  );
}
