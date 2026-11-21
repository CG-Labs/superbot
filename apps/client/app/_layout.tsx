import { Stack } from "expo-router";
import { SuperBotProvider } from "../src/SuperBotContext";
import { StatusBar } from "expo-status-bar";
import { AppLockProvider } from "../components/AppLock";
import { colors } from "../src/theme";
import { usePushTaps } from "../src/pushTaps";

export default function RootLayout() {
  usePushTaps();
  return (
    <SuperBotProvider>
      <StatusBar style="light" />
      <AppLockProvider>
        <Stack
          screenOptions={{
            headerShown: false,
            contentStyle: { backgroundColor: colors.bgMain },
          }}
        />
      </AppLockProvider>
    </SuperBotProvider>
  );
}
