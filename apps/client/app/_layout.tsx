import { Stack } from "expo-router";
import { SuperBotProvider } from "../src/SuperBotContext";
import { StatusBar } from "expo-status-bar";
import { AppLockProvider } from "../components/AppLock";
import { colors } from "../src/theme";

export default function RootLayout() {
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
