import { Stack } from "expo-router";
import { SuperBotProvider } from "../src/SuperBotContext";
import { StatusBar } from "expo-status-bar";
import { colors } from "../src/theme";

export default function RootLayout() {
  return (
    <SuperBotProvider>
      <StatusBar style="light" />
      <Stack
        screenOptions={{
          headerShown: false,
          contentStyle: { backgroundColor: colors.bgMain },
        }}
      />
    </SuperBotProvider>
  );
}