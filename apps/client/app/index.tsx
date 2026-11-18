import { Redirect } from "expo-router";
import { ActivityIndicator, View } from "react-native";
import { LoginScreen } from "../components/LoginScreen";
import { useSuperBot } from "../src/SuperBotContext";
import { colors } from "../src/theme";

export default function Index() {
  const { ready, api } = useSuperBot();

  if (!ready) {
    return (
      <View style={{ flex: 1, justifyContent: "center", backgroundColor: colors.bgMain }}>
        <ActivityIndicator color={colors.textDim} />
      </View>
    );
  }

  if (!api) {
    return <LoginScreen />;
  }

  return <Redirect href="/home" />;
}