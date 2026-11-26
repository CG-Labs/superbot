import { Link, Stack } from "expo-router";
import { StyleSheet, Text, View } from "react-native";
import { RouteScreen, useGoBack } from "../components/Shell";
import { kit, PageHeader } from "../components/ui";
import { themedStyles } from "../src/theme";

export default function NotFoundScreen() {
  const styles = useStyles();
  const back = useGoBack();
  return (
    <RouteScreen>
      <Stack.Screen options={{ title: "Oops!" }} />
      <PageHeader title="Not found" onBack={back} />
      <View style={styles.center}>
        <Text style={styles.title}>This screen doesn&apos;t exist.</Text>
        <Link href="/" style={styles.link}>
          Go to home screen!
        </Link>
      </View>
    </RouteScreen>
  );
}

const useStyles = themedStyles((t) => {
  const k = kit(t);
  return StyleSheet.create({
    center: k.center,
    title: { ...k.strong, fontSize: t.font.size.lg, lineHeight: t.font.lineHeight.lg },
    link: k.link,
  });
});
