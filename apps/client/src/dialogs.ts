import { Alert, Platform } from "react-native";

/** Yes/no confirmation: `window.confirm` on web and Electron, a native alert elsewhere. */
export function confirmAsync(title: string, message: string, confirmLabel = "Delete"): Promise<boolean> {
  if (Platform.OS === "web") {
    return Promise.resolve(typeof window !== "undefined" && window.confirm(`${title}\n\n${message}`));
  }
  return new Promise((resolve) => {
    Alert.alert(title, message, [
      { text: "Cancel", style: "cancel", onPress: () => resolve(false) },
      { text: confirmLabel, style: "destructive", onPress: () => resolve(true) },
    ], { cancelable: true, onDismiss: () => resolve(false) });
  });
}

export function showError(err: unknown, fallback = "Something went wrong"): void {
  const message = err instanceof Error ? err.message : fallback;
  if (Platform.OS === "web") {
    if (typeof window !== "undefined") window.alert(message);
    return;
  }
  Alert.alert("Error", message);
}
