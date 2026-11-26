import { useEffect } from "react";
import { AccessibilityInfo, Platform } from "react-native";

/**
 * Reads `message` out on iOS each time it changes. iOS has no live regions; Android and
 * the web read `aria-live` on the element itself, so this does nothing there.
 */
export function useAnnounce(message: string | null | undefined): void {
  useEffect(() => {
    if (message && Platform.OS === "ios") AccessibilityInfo.announceForAccessibility(message);
  }, [message]);
}
