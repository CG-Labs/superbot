import { useEffect, useState } from "react";
import { AccessibilityInfo, Platform } from "react-native";

/** `prefers-reduced-motion` on web, which can be read at once; native settings arrive later. */
function webPreference(): boolean | null {
  if (Platform.OS !== "web" || typeof window === "undefined" || !window.matchMedia) return null;
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/**
 * Whether the device asks for less motion (iOS and Android settings, `prefers-reduced-motion` on
 * web), following its changes; `null` until the setting is known.
 */
export function useMotionPreference(): boolean | null {
  const [reduced, setReduced] = useState(webPreference);
  useEffect(() => {
    let live = true;
    const set = (on: boolean) => live && setReduced(on);
    AccessibilityInfo.isReduceMotionEnabled()
      .then(set)
      .catch(() => live && setReduced((was) => was ?? false));
    const sub = AccessibilityInfo.addEventListener("reduceMotionChanged", set);
    return () => {
      live = false;
      sub.remove();
    };
  }, []);
  return reduced;
}

/**
 * Whether to hold motion back. Until the device's setting is known nothing moves, so no one who
 * asked for less motion sees something slide or fade in.
 */
export function useReducedMotion(): boolean {
  return useMotionPreference() !== false;
}
