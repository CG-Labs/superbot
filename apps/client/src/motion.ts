import { useEffect, useState } from "react";
import { AccessibilityInfo } from "react-native";

/** Whether the device asks for less motion (iOS and Android settings, `prefers-reduced-motion` on web). */
export function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    let live = true;
    AccessibilityInfo.isReduceMotionEnabled()
      .then((on) => live && setReduced(on))
      .catch(() => {});
    const sub = AccessibilityInfo.addEventListener("reduceMotionChanged", (on) => setReduced(on));
    return () => {
      live = false;
      sub.remove();
    };
  }, []);
  return reduced;
}
