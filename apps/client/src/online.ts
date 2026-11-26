import { useEffect, useState } from "react";
import { Platform } from "react-native";

/**
 * Whether the device says it's online. Browsers report it; native apps have no network
 * module, so there it's always true and a dropped event stream shows as reconnecting.
 */
export function useOnline(): boolean {
  const web = Platform.OS === "web" && typeof window !== "undefined" && typeof navigator !== "undefined";
  const [online, setOnline] = useState(() => (web ? navigator.onLine !== false : true));
  useEffect(() => {
    if (!web) return;
    const up = () => setOnline(true);
    const down = () => setOnline(false);
    window.addEventListener("online", up);
    window.addEventListener("offline", down);
    return () => {
      window.removeEventListener("online", up);
      window.removeEventListener("offline", down);
    };
  }, [web]);
  return online;
}
