import { Platform, Share } from "react-native";

/** "Copy" on web; the share sheet (which has Copy) on phones, so no native clipboard module is needed. */
export const COPY_LABEL = Platform.OS === "web" ? "Copy" : "Share";

/** Resolves true when the text was copied or shared. */
export async function copyText(text: string): Promise<boolean> {
  if (Platform.OS === "web") {
    if (typeof navigator === "undefined" || !navigator.clipboard) return false;
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      return false;
    }
  }
  const res = await Share.share({ message: text }).catch(() => null);
  return res?.action === Share.sharedAction;
}
