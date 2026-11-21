import Constants from "expo-constants";
import * as Notifications from "expo-notifications";
import { Platform } from "react-native";
import type { PushPermission } from "./push";

export interface PushDevice {
  /** Null where there is no push (web and Electron). */
  platform: "ios" | "android" | null;
  /** The EAS project the build was made for; Expo push tokens belong to it. */
  projectId: string | null;
  permission(): Promise<PushPermission>;
  /** Asks the phone. Android 13+ needs a channel before it will ask. */
  requestPermission(): Promise<PushPermission>;
  token(): Promise<string>;
  /** Calls back with each tapped push's data, starting with the one that opened the app. */
  onTap(cb: (data: unknown) => void): () => void;
}

function permissionOf(r: Notifications.NotificationPermissionsStatus): PushPermission {
  if (r.granted || r.ios?.status === Notifications.IosAuthorizationStatus.PROVISIONAL) return "granted";
  return r.status === "undetermined" || r.canAskAgain ? "undetermined" : "denied";
}

const platform = Platform.OS === "ios" || Platform.OS === "android" ? Platform.OS : null;

export const pushDevice: PushDevice = {
  platform,
  projectId: Constants.expoConfig?.extra?.eas?.projectId ?? Constants.easConfig?.projectId ?? null,
  async permission() {
    return permissionOf(await Notifications.getPermissionsAsync());
  },
  async requestPermission() {
    if (Platform.OS === "android") {
      await Notifications.setNotificationChannelAsync("default", { name: "SuperBot", importance: Notifications.AndroidImportance.HIGH });
    }
    return permissionOf(await Notifications.requestPermissionsAsync());
  },
  async token() {
    const projectId = pushDevice.projectId ?? undefined;
    return (await Notifications.getExpoPushTokenAsync({ projectId })).data;
  },
  onTap(cb) {
    Notifications.setNotificationHandler({
      handleNotification: async () => ({ shouldShowBanner: true, shouldShowList: true, shouldPlaySound: false, shouldSetBadge: false }),
    });
    const tapped = (r: Notifications.NotificationResponse | null) => {
      if (!r || r.actionIdentifier !== Notifications.DEFAULT_ACTION_IDENTIFIER) return;
      Notifications.clearLastNotificationResponse();
      cb(r.notification.request.content.data);
    };
    tapped(Notifications.getLastNotificationResponse());
    const sub = Notifications.addNotificationResponseReceivedListener(tapped);
    return () => sub.remove();
  },
};
