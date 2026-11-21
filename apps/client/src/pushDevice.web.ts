import type { PushDevice } from "./pushDevice";

/** Browsers and Electron get no push here (ADR 0080): pending approvals show in the inbox. */
export const pushDevice: PushDevice = {
  platform: null,
  projectId: null,
  permission: async () => "denied",
  requestPermission: async () => "denied",
  token: async () => {
    throw new Error("Push notifications need the iPhone or Android app.");
  },
  onTap: () => () => {},
};
