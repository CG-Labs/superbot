import * as LocalAuthentication from "expo-local-authentication";
import type { DeviceProbe } from "./appLock";

export interface LocalAuth {
  /** Null where the platform has no biometric API (web and Electron). */
  probe(): Promise<DeviceProbe | null>;
  /** Biometrics first, then the device passcode. */
  authenticate(promptMessage: string): Promise<{ success: true } | { success: false; error?: string }>;
}

export const localAuth: LocalAuth = {
  async probe() {
    const [hardware, enrolled, types, level] = await Promise.all([
      LocalAuthentication.hasHardwareAsync(),
      LocalAuthentication.isEnrolledAsync(),
      LocalAuthentication.supportedAuthenticationTypesAsync(),
      LocalAuthentication.getEnrolledLevelAsync(),
    ]);
    return { hardware, enrolled, types, level };
  },
  async authenticate(promptMessage) {
    const r = await LocalAuthentication.authenticateAsync({ promptMessage, cancelLabel: "Cancel" });
    return r.success ? { success: true } : { success: false, error: r.error };
  },
};
