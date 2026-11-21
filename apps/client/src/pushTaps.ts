import { useEffect } from "react";
import { router } from "expo-router";
import { pushLink, type PushLink } from "./push";
import { pushDevice, type PushDevice } from "./pushDevice";

const open = (l: PushLink) => router.push(l);

/** A tapped push opens its approval or Bot (ADR 0080); sign-in and App lock still come first. */
export function usePushTaps(device: PushDevice = pushDevice, go: (l: PushLink) => void = open) {
  useEffect(
    () =>
      device.onTap((data) => {
        const link = pushLink(data);
        if (link) go(link);
      }),
    [device, go],
  );
}
