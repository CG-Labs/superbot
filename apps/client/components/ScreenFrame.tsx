import React, { useMemo } from "react";
import { StyleSheet } from "react-native";
import { WebView } from "react-native-webview";
import { isAllowedScreenNavigation, serverOrigin } from "../src/screen";

interface Props {
  url: string;
  title: string;
}

/** Native live view: a WebView locked to the server's origin. No auth headers are sent; voxl's token is in `url`. */
export function ScreenFrame({ url, title }: Props) {
  const origin = useMemo(() => serverOrigin(url), [url]);
  return (
    <WebView
      source={{ uri: url }}
      style={styles.frame}
      accessibilityLabel={title}
      originWhitelist={[origin]}
      onShouldStartLoadWithRequest={(req) => isAllowedScreenNavigation(origin, req.url)}
      javaScriptEnabled
      domStorageEnabled
      incognito
      cacheEnabled={false}
      allowFileAccess={false}
      setSupportMultipleWindows={false}
      allowsBackForwardNavigationGestures={false}
      allowsInlineMediaPlayback
      mediaPlaybackRequiresUserAction={false}
    />
  );
}

const styles = StyleSheet.create({
  frame: { flex: 1, backgroundColor: "#000" },
});
