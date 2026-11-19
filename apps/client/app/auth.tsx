import { Redirect } from "expo-router";
import * as WebBrowser from "expo-web-browser";

// Single sign-on comes back here (see src/sso.ts). In a web popup this hands the URL
// to the window that opened it and closes; in the native auth session the browser
// returns the URL itself, so all that's left is to go home.
WebBrowser.maybeCompleteAuthSession();

export default function AuthReturn() {
  return <Redirect href="/" />;
}
