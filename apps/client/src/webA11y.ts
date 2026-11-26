import { Platform } from "react-native";
import tokens from "./tokens.json";

const STYLE_ID = "superbot-a11y";

/**
 * Web-wide rules React Native styles can't express: a visible ring on whatever has keyboard
 * focus (not on a mouse click), in the scheme's accent, and no animations or smooth scrolling
 * when the browser asks for reduced motion. Text fields keep their own focus styles.
 */
export function webA11yCss(): string {
  const ring = (accent: string) =>
    `:focus-visible:not(input):not(textarea) { outline: 2px solid ${accent}; outline-offset: 2px; }`;
  return [
    ring(tokens.color.light.accent),
    `@media (prefers-color-scheme: dark) { ${ring(tokens.color.dark.accent)} }`,
    "@media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation-duration: 0.01ms !important; animation-iteration-count: 1 !important; transition-duration: 0.01ms !important; scroll-behavior: auto !important; } }",
  ].join("\n");
}

/** Adds the rules to the page once; does nothing in the native apps. */
export function installWebA11y(doc: Document | undefined = typeof document === "undefined" ? undefined : document): void {
  if (Platform.OS !== "web" || !doc || doc.getElementById(STYLE_ID)) return;
  const style = doc.createElement("style");
  style.id = STYLE_ID;
  style.textContent = webA11yCss();
  doc.head.appendChild(style);
}
