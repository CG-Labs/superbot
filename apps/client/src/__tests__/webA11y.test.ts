import { Platform } from "react-native";
import tokens from "../tokens.json";
import { installWebA11y, webA11yCss } from "../webA11y";

function fakeDocument() {
  const nodes: Record<string, { id: string; textContent: string }> = {};
  const appended: unknown[] = [];
  return {
    appended,
    getElementById: (id: string) => nodes[id] ?? null,
    createElement: () => ({ id: "", textContent: "" }),
    head: {
      appendChild: (el: { id: string; textContent: string }) => {
        nodes[el.id] = el;
        appended.push(el);
      },
    },
  };
}

describe("web accessibility rules", () => {
  const os = Platform.OS;
  afterEach(() => Object.defineProperty(Platform, "OS", { value: os, configurable: true }));

  it("ring keyboard focus in each scheme's accent and stop motion when asked", () => {
    const css = webA11yCss();
    expect(css).toContain(`outline: 2px solid ${tokens.color.light.accent}`);
    expect(css).toMatch(new RegExp(`prefers-color-scheme: dark\\) \\{ [^}]*${tokens.color.dark.accent}`));
    expect(css).toContain(":focus-visible:not(input):not(textarea)");
    expect(css).toMatch(/prefers-reduced-motion: reduce\) \{[^}]*animation-duration: 0\.01ms !important/);
  });

  it("are added to the page once, on web only", () => {
    const doc = fakeDocument();
    Object.defineProperty(Platform, "OS", { value: "ios", configurable: true });
    installWebA11y(doc as unknown as Document);
    expect(doc.appended).toHaveLength(0);

    Object.defineProperty(Platform, "OS", { value: "web", configurable: true });
    installWebA11y(doc as unknown as Document);
    installWebA11y(doc as unknown as Document);
    expect(doc.appended).toEqual([{ id: "superbot-a11y", textContent: webA11yCss() }]);
  });
});
