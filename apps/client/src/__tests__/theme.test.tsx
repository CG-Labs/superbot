import React from "react";
import * as RN from "react-native";
import { renderHook } from "@testing-library/react-native";
import tokens from "../tokens.json";
import { colors, themes, ThemeScope, useTheme, type Palette } from "../theme";

function luminance(hex: string): number {
  const n = parseInt(hex.slice(1), 16);
  return [n >> 16, (n >> 8) & 255, n & 255]
    .map((v) => {
      const c = v / 255;
      return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
    })
    .reduce((sum, c, i) => sum + c * [0.2126, 0.7152, 0.0722][i], 0);
}

function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

describe("design tokens", () => {
  it("give light and dark the same colour names", () => {
    expect(Object.keys(tokens.color.dark).sort()).toEqual(Object.keys(tokens.color.light).sort());
    expect(Object.keys(tokens.shadow.dark).sort()).toEqual(Object.keys(tokens.shadow.light).sort());
  });

  describe.each(["light", "dark"] as const)("%s", (scheme) => {
    const c: Palette = themes[scheme].c;
    const grounds = ["bg", "surface", "raised", "elevated"] as const;

    it.each(grounds)("keeps body text, muted text and links at WCAG AA on %s", (ground) => {
      for (const fg of ["text", "textMuted", "accentText"] as const) {
        expect(contrast(c[fg], c[ground])).toBeGreaterThanOrEqual(4.5);
      }
      expect(contrast(c.textFaint, c[ground])).toBeGreaterThanOrEqual(3);
    });

    it("keeps text readable on the accent, in user bubbles and on tinted cards", () => {
      expect(contrast(c.onAccent, c.accent)).toBeGreaterThanOrEqual(4.5);
      expect(contrast(c.text, c.userBubble)).toBeGreaterThanOrEqual(4.5);
      expect(contrast(c.text, c.accentSoft)).toBeGreaterThanOrEqual(4.5);
      expect(contrast(c.accentText, c.accentSoft)).toBeGreaterThanOrEqual(4.5);
      expect(contrast(c.danger, c.dangerSoft)).toBeGreaterThanOrEqual(4.5);
      expect(contrast(c.warning, c.warningSoft)).toBeGreaterThanOrEqual(4.5);
      expect(contrast(c.success, c.successSoft)).toBeGreaterThanOrEqual(4.5);
      expect(contrast(c.text, c.codeBg)).toBeGreaterThanOrEqual(4.5);
    });

    it("keeps the console's selected pills readable: setup's progress, step numbers and tags", () => {
      expect(contrast(c.text, c.selected)).toBeGreaterThanOrEqual(4.5);
      expect(contrast(c.textMuted, c.selected)).toBeGreaterThanOrEqual(4.5);
    });
  });

  it("gives screens not yet on the design system the dark palette's neutrals", () => {
    expect(colors.bgMain).toBe(tokens.color.dark.bg);
    expect(colors.text).toBe(tokens.color.dark.text);
    expect(colors.border).toBe(tokens.color.dark.border);
  });
});

describe("useTheme", () => {
  afterEach(() => jest.restoreAllMocks());

  it.each([
    ["dark", "dark"],
    ["light", "light"],
    [null, "light"],
  ] as const)("follows the device setting %s", async (system, scheme) => {
    jest.spyOn(RN, "useColorScheme").mockReturnValue(system);
    const { result } = await renderHook(() => useTheme());
    expect(result.current.scheme).toBe(scheme);
    expect(result.current.c).toBe(themes[scheme].c);
  });

  it("holds a ThemeScope's children to its scheme", async () => {
    jest.spyOn(RN, "useColorScheme").mockReturnValue("light");
    const wrapper = ({ children }: { children: React.ReactNode }) => <ThemeScope scheme="dark">{children}</ThemeScope>;
    const { result } = await renderHook(() => useTheme(), { wrapper });
    expect(result.current.scheme).toBe("dark");
  });
});
