/// <reference types="node" />
import fs from "fs";
import path from "path";
import React from "react";
import * as RN from "react-native";
import { renderHook } from "@testing-library/react-native";
import { kit } from "../../components/ui";
import tokens from "../tokens.json";
import { botColorNames, botColors, themes, ThemeScope, useTheme, type Palette } from "../theme";

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

    it.each(grounds)("keeps the keyboard focus ring visible on %s", (ground) => {
      // WCAG 1.4.11: focus indicators need 3:1 against what's around them.
      expect(contrast(c.accent, c[ground])).toBeGreaterThanOrEqual(3);
    });

    it.each(["bg", "surface", "raised"] as const)("keeps skeleton blocks visible on %s, where they load", (ground) => {
      // Decorative, but they must still read as shapes.
      expect(contrast(c.selected, c[ground])).toBeGreaterThan(1.1);
    });

    it("keeps empty, error and offline states, banners and toasts readable", () => {
      // Empty-state glyphs, the reconnecting banner and error states.
      expect(contrast(c.accentText, c.accentSoft)).toBeGreaterThanOrEqual(4.5);
      expect(contrast(c.danger, c.dangerSoft)).toBeGreaterThanOrEqual(4.5);
      // The offline banner, and the success toast.
      expect(contrast(c.warning, c.warningSoft)).toBeGreaterThanOrEqual(4.5);
      expect(contrast(c.success, c.successSoft)).toBeGreaterThanOrEqual(4.5);
      // Pill buttons.
      expect(contrast(c.text, c.raised)).toBeGreaterThanOrEqual(4.5);
      expect(contrast(c.onAccent, c.accent)).toBeGreaterThanOrEqual(4.5);
    });
  });
});

/** Text colour, ground, and the contrast it needs: 4.5 for text, 3 for faint hints and large glyphs. */
type Pair = [fg: keyof Palette, bg: keyof Palette, min: number];
const body = (grounds: (keyof Palette)[]): Pair[] =>
  grounds.flatMap((g): Pair[] => [
    ["text", g, 4.5],
    ["textMuted", g, 4.5],
    ["accentText", g, 4.5],
    ["textFaint", g, 3],
  ]);
const status = (grounds: (keyof Palette)[]): Pair[] =>
  grounds.flatMap((g): Pair[] => [
    ["danger", g, 4.5],
    ["warning", g, 4.5],
    ["success", g, 4.5],
  ]);
const kitPairs: Pair[] = [
  ...body(["bg", "raised"]),
  ...status(["bg", "raised"]),
  ["onAccent", "accent", 4.5],
  ["danger", "dangerSoft", 4.5],
  ["warning", "warningSoft", 4.5],
  ["success", "successSoft", 4.5],
  ["accentText", "accentSoft", 4.5],
  ["text", "accentSoft", 4.5],
  ["textMuted", "selected", 4.5],
  ["text", "selected", 4.5],
  ["text", "codeBg", 4.5],
  ["text", "hover", 4.5],
];

/** Every screen of the app and the token pairs its text, tags, notices and buttons use (ADR 0345). */
const screens: Record<string, Pair[]> = {
  "chat and sidebar": [...body(["bg", "surface", "raised", "elevated"]), ["text", "userBubble", 4.5], ["onAccent", "accent", 4.5], ["text", "selected", 4.5]],
  "sign-in and the app lock": [...body(["bg", "raised"]), ["danger", "dangerSoft", 4.5], ["onAccent", "accent", 4.5], ["text", "codeBg", 4.5]],
  settings: [...kitPairs, ["text", "warningSoft", 4.5]],
  plan: kitPairs,
  secrets: kitPairs,
  team: kitPairs,
  "approval policy": kitPairs,
  users: [...kitPairs, ...body(["surface"])],
  roles: [...kitPairs, ...body(["surface"])],
  "service accounts": [...kitPairs, ...body(["surface"]), ["text", "codeBg", 4.5]],
  "audit log": [...kitPairs, ...body(["surface"])],
  "access review": kitPairs,
  "Bot settings": [
    ...body(["surface", "raised"]),
    ...status(["surface"]),
    ["onAccent", "accent", 4.5],
    ["danger", "dangerSoft", 4.5],
    ["text", "selected", 4.5],
    // A picked schedule preset is filled with the text colour, as in Chips.
    ["bg", "text", 4.5],
    ["accentText", "hover", 4.5],
    ["text", "codeBg", 4.5],
  ],
  "new Bot": [...body(["elevated", "bg"]), ["onAccent", "accent", 4.5], ["danger", "dangerSoft", 4.5], ["text", "selected", 4.5]],
  approvals: [...body(["elevated", "raised"]), ["warning", "warningSoft", 4.5], ["onAccent", "accent", 4.5]],
  "screen viewer": [...body(["bg", "surface"]), ["onAccent", "accent", 4.5], ["text", "raised", 4.5], ["danger", "dangerSoft", 4.5]],
};

describe.each(["light", "dark"] as const)("contrast on every screen in %s", (scheme) => {
  const c: Palette = themes[scheme].c;

  it.each(Object.entries(screens))("%s", (_name, pairs) => {
    const failing = pairs.filter(([fg, bg, min]) => contrast(c[fg], c[bg]) < min).map(([fg, bg, min]) => `${fg} on ${bg} < ${min}`);
    expect(failing).toEqual([]);
  });

  it("keeps every text style of the settings and admin kit readable where it sits", () => {
    const name = (hex: unknown) => (Object.keys(c) as (keyof Palette)[]).find((k) => c[k] === hex);
    /** Text styles drawn on a fill of their own rather than on a card or the canvas. */
    const filled: Record<string, keyof Palette> = { primaryText: "accent", dangerText: "dangerSoft" };
    const failing: string[] = [];
    for (const [key, style] of Object.entries(kit(themes[scheme])) as [string, Record<string, unknown>][]) {
      const fg = name(style.color);
      if (!fg) continue;
      const bg = name(style.backgroundColor) ?? filled[key];
      const min = fg === "textFaint" ? 3 : 4.5;
      for (const ground of bg ? [bg] : (["bg", "surface", "raised", "elevated"] as const)) {
        if (contrast(c[fg], c[ground]) < min) failing.push(`${key}: ${fg} on ${ground}`);
      }
    }
    expect(failing).toEqual([]);
  });
});

describe("every screen follows light and dark (ADR 0345)", () => {
  const root = path.join(__dirname, "..", "..");
  const sources = ["app", "components"].flatMap((dir) =>
    fs
      .readdirSync(path.join(root, dir))
      .filter((f) => /\.tsx?$/.test(f))
      .map((f) => `${dir}/${f}`),
  );
  const read = (f: string) => fs.readFileSync(path.join(root, f), "utf8");

  it("leaves no screen on the dark-only colours", () => {
    expect(sources.filter((f) => /<ThemeScope scheme="dark">/.test(read(f)))).toEqual([]);
  });

  it("keeps fixed colours to art, brands and remote screens", () => {
    const allowed = new Set([
      "components/BotAvatar.tsx", // A Bot's own art.
      "components/LoginScreen.tsx", // Apple's sign-in button is black or white by Apple's rules.
      "components/ScreenFrame.tsx", // The remote display's letterbox.
      "components/ScreenFrame.web.tsx",
      "components/ScreenViewer.tsx",
    ]);
    const hex = /["'`]#[0-9a-fA-F]{3,8}["'`]/;
    expect(sources.filter((f) => !allowed.has(f) && hex.test(read(f)))).toEqual([]);
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

describe("Bot colours", () => {
  it("each have a name for screen readers", () => {
    expect(botColorNames).toHaveLength(botColors.length);
  });
});
