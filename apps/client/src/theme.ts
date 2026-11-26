import React, { createContext, useContext } from "react";
import { Platform, StyleSheet, useColorScheme, type TextStyle } from "react-native";
import tokens from "./tokens.json";

export type Scheme = "light" | "dark";
export type Palette = typeof tokens.color.light;
type Weight = NonNullable<TextStyle["fontWeight"]>;

export interface Theme {
  scheme: Scheme;
  c: Palette;
  space: typeof tokens.space;
  radius: typeof tokens.radius;
  font: {
    size: typeof tokens.font.size;
    lineHeight: typeof tokens.font.lineHeight;
    weight: Record<keyof typeof tokens.font.weight, Weight>;
    /** The web font stack; native apps use the system font. */
    sans: string;
    mono: string;
  };
  shadow: typeof tokens.shadow.light;
  motion: typeof tokens.motion;
  layout: typeof tokens.layout;
}

const mono = Platform.select({ ios: "Menlo", android: "monospace", default: tokens.font.mono });

function theme(scheme: Scheme): Theme {
  return {
    scheme,
    c: tokens.color[scheme],
    space: tokens.space,
    radius: tokens.radius,
    font: {
      size: tokens.font.size,
      lineHeight: tokens.font.lineHeight,
      weight: tokens.font.weight as Record<keyof typeof tokens.font.weight, Weight>,
      sans: tokens.font.sans,
      mono,
    },
    shadow: tokens.shadow[scheme],
    motion: tokens.motion,
    layout: tokens.layout,
  };
}

export const themes: Record<Scheme, Theme> = { light: theme("light"), dark: theme("dark") };

const ForcedScheme = createContext<Scheme | null>(null);

/**
 * Holds everything inside it to one scheme, for a part that must look the same whatever the
 * device's setting. Every screen follows the device since ADR 0345, so none uses it today.
 */
export function ThemeScope({ scheme, children }: { scheme: Scheme; children: React.ReactNode }) {
  return React.createElement(ForcedScheme.Provider, { value: scheme }, children);
}

/** The theme for the device's light or dark setting, unless a `ThemeScope` holds it to one. */
export function useTheme(): Theme {
  const forced = useContext(ForcedScheme);
  const system = useColorScheme();
  return themes[forced ?? (system === "dark" ? "dark" : "light")];
}

/** A hook giving `factory`'s styles for the current theme, made once per scheme. */
export function themedStyles<T>(factory: (t: Theme) => T): () => T {
  const made: Partial<Record<Scheme, T>> = {};
  return function useThemedStyles() {
    const t = useTheme();
    return (made[t.scheme] ??= factory(t));
  };
}

/** Text styles of the type scale, by size name. */
export function type(t: Theme, size: keyof typeof tokens.font.size): TextStyle {
  return { fontSize: t.font.size[size], lineHeight: t.font.lineHeight[size] };
}

export const hairline = StyleSheet.hairlineWidth;

export const botColors = [
  "#f5f5f5",
  "#9a6b3f",
  "#e5484d",
  "#e8702e",
  "#e9a23b",
  "#4cc06a",
  "#4fb5a5",
  "#3b82f6",
  "#8b5cf6",
  "#e64a9c",
  "#7a7a7a",
];

/** What screen readers call each of `botColors`, in the same order. */
export const botColorNames = ["White", "Brown", "Red", "Orange", "Amber", "Green", "Teal", "Blue", "Purple", "Pink", "Grey"];

export const botShapes = [
  "waddle",
  "drop",
  "cloud",
  "bean",
  "onigiri",
  "peanut",
  "pebble",
  "square",
  "jelly",
  "gem",
  "gear",
  "heart",
];

export const HARNESS_NAMES: Record<string, string> = {
  claude: "Claude Code",
  codex: "Codex",
  pi: "Pi",
  hermes: "Hermes Agent",
};
