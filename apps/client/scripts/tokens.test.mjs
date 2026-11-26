// node --test scripts/tokens.test.mjs
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { css, withTokens } from "./tokens.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const tokens = JSON.parse(fs.readFileSync(path.join(root, "src/tokens.json"), "utf8"));

test("every colour is a property in light and in dark", () => {
  const block = css(tokens);
  const [light, dark] = block.split("@media (prefers-color-scheme: dark)");
  for (const [k, v] of Object.entries(tokens.color.light)) assert.ok(light.includes(`--c-${k.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)}: ${v};`), k);
  for (const [k, v] of Object.entries(tokens.color.dark)) assert.ok(dark.includes(`--c-${k.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)}: ${v};`), k);
  assert.ok(light.includes("--radius-pill: 999px;"));
  assert.ok(light.includes("--motion-fast: 120ms;"));
});

test("replaces only its own block, and puts it first when there is none", () => {
  const block = css(tokens);
  const once = withTokens("body { color: red; }\n", block);
  assert.ok(once.startsWith(block));
  assert.equal(withTokens(once, block), once);
  const edited = once.replace("--c-bg: #faf9f7;", "--c-bg: #000000;");
  assert.equal(withTokens(edited, block), once);
});
