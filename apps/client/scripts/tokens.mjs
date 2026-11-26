// Writes the design tokens (src/tokens.json, ADR 0335) into the admin console's CSS as custom properties,
// and into the sign-in page's own styles, which /login serves without the console's style sheet (ADR 0341).
//   npm run tokens        update web/styles.css and web/login.html
//   npm run tokens:check  verify both match src/tokens.json (CI)
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const tokensFile = path.join(root, "src/tokens.json");
const web = path.resolve(root, "../../web");
/** The files that carry the block. An HTML page must already have its markers inside its `<style>`. */
export const targets = ["styles.css", "login.html"];

const START = "/* tokens:start: made from apps/client/src/tokens.json by `npm run tokens`; edit that file, not this block */";
const END = "/* tokens:end */";

const kebab = (s) => s.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`);
const px = (v) => (typeof v === "number" && v !== 0 ? `${v}px` : String(v));

/** The CSS block for `tokens`: light by default, dark under `prefers-color-scheme: dark`. */
export function css(tokens) {
  const colors = (scheme, indent) => [
    ...Object.entries(tokens.color[scheme]).map(([k, v]) => `${indent}--c-${kebab(k)}: ${v};`),
    ...Object.entries(tokens.shadow[scheme]).map(([k, v]) => `${indent}--shadow-${kebab(k)}: ${v};`),
  ];
  const scale = [
    ...Object.entries(tokens.space).map(([k, v]) => `  --space-${k}: ${px(v)};`),
    ...Object.entries(tokens.radius).map(([k, v]) => `  --radius-${k}: ${px(v)};`),
    `  --font-sans: ${tokens.font.sans};`,
    `  --font-mono: ${tokens.font.mono};`,
    ...Object.entries(tokens.font.size).map(([k, v]) => `  --fs-${k}: ${px(v)};`),
    ...Object.entries(tokens.font.lineHeight).map(([k, v]) => `  --lh-${k}: ${px(v)};`),
    ...Object.entries(tokens.motion).map(([k, v]) => `  --motion-${k}: ${v}ms;`),
  ];
  return [
    START,
    ":root {",
    "  color-scheme: light dark;",
    ...colors("light", "  "),
    ...scale,
    "}",
    "@media (prefers-color-scheme: dark) {",
    "  :root {",
    ...colors("dark", "    "),
    "  }",
    "}",
    END,
  ].join("\n");
}

/** `text` with its tokens block replaced by `block`, or the block put first when it has none. */
export function withTokens(text, block) {
  const a = text.indexOf(START);
  const b = text.indexOf(END);
  if (a === -1 || b === -1) return `${block}\n\n${text}`;
  return text.slice(0, a) + block + text.slice(b + END.length);
}

/** Whether `text` has a tokens block to replace. */
export const hasTokens = (text) => text.includes(START) && text.includes(END);

const read = () => JSON.parse(fs.readFileSync(tokensFile, "utf8"));

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const block = css(read());
  const check = process.argv.includes("--check");
  let stale = false;
  for (const name of targets) {
    const file = path.join(web, name);
    const current = fs.readFileSync(file, "utf8");
    if (name.endsWith(".html") && !hasTokens(current)) {
      console.error(`web/${name} has no tokens block: put the tokens:start and tokens:end markers inside its <style>`);
      process.exit(1);
    }
    const next = withTokens(current, block);
    if (check) {
      if (next !== current) {
        console.error(`web/${name} is out of date with src/tokens.json: run \`npm run tokens\` in apps/client`);
        stale = true;
      } else console.log(`web/${name} matches src/tokens.json`);
    } else {
      fs.writeFileSync(file, next);
      console.log(`updated web/${name} tokens`);
    }
  }
  if (stale) process.exit(1);
}
