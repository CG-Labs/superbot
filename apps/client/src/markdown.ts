import { Lexer, type Token } from "marked";

export type { Token, Tokens } from "marked";

/** Block tokens for `src`: CommonMark with GitHub tables, strikethrough, task lists and bare URLs. */
export function parseMarkdown(src: string): Token[] {
  return new Lexer({ gfm: true, breaks: false }).lex(src);
}

const NAMED = new Map<string, string>(Object.entries({
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
  nbsp: "\u00a0",
  copy: "\u00a9",
  reg: "\u00ae",
  trade: "\u2122",
  hellip: "\u2026",
  mdash: "\u2014",
  ndash: "\u2013",
  lsquo: "\u2018",
  rsquo: "\u2019",
  ldquo: "\u201c",
  rdquo: "\u201d",
  middot: "\u00b7",
  times: "\u00d7",
}));

/** Decodes the character references marked leaves in text and link targets; unknown ones stay as written. */
export function decodeEntities(s: string): string {
  if (!s.includes("&")) return s;
  return s.replace(/&(#x[0-9a-f]{1,6}|#[0-9]{1,7}|[a-z]+);/gi, (whole, ref: string) => {
    if (ref[0] === "#") {
      const code = ref[1] === "x" || ref[1] === "X" ? parseInt(ref.slice(2), 16) : parseInt(ref.slice(1), 10);
      return code > 0 && code <= 0x10ffff && (code < 0xd800 || code > 0xdfff) ? String.fromCodePoint(code) : "\ufffd";
    }
    return NAMED.get(ref.toLowerCase()) ?? whole;
  });
}

const SAFE_SCHEMES = new Set(["http:", "https:", "mailto:"]);

/**
 * The URL to open for a link in a message, or null when it must not be opened. Messages come from
 * Bots, which repeat whatever a web page or a peer said, so only http(s) and mailto links open:
 * `javascript:`, `data:`, `file:` and app schemes don't, nor do relative links.
 */
export function safeHref(href: string | null | undefined): string | null {
  if (!href) return null;
  const url = decodeEntities(href).replace(/[\u0000-\u0020\u007f-\u009f]/g, "");
  const scheme = /^([a-z][a-z0-9+.-]*:)/i.exec(url)?.[1]?.toLowerCase();
  if (!scheme || !SAFE_SCHEMES.has(scheme)) return null;
  if (scheme !== "mailto:" && !/^https?:\/\/[^/?#]/i.test(url)) return null;
  return url;
}
