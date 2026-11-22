# 0115: The client's Markdown renderer, and the npm audit gate at High

## Status

Accepted (22 Nov 2026). Part of the SOC 2 readiness checklist of M4, [#50](https://github.com/CG-Labs/superbot/issues/50); closes checklist row CC7.1-2 in the [readiness checklist](../security/soc2-readiness-checklist.md). Finishes what [ADR 0092](0092-dependency-vulnerability-scanning.md) left open.

0114 is the highest number on `main`.

## Context

The client rendered Bot messages with `react-native-markdown-display` 7.0.2, which is built on `markdown-it` 10. `markdown-it` and its `linkify-it` have High advisories (quadratic-time parsing a message can trigger), and the library has no release on a fixed `markdown-it`. These were the only High or Critical npm findings, so ADR 0092 set the `npm audit` gate to Critical until the renderer was replaced.

The renderer also opened any link a message held with `Linking.openURL`, whatever its scheme, and loaded every image a message pointed at. Bot messages repeat what web pages and other Bots said, so both are a way in.

## Decision

- **Parse with `marked`, render in the client.** `marked` is maintained, has no dependencies and no open advisories, and its lexer turns Markdown into tokens without producing HTML. A small renderer ([`apps/client/components/Markdown.tsx`](../../apps/client/components/Markdown.tsx), helpers in [`apps/client/src/markdown.ts`](../../apps/client/src/markdown.ts)) maps the tokens to React Native views, so iOS, Android and web share one path and no HTML is ever put into the page. `react-native-markdown-display`, `markdown-it` and `linkify-it` are gone from the lockfile.
- **What renders.** As before: paragraphs, headings, bold, italic, strikethrough, inline code, fenced and indented code (monospace, selectable, scrolling sideways), block quotes, bulleted and numbered lists with nesting, tables (scrolling sideways), rules and hard line breaks. New with GitHub-flavoured Markdown: task-list boxes and bare URLs as links. Dropped: `markdown-it`'s typographer (straight quotes stay straight).
- **Raw HTML is text.** As with `markdown-it`'s `html: false`, HTML in a message is shown as written, never interpreted.
- **Only http(s) and mailto links open.** Every other scheme (`javascript:`, `data:`, `file:`, app schemes), relative links and hostless URLs render as plain text. The check runs after decoding character references and dropping control characters and whitespace, so `java&#115;cript:` or a split scheme is caught.
- **Images are links.** An image shows as a link, labelled with its alt text, to the image, instead of loading it, so a message can't make the app fetch a tracking pixel or a remote file. Screenshots reach the user through the screen viewer, not chat Markdown.
- **The npm gate is High.** [`dependency-audit.yml`](../../.github/workflows/dependency-audit.yml) now runs `npm audit --audit-level=high`. `npm audit` reports no High or Critical finding, so no npm finding is accepted. npm has no per-advisory ignore list: a future High with no fix is replaced or overridden, or, if it truly can't be, it's listed in checklist row CC7.1-2 with its reason in the change that relaxes the gate.

## Tests

- [`apps/client/components/__tests__/Markdown.test.tsx`](../../apps/client/components/__tests__/Markdown.test.tsx): headings, emphasis, code, lists, task lists, tables and quotes render; http links and bare URLs open; `javascript:`, `data:` and app links don't, and show as text; raw HTML shows as text; images aren't loaded.
- [`apps/client/src/__tests__/markdown.test.ts`](../../apps/client/src/__tests__/markdown.test.ts): the link check against disguised schemes, relative and hostless links; character references.

## Consequences

- Moderate npm advisories (in `glob` and `minimatch`, reached through Jest and other build tools) still print on every run and don't fail it; they are ordinary upgrades.
- The renderer is ours to maintain, about 200 lines. Markdown features `marked` parses but the renderer doesn't know show as their source text, not as nothing.
- Users tap to open an image instead of seeing it inline.
