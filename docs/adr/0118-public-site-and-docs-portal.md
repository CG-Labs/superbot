# 0118: The public site and docs portal, built as static files

## Status

Accepted (22 Nov 2026). First slice of the marketing site and docs portal of M4, [#44](https://github.com/CG-Labs/superbot/issues/44).

0116 is the highest number on `main`, and 0117 is taken by a pull request in flight ([PR #180](https://github.com/CG-Labs/superbot/pull/180)), so this is 0118. Renumber it if another ADR lands first.

## Context

M4 needs a public site with published plans and a docs portal. The docs already exist: about 150 Markdown files under `docs/` (guides, single sign-on guides, operations guides, the security pack, the SLO and every ADR), plus the install guide in `deploy/README.md`, `SECURITY.md` and `CHANGELOG.md`. They are written to be read on GitHub: relative links between them, links into the code (`../server/src/...`), and `#anchors` to GitHub's heading ids. Only the security pack's links are checked in CI (`server/tests/security_docs_links.rs`).

`site/` is a different page: the landing page and "Get started" form that every SuperBot server serves at `/` ([ADR 0022](0022-landing-and-signups.md)). It links to that server's own `/app/` and `/get-started`, so it can't be a standalone public site.

AGENTS.md asks for Rust first and a thin browser layer. #44 must not need a paid service, a new account, or anything published from CI.

## Decision

- **`superbot-site`, a small Rust generator** ([`server/src/bin/superbot-site/`](../../server/src/bin/superbot-site/main.rs)), renders the site with `pulldown-cmark` (default features off, HTML only; GitHub-flavoured tables, task lists, footnotes and strikethrough). It is a binary in the server crate, like `superbot-license`. The Docker build stage copies only `server/`, `web/` and `site/`, so a new workspace member would break image builds. `botd` doesn't use the crate, so it isn't linked into the server.
- **What it builds.** `target/site/` by default (`--out`): `index.html`, the landing page; `docs/`, the portal; `assets/`, the styles (`site/assets/site.css` plus `docs.css`), the mark and the search. Every link is relative, so the site works from any path, any host, or straight from disk.
- **Which pages.** Every `docs/**/*.md`, plus `deploy/README.md` as "Install", `SECURITY.md` and `CHANGELOG.md`. `.md` becomes `.html` and `README.md` becomes `index.html`. Two notes about another vendor's product are left out, because SuperBot doesn't publish under that name (AGENTS.md, [ADR 0002](0002-name.md)), and links to them go to GitHub. A new folder under `docs/` gets its own section automatically.
- **Links follow GitHub's rules and are checked.** A link to a portal page, or to a folder whose `README.md` is one, becomes a relative link to the HTML page. A link to any other repository file or folder goes to it on GitHub (`--repo-url`). Linked images are copied into the site. Each `#anchor` must match a heading, using GitHub's ids, which the pages also use. A missing file, a missing heading, or a link that climbs out of the repository is an error with its file and line. After writing, the build checks the output on its own: every `href` and `src` in every page, the landing page and navigation included, must name a file in the site, every `#anchor` must name an `id` there, and links starting with `/` are refused. Any problem makes the build exit 1.
- **Navigation.** A sidebar lists every page by section (Guides, Single sign-on, Operations, Security pack, Decisions, Background), with the current page marked and its section open. The docs home lists every page, each page has a breadcrumb and a link to its source on GitHub, and the header links the landing page, the plans and the repository.
- **Search runs in the browser.** The build writes an index of each page's title, section, headings and first 30,000 characters of text (`assets/search-index.js`, about 1.4 MB, 0.45 MB gzipped). [`search.js`](../../server/src/bin/superbot-site/assets/search.js) loads it the first time the search box gets focus. Every search word must match, matches in titles rank above matches in headings, and those above matches in the text. Results are built with `textContent`, never as HTML. The script is same-origin, so it runs under `script-src 'self'` with no inline code. Without JavaScript, the search box stays hidden and navigation still works.
- **The landing page** reuses the in-product page's copy and styles and adds a plans section. The plans are Self-host (licensed per seat, [ADR 0038](0038-self-host-license-key.md)), one card per managed tier, and Enterprise (custom). The managed tiers' names and limits come from [`deploy/tiers.example.json`](../../deploy/tiers.example.json), the plans SuperBot ships (`--tiers`): Bots, runs at once, runs a month, routine runs a day, model tokens and storage, whichever the tier sets. Models and machine types aren't shown ([ADR 0033](0033-tiers-model-routing.md)). No prices exist yet, so every card says "Pricing to be published" or "Contact sales", and the page states there is no free tier ([ADR 0068](0068-no-free-tier.md)). There are no customer quotes, logos or figures. "Contact sales" links to `--contact-url` (or `SUPERBOT_SITE_CONTACT_URL`). It must be a full URL, and it defaults to the repository until there is a sales contact.
- **The in-product landing page is unchanged.** Servers still serve `site/` at `/` from botd or Caddy.
- **CI builds it, nothing publishes it.** The `docs` workflow's `site` job runs the generator's unit tests, the search tests (`node --test`), and the build itself, which fails on any broken internal link. It then keeps the site as the `superbot-site` artifact for 14 days. It runs on changes to `docs/`, `site/`, the generator, the tiers example, the install guide, `SECURITY.md`, `CHANGELOG.md` or the workflows. The server workflow's `cargo test` runs the same unit tests, including one that builds the real repository.

## Publishing (an operator step)

Nothing here sets up GitHub Pages, DNS or hosting. To publish, an operator builds the site, or downloads the `superbot-site` artifact from a `docs` run on `main`, and serves the folder with any static file server:

```bash
cargo run --release --bin superbot-site -- --out /srv/superbot-public-site --contact-url https://<sales-contact-url>
```

With Caddy on its own host name:

```
<docs-domain> {
	encode gzip
	root * /srv/superbot-public-site
	header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
	header X-Content-Type-Options nosniff
	header Referrer-Policy strict-origin-when-cross-origin
	file_server
}
```

Or, under a path of an existing SuperBot server, add this before the final `handle` in its Caddyfile (`deploy/docker/Caddyfile`, or `/etc/caddy/Caddyfile` from the installer). Then reload Caddy:

```
	redir /public /public/
	handle_path /public/* {
		root * /srv/superbot-public-site
		file_server
	}
```

Rebuild and replace the folder to update it. The generator refuses to overwrite a folder it didn't make.

## Alternatives considered

- **mdBook.** It is Rust, but it needs a hand-kept `SUMMARY.md` for 150 pages, and a separate plugin installed in CI to check links. Its link rewriting covers only `.md` links, so the many links into code would break off GitHub. A generator of about 1,500 lines, tests included, that follows GitHub's rules is smaller to trust.
- **Zola, Hugo, MkDocs, Docusaurus or Astro.** Zola and Hugo want front matter in every file. The others bring a Python or Node toolchain and its dependency tree into CI, against Rust first and the npm audit gate ([ADR 0092](0092-dependency-vulnerability-scanning.md)).
- **Pagefind or lunr for search.** Pagefind is a separate binary to download and pin in CI, and lunr is a JavaScript dependency. Matching words across 150 pages is fast enough without either. Revisit if the index passes a few megabytes.
- **Serving the docs from botd.** Every server would carry about 7 MB of docs that change more often than the server does. Rejected for now. The path-mounted Caddy block above gives the same result where it's wanted.
- **Publishing from CI (GitHub Pages, Netlify, Vercel or a CDN).** These need repository settings or new accounts, which are out of scope. An owner can add publishing later from the same artifact.
- **Turning `site/index.html` into the public site.** It is the page each server shows its own users, with that server's sign-in and sign-up links. Keeping the two apart lets each say the right thing.

## Consequences

- A broken link or heading anywhere in `docs/`, or in the install guide, security policy or changelog, now fails CI, not only in the security pack. Renaming a heading means updating the links to it.
- The site is always buildable from a checkout, offline, with `cargo run --bin superbot-site`.
- Mermaid diagrams show as code, and there are no screenshots yet.
- Remaining on #44: choosing the domain and hosting and publishing the site (owner decisions), a sales contact for "Contact sales", prices once they're set, rendered diagrams, and the site in Compose and the installer if wanted.
