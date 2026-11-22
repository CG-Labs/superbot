// Docs search for the SuperBot site (ADR 0118). The index (assets/search-index.js) is
// loaded the first time the search box gets focus, and results are built with
// textContent only, so nothing from the index is ever parsed as HTML.
(function () {
  "use strict";

  function tokens(query) {
    return query.toLowerCase().split(/[^\p{L}\p{N}_]+/u).filter(Boolean);
  }

  function count(hay, needle, cap) {
    let n = 0;
    let i = hay.indexOf(needle);
    while (i !== -1 && n < cap) {
      n++;
      i = hay.indexOf(needle, i + needle.length);
    }
    return n;
  }

  // Pages holding every term, best first: matches in the title count most, then in
  // headings, then in the text, each capped so one long page can't win on length alone.
  function search(index, query, limit) {
    const terms = tokens(query);
    if (!terms.length) return [];
    const hits = [];
    for (const page of index) {
      const title = page.t.toLowerCase();
      const heads = page.h.join("\n").toLowerCase();
      const text = page.x.toLowerCase();
      let score = 0;
      let all = true;
      for (const term of terms) {
        const t = count(title, term, 3);
        const h = count(heads, term, 10);
        const x = count(text, term, 20);
        if (!t && !h && !x) {
          all = false;
          break;
        }
        score += t * 30 + h * 5 + x;
      }
      if (all) hits.push({ page, score });
    }
    hits.sort((a, b) => b.score - a.score || a.page.t.localeCompare(b.page.t));
    return hits.slice(0, limit).map((h) => h.page);
  }

  // A piece of the page's text around the earliest term it holds.
  function snippet(page, query, width) {
    const text = page.x;
    const lower = text.toLowerCase();
    let at = -1;
    for (const term of tokens(query)) {
      const i = lower.indexOf(term);
      if (i !== -1 && (at === -1 || i < at)) at = i;
    }
    const start = at === -1 ? 0 : Math.max(0, at - Math.floor(width / 3));
    const end = Math.min(text.length, start + width);
    return (start > 0 ? "…" : "") + text.slice(start, end).trim() + (end < text.length ? "…" : "");
  }

  const api = { tokens, search, snippet };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
    return;
  }

  // The site's top, from this script's own address (<root>/assets/search.js), so links
  // work under any path and nothing on the page decides where they point.
  const siteRoot = new URL("../", document.currentScript.src);

  function start() {
    const form = document.querySelector("form.search");
    if (!form) return;
    const input = form.querySelector("input");
    const list = form.querySelector(".results");
    const none = form.querySelector(".results-none");
    let loading = null;
    form.hidden = false;

    function load() {
      if (!loading) {
        loading = new Promise((resolve, reject) => {
          const script = document.createElement("script");
          script.src = new URL("assets/search-index.js", siteRoot).href;
          script.onload = () => resolve(window.SUPERBOT_SEARCH_INDEX || []);
          script.onerror = () => {
            loading = null;
            reject(new Error("search index did not load"));
          };
          document.head.appendChild(script);
        });
      }
      return loading;
    }

    function clear() {
      list.textContent = "";
      none.hidden = true;
    }

    function render(index) {
      const query = input.value;
      clear();
      const pages = search(index, query, 12);
      none.textContent = "No pages match.";
      none.hidden = !(tokens(query).length && !pages.length);
      for (const page of pages) {
        const li = document.createElement("li");
        const a = document.createElement("a");
        a.href = new URL(page.u, siteRoot).href;
        a.textContent = page.t;
        const section = document.createElement("span");
        section.className = "result-section";
        section.textContent = page.s;
        const text = document.createElement("p");
        text.textContent = snippet(page, query, 140);
        li.append(a, section, text);
        list.append(li);
      }
    }

    input.addEventListener("focus", () => load().catch(() => {}));
    input.addEventListener("input", () =>
      load().then(render, () => {
        clear();
        none.textContent = "Search couldn't load. Browse the sections below instead.";
        none.hidden = false;
      }),
    );
    input.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        input.value = "";
        clear();
      }
    });
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const first = list.querySelector("a");
      if (first) window.location.href = first.href;
    });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();
})();
