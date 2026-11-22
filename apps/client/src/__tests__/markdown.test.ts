import { decodeEntities, parseMarkdown, safeHref } from "../markdown";

describe("safeHref", () => {
  it("opens http, https and mailto links", () => {
    expect(safeHref("https://example.com/a?b=1")).toBe("https://example.com/a?b=1");
    expect(safeHref("HTTP://example.com")).toBe("HTTP://example.com");
    expect(safeHref("mailto:someone@example.com")).toBe("mailto:someone@example.com");
    expect(safeHref("https://example.com/?x=1&amp;y=2")).toBe("https://example.com/?x=1&y=2");
  });

  it("refuses script, data, file and app schemes, however they're disguised", () => {
    for (const href of [
      "javascript:alert(1)",
      "JavaScript:alert(1)",
      " javascript:alert(1)",
      "java\nscript:alert(1)",
      "java\tscript:alert(1)",
      "javascript&#58;alert(1)",
      "&#106;avascript:alert(1)",
      "vbscript:msgbox(1)",
      "data:text/html,<script>alert(1)</script>",
      "file:///etc/passwd",
      "intent://x#Intent;end",
      "superbot://settings",
    ]) {
      expect(safeHref(href)).toBeNull();
    }
  });

  it("refuses relative, protocol-relative, hostless and empty links", () => {
    for (const href of ["/settings", "../x", "//evil.example", "https:evil.example", "https:///x", "", null, undefined]) {
      expect(safeHref(href)).toBeNull();
    }
  });
});

describe("decodeEntities", () => {
  it("decodes named and numeric references and keeps unknown ones", () => {
    expect(decodeEntities("a &amp; b &lt;c&gt; &quot;d&quot; &#169; &#x2014; &bogus;")).toBe('a & b <c> "d" \u00a9 \u2014 &bogus;');
    expect(decodeEntities("&#0; &#xD800; &#x110000;")).toBe("\ufffd \ufffd \ufffd");
    expect(decodeEntities("&constructor; &toString; &__proto__;")).toBe("&constructor; &toString; &__proto__;");
  });
});

describe("parseMarkdown", () => {
  it("keeps raw HTML as an html token instead of interpreting it", () => {
    const [t] = parseMarkdown("<script>alert(1)</script>");
    expect(t).toMatchObject({ type: "html", text: "<script>alert(1)</script>" });
  });

  it("parses GitHub tables, strikethrough and task lists", () => {
    const types = parseMarkdown("| a |\n|---|\n| 1 |\n\n~~x~~\n\n- [x] done").map((t) => t.type);
    expect(types).toEqual(["table", "space", "paragraph", "space", "list"]);
  });
});
