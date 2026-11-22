import React from "react";
import { Linking } from "react-native";
import { fireEvent, render, screen } from "@testing-library/react-native";
import { Markdown } from "../Markdown";

describe("Markdown", () => {
  let open: jest.SpyInstance;
  beforeEach(() => {
    open = jest.spyOn(Linking, "openURL").mockResolvedValue(undefined);
  });
  afterEach(() => open.mockRestore());

  it("renders headings, emphasis, inline code and line breaks", async () => {
    await render(<Markdown>{"# Title\n\nSome **bold**, *italic*, ~~gone~~ and `npm test` &amp; more  \nnext line"}</Markdown>);
    expect(screen.getByRole("heading", { name: "Title" })).toBeOnTheScreen();
    expect(screen.getByText("bold")).toHaveStyle({ fontWeight: "700" });
    expect(screen.getByText("italic")).toHaveStyle({ fontStyle: "italic" });
    expect(screen.getByText("gone")).toHaveStyle({ textDecorationLine: "line-through" });
    expect(screen.getByText("npm test")).toHaveStyle({ fontFamily: "monospace" });
    expect(screen.getByText(/npm test & more next line$/)).toBeOnTheScreen();
  });

  it("keeps character references in inline code as written", async () => {
    await render(<Markdown>{"Use `&lt;div&gt;` for &lt;div&gt;"}</Markdown>);
    expect(screen.getByText("&lt;div&gt;")).toHaveStyle({ fontFamily: "monospace" });
    expect(screen.getByText(/for <div>$/)).toBeOnTheScreen();
  });

  it("renders fenced code verbatim", async () => {
    await render(<Markdown>{"```ts\nconst a = 1 < 2 && **b**;\n```"}</Markdown>);
    expect(screen.getByText("const a = 1 < 2 && **b**;")).toHaveStyle({ fontFamily: "monospace" });
  });

  it("renders bulleted, numbered, nested and task lists", async () => {
    await render(<Markdown>{"- one\n- two\n  - inner\n\n3. three\n4. four\n\n- [x] done\n- [ ] todo"}</Markdown>);
    expect(screen.getAllByText("\u2022")).toHaveLength(3);
    for (const s of ["one", "two", "inner", "3.", "three", "4.", "four", "\u2611", "done", "\u2610", "todo"]) {
      expect(screen.getByText(s)).toBeOnTheScreen();
    }
  });

  it("renders tables and blockquotes", async () => {
    await render(<Markdown>{"| Name | Score |\n|---|--:|\n| Ada | **9** |\n\n> quoted"}</Markdown>);
    expect(screen.getByText("Name")).toHaveStyle({ fontWeight: "700" });
    expect(screen.getByText("Score")).toHaveStyle({ textAlign: "right" });
    expect(screen.getByText("9")).toBeOnTheScreen();
    expect(screen.getByText("quoted")).toBeOnTheScreen();
  });

  it("opens http links and bare URLs", async () => {
    await render(<Markdown>{"See [the docs](https://example.com/docs) or https://example.org"}</Markdown>);
    await fireEvent.press(screen.getByRole("link", { name: "the docs" }));
    expect(open).toHaveBeenCalledWith("https://example.com/docs");
    await fireEvent.press(screen.getByRole("link", { name: "https://example.org" }));
    expect(open).toHaveBeenLastCalledWith("https://example.org");
  });

  it("shows unsafe links as plain text that opens nothing", async () => {
    await render(<Markdown>{"[click](javascript:alert(1)) [data](data:text/html,x) [app](superbot://x)"}</Markdown>);
    expect(screen.queryAllByRole("link")).toHaveLength(0);
    expect(screen.getByText("click data app")).toBeOnTheScreen();
  });

  it("shows raw HTML as text and never as markup", async () => {
    await render(<Markdown>{'<script>alert(1)</script>\n\nhi <img src=x onerror="alert(1)">'}</Markdown>);
    expect(screen.getByText("<script>alert(1)</script>")).toBeOnTheScreen();
    expect(screen.getByText('hi <img src=x onerror="alert(1)">')).toBeOnTheScreen();
  });

  it("shows images as a link to the image instead of loading them", async () => {
    await render(<Markdown>{"![a chart](https://example.com/c.png) ![](javascript:x)"}</Markdown>);
    expect(JSON.stringify(screen.toJSON())).not.toContain('"Image"');
    await fireEvent.press(screen.getByRole("link", { name: "a chart" }));
    expect(open).toHaveBeenCalledWith("https://example.com/c.png");
    expect(screen.getAllByRole("link")).toHaveLength(1);
  });
});
