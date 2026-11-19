import React from "react";
import { render } from "@testing-library/react-native";
import { ScreenFrame } from "../ScreenFrame";
import { ScreenFrame as WebScreenFrame } from "../ScreenFrame.web";

const mockWebViewProps = jest.fn();
jest.mock("react-native-webview", () => ({
  WebView: (props: Record<string, unknown>) => {
    mockWebViewProps(props);
    return null;
  },
}));

const URL = "https://bots.example.com/screen/6901/?token=t";

describe("ScreenFrame (native)", () => {
  beforeEach(() => mockWebViewProps.mockClear());

  it("loads the voxl link without auth headers and locks navigation to the server", async () => {
    await render(<ScreenFrame url={URL} title="Ada's screen" />);
    const props = mockWebViewProps.mock.calls.at(-1)?.[0];

    expect(props.source).toEqual({ uri: URL });
    expect(props.originWhitelist).toEqual(["https://bots.example.com"]);
    expect(props.incognito).toBe(true);
    expect(props.setSupportMultipleWindows).toBe(false);
    const allow = props.onShouldStartLoadWithRequest as (r: { url: string }) => boolean;
    expect(allow({ url: URL })).toBe(true);
    expect(allow({ url: "https://bots.example.com.evil.example/" })).toBe(false);
    expect(allow({ url: "https://evil.example/" })).toBe(false);
  });
});

describe("ScreenFrame (web)", () => {
  it("renders an iframe that sends no referrer", async () => {
    const element = WebScreenFrame({ url: URL, title: "Ada's screen" });
    expect(element.type).toBe("iframe");
    expect(element.props).toMatchObject({ src: URL, title: "Ada's screen", referrerPolicy: "no-referrer" });
  });
});
