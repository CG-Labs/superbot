import { BLOCKED, botParam, PLACEHOLDER_PROJECT_ID, projectProblem, pushLink, pushUnavailable } from "../push";
import { testSummary } from "../notifications";

describe("pushLink", () => {
  it("opens the inbox on a waiting approval", () => {
    expect(pushLink({ type: "approval", botId: "b1", approvalId: "ap_1", url: "/home?approval=ap_1" })).toEqual({ pathname: "/home", params: { approval: "ap_1" } });
  });

  it("opens the chat of a Bot whose routine finished", () => {
    expect(pushLink({ type: "routine", botId: "b1", url: "/home?bot=b1" })).toEqual({ pathname: "/home", params: { bot: "b1" } });
  });

  it("opens home for a test or an id that doesn't look like one", () => {
    expect(pushLink({ type: "test", url: "/home" })).toEqual({ pathname: "/home" });
    expect(pushLink({ type: "approval", approvalId: "../../settings" })).toEqual({ pathname: "/home" });
    expect(pushLink({ type: "routine", botId: 7 })).toEqual({ pathname: "/home" });
  });

  it("ignores pushes that aren't SuperBot's, and never follows their url", () => {
    expect(pushLink({ url: "https://example.com/phish" })).toBeNull();
    expect(pushLink({ type: "other", url: "/settings" })).toBeNull();
    expect(pushLink(null)).toBeNull();
    expect(pushLink("approval")).toBeNull();
  });
});

describe("botParam", () => {
  it("takes ids, not paths", () => {
    expect(botParam("b_1-x")).toBe("b_1-x");
    expect(botParam(["b2", "b3"])).toBe("b2");
    expect(botParam("a/b")).toBeNull();
    expect(botParam(undefined)).toBeNull();
  });
});

describe("projectProblem", () => {
  it("needs the EAS project whoever builds the app sets", () => {
    expect(projectProblem(null)).toMatch(/no Expo project/);
    expect(projectProblem(PLACEHOLDER_PROJECT_ID)).toMatch(/no Expo project/);
    expect(projectProblem("2b5b6a52-8f8e-4c4a-9d7e-6f1c0a9b3e21")).toBeNull();
  });
});

describe("pushUnavailable", () => {
  it("says why push can't be turned on", () => {
    expect(pushUnavailable(undefined, false)).toMatch(/iPhone and Android apps/);
    expect(pushUnavailable({ available: false, provider: null, device: null }, true)).toMatch(/PUSH_PROVIDER=expo/);
    expect(pushUnavailable({ available: true, provider: "expo", device: null }, true)).toBeNull();
    expect(pushUnavailable(undefined, true)).toBeNull();
    expect(BLOCKED).toMatch(/phone's settings/);
  });
});

it("names push in a notification test's result", () => {
  expect(testSummary({ ok: false, results: [{ channel: "push", ok: false, error: "DeviceNotRegistered" }] })).toBe("Push failed: DeviceNotRegistered");
});
