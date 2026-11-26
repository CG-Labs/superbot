import React from "react";
import * as RN from "react-native";
import { act, render, screen, userEvent } from "@testing-library/react-native";
import { TeammateLoginPanel } from "../TeammateLoginPanel";
import { themes } from "../../src/theme";
import type { LoginEvent, TeammateLoginsView } from "../../src/types";

const view = (state: "logged_in" | "logged_out"): TeammateLoginsView => ({
  machineId: "m1",
  owner: { id: "u1", name: "Ada" },
  forUser: "u2",
  logins: "on",
  hasUser: true,
  harnesses: { claude: { state, serverKey: false }, codex: { state: "logged_out", serverKey: false } },
});

/** A fake server: one login, which the test drives. */
function fakeApi() {
  let state: "logged_in" | "logged_out" = "logged_out";
  const login: { onEvent?: (e: LoginEvent) => void; end?: () => void; stop: jest.Mock } = { stop: jest.fn() };
  return {
    login,
    loggedIn: () => (state = "logged_in"),
    teammateLogins: jest.fn(async () => view(state)),
    startTeammateLogin: jest.fn((_owner: string, _harness: string, onEvent: (e: LoginEvent) => void) => {
      login.onEvent = onEvent;
      const done = new Promise<void>((resolve) => (login.end = resolve));
      login.stop.mockImplementation(() => login.end?.());
      return { stop: login.stop, done };
    }),
    teammateLoginInput: jest.fn(async () => {}),
    stopTeammateLogin: jest.fn(async () => {}),
    teammateLogout: jest.fn(async () => {
      state = "logged_out";
      return view(state);
    }),
  };
}

describe("TeammateLoginPanel (ADR 0062)", () => {
  it("logs you in with your own account on the owner's computer, never theirs", async () => {
    const api = fakeApi();
    const user = userEvent.setup();
    await render(<TeammateLoginPanel api={api} ownerId="u1" ownerName="Ada" harness="claude" canWrite />);
    expect(await screen.findByText(/refused until you log in\. Ada's login is never used for you/)).toBeOnTheScreen();

    await user.press(screen.getByLabelText("Log in to Claude Code"));
    expect(api.startTeammateLogin).toHaveBeenCalledWith("u1", "claude", expect.any(Function));
    await act(async () => {
      api.login.onEvent?.({ type: "started", loginId: "l9" });
      api.login.onEvent?.({ type: "output", text: "\u001b[1mOpen https://example.com/auth\u001b[0m\r\nPaste the code: " });
    });
    expect(screen.getByText(/Paste the code:/)).toBeOnTheScreen();
    expect(screen.getByLabelText("Open the login link")).toBeOnTheScreen();
    await user.type(screen.getByLabelText("Login code"), "code-1");
    await user.press(screen.getByLabelText("Send code"));
    expect(api.teammateLoginInput).toHaveBeenCalledWith("u1", "l9", "code-1");

    api.loggedIn();
    await act(async () => {
      api.login.onEvent?.({ type: "exit", success: true, status: "exit status: 0", loggedIn: true });
      api.login.end?.();
    });
    expect(await screen.findByText("Logged in with your own account on Ada's computer.")).toBeOnTheScreen();
    expect(screen.getByText("Logged in.")).toBeOnTheScreen();

    await user.press(screen.getByLabelText("Log out of Claude Code"));
    expect(api.teammateLogout).toHaveBeenCalledWith("u1", "claude");
    expect(await screen.findByText("Logged out.")).toBeOnTheScreen();
  });

  it("stops a running login when asked or when it closes", async () => {
    const api = fakeApi();
    const user = userEvent.setup();
    const ui = await render(<TeammateLoginPanel api={api} ownerId="u1" ownerName="Ada" harness="claude" canWrite />);
    await user.press(await screen.findByLabelText("Log in to Claude Code"));
    await act(async () => api.login.onEvent?.({ type: "started", loginId: "l9" }));
    await user.press(screen.getByLabelText("Stop login"));
    expect(api.stopTeammateLogin).toHaveBeenCalledWith("u1", "l9");
    expect(api.login.stop).toHaveBeenCalledTimes(1);

    await user.press(await screen.findByLabelText("Log in to Claude Code"));
    await ui.unmount();
    expect(api.login.stop).toHaveBeenCalledTimes(2);
  });

  it("offers read-only people nothing the server would refuse", async () => {
    const api = fakeApi();
    await render(<TeammateLoginPanel api={api} ownerId="u1" ownerName="Ada" harness="claude" canWrite={false} />);
    expect(await screen.findByText(/refused until you log in/)).toBeOnTheScreen();
    expect(screen.queryByLabelText("Log in to Claude Code")).not.toBeOnTheScreen();
  });

  it("says this server when the owner's Bots run here (ADR 0064)", async () => {
    const api = fakeApi();
    api.teammateLogins.mockResolvedValueOnce({ ...view("logged_out"), machineId: null, on: "server" });
    await render(<TeammateLoginPanel api={api} ownerId="u1" ownerName="Ada" harness="claude" canWrite />);
    expect(await screen.findByText(/Your runs for Ada's Bots on this server are refused until you log in/)).toBeOnTheScreen();
    expect(screen.getByLabelText("Log in to Claude Code")).toBeOnTheScreen();
  });

  it("shows the server's words when it refuses, with a retry", async () => {
    const api = fakeApi();
    api.teammateLogins.mockRejectedValueOnce(new Error("Machine not found"));
    await render(<TeammateLoginPanel api={api} ownerId="u1" ownerName="Ada" harness="claude" canWrite />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Couldn't check your Claude Code login. Machine not found");
    expect(screen.queryByLabelText("Log in to Claude Code")).not.toBeOnTheScreen();
    await userEvent.setup().press(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByLabelText("Log in to Claude Code")).toBeOnTheScreen();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("shows a skeleton while it checks your login, under its heading", async () => {
    const api = fakeApi();
    let answer: (v: TeammateLoginsView) => void = () => {};
    api.teammateLogins.mockImplementationOnce(() => new Promise<TeammateLoginsView>((resolve) => (answer = resolve)));
    await render(<TeammateLoginPanel api={api} ownerId="u1" ownerName="Ada" harness="claude" canWrite />);
    expect(screen.getByRole("heading", { name: "Your Claude Code login" })).toBeOnTheScreen();
    expect(screen.getByRole("progressbar", { name: "Loading your Claude Code login" })).toBeOnTheScreen();
    await act(async () => answer(view("logged_out")));
    expect(screen.queryByRole("progressbar")).toBeNull();
    expect(screen.getByLabelText("Log in to Claude Code")).toBeOnTheScreen();
  });

  it("says in plain words when logging out fails", async () => {
    const api = fakeApi();
    api.teammateLogins.mockResolvedValueOnce(view("logged_in"));
    api.teammateLogout.mockRejectedValueOnce(new TypeError("Network request failed"));
    await render(<TeammateLoginPanel api={api} ownerId="u1" ownerName="Ada" harness="claude" canWrite />);
    await userEvent.setup().press(await screen.findByLabelText("Log out of Claude Code"));
    expect(await screen.findByRole("alert")).toHaveTextContent("Can't reach the server. Check your connection and try again.");
    expect(screen.queryByRole("button", { name: "Try again" })).toBeNull();
  });

  it.each(["light", "dark"] as const)("follows the device's %s setting", async (scheme) => {
    jest.spyOn(RN, "useColorScheme").mockReturnValue(scheme);
    await render(<TeammateLoginPanel api={fakeApi()} ownerId="u1" ownerName="Ada" harness="claude" canWrite />);
    const c = themes[scheme].c;
    expect(screen.getByText("Your Claude Code login")).toHaveStyle({ color: c.text });
    expect(await screen.findByText("Log in with your own account")).toHaveStyle({ color: c.accentText });
    jest.restoreAllMocks();
  });
});
