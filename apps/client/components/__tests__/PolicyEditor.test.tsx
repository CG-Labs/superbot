import React from "react";
import { render, screen, userEvent, within } from "@testing-library/react-native";
import { PolicyEditor } from "../PolicyEditor";
import PolicyScreen from "../../app/policy";
import type { NewPolicyRule, Policy, PolicyAction, PolicyOverride, PolicyPatch, PolicyRule, PolicyView } from "../../src/types";

const mockCtx: Record<string, unknown> = {};
const mockParams: { bot?: string } = {};
jest.mock("expo-router", () => ({
  Redirect: () => null,
  router: { canGoBack: () => false, back: jest.fn(), replace: jest.fn() },
  useLocalSearchParams: () => mockParams,
}));
jest.mock("../../src/SuperBotContext", () => ({ useSuperBot: () => mockCtx }));
// A backstop for slow CI runners; the warm-up and fake timers below keep each test well under 1 s.
jest.setTimeout(20_000);

const CLASSES = [
  { id: "shell_destructive", label: "Destructive shell command" },
  { id: "git_push", label: "Pushes to a git remote" },
];

/** A fake botd: a global policy, per-Bot overrides where null inherits, and rules. */
function fakeApi() {
  let global: Policy = { mode: "ask", classes: { shell_destructive: "ask", git_push: "ask" }, timeoutMinutes: 10, sandbox: true };
  const sandbox = { harnesses: ["claude", "codex"], available: true };
  const overrides = new Map<string, PolicyOverride>();
  let rules: PolicyRule[] = [{ id: "g1", botId: null, action: "deny", tool: "shell", pattern: "rm -rf /*", note: "never", at: 1 }];
  let n = 0;
  const effective = (o?: PolicyOverride): Policy => ({
    mode: o?.mode ?? global.mode,
    classes: { ...global.classes, ...o?.classes },
    timeoutMinutes: o?.timeoutMinutes ?? global.timeoutMinutes,
    sandbox: o?.sandbox ?? global.sandbox,
  });
  const botView = (id: string): PolicyView => ({
    policy: effective(overrides.get(id)),
    override: overrides.get(id) ?? null,
    classes: CLASSES,
    rules: rules.filter((r) => r.botId === null || r.botId === id),
    sandbox,
  });
  return {
    policyView: jest.fn(async (botId?: string) => (botId ? botView(botId) : { policy: global, classes: CLASSES, rules: rules.filter((r) => r.botId === null), sandbox })),
    patchGlobalPolicy: jest.fn(async (p: PolicyPatch) => {
      global = {
        mode: p.mode ?? global.mode,
        classes: { ...global.classes, ...(p.classes as Record<string, PolicyAction>) },
        timeoutMinutes: p.timeoutMinutes ?? global.timeoutMinutes,
        sandbox: p.sandbox ?? global.sandbox,
      };
      return global;
    }),
    patchBotPolicy: jest.fn(async (id: string, p: PolicyPatch) => {
      const o: PolicyOverride = { ...overrides.get(id), classes: { ...overrides.get(id)?.classes } };
      if (p.mode !== undefined) o.mode = p.mode ?? undefined;
      if (p.timeoutMinutes !== undefined) o.timeoutMinutes = p.timeoutMinutes ?? undefined;
      if (p.sandbox !== undefined) o.sandbox = p.sandbox ?? undefined;
      for (const [k, a] of Object.entries(p.classes ?? {})) {
        if (a === null) delete o.classes![k];
        else o.classes![k] = a;
      }
      if (!Object.keys(o.classes!).length) delete o.classes;
      if (o.mode === undefined) delete o.mode;
      if (o.timeoutMinutes === undefined) delete o.timeoutMinutes;
      if (o.sandbox === undefined) delete o.sandbox;
      if (Object.keys(o).length) overrides.set(id, o);
      else overrides.delete(id);
      return botView(id);
    }),
    resetBotPolicy: jest.fn(async (id: string) => {
      overrides.delete(id);
      return botView(id);
    }),
    addPolicyRule: jest.fn(async (r: NewPolicyRule) => {
      const rule: PolicyRule = { id: `r${++n}`, botId: r.botId ?? null, action: r.action, tool: r.tool, pattern: r.pattern, note: r.note ?? null, at: 10 + n };
      rules = [...rules, rule];
      return rule;
    }),
    deletePolicyRule: jest.fn(async (id: string) => {
      rules = rules.filter((r) => r.id !== id);
    }),
  };
}

const yes = jest.fn(async () => true);

// The first render loads and transforms most of React Native, which takes seconds on a cold CI runner.
// Pay for it here, not in whichever test runs first.
beforeAll(async () => {
  const { unmount } = await render(<PolicyEditor api={fakeApi()} canEdit onBack={jest.fn()} confirm={yes} />);
  await screen.findByLabelText("Pushes to a git remote");
  await unmount();
}, 60_000);
// userEvent.press holds each press for a real 130 ms; fake timers skip that wait.
beforeEach(() => jest.useFakeTimers());
afterEach(() => jest.useRealTimers());

describe("PolicyEditor (ADR 0049)", () => {
  beforeEach(() => yes.mockClear());

  it("lets an admin set class actions and the timeout for all Bots", async () => {
    const api = fakeApi();
    const user = userEvent.setup();
    await render(<PolicyEditor api={api} canEdit onBack={jest.fn()} confirm={yes} />);
    const push = await screen.findByLabelText("Pushes to a git remote");
    await user.press(within(push).getByRole("radio", { name: "Deny" }));
    expect(api.patchGlobalPolicy).toHaveBeenLastCalledWith({ classes: { git_push: "deny" } });
    expect(await screen.findByText("Pushes to a git remote: Deny.")).toBeOnTheScreen();
    expect(within(push).getByRole("radio", { name: "Deny" })).toBeChecked();

    const minutes = screen.getByLabelText("Minutes to wait");
    await user.clear(minutes);
    await user.type(minutes, "0");
    expect(screen.getByText(/whole minutes from 1 to 1440/)).toBeOnTheScreen();
    expect(screen.getByRole("button", { name: "Save time to answer" })).toBeDisabled();
    await user.clear(minutes);
    await user.type(minutes, "30");
    await user.press(screen.getByRole("button", { name: "Save time to answer" }));
    expect(api.patchGlobalPolicy).toHaveBeenLastCalledWith({ timeoutMinutes: 30 });
    expect(await screen.findByText("Approvals now wait 30 minutes.")).toBeOnTheScreen();
    expect(screen.getByText(/denied after 30 minutes/)).toBeOnTheScreen();
  });

  it("asks before turning approvals off, and does nothing when told no", async () => {
    const api = fakeApi();
    const no = jest.fn(async () => false);
    const user = userEvent.setup();
    await render(<PolicyEditor api={api} canEdit onBack={jest.fn()} confirm={no} />);
    await user.press(await screen.findByRole("radio", { name: "Bypass" }));
    expect(no).toHaveBeenCalledWith("Turn approvals off?", expect.stringContaining("every Bot"), "Bypass");
    expect(api.patchGlobalPolicy).not.toHaveBeenCalled();
  });

  it("asks before turning the sandbox off for all Bots, and turns it back on", async () => {
    const api = fakeApi();
    const no = jest.fn(async () => false);
    const user = userEvent.setup();
    const { rerender } = await render(<PolicyEditor api={api} canEdit onBack={jest.fn()} confirm={no} />);
    const card = await screen.findByLabelText("Sandbox");
    expect(within(card).getByText(/Claude Code and Codex have one/)).toBeOnTheScreen();
    expect(within(card).getByRole("radio", { name: "On" })).toBeChecked();
    await user.press(within(card).getByRole("radio", { name: "Off" }));
    expect(no).toHaveBeenCalledWith("Turn the sandbox off?", expect.stringContaining("every Bot"), "Turn off");
    expect(api.patchGlobalPolicy).not.toHaveBeenCalled();

    await rerender(<PolicyEditor api={api} canEdit onBack={jest.fn()} confirm={yes} />);
    await user.press(within(screen.getByLabelText("Sandbox")).getByRole("radio", { name: "Off" }));
    expect(api.patchGlobalPolicy).toHaveBeenLastCalledWith({ sandbox: false });
    expect(await screen.findByText("Sandbox off.")).toBeOnTheScreen();
    yes.mockClear();
    await user.press(within(screen.getByLabelText("Sandbox")).getByRole("radio", { name: "On" }));
    expect(yes).not.toHaveBeenCalled();
    expect(api.patchGlobalPolicy).toHaveBeenLastCalledWith({ sandbox: true });
    expect(await screen.findByText("Sandbox on.")).toBeOnTheScreen();
  });

  it("sets a Bot's sandbox and puts it back to the default", async () => {
    const api = fakeApi();
    const user = userEvent.setup();
    await render(<PolicyEditor api={api} bot={{ id: "b1", name: "Scout" }} canEdit onBack={jest.fn()} confirm={yes} />);
    const card = await screen.findByLabelText("Sandbox");
    expect(within(card).getByRole("radio", { name: "Default (On)" })).toBeChecked();
    await user.press(within(card).getByRole("radio", { name: "Off" }));
    expect(yes).toHaveBeenCalledWith("Turn the sandbox off?", expect.stringContaining("Scout"), "Turn off");
    expect(api.patchBotPolicy).toHaveBeenLastCalledWith("b1", { sandbox: false });
    expect(await screen.findByText("Sandbox off.")).toBeOnTheScreen();
    expect(within(screen.getByLabelText("Sandbox")).getByRole("radio", { name: "Off" })).toBeChecked();
    await user.press(within(screen.getByLabelText("Sandbox")).getByRole("radio", { name: "Default (On)" }));
    expect(api.patchBotPolicy).toHaveBeenLastCalledWith("b1", { sandbox: null });
    expect(await screen.findByText("Following the default sandbox.")).toBeOnTheScreen();
  });

  it("warns when sandboxes can't start on the server", async () => {
    const api = fakeApi();
    const view = await api.policyView();
    api.policyView.mockResolvedValue({ ...view, sandbox: { harnesses: ["claude", "codex"], available: false } });
    await render(<PolicyEditor api={api} canEdit onBack={jest.fn()} confirm={yes} />);
    expect(await screen.findByText(/can't start on this server/)).toBeOnTheScreen();
  });

  it("puts a Bot's class and timeout back to the default one at a time", async () => {
    const api = fakeApi();
    const user = userEvent.setup();
    await render(<PolicyEditor api={api} bot={{ id: "b1", name: "Scout" }} canEdit onBack={jest.fn()} confirm={yes} />);
    expect(await screen.findByText("Approvals for Scout")).toBeOnTheScreen();
    const push = screen.getByLabelText("Pushes to a git remote");
    expect(within(push).getByRole("radio", { name: "Default (Ask)" })).toBeChecked();
    await user.press(within(push).getByRole("radio", { name: "Allow" }));
    expect(api.patchBotPolicy).toHaveBeenLastCalledWith("b1", { classes: { git_push: "allow" } });
    expect(await screen.findByText("Pushes to a git remote: Allow.")).toBeOnTheScreen();
    expect(screen.getByRole("button", { name: "Reset Scout to the default policy" })).toBeOnTheScreen();

    await user.press(within(push).getByRole("radio", { name: "Default (Ask)" }));
    expect(api.patchBotPolicy).toHaveBeenLastCalledWith("b1", { classes: { git_push: null } });
    expect(await screen.findByText("Pushes to a git remote: following the default.")).toBeOnTheScreen();
    expect(screen.queryByRole("button", { name: "Reset Scout to the default policy" })).toBeNull();

    const minutes = screen.getByLabelText("Minutes to wait");
    await user.clear(minutes);
    await user.type(minutes, "5");
    await user.press(screen.getByRole("button", { name: "Save time to answer" }));
    await user.press(await screen.findByRole("button", { name: "Use default (10 minutes)" }));
    expect(api.patchBotPolicy).toHaveBeenLastCalledWith("b1", { timeoutMinutes: null });
    expect(await screen.findByText(/denied after 10 minutes \(the default\)/)).toBeOnTheScreen();
  });

  it("lets a Bot keep the default timeout as its own", async () => {
    const api = fakeApi();
    const user = userEvent.setup();
    await render(<PolicyEditor api={api} bot={{ id: "b1", name: "Scout" }} canEdit onBack={jest.fn()} confirm={yes} />);
    const save = await screen.findByRole("button", { name: "Save time to answer" });
    expect(save).toBeEnabled();
    await user.press(save);
    expect(api.patchBotPolicy).toHaveBeenLastCalledWith("b1", { timeoutMinutes: 10 });
    expect(await screen.findByRole("button", { name: "Use default (10 minutes)" })).toBeOnTheScreen();
    expect(screen.getByRole("button", { name: "Save time to answer" })).toBeDisabled();
  });

  it("adds a rule for the Bot and deletes one after asking", async () => {
    const api = fakeApi();
    const user = userEvent.setup();
    await render(<PolicyEditor api={api} bot={{ id: "b1", name: "Scout" }} canEdit onBack={jest.fn()} confirm={yes} />);
    expect(await screen.findByText("rm -rf /*")).toBeOnTheScreen();
    expect(screen.getByText("All Bots")).toBeOnTheScreen();

    expect(screen.getByRole("button", { name: "Add rule" })).toBeDisabled();
    await user.press(within(screen.getByLabelText("Rule action")).getByRole("radio", { name: "Allow" }));
    await user.press(within(screen.getByLabelText("Rule tool")).getByRole("radio", { name: "Shell" }));
    await user.type(screen.getByLabelText("Rule pattern"), " git push origin * ");
    await user.type(screen.getByLabelText("Rule note"), "release flow");
    await user.press(screen.getByRole("button", { name: "Add rule" }));
    expect(api.addPolicyRule).toHaveBeenCalledWith({ botId: "b1", action: "allow", tool: "shell", pattern: "git push origin *", note: "release flow" });
    expect(await screen.findByText("Allow rule added.")).toBeOnTheScreen();
    expect(screen.getByText("git push origin *")).toBeOnTheScreen();
    expect(screen.getByText("This Bot")).toBeOnTheScreen();
    expect(screen.getByLabelText("Rule pattern").props.value).toBe("");

    await user.press(screen.getByRole("button", { name: "Delete rule rm -rf /*" }));
    expect(yes).toHaveBeenCalledWith("Delete this deny rule?", expect.stringContaining("every Bot"));
    expect(api.deletePolicyRule).toHaveBeenCalledWith("g1");
    expect(await screen.findByText("Rule deleted.")).toBeOnTheScreen();
    expect(screen.queryByText("rm -rf /*")).toBeNull();
  });

  it("shows a server refusal and keeps the draft", async () => {
    const api = fakeApi();
    api.addPolicyRule.mockRejectedValueOnce(new Error("pattern is required"));
    const user = userEvent.setup();
    await render(<PolicyEditor api={api} canEdit onBack={jest.fn()} confirm={yes} />);
    await user.type(await screen.findByLabelText("Rule pattern"), "curl *");
    await user.press(screen.getByRole("button", { name: "Add rule" }));
    expect(await screen.findByText("pattern is required")).toBeOnTheScreen();
    expect(screen.getByLabelText("Rule pattern").props.value).toBe("curl *");
  });

  it("is read-only for everyone but admins", async () => {
    const api = fakeApi();
    await render(<PolicyEditor api={api} canEdit={false} onBack={jest.fn()} confirm={yes} />);
    expect(await screen.findByText("Only an admin can change the approval policy.")).toBeOnTheScreen();
    expect(screen.getByText("rm -rf /*")).toBeOnTheScreen();
    for (const r of screen.getAllByRole("radio")) expect(r).toBeDisabled();
    expect(screen.queryByLabelText("Minutes to wait")).toBeNull();
    expect(screen.queryByRole("button", { name: "Add rule" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Delete rule/ })).toBeNull();
  });

  it("says why when the policy can't be read", async () => {
    const api = fakeApi();
    api.policyView.mockRejectedValue(new Error("Bot not found"));
    await render(<PolicyEditor api={api} bot={{ id: "b9", name: "this Bot" }} canEdit onBack={jest.fn()} />);
    expect(await screen.findByText("Bot not found")).toBeOnTheScreen();
  });
});

describe("the /policy screen", () => {
  it("opens a Bot's policy by its id, with edits for admins only", async () => {
    const api = fakeApi();
    Object.assign(mockCtx, { ready: true, api, bots: [{ id: "b1", name: "Scout" }], can: (p: string) => p !== "admin" });
    mockParams.bot = "b1";
    await render(<PolicyScreen />);
    expect(await screen.findByText("Approvals for Scout")).toBeOnTheScreen();
    expect(api.policyView).toHaveBeenCalledWith("b1");
    expect(screen.getByText("Only an admin can change the approval policy.")).toBeOnTheScreen();
  });
});
