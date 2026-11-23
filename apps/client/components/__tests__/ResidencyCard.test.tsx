import React from "react";
import { render, screen, userEvent, waitFor } from "@testing-library/react-native";
import { ResidencyCard } from "../ResidencyCard";
import { ApiError } from "../../src/api";
import { MARKDOWN } from "../../src/fileTypes";
import type { MyResidency } from "../../src/types";

const AT = Date.UTC(2026, 10, 22);
const mine: MyResidency = {
  pin: { on: "user", region: "gb-lon", pinnedAt: AT, reference: "DPA-2026-014" },
  ownPin: null,
  status: "kept",
  machine: null,
  backups: { kept: 0, inRegion: 0, outside: 0 },
  modelRoutes: { inRegion: true, gap: null },
  reports: ["user"],
};

function fakeApi(v: MyResidency | null) {
  return {
    myResidency: jest.fn(async () => v),
    myResidencyReport: jest.fn(async (on: "user" | "team") => ({ text: `# Data residency report (${on})\n`, fileName: `superbot-residency-${on}-x-20261123.md` })),
  };
}

describe("ResidencyCard (ADR 0168)", () => {
  it("shows nothing when nothing pins your data, or the server is from before it", async () => {
    for (const v of [null, { pin: null, ownPin: null, reports: [] }]) {
      const api = fakeApi(v as MyResidency | null);
      const { toJSON } = await render(<ResidencyCard api={api} />);
      await waitFor(() => expect(toJSON()).toBeNull());
      expect(api.myResidency).toHaveBeenCalled();
    }
  });

  it("says when it couldn't load, and tries again", async () => {
    const api = fakeApi(mine);
    api.myResidency.mockRejectedValueOnce(new ApiError("Server error", 500));
    const user = userEvent.setup();
    await render(<ResidencyCard api={api} />);
    expect(await screen.findByText("Couldn't load your data's residency: Server error")).toBeOnTheScreen();
    await user.press(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByText(/Your data is pinned to gb-lon/)).toBeOnTheScreen();
    expect(api.myResidency).toHaveBeenCalledTimes(2);
  });

  it("shows your pin and saves its report as Markdown", async () => {
    const api = fakeApi(mine);
    const save = jest.fn(async () => {});
    const user = userEvent.setup();
    await render(<ResidencyCard api={api} save={save} />);
    expect(await screen.findByText("Your data is pinned to gb-lon under DPA-2026-014, since 2026-11-22.")).toBeOnTheScreen();
    expect(screen.getByText(/Chats and accounts are kept where this server runs/)).toBeOnTheScreen();
    await user.press(screen.getByRole("button", { name: "Download your report" }));
    expect(api.myResidencyReport).toHaveBeenCalledWith("user");
    expect(save).toHaveBeenCalledWith("superbot-residency-user-x-20261123.md", "# Data residency report (user)\n", "Save residency report", MARKDOWN);
    expect(await screen.findByText(/Report saved/)).toBeOnTheScreen();
  });

  it("tells a team member who can get the team's report, and says why a download failed", async () => {
    const team: MyResidency = { ...mine, pin: { on: "team", region: "de-fra-2", pinnedAt: AT, team: { id: "t1", name: "Acme" } }, reports: [] };
    const { rerender } = await render(<ResidencyCard api={fakeApi(team)} />);
    expect(await screen.findByText("Your team's owners and admins can download its residency report.")).toBeOnTheScreen();
    expect(screen.queryByRole("button")).toBeNull();

    const api = fakeApi({ ...team, reports: ["team"] });
    api.myResidencyReport.mockRejectedValueOnce(new ApiError("You can get 5 residency reports every 10 minutes. Try again in 60 seconds.", 429));
    const user = userEvent.setup();
    await rerender(<ResidencyCard api={api} save={jest.fn()} />);
    await user.press(await screen.findByRole("button", { name: "Download the team's report" }));
    expect(await screen.findByText(/Try again in 60 seconds/)).toBeOnTheScreen();
  });
});
