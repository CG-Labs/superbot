import React from "react";
import { render, screen, userEvent, waitFor, within } from "@testing-library/react-native";
import { AccessReview } from "../AccessReview";
import { ApiError, type SuperBotApi } from "../../src/api";
import { saveCsv } from "../../src/saveCsv";
import type { AccessReview as Report, AccessReviewPerson, AccessReviewSignOff } from "../../src/types";

jest.mock("../../src/saveCsv", () => ({ saveCsv: jest.fn(async () => {}) }));

const person = (p: Partial<AccessReviewPerson>): AccessReviewPerson => ({
  id: "u1",
  name: "Ada",
  email: "ada@example.com",
  role: "member",
  status: "active",
  breakGlass: false,
  createdAt: 0,
  scim: null,
  team: null,
  mfa: { enabled: true, enabledAt: 1 },
  lastLogin: null,
  botAccess: { all: false, bots: [] },
  sessions: [],
  apiTokens: [],
  machine: null,
  ...p,
});

const signOff = (p: Partial<AccessReviewSignOff> = {}): AccessReviewSignOff => ({
  eventId: 9,
  at: Date.UTC(2026, 10, 22),
  time: "2026-11-22T00:00:00.000Z",
  reviewer: { id: "u9", name: "Lee", email: "lee@example.com", role: "admin", method: "sso" },
  digest: "d1",
  summary: null,
  notes: "Q4",
  ...p,
});

const report = (p: Partial<Report> = {}): Report => ({
  generatedAt: Date.UTC(2026, 10, 22, 9, 0, 0),
  generatedTime: "2026-11-22T09:00:00.000Z",
  digest: "d1",
  summary: { people: 2, active: 1, disabled: 1, admins: 0, activeWithoutMfa: 0, scimManaged: 1, browserSessions: 0, apiAccess: 0, machines: 0 },
  groups: [
    { tenant: null, team: { id: "t1", name: "Research" }, people: [person({})] },
    { tenant: "okta", team: null, people: [person({ id: "u2", name: "Bo", status: "disabled", scim: { tenant: "okta", deleted: false } })] },
  ],
  reviews: [],
  ...p,
});

function fakeApi(r: Report = report()) {
  return {
    accessReview: jest.fn(async () => r),
    accessReviewCsv: jest.fn(async (_d: string) => ({ csv: "generated_at\r\n", fileName: "superbot-access-review-20261122-090500.csv" as string | null })),
    completeAccessReview: jest.fn(async (_d: string, _n?: string) => signOff({ eventId: 10, notes: "checked" })),
  };
}

async function open(api = fakeApi()) {
  const user = userEvent.setup();
  await render(<AccessReview api={api as unknown as SuperBotApi} onBack={jest.fn()} />);
  await screen.findByTestId("access-review");
  return { api, user };
}

beforeEach(() => jest.mocked(saveCsv).mockClear());

describe("AccessReview", () => {
  it("lists everyone by tenant and team, with what to look at twice", async () => {
    await open();
    expect(screen.getByText(/^Team: Research/)).toBeOnTheScreen();
    expect(screen.getAllByText(/^SCIM: okta/)).toHaveLength(2);
    const bo = within(screen.getByLabelText("Access of Bo"));
    expect(bo.getByText("Disabled")).toBeOnTheScreen();
    expect(bo.getByText("SCIM: okta")).toBeOnTheScreen();
    expect(bo.getByText("Last sign-in: Never signed in")).toBeOnTheScreen();
    expect(screen.getByText("None yet.")).toBeOnTheScreen();
  });

  it("lists service accounts with their owner, what they can use, flags and tokens", async () => {
    const sa = {
      id: "sa1",
      name: "CI deploy",
      description: "Deploys main",
      role: "member" as const,
      status: "active" as const,
      createdAt: 0,
      createdBy: "u1",
      customRole: null,
      team: { id: "t1", name: "Research", role: "member" },
      owner: { id: "u1", name: "Ada", email: "ada@example.com", status: "disabled" },
      ownerActive: false,
      permissions: ["account", "read", "write"],
      teamPermissions: [],
      effective: [],
      botAccess: { all: false, bots: [] },
      tokens: [{ id: "st1", name: "Nightly", preview: "sbsa_…ab12", scopes: null, createdAt: 0, expiresAt: Date.UTC(2027, 0, 1), lastUsedAt: null, replaced: false }],
      flags: ["owner_inactive", "unscoped_token"],
    };
    const r = report({ serviceAccounts: [sa], summary: { ...report().summary, serviceAccounts: 1, serviceApiAccess: 1 } });
    await open(fakeApi(r));
    expect(screen.getByText(/1 service accounts with 1 live tokens/)).toBeOnTheScreen();
    const card = within(screen.getByLabelText("Access of service account CI deploy"));
    expect(card.getByText("member, in Research")).toBeOnTheScreen();
    expect(card.getByText("Owner inactive")).toBeOnTheScreen();
    expect(card.getByText("Token with everything")).toBeOnTheScreen();
    expect(card.getByText("Owner: Ada (inactive)")).toBeOnTheScreen();
    expect(card.getByText("Can use today: Nothing")).toBeOnTheScreen();
    expect(card.getByText(/^Token: Nightly sbsa_…ab12: everything it holds; expires .*; never used$/)).toBeOnTheScreen();
  });

  it("flags a service account whose owner is off its team", async () => {
    const sa = {
      id: "sa2",
      name: "Sync",
      description: "",
      role: "member" as const,
      status: "active" as const,
      createdAt: 0,
      createdBy: "u1",
      customRole: null,
      team: { id: "t1", name: "Research", role: "member" },
      owner: { id: "u2", name: "Bo", email: "bo@example.com", status: "active" },
      ownerActive: true,
      ownerOnTeam: false,
      permissions: ["account", "read", "write"],
      teamPermissions: [],
      effective: ["account", "read", "write"],
      botAccess: { all: false, bots: [] },
      tokens: [],
      flags: ["owner_off_team"],
    };
    await open(fakeApi(report({ serviceAccounts: [sa], summary: { ...report().summary, serviceAccounts: 1 } })));
    const card = within(screen.getByLabelText("Access of service account Sync"));
    expect(card.getByText("member, in Research (acts in no team)")).toBeOnTheScreen();
    expect(card.getByText("Owner off its team")).toBeOnTheScreen();
  });

  it("leaves the section out when there are no service accounts", async () => {
    await open();
    expect(screen.queryByText(/^Service accounts/)).toBeNull();
  });

  it("signs off on the report it shows, with notes, and lists the sign-off", async () => {
    const { api, user } = await open();
    await user.type(screen.getByLabelText("Review notes"), "checked");
    await user.press(screen.getByText("Mark as reviewed"));
    expect(api.completeAccessReview).toHaveBeenCalledWith("d1", "checked");
    expect(await screen.findByText(/^Signed off at/)).toBeOnTheScreen();
    expect(screen.getByText("checked")).toBeOnTheScreen();
    expect(screen.queryByText("None yet.")).toBeNull();
  });

  it("drops the sign-off message once a reload shows different access", async () => {
    const { api, user } = await open();
    await user.press(screen.getByText("Mark as reviewed"));
    expect(await screen.findByText(/^Signed off at/)).toBeOnTheScreen();
    api.accessReview.mockResolvedValueOnce(report({ digest: "d2" }));
    await user.press(screen.getByText("Reload"));
    await waitFor(() => expect(screen.queryByText(/^Signed off at/)).toBeNull());
  });

  it("says to reload when access changed since it loaded", async () => {
    const api = fakeApi();
    api.completeAccessReview.mockRejectedValueOnce(new ApiError("changed", 409));
    const { user } = await open(api);
    await user.press(screen.getByText("Mark as reviewed"));
    expect(await screen.findByText("Access changed since this report loaded. Reload it and review it again.")).toBeOnTheScreen();
    await user.press(screen.getByText("Reload"));
    expect(api.accessReview).toHaveBeenCalledTimes(2);
  });

  it("exports the CSV under the server's name", async () => {
    const { api, user } = await open();
    await user.press(screen.getByText("Export CSV"));
    expect(api.accessReviewCsv).toHaveBeenCalledWith("d1");
    expect(saveCsv).toHaveBeenCalledWith("superbot-access-review-20261122-090500.csv", "generated_at\r\n", "Export access review");
  });

  it("names the CSV by when it was exported when the server gives no name", async () => {
    const api = fakeApi();
    api.accessReviewCsv.mockResolvedValueOnce({ csv: "generated_at\r\n", fileName: null });
    jest.spyOn(Date, "now").mockReturnValue(Date.UTC(2026, 10, 22, 10, 0, 0));
    const { user } = await open(api);
    await user.press(screen.getByText("Export CSV"));
    expect(saveCsv).toHaveBeenCalledWith("superbot-access-review-20261122-100000.csv", "generated_at\r\n", "Export access review");
    jest.restoreAllMocks();
  });

  it("refuses to export a report that is no longer current", async () => {
    const api = fakeApi();
    api.accessReviewCsv.mockRejectedValueOnce(new ApiError("changed", 409));
    const { user } = await open(api);
    await user.press(screen.getByText("Export CSV"));
    expect(await screen.findByText("Access changed since this report loaded. Reload it before exporting.")).toBeOnTheScreen();
    expect(saveCsv).not.toHaveBeenCalled();
  });

  it("shows why it couldn't load", async () => {
    const api = fakeApi();
    api.accessReview.mockRejectedValueOnce(new ApiError("Admins only", 403));
    await render(<AccessReview api={api as unknown as SuperBotApi} onBack={jest.fn()} />);
    expect(await screen.findByText("Admins only")).toBeOnTheScreen();
  });

  it("tries again after a failed load", async () => {
    const api = fakeApi();
    api.accessReview.mockRejectedValueOnce(new Error("Network down"));
    const user = userEvent.setup();
    await render(<AccessReview api={api as unknown as SuperBotApi} onBack={jest.fn()} />);
    await user.press(await screen.findByText("Retry"));
    expect(await screen.findByTestId("access-review")).toBeOnTheScreen();
    expect(screen.queryByText("Network down")).toBeNull();
  });
});
