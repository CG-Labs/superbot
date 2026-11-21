import { isQueued, workingLabel } from "../runQueue";

describe("queued runs", () => {
  it("say where they are in line and why", () => {
    const queued = { reason: "at_capacity" as const, host: "server" as const, position: 2, running: 3, limit: 3 };
    const bot = { working: true, status: "Queued", queued };
    expect(isQueued(bot)).toBe(true);
    expect(workingLabel(bot)).toBe("Queued, #2 in line: this server runs 3 tasks at once");
    const next = { ...queued, host: "machine" as const, position: 1, limit: 1 };
    expect(workingLabel({ working: true, queued: next })).toBe("Queued, next in line: its computer runs 1 task at once");
  });

  it("fall back to the server's status once running, and for older servers", () => {
    expect(isQueued({ working: true, status: "Thinking" })).toBe(false);
    expect(workingLabel({ working: true, status: "Running: ls" })).toBe("Running: ls");
    expect(workingLabel({ working: true })).toBe("Working");
    const starting = { reason: "starting" as const, host: "server" as const };
    expect(workingLabel({ working: true, status: "Starting", queued: starting })).toBe("Starting");
    expect(isQueued({ working: false, queued: { reason: "at_capacity", host: "server", position: 1, limit: 2 } })).toBe(false);
  });
});
