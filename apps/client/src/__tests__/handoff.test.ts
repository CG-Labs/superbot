import {
  applyHandoffHistory,
  applyHandoffMessage,
  isOpenHandoff,
  latestOpenHandoff,
  withoutHandoff,
  withPicked,
} from "../handoff";
import type { Message } from "../types";

const handoff = (id: number, picked?: number | null): Message => ({
  id,
  botId: "b1",
  role: "bot",
  text: "",
  question: { title: "Log in to the bank", options: ["Done", "I can't right now"], handoff: true, picked },
  at: id,
});
const user = (id: number): Message => ({ id, botId: "b1", role: "user", text: "hi", at: id });
const bot = (id: number): Message => ({ id, botId: "b1", role: "bot", text: "ok", at: id });

describe("open handoffs", () => {
  it("recognizes unanswered handoff cards only", () => {
    expect(isOpenHandoff(handoff(1))).toBe(true);
    expect(isOpenHandoff(handoff(1, 0))).toBe(false);
    const choice = { ...bot(2), question: { title: "Pick", options: ["A"] } };
    expect(isOpenHandoff(choice)).toBe(false);
  });

  it("finds the latest open handoff unless the user moved on", () => {
    expect(latestOpenHandoff([bot(1), handoff(2), bot(3)])?.id).toBe(2);
    expect(latestOpenHandoff([handoff(1), handoff(2)])?.id).toBe(2);
    expect(latestOpenHandoff([handoff(1), user(2)])).toBeUndefined();
    expect(latestOpenHandoff([handoff(1, 0)])).toBeUndefined();
    expect(latestOpenHandoff([])).toBeUndefined();
  });
});

describe("live updates", () => {
  it("adds a new handoff and clears it when the user answers in chat", () => {
    let map = applyHandoffMessage({}, handoff(5));
    expect(map.b1.id).toBe(5);
    map = applyHandoffMessage(map, bot(6));
    expect(map.b1.id).toBe(5);
    map = applyHandoffMessage(map, user(4));
    expect(map.b1.id).toBe(5);
    map = applyHandoffMessage(map, user(7));
    expect(map.b1).toBeUndefined();
  });

  it("replaces a Bot's entry from its loaded history", () => {
    const map = applyHandoffHistory({ b1: handoff(1) }, "b1", [handoff(1), user(2)]);
    expect(map.b1).toBeUndefined();
    expect(applyHandoffHistory({}, "b1", [handoff(3)]).b1.id).toBe(3);
  });

  it("removes only the matching card", () => {
    const map = { b1: handoff(3) };
    expect(withoutHandoff(map, "b1", 2)).toBe(map);
    expect(withoutHandoff(map, "b1", 3).b1).toBeUndefined();
    expect(withoutHandoff(map, "b1").b1).toBeUndefined();
  });

  it("marks a card picked without touching others", () => {
    const list = withPicked([handoff(1), handoff(2)], 2, 0);
    expect(list[0].question?.picked).toBeUndefined();
    expect(list[1].question?.picked).toBe(0);
  });
});
