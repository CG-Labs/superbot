import { Share } from "react-native";
import * as Sharing from "expo-sharing";
import { saveCsv } from "../saveCsv";
import { saveCsv as saveCsvWeb } from "../saveCsv.web";
import { MARKDOWN } from "../fileTypes";

const mockFiles: { uri: string; created?: unknown; text?: string }[] = [];
jest.mock("expo-file-system", () => ({
  Paths: { cache: { uri: "file:///cache/" } },
  File: class {
    uri: string;
    constructor(dir: { uri: string }, name: string) {
      this.uri = dir.uri + name;
      mockFiles.push(this as never);
    }
    create(o: unknown) {
      (this as unknown as { created: unknown }).created = o;
    }
    async write(text: string) {
      (this as unknown as { text: string }).text = text;
    }
  },
}));
jest.mock("expo-sharing", () => ({ isAvailableAsync: jest.fn(async () => true), shareAsync: jest.fn(async () => {}) }));

const CSV = "id,time\r\n1,2026-11-19T13:00:00.000Z\r\n";

beforeEach(() => {
  mockFiles.length = 0;
  jest.clearAllMocks();
});

describe("saveCsv on phones", () => {
  it("writes the file to the cache and opens the share sheet", async () => {
    await saveCsv("superbot-audit-x.csv", CSV);
    expect(mockFiles[0]).toMatchObject({ uri: "file:///cache/superbot-audit-x.csv", created: { overwrite: true }, text: CSV });
    expect(Sharing.shareAsync).toHaveBeenCalledWith("file:///cache/superbot-audit-x.csv", expect.objectContaining({ mimeType: "text/csv" }));
  });

  it("shares other kinds of file as what they are", async () => {
    await saveCsv("superbot-residency-user-20261123.md", "# Report\n", "Save residency report", MARKDOWN);
    expect(Sharing.shareAsync).toHaveBeenCalledWith("file:///cache/superbot-residency-user-20261123.md", {
      mimeType: "text/markdown",
      UTI: "net.daringfireball.markdown",
      dialogTitle: "Save residency report",
    });
  });

  it("shares the text where file sharing isn't available", async () => {
    jest.mocked(Sharing.isAvailableAsync).mockResolvedValueOnce(false);
    const share = jest.spyOn(Share, "share").mockResolvedValue({ action: Share.sharedAction, activityType: undefined });
    await saveCsv("superbot-audit-x.csv", CSV);
    expect(share).toHaveBeenCalledWith({ title: "superbot-audit-x.csv", message: CSV });
    expect(Sharing.shareAsync).not.toHaveBeenCalled();
  });
});

describe("saveCsv on web", () => {
  const realDocument = (globalThis as { document?: unknown }).document;
  const realCreate = URL.createObjectURL;
  const realRevoke = URL.revokeObjectURL;
  afterEach(() => {
    (globalThis as { document?: unknown }).document = realDocument;
    URL.createObjectURL = realCreate;
    URL.revokeObjectURL = realRevoke;
    jest.useRealTimers();
  });

  it("downloads the CSV under the given name, then lets the blob go", async () => {
    jest.useFakeTimers();
    const a = { href: "", download: "", rel: "", click: jest.fn(), remove: jest.fn() };
    const appendChild = jest.fn();
    (globalThis as { document?: unknown }).document = { createElement: jest.fn(() => a), body: { appendChild } };
    let blob: Blob | undefined;
    URL.createObjectURL = jest.fn((b: Blob) => {
      blob = b;
      return "blob:x";
    });
    URL.revokeObjectURL = jest.fn();

    await saveCsvWeb("superbot-audit-x.csv", CSV);
    expect(a).toMatchObject({ href: "blob:x", download: "superbot-audit-x.csv" });
    expect(appendChild).toHaveBeenCalledWith(a);
    expect(a.click).toHaveBeenCalled();
    expect(a.remove).toHaveBeenCalled();
    expect(blob?.type).toBe("text/csv;charset=utf-8");
    expect(await blob?.text()).toBe(CSV);
    expect(URL.revokeObjectURL).not.toHaveBeenCalled();
    jest.runAllTimers();
    expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:x");
    await saveCsvWeb("r.md", "# Report\n", undefined, MARKDOWN);
    expect(blob?.type).toBe("text/markdown;charset=utf-8");
  });
});
