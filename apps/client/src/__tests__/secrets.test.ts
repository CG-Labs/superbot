import { managedIn, normalizeSecretName, savedLine, secretNameProblem, secretValueProblem } from "../secrets";

describe("personal secret names and values (ADR 0044)", () => {
  it("turns what people type into an environment variable name", () => {
    expect(normalizeSecretName("  openai api-key ")).toBe("OPENAI_API_KEY");
    expect(normalizeSecretName("GITHUB_TOKEN")).toBe("GITHUB_TOKEN");
  });

  it("flags names the server refuses", () => {
    expect(secretNameProblem("OPENAI_API_KEY")).toBeNull();
    expect(secretNameProblem("")).toMatch(/Give it a name/);
    expect(secretNameProblem("1PASSWORD")).toMatch(/environment variable name/);
    expect(secretNameProblem("BAD.NAME")).toMatch(/environment variable name/);
    expect(secretNameProblem("X".repeat(129))).toMatch(/environment variable name/);
    for (const reserved of ["PATH", "BOT_TOKEN", "SUPERBOT_MASTER_KEY", "SSO_X_CLIENT_SECRET", "LINODE_TOKEN", "LD_PRELOAD"]) {
      expect(secretNameProblem(reserved)).toBe(`${reserved} is reserved by SuperBot.`);
    }
  });

  it("flags values the server refuses", () => {
    expect(secretValueProblem("sk-123")).toBeNull();
    expect(secretValueProblem("")).toMatch(/Paste/);
    expect(secretValueProblem("a\0b")).toMatch(/NUL/);
    expect(secretValueProblem("x".repeat(64 * 1024))).toBeNull();
    expect(secretValueProblem("x".repeat(64 * 1024 + 1))).toMatch(/64 KB/);
  });

  it("says when a secret was saved and last replaced", () => {
    const nov3 = Date.UTC(2026, 10, 3, 12) / 1000;
    const nov20 = Date.UTC(2026, 10, 20, 9) / 1000;
    expect(savedLine({ name: "A", createdAt: nov3, updatedAt: nov3 })).toBe("Saved 3 Nov 2026");
    expect(savedLine({ name: "A", createdAt: nov3, updatedAt: nov3 + 60 })).toBe("Saved 3 Nov 2026");
    expect(savedLine({ name: "A", createdAt: nov3, updatedAt: nov20 })).toBe("Saved 3 Nov 2026 · replaced 20 Nov 2026");
    expect(savedLine({ name: "A", updatedAt: nov20 })).toBe("Saved 20 Nov 2026");
    expect(savedLine({ name: "A", store: "sealed", saved: true, createdAt: nov3, updatedAt: nov3 })).toBe("Saved 3 Nov 2026");
  });

  it("says who keeps a secret held in an external store (ADR 0174)", () => {
    expect(managedIn({ name: "A", updatedAt: 1 })).toBeNull();
    expect(managedIn({ name: "A", store: "sealed" })).toBeNull();
    expect(managedIn({ name: "A", store: "gcp-secret-manager" })).toBe("GCP Secret Manager");
    expect(managedIn({ name: "A", store: "azure-keyvault" })).toBe("Azure Key Vault");
    expect(managedIn({ name: "A", store: "new-backend" })).toBe("new-backend");
    expect(savedLine({ name: "A", store: "vault", saved: false })).toBe("Set for you by an admin in HashiCorp Vault");
    expect(savedLine({ name: "A" })).toBe("Saved");
  });
});
