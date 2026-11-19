// SuperBot approval gate for Pi, loaded with `pi --extension`. Pi runs only
// TypeScript extensions, so this is a thin bridge: every tool call goes through
// `botctl hook pi`, which asks botd. Anything but a clean exit 0 blocks the call.
import { spawn } from "node:child_process";

export default function (pi: any) {
  pi.on("tool_call", async (event: any) => {
    const payload = JSON.stringify({
      hook_event_name: "PreToolUse",
      tool_name: event.toolName,
      tool_input: event.input,
      cwd: process.cwd(),
    });
    const result = await new Promise<{ code: number | null; stderr: string }>((resolve) => {
      const child = spawn(process.env.SUPERBOT_BOTCTL || "botctl", ["hook", "pi"], { stdio: ["pipe", "ignore", "pipe"] });
      let stderr = "";
      child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
      child.on("error", (e: Error) => resolve({ code: null, stderr: String(e) }));
      child.on("close", (code: number | null) => resolve({ code, stderr }));
      child.stdin.end(payload);
    });
    if (result.code === 0) return undefined;
    return { block: true, reason: result.stderr.trim() || "Blocked by SuperBot's approval gate." };
  });
}
