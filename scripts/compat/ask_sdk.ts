// Phase 2: does an `ask` still prompt a user under --dangerously-skip-permissions? `claude -p` can't
// show a prompt, but the Agent SDK calls `canUseTool` where Claude Code would, so this runs the same
// guard through the SDK, against the mock API, and records whether the callback fired.
// See README, "Compatibility checks".
//
//   bun scripts/compat/ask_sdk.ts --version 2.1.303 --sdk-dir /tmp/sdk --out results
//
// --sdk-dir holds `npm install @anthropic-ai/claude-agent-sdk@<the release bundling --version>`, which
// brings its own Claude Code binary of that version. Must not run as root.
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { makeSandbox, PROMPT } from "./harness";
import { ASK_COMMAND, evaluateAsk, SEMVER, type CheckResult, type LegResult, type Mode, type VersionLabel } from "./lib";

const { values } = parseArgs({
  options: {
    version: { type: "string" },
    labels: { type: "string", default: "" },
    "sdk-dir": { type: "string" },
    out: { type: "string", default: "compat-results" },
  },
});
const version = values.version ?? "";
if (!SEMVER.test(version)) throw new Error("--version x.y.z is required");

const leg: LegResult = { version, labels: values.labels!.split(",").filter(Boolean) as VersionLabel[], checks: [] };

async function load(): Promise<any> {
  try {
    const dir = join(values["sdk-dir"]!, "node_modules", "@anthropic-ai", "claude-agent-sdk");
    const pkg = await Bun.file(join(dir, "package.json")).json();
    if (pkg.claudeCodeVersion !== version) {
      leg.error = "version_mismatch";
      return null;
    }
    return await import(pathToFileURL(join(dir, "sdk.mjs")).href);
  } catch {
    leg.error = "sdk_unavailable";
    return null;
  }
}

// One SDK session. The callback records what it was asked and always denies, so nothing it is asked
// about can run through it.
async function check(sdk: any, mode: Mode): Promise<CheckResult> {
  const sandbox = makeSandbox(ASK_COMMAND);
  const prompted: string[] = [];
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), 120_000);
  try {
    const q = sdk.query({
      prompt: PROMPT,
      options: {
        cwd: sandbox.project,
        env: sandbox.env,
        tools: ["Bash"],
        settingSources: ["project"],
        permissionMode: mode === "bypass" ? "bypassPermissions" : "default",
        allowDangerouslySkipPermissions: mode === "bypass",
        persistSession: false,
        abortController: abort,
        canUseTool: async (tool: string, input: Record<string, unknown>) => {
          if (tool === "Bash" && typeof input.command === "string") prompted.push(input.command);
          return { behavior: "deny", message: "Compatibility check: nothing may run." };
        },
      },
    });
    for await (const _ of q) {
      // Drain; only the callback and the side effects matter.
    }
  } catch (e) {
    console.error(`SDK run failed for ${mode}: ${String((e as Error)?.message ?? e).slice(-500)}`);
  } finally {
    clearTimeout(timer);
    sandbox.close();
  }
  const result = evaluateAsk(mode, sandbox.observe(), prompted);
  console.log(`${mode}/ask_prompt: ${result.status}${result.failed.length ? ` (${result.failed.join(", ")})` : ""}`);
  return result;
}

const sdk = await load();
if (sdk) {
  // Normal mode too, as the control: if an `ask` doesn't prompt there either, it says so under
  // normal/ask_prompt, and the bypass result is not the news.
  for (const mode of ["normal", "bypass"] as Mode[]) leg.checks.push(await check(sdk, mode));
}

mkdirSync(values.out!, { recursive: true });
writeFileSync(join(values.out!, `ask-sdk-${version}.json`), JSON.stringify(leg, null, 2));
const bad = leg.error || leg.checks.some((c) => c.status !== "pass");
console.log(`${version}: ${bad ? "problem" : "ok"}`);
process.exit(bad ? 1 : 0);
