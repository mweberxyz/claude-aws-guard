// Works out which Claude Code versions the compatibility check runs against and writes them as a
// matrix to $GITHUB_OUTPUT (or prints it). Run from the workflow: MIN_CLAUDE_CODE=2.1.295 bun scripts/compat/versions.ts
import { appendFileSync } from "node:fs";
import { selectSdk, selectVersions } from "./lib";

async function npmView(pkg: string, ...args: string[]): Promise<unknown> {
  const proc = Bun.spawn(["npm", "view", pkg, ...args, "--json"], { stdout: "pipe", stderr: "inherit" });
  const [out, code] = await Promise.all([new Response(proc.stdout).text(), proc.exited]);
  if (code !== 0) throw new Error(`npm view ${pkg} ${args.join(" ")} exited ${code}`);
  return JSON.parse(out);
}

const minimum = process.env.MIN_CLAUDE_CODE ?? "";
const published = (await npmView("@anthropic-ai/claude-code", "versions")) as string[];
const latest = (await npmView("@anthropic-ai/claude-code", "dist-tags.latest")) as string;
// Each Agent SDK release bundles one Claude Code version; the SDK check uses the one that matches.
const sdks = await npmView("@anthropic-ai/claude-agent-sdk@>=0.3.0", "version", "claudeCodeVersion");

// selectVersions and selectSdk only return plain x.y.z, so what reaches the workflow is safe to use in
// a command line. An empty sdk means no SDK release bundles that version.
const matrix = JSON.stringify({
  include: selectVersions(published, minimum, latest).map((s) => ({
    version: s.version,
    labels: s.labels.join(","),
    sdk: selectSdk(sdks, s.version) ?? "",
  })),
});
console.log(matrix);
if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `matrix=${matrix}\n`);
