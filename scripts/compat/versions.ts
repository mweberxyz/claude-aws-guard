// Works out which Claude Code versions the compatibility check runs against and writes them as a
// matrix to $GITHUB_OUTPUT (or prints it). Run from the workflow: MIN_CLAUDE_CODE=2.1.295 bun scripts/compat/versions.ts
import { appendFileSync } from "node:fs";
import { selectVersions } from "./lib";

async function npmView(pkg: string, ...args: string[]): Promise<unknown> {
  const proc = Bun.spawn(["npm", "view", pkg, ...args, "--json"], { stdout: "pipe", stderr: "inherit" });
  const [out, code] = await Promise.all([new Response(proc.stdout).text(), proc.exited]);
  if (code !== 0) throw new Error(`npm view ${pkg} ${args.join(" ")} exited ${code}`);
  return JSON.parse(out);
}

const minimum = process.env.MIN_CLAUDE_CODE ?? "";
const published = (await npmView("@anthropic-ai/claude-code", "versions")) as string[];
const latest = (await npmView("@anthropic-ai/claude-code", "dist-tags.latest")) as string;

// selectVersions only returns plain x.y.z, so what reaches the workflow is safe to use in a command line.
const matrix = JSON.stringify({
  include: selectVersions(published, minimum, latest).map((s) => ({ version: s.version, labels: s.labels.join(",") })),
});
console.log(matrix);
if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `matrix=${matrix}\n`);
