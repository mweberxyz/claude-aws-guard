// Reads the results the probe jobs uploaded, writes the run summary, and opens, updates or closes the
// compatibility issue. Runs in a job that has `issues: write` and runs nothing from npm.
//
//   bun scripts/compat/report.ts results [--dry-run]
//
// Env: MATRIX (the versions job's output), GITHUB_REPOSITORY, GITHUB_SERVER_URL, GITHUB_RUN_ID,
// GITHUB_STEP_SUMMARY, and GH_TOKEN for `gh`.
//
// The results come from jobs that run code from npm and from the pull request under test, so they are
// untrusted: sanitizeLeg keeps only values from fixed lists, and every word of the issue text is written
// in lib.ts.
import { appendFileSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { mergeLegs, planActions, renderReport, sanitizeLeg, sanitizeMatrix, withMissing, type Action, type LegResult } from "./lib";

const { values, positionals } = parseArgs({ options: { "dry-run": { type: "boolean", default: false } }, allowPositionals: true });
const dir = positionals[0] ?? "results";
const repo = process.env.GITHUB_REPOSITORY ?? "";
const runUrl = `${process.env.GITHUB_SERVER_URL ?? "https://github.com"}/${repo}/actions/runs/${process.env.GITHUB_RUN_ID ?? ""}`;
const LABEL = "compat-check";

function* jsonFiles(root: string): Generator<string> {
  let names: string[] = [];
  try {
    names = readdirSync(root);
  } catch {}
  for (const name of names) {
    const path = join(root, name);
    if (statSync(path).isDirectory()) yield* jsonFiles(path);
    else if (name.endsWith(".json")) yield path;
  }
}

const legs: LegResult[] = [];
for (const file of jsonFiles(dir)) {
  try {
    const leg = sanitizeLeg(JSON.parse(readFileSync(file, "utf8")));
    if (leg) legs.push(leg);
  } catch {}
}
const all = withMissing(mergeLegs(legs), sanitizeMatrix(process.env.MATRIX));

async function gh(...args: string[]): Promise<string> {
  const proc = Bun.spawn(["gh", ...args, "--repo", repo], { stdout: "pipe", stderr: "inherit", env: process.env });
  const [out, code] = await Promise.all([new Response(proc.stdout).text(), proc.exited]);
  if (code !== 0) throw new Error(`gh ${args.slice(0, 2).join(" ")} exited ${code}`);
  return out;
}

const summary = all.length ? renderReport(all, runUrl) : "No results were produced.";
console.log(summary);
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `## Claude Code compatibility\n\n${summary}\n`);

let open: number | null = null;
if (!values["dry-run"]) {
  const found = JSON.parse(await gh("issue", "list", "--label", LABEL, "--state", "open", "--json", "number", "--limit", "1"));
  open = found[0]?.number ?? null;
}
const actions: Action[] = planActions(all, runUrl, open);

for (const a of actions) {
  console.log(`${a.type}${"number" in a ? ` #${a.number}` : ""}`);
  if (values["dry-run"]) continue;
  if (a.type === "create") {
    await gh("label", "create", LABEL, "--description", "Claude Code behavior no longer matches the docs", "--color", "B60205", "--force");
    await gh("issue", "create", "--title", a.title, "--label", LABEL, "--body", a.body);
  } else if (a.type === "comment") {
    await gh("issue", "comment", String(a.number), "--body", a.body);
  } else {
    await gh("issue", "close", String(a.number), "--reason", "completed");
  }
}
