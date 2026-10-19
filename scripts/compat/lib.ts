// Pure logic for the Claude Code compatibility check (see README, "Compatibility checks").
// No I/O here, so the version selection and the assertions are unit tested in-process.

export type Mode = "normal" | "bypass";
export type Status = "pass" | "fail" | "error";

// Everything the documented behavior rests on, as the stdin of a hook says it.
// https://code.claude.com/docs/en/hooks (common input fields)
export const DOCUMENTED_PERMISSION_MODES = ["default", "plan", "acceptEdits", "auto", "dontAsk", "bypassPermissions"];

export interface Case {
  id: "allow" | "deny" | "ask" | "passthrough";
  command: string;
  // What the guard writes to the audit log for this command; null when it must stay silent.
  audit: "allow" | "deny" | "ask" | null;
  // Whether the fake `aws` shim should have been run with these arguments.
  executes: boolean;
}

export const CASES: Case[] = [
  { id: "allow", command: "aws s3 ls --profile test", audit: "allow", executes: true },
  { id: "deny", command: "aws iam list-users --profile prod", audit: "deny", executes: false },
  { id: "ask", command: "aws s3 cp ./x s3://b/x --profile test", audit: "ask", executes: false },
  { id: "passthrough", command: "echo hello", audit: null, executes: false },
];

// ---- Versions ----------------------------------------------------------------------------------

export const SEMVER = /^\d+\.\d+\.\d+$/;

export function compareVersions(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) if (pa[i] !== pb[i]) return pa[i] - pb[i];
  return 0;
}

export type VersionLabel = "minimum" | "previous" | "latest";

export interface VersionSpec {
  version: string;
  labels: VersionLabel[];
}

// The minimum we declare, the newest release, and the release just before it. `published` is every
// version on npm; pre-releases and anything that isn't plain x.y.z are ignored.
export function selectVersions(published: string[], minimum: string, latest: string): VersionSpec[] {
  const stable = published.filter((v) => SEMVER.test(v)).sort(compareVersions);
  for (const [name, v] of [["minimum", minimum], ["latest", latest]]) {
    if (!SEMVER.test(v)) throw new Error(`${name} version ${JSON.stringify(v)} is not x.y.z`);
    if (!stable.includes(v)) throw new Error(`${name} version ${v} is not published on npm`);
  }
  const previous = stable.filter((v) => compareVersions(v, latest) < 0).pop();
  if (!previous) throw new Error(`no release before ${latest}`);

  const specs = new Map<string, VersionLabel[]>();
  for (const [label, version] of [["minimum", minimum], ["previous", previous], ["latest", latest]] as const) {
    specs.set(version, [...(specs.get(version) ?? []), label]);
  }
  return [...specs].map(([version, labels]) => ({ version, labels })).sort((a, b) => compareVersions(a.version, b.version));
}

// ---- Observations ------------------------------------------------------------------------------

interface HookEntry {
  command?: string;
  permissionMode?: string;
}

// The logging hook appends each Bash call's stdin JSON, one document per line.
export function parseHookLog(text: string): HookEntry[] {
  const entries: HookEntry[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    let doc: any;
    try {
      doc = JSON.parse(line);
    } catch {
      continue;
    }
    if (doc?.tool_name !== undefined && doc.tool_name !== "Bash") continue;
    entries.push({ command: doc?.tool_input?.command, permissionMode: doc?.permission_mode });
  }
  return entries;
}

export interface AuditEntry {
  decision?: string;
  reason?: string;
  cmd?: string;
}

// The audit log can also hold non-JSON error text if the hook itself breaks; skip it.
export function parseAuditLog(text: string): AuditEntry[] {
  const entries: AuditEntry[] = [];
  for (const line of text.split("\n")) {
    try {
      const doc = JSON.parse(line);
      if (doc && typeof doc === "object") entries.push(doc);
    } catch {}
  }
  return entries;
}

// What Claude Code sent back to the (mock) model as the result of the tool call.
export interface ToolResult {
  isError: boolean;
  text: string;
}

export interface Observation {
  hookLog: string;
  auditLog: string;
  // The argument string of every call the fake `aws` shim received, one per line.
  shimLog: string;
  // Undefined if Claude Code never reported a result for the tool call.
  toolResult?: ToolResult;
}

export type FailureCode =
  | "hook_not_run" // Claude Code processed the call but the logging hook never saw it
  | "permission_mode" // the hook payload's permission_mode isn't what the mode implies
  | "audit_decision" // the audit log has the command, with the wrong decision
  | "audit_missing" // the guard didn't log a decision it should have
  | "audit_unexpected" // the guard logged a command it should have ignored
  | "unexpected_execution" // the command ran although it must not have
  | "missing_execution" // the command didn't run although it must have
  | "reason_not_shown" // a denied call's reason did not reach Claude
  | "no_prompt"; // an `ask` never reached the permission callback, so no user would have been asked

export interface CheckResult {
  mode: Mode;
  id: Case["id"] | "ask_prompt";
  status: Status;
  failed: FailureCode[];
}

const modeOk = (mode: Mode, m?: string) =>
  mode === "bypass" ? m === "bypassPermissions" : m !== undefined && m !== "bypassPermissions" && DOCUMENTED_PERMISSION_MODES.includes(m);

// Assertions use side effects only: what the hook saw, what the guard logged, what the shim ran, and
// what Claude was told. The tool call is scripted, so there is no excuse for it not happening: if
// Claude Code never reported back on it, the harness is broken ("error"); if it did but the hook
// never ran, that is a regression ("fail").
export function evaluate(c: Case, mode: Mode, obs: Observation): CheckResult {
  const result = (status: Status, failed: FailureCode[] = []): CheckResult => ({ mode, id: c.id, status, failed });
  if (!obs.toolResult) return result("error");

  const seen = parseHookLog(obs.hookLog).filter((e) => e.command === c.command);
  if (seen.length === 0) return result("fail", ["hook_not_run"]);

  const failed: FailureCode[] = [];
  if (!seen.every((e) => modeOk(mode, e.permissionMode))) failed.push("permission_mode");

  const audit = parseAuditLog(obs.auditLog);
  const mine = audit.filter((e) => e.cmd === c.command);
  if (c.audit === null) {
    if (audit.length > 0) failed.push("audit_unexpected");
  } else if (mine.length === 0) {
    failed.push("audit_missing");
  } else if (!mine.every((e) => e.decision === c.audit)) {
    failed.push("audit_decision");
  }

  const ran = c.command.startsWith("aws ") && obs.shimLog.split("\n").includes(c.command.replace(/^aws /, ""));
  if (c.executes && !ran) failed.push("missing_execution");
  if (!c.executes && ran) failed.push("unexpected_execution");

  // A denied call has to tell Claude why, so it can correct itself.
  if (c.audit === "deny") {
    const reason = mine.find((e) => typeof e.reason === "string" && e.reason !== "")?.reason;
    if (reason && !(obs.toolResult.isError && obs.toolResult.text.includes(reason))) failed.push("reason_not_shown");
  }

  return result(failed.length ? "fail" : "pass", failed);
}

// ---- Agent SDK: does an `ask` prompt? ----------------------------------------------------------

export const ASK_COMMAND = CASES.find((c) => c.id === "ask")!.command;

// The Agent SDK calls `canUseTool` where Claude Code would show a permission prompt, so a call to it
// is the direct evidence that an `ask` would have asked a user. `prompted` is every command the
// callback was asked about. The callback always denies, so the command can only run if something
// skipped the prompt: that is the second assertion.
export function evaluateAsk(mode: Mode, obs: Observation, prompted: string[]): CheckResult {
  const result = (status: Status, failed: FailureCode[] = []): CheckResult => ({ mode, id: "ask_prompt", status, failed });
  if (!obs.toolResult) return result("error");
  const seen = parseHookLog(obs.hookLog).filter((e) => e.command === ASK_COMMAND);
  if (seen.length === 0) return result("fail", ["hook_not_run"]);

  const failed: FailureCode[] = [];
  if (!seen.every((e) => modeOk(mode, e.permissionMode))) failed.push("permission_mode");
  if (!prompted.includes(ASK_COMMAND)) failed.push("no_prompt");
  if (obs.shimLog.split("\n").includes(ASK_COMMAND.replace(/^aws /, ""))) failed.push("unexpected_execution");
  return result(failed.length ? "fail" : "pass", failed);
}

// The Agent SDK release that bundles a given Claude Code version, from
// `npm view @anthropic-ai/claude-agent-sdk version claudeCodeVersion --json`. Undefined if there is none.
export function selectSdk(listing: unknown, claudeCodeVersion: string): string | undefined {
  const entries = Array.isArray(listing) ? listing : [listing];
  return entries
    .filter((e: any) => e?.claudeCodeVersion === claudeCodeVersion && typeof e.version === "string" && SEMVER.test(e.version))
    .map((e: any) => e.version as string)
    .sort(compareVersions)
    .pop();
}

// ---- Results across versions -------------------------------------------------------------------

export interface LegResult {
  version: string;
  labels: VersionLabel[];
  // What `claude --version` printed, when it could be read.
  observedVersion?: string;
  checks: CheckResult[];
  // A harness problem that stopped the leg (wrong version, claude failing to run), if any.
  error?: ErrorCode;
}

export type ErrorCode = "version_mismatch" | "claude_failed" | "no_results" | "sdk_unavailable";

export function legStatus(leg: LegResult): Status {
  if (leg.checks.some((c) => c.status === "fail")) return "fail";
  if (leg.error || leg.checks.some((c) => c.status === "error")) return "error";
  if (leg.checks.length === 0) return "error";
  return "pass";
}

// ---- Untrusted input ---------------------------------------------------------------------------

const STATUSES: Status[] = ["pass", "fail", "error"];
const MODES: Mode[] = ["normal", "bypass"];
const IDS: string[] = [...CASES.map((c) => c.id), "ask_prompt"];
const FAILURES: FailureCode[] = [
  "hook_not_run",
  "permission_mode",
  "audit_decision",
  "audit_missing",
  "audit_unexpected",
  "unexpected_execution",
  "missing_execution",
  "reason_not_shown",
  "no_prompt",
];
const LABELS: VersionLabel[] = ["minimum", "previous", "latest"];
const ERRORS: ErrorCode[] = ["version_mismatch", "claude_failed", "no_results", "sdk_unavailable"];

// The probe jobs run code from npm and from the pull request under test, so what they write is not
// trusted by the job that files issues. Every field is checked against a fixed list and anything else
// is dropped; nothing free-form survives, so nothing a probe could influence reaches an issue body.
export function sanitizeLeg(raw: unknown): LegResult | null {
  const r = raw as any;
  if (!r || typeof r !== "object" || typeof r.version !== "string" || !SEMVER.test(r.version)) return null;
  const labels = Array.isArray(r.labels) ? LABELS.filter((l) => r.labels.includes(l)) : [];
  const checks: CheckResult[] = [];
  for (const c of Array.isArray(r.checks) ? r.checks : []) {
    if (!MODES.includes(c?.mode) || !IDS.includes(c?.id) || !STATUSES.includes(c?.status)) continue;
    checks.push({
      mode: c.mode,
      id: c.id,
      status: c.status,
      failed: Array.isArray(c.failed) ? FAILURES.filter((f) => c.failed.includes(f)) : [],
    });
  }
  const leg: LegResult = { version: r.version, labels, checks };
  if (typeof r.observedVersion === "string" && SEMVER.test(r.observedVersion)) leg.observedVersion = r.observedVersion;
  if (ERRORS.includes(r.error)) leg.error = r.error;
  return leg;
}

// ---- Report text -------------------------------------------------------------------------------

const ICON: Record<Status, string> = { pass: "✅", fail: "❌", error: "⚠️" };

export const LEGEND = "✅ pass · ❌ fail · ⚠️ harness error (Claude Code never reported back on the call, or could not run)";

const ERROR_TEXT: Record<ErrorCode, string> = {
  version_mismatch: "the installed `claude` isn't the requested version",
  claude_failed: "`claude` ran but never reported back on the call, so nothing could be judged. The mock API probably lacks something this release needs",
  no_results: "the job produced no results (install or runner failure)",
  sdk_unavailable: "the Agent SDK release bundling this version could not be loaded",
};

const FAILURE_TEXT: Record<FailureCode, string> = {
  hook_not_run: "Claude Code ran the command but the hook never saw it",
  permission_mode: "`permission_mode` in the hook payload was not what the mode implies",
  audit_decision: "the audit log recorded a different decision",
  audit_missing: "no audit line was written",
  audit_unexpected: "an audit line was written for a command that should pass through",
  unexpected_execution: "the command ran, but must not have",
  missing_execution: "the command did not run, but must have",
  reason_not_shown: "Claude was not told why the call was denied",
  no_prompt: "the `ask` never reached the permission callback, so a user would not have been asked",
};

const label = (leg: LegResult) => `${leg.version} (${leg.labels.join(", ") || "unlabeled"})`;

export function summaryTable(legs: LegResult[]): string {
  const rows = new Set<string>();
  for (const leg of legs) for (const c of leg.checks) rows.add(`${c.mode}/${c.id}`);
  const header = ["Check", ...legs.map(label)];
  const lines = [`| ${header.join(" | ")} |`, `|${header.map(() => "---").join("|")}|`];
  for (const row of [...rows].sort()) {
    const cells = legs.map((leg) => {
      const c = leg.checks.find((c) => `${c.mode}/${c.id}` === row);
      return c ? ICON[c.status] : "";
    });
    lines.push(`| \`${row}\` | ${cells.join(" | ")} |`);
  }
  lines.push(`| **Leg** | ${legs.map((l) => ICON[legStatus(l)]).join(" | ")} |`);
  return lines.join("\n");
}

// What a failure most likely means, from which versions failed.
export function classify(legs: LegResult[]): string {
  const bad = legs.filter((l) => legStatus(l) !== "pass");
  if (bad.length === 0) return "All legs pass.";
  const has = (l: VersionLabel) => bad.some((b) => b.labels.includes(l));
  const covered = (l: VersionLabel) => legs.some((leg) => leg.labels.includes(l));
  const onlyLatest = has("latest") && !has("minimum") && !has("previous") && covered("minimum") && covered("previous");
  if (onlyLatest) {
    return "**Only the latest release fails.** Claude Code's behavior probably changed upstream in that release. Check the release notes, decide whether the README and SECURITY.md claims still hold, and fix the plugin or the docs.";
  }
  if (has("minimum")) {
    return "**The declared minimum version fails.** Either an assumption in the docs was wrong from the start, or the harness is broken. Check this before the newer legs.";
  }
  return "**More than the latest release fails.** Look at the legs below; if every leg fails the same way, suspect the harness or the mock API first.";
}

export function renderReport(legs: LegResult[], runUrl: string): string {
  const out = [classify(legs), "", summaryTable(legs), "", LEGEND, ""];
  for (const leg of legs) {
    const notes: string[] = [];
    if (leg.error) notes.push(`- ${ERROR_TEXT[leg.error]}`);
    for (const c of leg.checks) {
      for (const f of c.failed) notes.push(`- \`${c.mode}/${c.id}\`: ${FAILURE_TEXT[f]}`);
    }
    if (notes.length) out.push(`**${label(leg)}**`, "", ...notes, "");
  }
  out.push(`Run: ${runUrl}`);
  return out.join("\n");
}

// ---- Combining legs and deciding what to do about them -----------------------------------------

// One version can be reported by several scripts.
export function mergeLegs(legs: LegResult[]): LegResult[] {
  const merged = new Map<string, LegResult>();
  for (const leg of legs) {
    const into = merged.get(leg.version);
    if (!into) {
      merged.set(leg.version, { ...leg, labels: [...leg.labels], checks: [...leg.checks] });
      continue;
    }
    into.labels = LABELS.filter((l) => into.labels.includes(l) || leg.labels.includes(l));
    into.checks.push(...leg.checks);
    into.observedVersion ??= leg.observedVersion;
    into.error ??= leg.error;
  }
  return [...merged.values()].sort((a, b) => compareVersions(a.version, b.version));
}

// The matrix the versions job produced ({"include":[{"version":"2.1.303","labels":"latest"}]}), checked
// like the results are. Empty if it can't be read, e.g. because that job failed.
export function sanitizeMatrix(raw: string | undefined): VersionSpec[] {
  try {
    const include = JSON.parse(raw ?? "").include;
    const specs: VersionSpec[] = [];
    for (const m of Array.isArray(include) ? include : []) {
      if (typeof m?.version !== "string" || !SEMVER.test(m.version)) continue;
      const wanted = typeof m.labels === "string" ? m.labels.split(",") : [];
      specs.push({ version: m.version, labels: LABELS.filter((l) => wanted.includes(l)) });
    }
    return specs;
  } catch {
    return [];
  }
}

// A version that should have reported but left no results (the install or the runner failed).
export function withMissing(legs: LegResult[], expected: VersionSpec[]): LegResult[] {
  const have = new Set(legs.map((l) => l.version));
  const missing = expected.filter((e) => !have.has(e.version));
  return mergeLegs([...legs, ...missing.map((e): LegResult => ({ ...e, checks: [], error: "no_results" }))]);
}

export type Action =
  | { type: "create"; title: string; body: string }
  | { type: "comment"; number: number; body: string }
  | { type: "close"; number: number };

export const ISSUE_TITLE = "Claude Code compatibility check failed";

// One open issue at a time: a problem opens it or adds to it, and a clean run closes it.
export function planActions(legs: LegResult[], runUrl: string, openIssue: number | null): Action[] {
  const problem = legs.length === 0 || legs.some((l) => legStatus(l) !== "pass");
  const body = legs.length === 0 ? `No results were produced.\n\nRun: ${runUrl}` : renderReport(legs, runUrl);
  if (problem) {
    return openIssue === null ? [{ type: "create", title: ISSUE_TITLE, body }] : [{ type: "comment", number: openIssue, body }];
  }
  if (openIssue === null) return [];
  return [
    { type: "comment", number: openIssue, body: `Everything passes again.\n\n${body}` },
    { type: "close", number: openIssue },
  ];
}
