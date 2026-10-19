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
  | "reason_not_shown"; // a denied call's reason did not reach Claude

export interface CheckResult {
  mode: Mode;
  id: Case["id"];
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

export type ErrorCode = "version_mismatch" | "claude_failed";

export function legStatus(leg: LegResult): Status {
  if (leg.checks.some((c) => c.status === "fail")) return "fail";
  if (leg.error || leg.checks.some((c) => c.status === "error")) return "error";
  if (leg.checks.length === 0) return "error";
  return "pass";
}
