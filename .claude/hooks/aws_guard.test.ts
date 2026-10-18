import { describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const SCRIPT = join(import.meta.dir, "aws_guard.ts");
const SETTINGS = join(import.meta.dir, "..", "settings.json");

// Runs the script the way Claude Code does: JSON on stdin, decision on stdout, audit line on stderr.
async function run(stdin: string) {
  const proc = Bun.spawn(["bun", "run", SCRIPT], {
    stdin: new Blob([stdin]),
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  const out = stdout.trim() ? JSON.parse(stdout) : null;
  return {
    exitCode,
    stderr,
    decision: out?.hookSpecificOutput?.permissionDecision as string | undefined,
    reason: out?.hookSpecificOutput?.permissionDecisionReason as string | undefined,
    out,
  };
}

const hook = (command: string) => run(JSON.stringify({ tool_input: { command } }));

const P = "aws --profile sandbox";

describe("passthrough", () => {
  test.each(["ls -la", "echo hello", "git status", "cat awsome.txt", "echo laws"])(
    "%s prints nothing, exits 0, writes no audit line",
    async (cmd) => {
      const r = await hook(cmd);
      expect(r.exitCode).toBe(0);
      expect(r.out).toBeNull();
      expect(r.stderr).toBe("");
    },
  );

  test("empty input command passes through", async () => {
    const r = await run(JSON.stringify({ tool_input: {} }));
    expect(r.out).toBeNull();
    expect(r.exitCode).toBe(0);
  });
});

describe("decisions", () => {
  const cases: [string, string, "allow" | "deny" | "ask"][] = [
    // read-only verbs need a narrowing --query
    ["narrowing query", `${P} ec2 describe-instances --query "Reservations[].Instances[].InstanceId"`, "allow"],
    ["query via =", `${P} ec2 describe-instances --query=Foo`, "allow"],
    ["no query", `${P} ec2 describe-instances`, "deny"],
    ["empty query", `${P} ec2 describe-instances --query ""`, "deny"],
    ["query @", `${P} ec2 describe-instances --query @`, "deny"],
    ["query *", `${P} ec2 describe-instances --query '*'`, "deny"],
    ["query [*]", `${P} ec2 describe-instances --query '[*]'`, "deny"],
    ["query []", `${P} ec2 describe-instances --query '[]'`, "deny"],
    ["query *.*", `${P} ec2 describe-instances --query '*.*'`, "deny"],
    ["list- needs query", `${P} lambda list-functions`, "deny"],
    ["get- with query", `${P} lambda get-function --function-name f --query Configuration.Runtime`, "allow"],
    ["head- needs query", `${P} s3api head-object --bucket b --key k`, "deny"],
    ["lookup- needs query", `${P} cloudtrail lookup-events`, "deny"],
    ["batch-get- needs query", `${P} dynamodb batch-get-item --request-items file://x`, "deny"],
    ["query value is not mistaken for service", `aws --query Foo --profile sandbox ec2 describe-instances`, "allow"],

    // s3 ls and dry runs
    ["s3 ls without query", `${P} s3 ls`, "allow"],
    ["AWS_PROFILE assignment", "AWS_PROFILE=sandbox aws s3 ls", "allow"],
    ["dry-run", `${P} ec2 run-instances --dry-run`, "allow"],
    ["dry-run with =", `${P} ec2 run-instances --dry-run=true`, "allow"],

    // mutations ask
    ["run-instances", `${P} ec2 run-instances`, "ask"],
    ["s3 cp", `${P} s3 cp a s3://b/a`, "ask"],
    ["s3 sync", `${P} s3 sync . s3://b`, "ask"],
    ["s3 rm", `${P} s3 rm s3://b/a`, "ask"],
    ["iam read-only verb is not a hard deny", `${P} iam list-users --query 'Users[].UserName'`, "allow"],

    // hard denies
    ["iam create", `${P} iam create-user --user-name x`, "deny"],
    ["iam attach", `${P} iam attach-user-policy --user-name x`, "deny"],
    ["iam put", `${P} iam put-user-policy --user-name x`, "deny"],
    ["iam update", `${P} iam update-user --user-name x`, "deny"],
    ["iam delete", `${P} iam delete-user --user-name x`, "deny"],
    ["iam add", `${P} iam add-user-to-group`, "deny"],
    ["sts assume-role", `${P} sts assume-role --role-arn r`, "deny"],
    ["sts assume-role-with-saml", `${P} sts assume-role-with-saml`, "deny"],
    ["organizations anything", `${P} organizations list-accounts --query 'Accounts[].Id'`, "deny"],
    ["kms schedule-key-deletion", `${P} kms schedule-key-deletion --key-id k`, "deny"],
    ["kms disable-key", `${P} kms disable-key --key-id k`, "deny"],
    ["kms put-key-policy", `${P} kms put-key-policy --key-id k`, "deny"],
    ["s3api delete-bucket", `${P} s3api delete-bucket --bucket b`, "deny"],
    ["s3api delete-bucket-policy", `${P} s3api delete-bucket-policy --bucket b`, "deny"],
    ["s3api put-bucket-policy", `${P} s3api put-bucket-policy --bucket b`, "deny"],
    ["s3api put-public-access-block", `${P} s3api put-public-access-block --bucket b`, "deny"],
    ["s3api put-bucket-acl", `${P} s3api put-bucket-acl --bucket b`, "deny"],
    ["s3 rb", `${P} s3 rb s3://b`, "deny"],
    ["get-secret-value", `${P} secretsmanager get-secret-value --secret-id s --query SecretString`, "deny"],
    ["configure", `${P} configure`, "deny"],
    ["configure set", `${P} configure set region us-east-1`, "deny"],
    ["ssm with-decryption", `${P} ssm get-parameter --name n --with-decryption --query Parameter.Value`, "deny"],
    ["ssm with-decryption =", `${P} ssm get-parameter --name n --with-decryption=true --query Parameter.Value`, "deny"],
    ["ssm without decryption", `${P} ssm get-parameter --name n --query Parameter.Value`, "allow"],

    // profile rules
    ["no profile", "aws ec2 describe-instances --query Foo", "deny"],
    ["no profile, s3 ls", "aws s3 ls", "deny"],
    ["--profile=value", "aws --profile=sandbox s3 ls", "allow"],
    ["prod profile", "aws --profile prod s3 ls", "deny"],
    ["Prod profile, case-insensitive", "aws --profile MyProD-admin s3 ls", "deny"],
    ["prod via AWS_PROFILE", "AWS_PROFILE=prod aws s3 ls", "deny"],
    ["prod via --profile=", "aws --profile=prod s3 ls", "deny"],
    ["--profile overrides AWS_PROFILE", "AWS_PROFILE=prod aws --profile sandbox s3 ls", "allow"],

    // compound / indirect / wrappers / unparseable
    ["semicolon", `${P} s3 ls; echo hi`, "ask"],
    ["&&", `${P} s3 ls && echo hi`, "ask"],
    ["pipe", `${P} s3 ls | head`, "ask"],
    ["backticks", `echo \`${P} s3 ls\``, "ask"],
    ["newline", `${P} s3 ls\necho hi`, "ask"],
    ["$(", `echo $(${P} s3 ls)`, "ask"],
    ["eval", `eval "${P} s3 ls"`, "ask"],
    ["bash -c", `bash -c "${P} s3 ls"`, "ask"],
    ["xargs", `echo x | xargs ${P} s3 ls`, "ask"],
    ["unterminated quote", `${P} ec2 describe-instances --query "Foo`, "ask"],
    ["sudo wrapper", "sudo aws --profile sandbox s3 ls", "ask"],
    ["time wrapper", "time aws --profile sandbox s3 ls", "ask"],

    // path-prefixed and quoted aws
    ["absolute path", "/usr/local/bin/aws --profile sandbox s3 ls", "ask"],
    ["relative path", "./aws --profile sandbox iam delete-user", "ask"],
    ["home path", "~/bin/aws --profile sandbox s3 ls", "ask"],
    ["quoted aws gets full rules (deny)", `"aws" --profile sandbox ec2 describe-instances`, "deny"],
    ["quoted aws gets full rules (allow)", `"aws" --profile sandbox ec2 describe-instances --query "A[].B"`, "allow"],
    ["single-quoted aws", `'aws' --profile sandbox s3 ls`, "allow"],
  ];

  test.each(cases)("%s", async (_name, cmd, expected) => {
    const r = await hook(cmd);
    expect(r.exitCode).toBe(0);
    expect(r.decision).toBe(expected);
    expect(r.reason).toBeTruthy();
  });

  test("output shape", async () => {
    const r = await hook(`${P} s3 ls`);
    expect(r.out.hookSpecificOutput.hookEventName).toBe("PreToolUse");
  });
});

describe("fail closed", () => {
  test.each([["not json"], [""], ["{"]])("malformed stdin %p is denied with the error", async (stdin) => {
    const r = await run(stdin);
    expect(r.decision).toBe("deny");
    expect(r.reason).toContain("aws_guard script failed");
  });

  test("a non-string command is denied, not passed through", async () => {
    const r = await run(JSON.stringify({ tool_input: { command: 42 } }));
    expect(r.decision).toBe("deny");
  });
});

describe("audit log", () => {
  test("one JSON line per aws call with ts, decision, reason, cmd", async () => {
    const cmd = `${P} iam delete-user --user-name x`;
    const r = await hook(cmd);
    const lines = r.stderr.trim().split("\n");
    expect(lines).toHaveLength(1);
    const entry = JSON.parse(lines[0]);
    expect(entry.decision).toBe("deny");
    expect(entry.reason).toBe(r.reason);
    expect(entry.cmd).toBe(cmd);
    expect(new Date(entry.ts).toString()).not.toBe("Invalid Date");
  });
});

// Exercises the exact command string from settings.json, so the shell wrapper is covered too.
describe("settings.json wrapper", () => {
  const settings = JSON.parse(readFileSync(SETTINGS, "utf8"));
  const hookCfg = settings.hooks.PreToolUse[0].hooks[0];

  async function wrapper(home: string, command: string) {
    const proc = Bun.spawn(["sh", "-c", hookCfg.command], {
      stdin: new Blob([JSON.stringify({ tool_input: { command } })]),
      stdout: "pipe",
      stderr: "pipe",
      env: { ...process.env, HOME: home, CLAUDE_PROJECT_DIR: join(import.meta.dir, "..", "..") },
    });
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited,
    ]);
    return { stdout, stderr, exitCode };
  }

  test("registration: Bash matcher, timeout, onFailure block", () => {
    expect(settings.hooks.PreToolUse[0].matcher).toBe("Bash");
    expect(hookCfg.timeout).toBe(10);
    expect(hookCfg.onFailure).toBe("block");
  });

  test("appends audit lines to ~/.claude/aws-audit.log, none for non-aws", async () => {
    const home = mkdtempSync(join(tmpdir(), "aws-guard-"));
    mkdirSync(join(home, ".claude"));
    await wrapper(home, `${P} s3 ls`);
    await wrapper(home, `${P} iam delete-user --user-name x`);
    await wrapper(home, "ls -la");
    const log = readFileSync(join(home, ".claude", "aws-audit.log"), "utf8").trim().split("\n");
    expect(log.map((l) => JSON.parse(l).decision)).toEqual(["allow", "deny"]);
  });

  test("exits 2 (blocks) when the audit log can't be opened", async () => {
    const home = mkdtempSync(join(tmpdir(), "aws-guard-")); // no .claude dir
    const r = await wrapper(home, "ls -la");
    expect(r.exitCode).toBe(2);
    expect(r.stderr).toContain("aws_guard failed");
  });

  test("permissions.deny lists the hard-deny commands", () => {
    expect(settings.permissions.deny).toEqual(
      expect.arrayContaining([
        "Bash(aws iam:*)",
        "Bash(aws organizations:*)",
        "Bash(aws sts assume-role:*)",
        "Bash(aws configure:*)",
        "Bash(aws secretsmanager get-secret-value:*)",
      ]),
    );
  });
});
