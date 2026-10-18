import { describe, expect, test } from "bun:test";
import { evaluate, parseAws, shellSplit } from "./aws_guard_lib";

describe("shellSplit", () => {
  test.each<[string, string, string[]]>([
    ["plain words", "a b  c", ["a", "b", "c"]],
    ["tabs and leading/trailing space", "  a\tb  ", ["a", "b"]],
    ["empty string", "", []],
    ["single quotes are literal", `'a b' 'c\\d'`, ["a b", "c\\d"]],
    ["double quotes group", `"a b" c`, ["a b", "c"]],
    ["backslash escapes quote inside double quotes", `"a\\"b"`, [`a"b`]],
    ["backslash escapes backslash inside double quotes", `"a\\\\b"`, ["a\\b"]],
    ["backslash escapes $ and backtick inside double quotes", `"\\$x \\\`y"`, ["$x `y"]],
    ["other backslash inside double quotes is kept", `"a\\nb"`, ["a\\nb"]],
    ["backslash outside quotes escapes next char", `a\\ b`, ["a b"]],
    ["adjacent quoted and bare parts join", `a"b c"'d'`, ["ab cd"]],
    ["empty quoted string is a token", `a "" b`, ["a", "", "b"]],
    ["trailing backslash is kept as a plain char", `a\\`, ["a\\"]],
  ])("%s", (_n, input, expected) => {
    expect(shellSplit(input)).toEqual(expected);
  });

  test.each([`"abc`, `'abc`, `a "b 'c'`])("unterminated quote %p is an error", (input) => {
    expect(shellSplit(input)).toEqual({ error: "Unparseable command (unterminated quote)" });
  });
});

describe("parseAws", () => {
  const ok = (cmd: string) => {
    const p = parseAws(cmd);
    if ("error" in p) throw new Error(p.error);
    return p;
  };

  test("service, op, profile, query", () => {
    const p = ok("aws --profile dev ec2 describe-instances --query Foo");
    expect([p.service, p.op, p.profile, p.query]).toEqual(["ec2", "describe-instances", "dev", "Foo"]);
  });

  test.each(["--region us-east-1", "--output json", "--endpoint-url http://x", "--ca-bundle f",
    "--color on", "--cli-read-timeout 5", "--cli-connect-timeout 5", "--cli-binary-format raw-in-base64-out",
    "--cli-auto-prompt on"])("value of %s is not mistaken for the service", (flag) => {
    const p = ok(`aws ${flag} --profile dev ec2 describe-instances`);
    expect([p.service, p.op]).toEqual(["ec2", "describe-instances"]);
  });

  test("--flag=value forms", () => {
    const p = ok("aws --profile=dev --region=us-east-1 ec2 describe-instances --query=Foo");
    expect([p.service, p.op, p.profile, p.query]).toEqual(["ec2", "describe-instances", "dev", "Foo"]);
  });

  test("value containing = is kept whole", () => {
    expect(ok("aws --query=a=b ec2 x").query).toBe("a=b");
  });

  test("boolean flags don't consume the next token", () => {
    const p = ok("aws --no-paginate --debug ec2 describe-instances");
    expect([p.service, p.op]).toEqual(["ec2", "describe-instances"]);
  });

  test("short flags are skipped", () => {
    expect(ok("aws -h ec2 x").service).toBe("ec2");
  });

  test("missing service/op are empty strings", () => {
    const p = ok("aws");
    expect([p.service, p.op]).toEqual(["", ""]);
  });

  test("a trailing value flag with no value gives undefined", () => {
    expect(ok("aws ec2 x --profile").profile).toBeUndefined();
  });

  test("AWS_PROFILE assignment, last one wins, --profile overrides", () => {
    expect(ok("AWS_PROFILE=a aws s3 ls").profile).toBe("a");
    expect(ok("AWS_PROFILE=a AWS_PROFILE=b aws s3 ls").profile).toBe("b");
    expect(ok("AWS_PROFILE=a aws --profile c s3 ls").profile).toBe("c");
  });

  test("assignment value containing = is kept whole", () => {
    expect(ok("AWS_PROFILE=a=b aws s3 ls").profile).toBe("a=b");
  });

  test("quoted tokens are unquoted", () => {
    const p = ok(`"aws" --profile "my dev" s3 ls`);
    expect(p.profile).toBe("my dev");
  });

  test("has() matches --flag and --flag=value, not prefixes", () => {
    const p = ok("aws --profile d ec2 x --dry-run --foo=bar");
    expect(p.has("--dry-run")).toBe(true);
    expect(p.has("--foo")).toBe(true);
    expect(p.has("--dry")).toBe(false);
    expect(p.has("--missing")).toBe(false);
  });

  test.each(["sudo aws s3 ls", "/usr/bin/aws s3 ls", "echo hi", ""])(
    "not directly aws: %p is an error",
    (cmd) => {
      expect(parseAws(cmd)).toEqual({ error: "aws is not the command being run directly" });
    },
  );

  test("unterminated quote is an error", () => {
    expect(parseAws(`aws "x`)).toEqual({ error: "Unparseable command (unterminated quote)" });
  });
});

describe("evaluate", () => {
  test("passthrough detection", () => {
    for (const c of ["", "ls", "echo awsome", "awscli", "echo laws", "aws-vault exec x"]) {
      expect(evaluate(c)).toEqual({ decision: "passthrough" });
    }
    for (const c of ["aws", "x; aws s3", "(aws s3 ls)", "ls /var/aws", `"aws" s3`, "'aws'"]) {
      expect(evaluate(c).decision).not.toBe("passthrough");
    }
  });

  test("bare `aws` (no profile) is denied", () => {
    expect(evaluate("aws").decision).toBe("deny");
  });

  test("deny reasons name the blocked command", () => {
    expect(evaluate("aws --profile d iam delete-user")).toEqual({
      decision: "deny",
      reason: "aws iam delete-user is blocked by policy",
    });
  });

  test("ssm --with-decryption is denied, with or without =value", () => {
    for (const f of ["--with-decryption", "--with-decryption=true"]) {
      expect(evaluate(`aws --profile d ssm get-parameter --query Foo ${f}`)).toEqual({
        decision: "deny",
        reason: "Decrypting SSM parameters is blocked",
      });
    }
  });

  test("deny beats a missing profile, prod beats an allowed read", () => {
    expect(evaluate("aws iam delete-user").reason).toContain("blocked by policy");
    expect(evaluate("aws --profile prod ec2 describe-instances --query Foo").reason).toContain("Prod");
  });

  test("query is trimmed before the wildcard check", () => {
    expect(evaluate("aws --profile d ec2 describe-instances --query ' @ '").decision).toBe("deny");
    expect(evaluate("aws --profile d ec2 describe-instances --query '   '").decision).toBe("deny");
  });

  test("a query merely containing a wildcard is accepted", () => {
    expect(evaluate("aws --profile d ec2 describe-instances --query 'Reservations[*].Id'").decision).toBe("allow");
    expect(evaluate("aws --profile d ec2 describe-instances --query '@.Foo'").decision).toBe("allow");
  });

  test("read verbs are matched by prefix only", () => {
    expect(evaluate("aws --profile d ec2 modify-describe-thing").decision).toBe("ask");
    expect(evaluate("aws --profile d ec2 describe").decision).toBe("ask");
  });

  test("service-less op doesn't crash", () => {
    expect(evaluate("aws --profile d").decision).toBe("ask");
  });

  test("ask reason names service and op", () => {
    expect(evaluate("aws --profile d ec2 run-instances").reason).toBe(
      "Mutating or unrecognized: aws ec2 run-instances",
    );
  });
});
