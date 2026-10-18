import { describe, expect, test } from "bun:test";
import { evaluate, parseAws, shellSplit, type Verdict } from "../plugins/aws-guard/src/aws_guard_lib";

const reasonOf = (v: Verdict) => ("reason" in v ? v.reason : undefined);

const P = "aws --profile sandbox";

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
  // Full policy matrix.
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

  test.each(cases)("%s", (_name, cmd, expected) => {
    const r = evaluate(cmd);
    expect(r.decision).toBe(expected);
    expect("reason" in r && r.reason).toBeTruthy();
  });

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
    expect(reasonOf(evaluate("aws iam delete-user"))).toContain("blocked by policy");
    expect(reasonOf(evaluate("aws --profile prod ec2 describe-instances --query Foo"))).toContain("Prod");
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
    expect(reasonOf(evaluate("aws --profile d ec2 run-instances"))).toBe(
      "Mutating or unrecognized: aws ec2 run-instances",
    );
  });
});
