import { describe, expect, it } from "vitest";
import { parseArgs } from "../../src/infrastructure/cli/args.js";

const parse = (argv: string[], env: Record<string, string | undefined> = {}) => parseArgs(argv, env);
const value = (argv: string[], env: Record<string, string | undefined> = {}) => {
  const r = parse(argv, env);
  if (!r.ok) throw new Error(r.error);
  return r.value;
};

describe("parseArgs: top level", () => {
  it("shows help for no arguments, --help, -h and help", () => {
    for (const argv of [[], ["--help"], ["-h"], ["help"]]) expect(value(argv)).toEqual({ kind: "help" });
  });

  it("shows the version", () => {
    expect(value(["--version"])).toEqual({ kind: "version" });
    expect(value(["-v"])).toEqual({ kind: "version" });
  });

  it("rejects an unknown command without echoing it in full", () => {
    const r = parse(["x".repeat(200)]);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.length).toBeLessThan(80);
  });
});

describe("parseArgs: rls", () => {
  it("takes one or more paths and defaults to text, with a fix, failing on proven", () => {
    expect(value(["rls", "supabase/migrations"])).toEqual({
      kind: "rls",
      paths: ["supabase/migrations"],
      format: "text",
      out: null,
      fromAudit: null,
      database: { kind: "container" },
      proposeFix: true,
      failOn: "proven",
    });
    expect(value(["rls", "a.sql", "b.sql"])).toMatchObject({ paths: ["a.sql", "b.sql"] });
  });

  it("reads format flags and refuses both at once", () => {
    expect(value(["rls", "m", "--json"])).toMatchObject({ format: "json" });
    expect(value(["rls", "--markdown", "m"])).toMatchObject({ format: "markdown" });
    expect(parse(["rls", "m", "--json", "--markdown"]).ok).toBe(false);
  });

  it("reads value flags in any position", () => {
    expect(value(["rls", "--out", "o", "m", "--from-audit", "a.json", "--fail-on", "none", "--no-fix"])).toMatchObject({
      paths: ["m"],
      out: "o",
      fromAudit: "a.json",
      failOn: "none",
      proposeFix: false,
    });
  });

  it("needs a path", () => {
    expect(parse(["rls"])).toEqual({ ok: false, error: "rls needs a migrations directory or at least one .sql file" });
    expect(parse(["rls", "--json"]).ok).toBe(false);
  });

  it("rejects a flag without a value, or whose value is another flag", () => {
    expect(parse(["rls", "m", "--out"]).ok).toBe(false);
    expect(parse(["rls", "m", "--out", "--json"]).ok).toBe(false);
  });

  it("rejects unknown options and bad --fail-on values", () => {
    expect(parse(["rls", "m", "--frobnicate"]).ok).toBe(false);
    expect(parse(["rls", "m", "--fail-on", "sometimes"]).ok).toBe(false);
  });

  it("never picks up a database URL from the environment on its own", () => {
    expect(value(["rls", "m"], { PROOF_AUDIT_DATABASE_URL: "postgres://env", DATABASE_URL: "postgres://other" })).toMatchObject({ database: { kind: "container" } });
  });

  it("reads a URL given on the command line", () => {
    expect(value(["rls", "m", "--database-url", "postgres://u@127.0.0.1/d"])).toMatchObject({ database: { kind: "url", url: "postgres://u@127.0.0.1/d", fromEnv: null, yesThisIsThrowaway: false } });
  });

  it("reads the URL from the environment variable named by --database-url-env", () => {
    expect(value(["rls", "m", "--database-url-env", "MY_URL"], { MY_URL: "postgres://u@127.0.0.1/d" })).toMatchObject({ database: { kind: "url", url: "postgres://u@127.0.0.1/d", fromEnv: "MY_URL" } });
  });

  it("refuses --database-url-env when the variable is unset or empty, and both URL flags at once", () => {
    expect(parse(["rls", "m", "--database-url-env", "MY_URL"], {}).ok).toBe(false);
    expect(parse(["rls", "m", "--database-url-env", "MY_URL"], { MY_URL: "" }).ok).toBe(false);
    expect(parse(["rls", "m", "--database-url", "postgres://a", "--database-url-env", "X"], { X: "postgres://b" }).ok).toBe(false);
  });

  it("records --yes-this-is-throwaway and refuses it without a URL", () => {
    expect(value(["rls", "m", "--database-url", "postgres://u@127.0.0.1/d", "--yes-this-is-throwaway"])).toMatchObject({ database: { yesThisIsThrowaway: true } });
    expect(parse(["rls", "m", "--yes-this-is-throwaway"]).ok).toBe(false);
  });
});

describe("parseArgs: verify", () => {
  it("takes a proofs file", () => {
    expect(value(["verify", "proofs.jsonl"])).toEqual({ kind: "verify", proofs: "proofs.jsonl", against: null, root: null, database: { kind: "container" } });
  });

  it("takes the same database options as rls", () => {
    expect(value(["verify", "p", "--database-url-env", "U", "--yes-this-is-throwaway"], { U: "postgres://u@localhost/d" })).toMatchObject({ database: { kind: "url", fromEnv: "U", yesThisIsThrowaway: true } });
    expect(value(["verify", "p"], { PROOF_AUDIT_DATABASE_URL: "postgres://env" })).toMatchObject({ database: { kind: "container" } });
  });

  it("takes every path after --against up to the next flag", () => {
    expect(value(["verify", "p.jsonl", "--against", "a.sql", "b", "--root", "r"])).toMatchObject({ against: ["a.sql", "b"], root: "r" });
  });

  it("needs the proofs file, exactly one, and a path after --against", () => {
    expect(parse(["verify"]).ok).toBe(false);
    expect(parse(["verify", "a", "b"]).ok).toBe(false);
    expect(parse(["verify", "a", "--against"]).ok).toBe(false);
    expect(parse(["verify", "a", "--nope"]).ok).toBe(false);
  });
});
