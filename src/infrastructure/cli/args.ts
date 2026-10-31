import { err, ok, type Result } from "../../domain/result.js";

export type Format = "text" | "json" | "markdown";

export type Command =
  | { readonly kind: "help" }
  | { readonly kind: "version" }
  | {
      readonly kind: "rls";
      readonly paths: readonly string[];
      readonly format: Format;
      readonly out: string | null;
      readonly fromAudit: string | null;
      readonly databaseUrl: string | null;
      readonly proposeFix: boolean;
      readonly failOn: "proven" | "none";
    }
  | {
      readonly kind: "verify";
      readonly proofs: string;
      readonly against: readonly string[] | null;
      readonly root: string | null;
      readonly databaseUrl: string | null;
    };

export const USAGE = `proof-audit: prove Supabase row-level-security holes against a throwaway local database.

usage:
  proof-audit rls <migrations-dir | file.sql...> [options]
  proof-audit verify <proofs.jsonl> [options]

rls options:
  --json                  print the report as JSON
  --markdown              print the report as Markdown
  --out <dir>             also write report.md, report.json, proofs.jsonl,
                          verification-contract.json and fix.sql into <dir>
  --from-audit <file>     JSON report of the saas-audit static auditor: prioritise its tables
                          and show which of its findings were proven
  --no-fix                do not propose or verify a fix
  --fail-on <proven|none> exit 1 when something was proven (default) or never
  --database-url <url>    use a Postgres server you started on this machine (loopback only)
                          instead of a throwaway container; also read from PROOF_AUDIT_DATABASE_URL

verify options:
  --against <paths...>    replay the recorded probes against these migrations (the fix applied?)
  --root <dir>            resolve the recorded input paths from <dir> (default: current directory)
  --database-url <url>    as above

other: --help, --version

exit codes: 0 ok, 1 holes proven (rls) or evidence not reproduced (verify), 2 usage or bad input,
3 the sandbox could not run, the run was incomplete, or the inputs changed since the evidence.
`;

function value(args: readonly string[], i: number, flag: string): Result<string, string> {
  const v = args[i + 1];
  return v === undefined || v.startsWith("--") ? err(`${flag} needs a value`) : ok(v);
}

export function parseArgs(argv: readonly string[], env: Readonly<Record<string, string | undefined>>): Result<Command, string> {
  const [sub, ...rest] = argv;
  if (sub === undefined || sub === "--help" || sub === "-h" || sub === "help") return ok({ kind: "help" });
  if (sub === "--version" || sub === "-v") return ok({ kind: "version" });
  const envUrl = env.PROOF_AUDIT_DATABASE_URL && env.PROOF_AUDIT_DATABASE_URL !== "" ? env.PROOF_AUDIT_DATABASE_URL : null;

  if (sub === "rls") {
    const paths: string[] = [];
    let format: Format = "text";
    let out: string | null = null;
    let fromAudit: string | null = null;
    let databaseUrl = envUrl;
    let proposeFix = true;
    let failOn: "proven" | "none" = "proven";
    for (let i = 0; i < rest.length; i++) {
      const a = rest[i] as string;
      if (a === "--json" || a === "--markdown") {
        const next: Format = a === "--json" ? "json" : "markdown";
        if (format !== "text" && format !== next) return err("choose one of --json and --markdown");
        format = next;
      } else if (a === "--no-fix") proposeFix = false;
      else if (a === "--out" || a === "--from-audit" || a === "--database-url" || a === "--fail-on") {
        const v = value(rest, i, a);
        if (!v.ok) return v;
        i += 1;
        if (a === "--out") out = v.value;
        else if (a === "--from-audit") fromAudit = v.value;
        else if (a === "--database-url") databaseUrl = v.value;
        else if (v.value === "proven" || v.value === "none") failOn = v.value;
        else return err("--fail-on takes proven or none");
      } else if (a.startsWith("-")) return err(`unknown option ${a.slice(0, 40)}`);
      else paths.push(a);
    }
    if (paths.length === 0) return err("rls needs a migrations directory or at least one .sql file");
    return ok({ kind: "rls", paths, format, out, fromAudit, databaseUrl, proposeFix, failOn });
  }

  if (sub === "verify") {
    let proofs: string | null = null;
    let against: string[] | null = null;
    let root: string | null = null;
    let databaseUrl = envUrl;
    for (let i = 0; i < rest.length; i++) {
      const a = rest[i] as string;
      if (a === "--against") {
        against = [];
        while (i + 1 < rest.length && !(rest[i + 1] as string).startsWith("--")) {
          against.push(rest[i + 1] as string);
          i += 1;
        }
        if (against.length === 0) return err("--against needs at least one path");
      } else if (a === "--root" || a === "--database-url") {
        const v = value(rest, i, a);
        if (!v.ok) return v;
        i += 1;
        if (a === "--root") root = v.value;
        else databaseUrl = v.value;
      } else if (a.startsWith("-")) return err(`unknown option ${a.slice(0, 40)}`);
      else if (proofs === null) proofs = a;
      else return err("verify takes one proofs.jsonl file");
    }
    if (proofs === null) return err("verify needs a proofs.jsonl file");
    return ok({ kind: "verify", proofs, against, root, databaseUrl });
  }
  return err(`unknown command ${sub.slice(0, 40)}`);
}
