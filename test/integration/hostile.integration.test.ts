import pg from "pg";
import { describe, expect, it } from "vitest";
import { analyzeRls } from "../../src/application/analyze.js";
import type { ProbeRun, Sandbox, SandboxProvider } from "../../src/application/ports.js";
import { verifyEvidence } from "../../src/application/verify.js";
import { encodeProofsJsonl, decodeProofsJsonl } from "../../src/domain/evidence/proofs.js";
import { sealProof } from "../../src/domain/proof/hash.js";
import { UrlSandboxProvider } from "../../src/infrastructure/postgres/url-provider.js";
import { analyze, clock, endpoint, haveDatabase, sqlFile, tool } from "./support.js";

/**
 * Hostile migrations, built at run time. Each one tries to make the tool report something the database did not do:
 * replace the code that decides a verdict, repoint name resolution, redefine the platform's `auth.*`, hide a table,
 * or escape the sandbox role. None of them may produce a false CLEAN or a false PROVEN.
 */
const OPEN_TABLE = "create table public.secrets (id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users (id), v text);\n";

const adminClient = async (database?: string): Promise<pg.Client> => {
  const e = endpoint();
  const client = new pg.Client({ host: e.host, port: e.port, user: e.user, ...(e.password === null ? {} : { password: e.password }), database: database ?? e.database, ssl: false });
  await client.connect();
  return client;
};

/** Run SQL as the real superuser in the newest sandbox database, to play a compromise the sandbox roles cannot cause. */
async function tamperAsAdmin(statements: readonly string[]): Promise<void> {
  const admin = await adminClient();
  try {
    const found = await admin.query("select datname from pg_database where datname like 'proof\\_audit\\_%' order by oid desc limit 1");
    const name = String(found.rows[0]?.datname);
    const db = await adminClient(name);
    try {
      for (const s of statements) await db.query(s);
    } finally {
      await db.end();
    }
  } finally {
    await admin.end();
  }
}

/** A provider whose sandbox runs `before` (as the superuser) just before the first batch of probes. */
function tamperBeforeProbes(statements: readonly string[]): SandboxProvider {
  const inner = new UrlSandboxProvider(endpoint());
  return {
    async create() {
      const created = await inner.create();
      const real = created.sandbox;
      let done = false;
      const sandbox: Sandbox = {
        apply: (s) => real.apply(s),
        applyFirstSuccess: (g) => real.applyFirstSuccess(g),
        scalars: (q) => real.scalars(q),
        catalog: () => real.catalog(),
        fingerprint: () => real.fingerprint(),
        fork: () => real.fork(),
        dispose: () => real.dispose(),
        run: async (probes: readonly ProbeRun[]) => {
          if (!done) {
            done = true;
            await tamperAsAdmin(statements);
          }
          return real.run(probes);
        },
      };
      return { sandbox, environment: created.environment };
    },
  };
}

const run = (provider: SandboxProvider, content: string) =>
  analyzeRls({ files: [sqlFile("m/001.sql", content)], loadWarnings: [], inputsComplete: true, audit: null, proposeFix: true, tool }, { provider, clock });

const verdict = (r: Awaited<ReturnType<typeof analyze>>, id: string) => r.proofs.find((p) => p.id === id)?.verdict;
const kinds = (r: Awaited<ReturnType<typeof analyze>>) => r.integrity.violations.map((v) => v.kind);

describe.skipIf(!haveDatabase)("hostile migrations cannot forge a verdict", () => {
  it("a replacement of the tool's own probe function is refused, flagged, and the open table is still observed as open", async () => {
    const r = await analyze([
      sqlFile(
        "m/001.sql",
        `create or replace function proof_audit.run_probe(p_role text, p_claims text, p_sql text) returns jsonb language sql as $$ select '{"ok":false,"sqlstate":"42501","message":"denied"}'::jsonb $$;\n${OPEN_TABLE}`,
      ),
    ]);
    expect(r.migrationErrors.map((e) => e.sqlstate)).toEqual(["3F000"]);
    expect(verdict(r, "public.secrets/anon-read")).toBe("PROVEN_VULNERABLE");
    expect(r.integrity.status).toBe("INTEGRITY_VIOLATION");
    expect(kinds(r)).toContain("targets-tool-internals");
    expect(r.findings.some((f) => f.tier === "CLEAN")).toBe(false);
    expect(r.findings.find((f) => f.subject === "public.secrets")?.tier).toBe("INCONCLUSIVE");
  });

  it("repointing the database search_path and shadowing the built-in functions the old harness called changes nothing", async () => {
    const r = await analyze([
      sqlFile(
        "m/001.sql",
        `create function public.set_config(text, text, boolean) returns text language sql as $$ select 'forged'::text $$;
create function public.jsonb_build_object(text, text, text, text) returns jsonb language sql as $$ select '{"ok":false,"sqlstate":"42501"}'::jsonb $$;
create function public."left"(text, int) returns text language sql as $$ select 'x'::text $$;
do $$ begin execute format('alter database %I set search_path = public, pg_catalog', current_database()); exception when others then null; end $$;
${OPEN_TABLE}`,
      ),
    ]);
    expect(verdict(r, "public.secrets/anon-read")).toBe("PROVEN_VULNERABLE");
    expect(verdict(r, "public.secrets/cross-read")).toBe("PROVEN_VULNERABLE");
    expect(kinds(r)).toContain("alters-protected-setting");
    expect(r.integrity.violations.filter((v) => v.kind === "platform-changed")).toEqual([]);
  });

  it("direct writes to the system catalog are refused", async () => {
    const r = await analyze([sqlFile("m/001.sql", `update pg_catalog.pg_proc set prosrc = 'select 1' where proname = 'set_config';\n${OPEN_TABLE}`)]);
    expect(r.migrationErrors.map((e) => e.sqlstate)).toEqual(["42501"]);
    expect(kinds(r)).toContain("catalog-write");
    expect(r.integrity.violations.find((v) => v.kind === "catalog-write")?.outcome).toBe("blocked");
    expect(verdict(r, "public.secrets/anon-read")).toBe("PROVEN_VULNERABLE");
  });

  it("redefining auth.uid() is refused: the platform keeps providing it, and the attempt is reported", async () => {
    const r = await analyze([
      sqlFile(
        "m/001.sql",
        `create or replace function auth.uid() returns uuid language sql as $$ select 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'::uuid $$;
create table public.docs (id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users (id));
alter table public.docs enable row level security;
create policy mine on public.docs for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());`,
      ),
    ]);
    expect(r.migrationErrors.map((e) => e.sqlstate)).toEqual(["42501"]);
    expect(r.integrity.violations[0]).toMatchObject({ kind: "redefines-platform-object", detail: "CREATE FUNCTION auth.uid", outcome: "blocked" });
    expect(verdict(r, "public.docs/cross-read")).toBe("NOT_REPRODUCED");
    expect(verdict(r, "public.docs/own-read")).toBe("ACCESS_OK");
    expect(r.findings.every((f) => f.tier === "INCONCLUSIVE")).toBe(true);
  });

  it.each([
    ["an event trigger", "create function public.noop() returns event_trigger language plpgsql as $$ begin end $$;\ncreate event trigger evil on ddl_command_end execute function public.noop();", "event-trigger"],
    ["session_replication_role for a role", "alter role anon set session_replication_role = replica;", "alters-protected-setting"],
    ["row_security for the database", "alter database postgres set row_security = off;", "alters-protected-setting"],
    ["ALTER SYSTEM", "alter system set search_path = 'evil';", "alters-protected-setting"],
    ["moving a table into an extension", "do $$ begin execute 'create table public.hidden (id int, v text)'; execute 'grant all on public.hidden to anon'; alter extension pgcrypto add table public.hidden; end $$;", "redefines-platform-object"],
  ])("%s is refused or reported, and the run is INTEGRITY_VIOLATION", async (_name, sql, kind) => {
    const r = await analyze([sqlFile("m/001.sql", `${sql}\n${OPEN_TABLE}`)]);
    expect(kinds(r)).toContain(kind);
    expect(r.integrity.status).toBe("INTEGRITY_VIOLATION");
    expect(r.findings.some((f) => f.tier === "CLEAN" || f.tier === "PROVEN")).toBe(false);
    expect(verdict(r, "public.secrets/anon-read")).toBe("PROVEN_VULNERABLE");
  });

  it("a table hidden with ALTER EXTENSION is still found and probed", async () => {
    const r = await analyze([
      sqlFile("m/001.sql", "do $$ begin execute 'create table public.hidden (id int, v text)'; execute 'grant all on public.hidden to anon'; end $$;\nalter extension pgcrypto add table public.hidden;"),
    ]);
    expect(r.migrationErrors.map((e) => e.sqlstate)).toEqual(["42501"]);
    expect(r.findings.map((f) => f.subject)).toContain("public.hidden");
    expect(verdict(r, "public.hidden/anon-read")).not.toBeUndefined();
  });
});

describe.skipIf(!haveDatabase)("the migration role is not a superuser", () => {
  const attempts: [string, string][] = [
    ["COPY ... PROGRAM", "copy (select 1) to program 'touch /tmp/proof-audit-pwned'"],
    ["COPY ... FROM PROGRAM", "create table public.t_in (x text); copy public.t_in from program 'id'"],
    ["COPY to a server file", "copy (select 1) to '/tmp/proof-audit-pwned'"],
    ["ALTER SYSTEM", "alter system set work_mem = '8MB'"],
    ["reading a server file", "select pg_read_file('/etc/passwd')"],
    ["listing a server directory", "select pg_ls_dir('/')"],
    ["lo_import of a server file", "select lo_import('/etc/passwd')"],
    ["lo_export to a server file", "select lo_export(0, '/tmp/proof-audit-pwned')"],
    ["an untrusted extension", "create extension dblink"],
    ["an untrusted language", "create extension plpython3u"],
    ["a C function", "create function public.evil() returns int language c as '/lib/x86_64-linux-gnu/libc.so.6', 'abs'"],
    ["a tablespace", "create tablespace evil location '/tmp'"],
    ["an event trigger", "create event trigger evil on ddl_command_end execute function pg_catalog.pg_event_trigger_ddl_commands()"],
    ["changing the superuser's password", `alter role "${endpoint().user}" password 'x'`],
    ["becoming the superuser", `set role "${endpoint().user}"`],
    ["session authorization", `set session authorization "${endpoint().user}"`],
    ["session_replication_role", "set session_replication_role = replica"],
    ["making itself a superuser", "alter role current_user superuser"],
    ["dropping another database", "drop database postgres"],
    ["reading password hashes", "select rolpassword from pg_authid limit 1"],
    ["terminating another session", "select pg_terminate_backend(pid) from pg_stat_activity where pid <> pg_backend_pid() and usename = current_user is not true"],
  ];

  it.each(attempts)("cannot use %s", async (_name, statement) => {
    const created = await new UrlSandboxProvider(endpoint()).create();
    try {
      const [outcome] = await created.sandbox.apply([statement]);
      expect(outcome?.ok, `${statement} must not succeed`).toBe(false);
    } finally {
      await created.sandbox.dispose();
    }
  });

  it("a SECURITY DEFINER function it creates runs with its own rights, not a superuser's, and cannot be handed to one", async () => {
    const created = await new UrlSandboxProvider(endpoint()).create();
    try {
      const out = await created.sandbox.apply([
        "create function public.whoami() returns text language sql security definer as $$ select current_setting('is_superuser') $$",
        `alter function public.whoami() owner to "${endpoint().user}"`,
      ]);
      expect(out.map((o) => o.ok)).toEqual([true, false]);
      expect(await created.sandbox.scalars(["select public.whoami()"])).toEqual([{ ok: true, value: "off" }]);
    } finally {
      await created.sandbox.dispose();
    }
  });

  it("everything it attempted left the platform as it was", async () => {
    const statements = attempts.map(([, s]) => s);
    const r = await analyze([sqlFile("m/001.sql", `${statements.join(";\n")};\n${OPEN_TABLE}`)]);
    expect(r.integrity.violations.filter((v) => v.kind === "platform-changed")).toEqual([]);
  });
});

describe.skipIf(!haveDatabase)("a compromised platform is detected, and the probes do not depend on it", () => {
  it("shadowed built-ins and a repointed search_path, installed by the superuser, change neither a verdict nor the report's honesty", async () => {
    const baseline = await analyze([sqlFile("m/001.sql", OPEN_TABLE)]);
    const r = await run(
      tamperBeforeProbes([
        "create schema evil",
        "create function evil.set_config(text, text, boolean) returns text language sql as $$ select 'forged'::text $$",
        "create function evil.jsonb_build_object(text, boolean, text, text, text, text) returns jsonb language sql as $$ select '{\"ok\":false,\"sqlstate\":\"42501\"}'::jsonb $$",
        "do $$ begin execute format('alter database %I set search_path = evil, public', current_database()); end $$",
      ]),
      OPEN_TABLE,
    );
    expect(r.proofs.map((p) => `${p.id}:${p.verdict}`)).toEqual(baseline.proofs.map((p) => `${p.id}:${p.verdict}`));
    expect(r.integrity.status).toBe("INTEGRITY_VIOLATION");
    expect(r.integrity.violations.map((v) => v.detail).join("\n")).toContain("setting database=current role=- changed (after the probes)");
    expect(r.findings.every((f) => f.tier === "INCONCLUSIVE")).toBe(true);
  });

  it("a replaced auth.uid() is detected by the fingerprint, not trusted", async () => {
    const r = await run(
      tamperBeforeProbes(["create or replace function auth.uid() returns uuid language sql as $$ select 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'::uuid $$"]),
      "create table public.docs (id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users (id));\nalter table public.docs enable row level security;\ncreate policy mine on public.docs for all to authenticated using (user_id = auth.uid());",
    );
    expect(r.integrity.violations.map((v) => v.detail)).toContain("function auth.uid() changed (after the probes)");
    expect(r.findings.every((f) => f.tier === "INCONCLUSIVE")).toBe(true);
  });

  it("an event trigger created by the superuser is detected", async () => {
    const r = await run(tamperBeforeProbes(["create function public.noop() returns event_trigger language plpgsql as $$ begin end $$", "create event trigger evil on ddl_command_end execute function public.noop()"]), OPEN_TABLE);
    expect(r.integrity.violations.map((v) => v.detail).join("\n")).toContain("event trigger evil appeared");
  });
});

describe.skipIf(!haveDatabase)("verdicts come from what the database did", () => {
  it("a rule that swallows updates and deletes is observed: those probes are refused, and the open read is still proven", async () => {
    const r = await analyze([
      sqlFile("m/001.sql", `${OPEN_TABLE}create rule no_update as on update to public.secrets do instead nothing;\ncreate rule no_delete as on delete to public.secrets do instead nothing;\n`),
    ]);
    expect(verdict(r, "public.secrets/anon-update")).toBe("NOT_REPRODUCED");
    expect(verdict(r, "public.secrets/anon-delete")).toBe("NOT_REPRODUCED");
    expect(verdict(r, "public.secrets/anon-read")).toBe("PROVEN_VULNERABLE");
    expect(r.integrity.status).toBe("INTACT");
  });

  it("a trigger that raises permission denied for the anonymous role is a real denial and is recorded as one", async () => {
    const r = await analyze([
      sqlFile(
        "m/001.sql",
        `${OPEN_TABLE}create function public.deny_anon() returns trigger language plpgsql as $$ begin if current_user = 'anon' then raise exception 'no' using errcode = '42501'; end if; return new; end $$;
create trigger t before insert on public.secrets for each row execute function public.deny_anon();`,
      ),
    ]);
    expect(verdict(r, "public.secrets/anon-insert")).toBe("NOT_REPRODUCED");
    expect(verdict(r, "public.secrets/cross-insert")).toBe("PROVEN_VULNERABLE");
  });

  it("a trigger that sets the reply setting itself, or raises the tool's own error code, cannot fake an observation", async () => {
    const r = await analyze([
      sqlFile(
        "m/001.sql",
        `${OPEN_TABLE}create function public.fake() returns trigger language plpgsql as $$ begin perform pg_catalog.set_config('proof_audit.reply', '{"ok": false, "sqlstate": "42501", "message": "denied"}', false); raise exception 'x' using errcode = 'PA000'; end $$;
create trigger t before insert on public.secrets for each row execute function public.fake();`,
      ),
    ]);
    const p = r.proofs.find((x) => x.id === "public.secrets/anon-insert");
    expect(p?.verdict).toBe("INCONCLUSIVE");
    expect(p?.observation.status).toBe("not-run");
  });
});

describe.skipIf(!haveDatabase)("loopback mode is refused on a server that is not obviously a throwaway", () => {
  it("refuses a server that holds another database, unless told it is a throwaway, and leaves nothing behind", async () => {
    const other = `pa_other_${Date.now().toString(36)}`;
    const admin = await adminClient();
    try {
      await admin.query(`create database ${other}`);
      await expect(new UrlSandboxProvider(endpoint()).create()).rejects.toThrow(/holds other databases \(.*pa_other_/);
      const ok = await new UrlSandboxProvider(endpoint(), { yesThisIsThrowaway: true }).create();
      await ok.sandbox.dispose();
      const leftovers = await admin.query("select count(*)::int as n from pg_roles where rolname like 'pa\\_migrator\\_%' or rolname like 'pa\\_prober\\_%'");
      expect(leftovers.rows[0]?.n).toBe(0);
    } finally {
      await admin.query(`drop database if exists ${other}`);
      await admin.end();
    }
  });

  it("creates its two roles per run and removes them with the database", async () => {
    const admin = await adminClient();
    try {
      const created = await new UrlSandboxProvider(endpoint()).create();
      const during = await admin.query("select count(*)::int as n from pg_roles where rolname like 'pa\\_migrator\\_%' or rolname like 'pa\\_prober\\_%'");
      expect(during.rows[0]?.n).toBe(2);
      await created.sandbox.dispose();
      const after = await admin.query("select count(*)::int as n from pg_roles where rolname like 'pa\\_migrator\\_%' or rolname like 'pa\\_prober\\_%'");
      expect(after.rows[0]?.n).toBe(0);
    } finally {
      await admin.end();
    }
  });
});

describe.skipIf(!haveDatabase)("evidence that carries SQL is not executed", () => {
  it("forged evidence with a valid hash and a COPY ... PROGRAM fix is refused before anything runs", async () => {
    const report = await analyze([sqlFile("m/001.sql", OPEN_TABLE)]);
    const meta = { tool, image: report.environment.image, inputs: report.inputs, fixStatements: ["COPY (SELECT 1) TO PROGRAM 'touch /tmp/proof-audit-pwned'"], fixSha256: null };
    const proofs = [...report.proofs, ...(report.verification?.after ?? [])].map(({ hash: _h, ...p }) => sealProof(p));
    const text = encodeProofsJsonl(meta, proofs);
    expect(decodeProofsJsonl(text).ok).toBe(true);
    const statements: string[] = [];
    const inner = new UrlSandboxProvider(endpoint());
    const provider: SandboxProvider = {
      async create() {
        const created = await inner.create();
        const apply = created.sandbox.apply.bind(created.sandbox);
        created.sandbox.apply = async (s) => {
          statements.push(...s);
          return apply(s);
        };
        return created;
      },
    };
    const r = await verifyEvidence({ proofsText: text, readInput: async (p) => ({ path: p, content: OPEN_TABLE, bytes: OPEN_TABLE.length }), against: null }, { provider, clock });
    expect(r.status).toBe("invalid");
    expect(statements.some((s) => s.includes("PROGRAM"))).toBe(false);
  });
});

describe.skipIf(!haveDatabase)("examples/hostile-app", () => {
  it("is refused on every count, changes no verdict and ends INTEGRITY_VIOLATION", async () => {
    const { loadSqlInputs } = await import("../../src/infrastructure/fs/files.js");
    const { files } = await loadSqlInputs(["examples/hostile-app/supabase/migrations"], process.cwd());
    const r = await analyze(files);
    expect(r.integrity.status).toBe("INTEGRITY_VIOLATION");
    expect(new Set(kinds(r))).toEqual(new Set(["redefines-platform-object", "targets-tool-internals", "alters-protected-setting", "event-trigger"]));
    expect(r.integrity.violations.every((v) => v.outcome === "blocked")).toBe(true);
    expect(r.migrationErrors.map((e) => e.line)).toEqual([5, 9, 10, 13, 14]);
    expect(verdict(r, "public.customers/anon-read")).toBe("PROVEN_VULNERABLE");
    expect(r.findings.map((f) => f.tier)).toEqual(["INCONCLUSIVE"]);
    expect(r.fix).toBeNull();
  });
});
