import { describe, expect, it } from "vitest";
import { findMention, locateStatic, locateTableCause, locateViewCause, type SourceMap } from "../../../src/domain/interchange/locate.js";
import { tableRootCauses, viewRootCauses } from "../../../src/domain/interchange/rootcause.js";
import { parseMigrations } from "../../../src/domain/sql/parser.js";

function mapOf(sql: string, path = "m.sql"): SourceMap & { readonly model: ReturnType<typeof parseMigrations>["model"] } {
  const parsed = parseMigrations([{ path, content: sql }]);
  return { statements: parsed.statements, sources: parsed.sources, model: parsed.model };
}

const steps = (located: { trace: readonly { kind: string; line: number }[] } | null): [string, number][] => (located === null ? [] : located.trace.map((t) => [t.kind, t.line]));

describe("findMention", () => {
  const { statements } = mapOf("-- c\nselect 1;\ncomment on table public.Odd is 'x';\ncomment on table \"Quoted Name\" is 'y';\ncreate index on public.plain (a);\n");

  it("finds the first statement that names every identifier, case-folding unquoted words", () => {
    expect(findMention(statements, ["plain"])).toEqual({ file: "m.sql", line: 5 });
    expect(findMention(statements, ["odd"])).toEqual({ file: "m.sql", line: 3 });
    expect(findMention(statements, ["ODD"])).toEqual({ file: "m.sql", line: 3 });
  });

  it("matches a quoted identifier exactly, with its case", () => {
    expect(findMention(statements, ["Quoted Name"])).toEqual({ file: "m.sql", line: 4 });
    expect(findMention(statements, ["quoted name"])).toBeNull();
  });

  it("needs all the names in one statement, ignores string literals and gives up when none matches", () => {
    expect(findMention(statements, ["plain", "odd"])).toBeNull();
    expect(findMention(statements, ["x"])).toBeNull();
    expect(findMention(statements, ["missing"])).toBeNull();
  });

  it("skips statements that are not SQL", () => {
    const parsed = parseMigrations([{ path: "m.sql", content: "\\connect other\nselect 1;\n" }]);
    expect(findMention(parsed.statements, ["connect"])).toBeNull();
  });
});

describe("locateTableCause", () => {
  const sql = `create table public.t (id uuid primary key, user_id uuid references auth.users (id));
alter table public.t enable row level security;
create policy "A" on public.t for select using (true);
create policy b on public.t for all to authenticated using (auth.role() = 'authenticated');
`;
  const m = mapOf(sql);
  const table = m.model.tables[0];
  if (table === undefined) throw new Error("no table");
  const causes = tableRootCauses(table);

  it("goes from the policy through the switch to the table for an always-true policy", () => {
    const cause = causes.find((c) => c.kind === "policy-always-true");
    expect(steps(locateTableCause(m, table, cause ?? null, false))).toEqual([["entrypoint", 3], ["propagation", 2], ["sink", 1]]);
  });

  it("lists every policy as part of a missing owner comparison", () => {
    const cause = causes.find((c) => c.kind === "owner-not-compared");
    const located = locateTableCause(m, table, cause ?? null, false);
    expect(steps(located)).toEqual([["entrypoint", 2], ["propagation", 3], ["propagation", 4], ["sink", 1]]);
    expect(located?.anchor).toEqual({ file: "m.sql", line: 2 });
  });

  it("starts at the table when row level security is off, with the last switch as the propagation", () => {
    const off = mapOf("create table public.t (id uuid primary key);\nalter table public.t disable row level security;\n");
    const offTable = off.model.tables[0];
    const cause = tableRootCauses(offTable ?? table).find((c) => c.kind === "rls-disabled");
    expect(steps(locateTableCause(off, offTable ?? table, cause ?? null, false))).toEqual([["entrypoint", 1], ["propagation", 2], ["sink", 1]]);
    const never = mapOf("create table public.t (id uuid primary key);\n");
    const neverTable = never.model.tables[0] ?? table;
    expect(steps(locateTableCause(never, neverTable, tableRootCauses(neverTable)[0] ?? null, false))).toEqual([["entrypoint", 1], ["sink", 1]]);
  });

  it("falls back to the table declaration when the statement of a policy cannot be found", () => {
    const other = mapOf("create table public.t (id uuid primary key, user_id uuid);\n");
    const cause = causes.find((c) => c.kind === "policy-always-true");
    const located = locateTableCause(other, table, cause ?? null, false);
    expect(steps(located)).toEqual([["entrypoint", 1], ["sink", 1]]);
    expect(located?.trace[0]?.description).toContain("could not be found");
  });

  it("finds a policy statement the reader did not index by the names it mentions", () => {
    const hidden = mapOf("create table public.t (id uuid primary key);\ndo $$ begin null; end $$;\ncomment on policy \"A\" on public.t is 'x';\n");
    const cause = causes.find((c) => c.kind === "policy-always-true");
    expect(steps(locateTableCause(hidden, table, cause ?? null, false))[0]).toEqual(["entrypoint", 3]);
  });

  it("is one sink for what no static cause explains, and for a table that could not be tested", () => {
    expect(steps(locateTableCause(m, table, null, false))).toEqual([["sink", 1]]);
    expect(locateTableCause(m, table, null, true)?.trace[0]?.description).toContain("could not be fully tested");
  });

  it("is null when no statement names the table", () => {
    expect(locateTableCause(mapOf("select 1;\n"), table, null, false)).toBeNull();
  });
});

describe("locateViewCause", () => {
  const sql = `create table public.base (id uuid primary key, user_id uuid references auth.users (id));
alter table public.base enable row level security;
create table public.other (id uuid primary key);
alter table public.other enable row level security;
create view public.v as select b.id from public.base b join public.other o on o.id = b.id;
`;
  const m = mapOf(sql);
  const view = m.model.views[0];
  if (view === undefined) throw new Error("no view");
  const model = { tables: m.model.tables, views: m.model.views };
  const cause = viewRootCauses(view, model)[0] ?? null;

  it("goes from the view to the protected tables it reads", () => {
    expect(cause?.kind).toBe("view-bypasses-rls");
    expect(steps(locateViewCause(m, view, model, cause, false))).toEqual([["entrypoint", 5], ["propagation", 1], ["sink", 3]]);
  });

  it("is one sink for an unexplained or untested view", () => {
    expect(steps(locateViewCause(m, view, model, null, false))).toEqual([["sink", 5]]);
    expect(locateViewCause(m, view, model, null, true)?.trace[0]?.description).toContain("could not be fully tested");
  });

  it("skips a protected table that no statement declares and is null when the view itself is not found", () => {
    const first = m.model.tables[0];
    if (first === undefined) throw new Error("no table");
    const dependent = { ...view, dependsOn: [{ schema: "public", name: "hidden" }] };
    const hidden = { tables: [{ ...first, name: { schema: "public", name: "hidden" } }], views: [dependent] };
    expect(steps(locateViewCause(m, dependent, hidden, cause, false))).toEqual([["entrypoint", 5]]);
    expect(locateViewCause(mapOf("select 1;\n"), view, model, cause, false)).toBeNull();
  });
});

describe("locateStatic", () => {
  const m = mapOf("create table public.docs (id uuid primary key);\ncreate policy \"Owner write\" on public.docs for update using (true);\n");

  it("starts at the flagged policy and ends at the table", () => {
    expect(steps(locateStatic(m, "public.docs", "Owner write", "flagged"))).toEqual([["entrypoint", 2], ["sink", 1]]);
  });

  it("starts at the table when the finding names no policy or the policy is not found", () => {
    expect(steps(locateStatic(m, "public.docs", null, "flagged"))).toEqual([["entrypoint", 1], ["sink", 1]]);
    expect(steps(locateStatic(m, "public.docs", "Missing", "flagged"))).toEqual([["entrypoint", 1], ["sink", 1]]);
  });

  it("is null for a table no statement names", () => {
    expect(locateStatic(m, "public.ghost", null, "flagged")).toBeNull();
  });
});
