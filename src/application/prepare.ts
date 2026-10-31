import type { SeedTableResult, StatementError } from "../domain/analysis/types.js";
import { catalogToModel, parseCatalog } from "../domain/catalog/snapshot.js";
import { viewCountQueries, viewsOverProtectedTables, type SeedCounts, type ViewCounts } from "../domain/proof/plan.js";
import { qualifiedKey, type SchemaModel } from "../domain/schema/model.js";
import { planSeed } from "../domain/seed/plan.js";
import type { SqlStatement } from "../domain/sql/statement.js";
import { identitySeedStatements } from "../domain/supabase/shim.js";
import { scanForTampering, type TamperAttempt } from "../domain/integrity/attempts.js";
import { compareFingerprints, parseFingerprint, type Fingerprint } from "../domain/integrity/fingerprint.js";
import type { IntegrityViolation } from "../domain/analysis/types.js";
import { SandboxError, type Sandbox } from "./ports.js";

export interface Prepared {
  /** What the database holds after the migrations ran. */
  readonly model: SchemaModel;
  readonly serverVersion: string;
  readonly truncated: boolean;
  readonly migrationErrors: readonly StatementError[];
  readonly seeding: readonly SeedTableResult[];
  readonly seedCounts: ReadonlyMap<string, SeedCounts>;
  readonly viewCounts: ReadonlyMap<string, ViewCounts>;
  readonly warnings: readonly string[];
  /** The platform part of the sandbox before any migration ran. */
  readonly baseline: Fingerprint;
  /** Statements that touch the test environment, found in the migration text. */
  readonly attempts: readonly TamperAttempt[];
  /** For each statement, by `file:line`, whether the database accepted it. */
  readonly outcomes: ReadonlyMap<string, boolean>;
  /** Differences between the baseline and the platform after the migrations and the seed rows. */
  readonly platformChanges: readonly IntegrityViolation[];
}

/** Read the fingerprint and return what differs from the baseline. */
export async function checkPlatform(sandbox: Sandbox, baseline: Fingerprint, when: string): Promise<IntegrityViolation[]> {
  const parsed = parseFingerprint(await sandbox.fingerprint());
  if (!parsed.ok) throw new SandboxError(`the database returned a platform fingerprint the tool could not read: ${parsed.error}`);
  return compareFingerprints(baseline, parsed.value, when);
}

const oneLine = (text: string, max: number): string => {
  const flat = text.replace(/\s+/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
};

const toNumber = (value: number | string | null | undefined): number => {
  const n = typeof value === "string" ? Number(value) : (value ?? 0);
  return Number.isFinite(n) ? n : 0;
};

/**
 * Bring a fresh sandbox to the state every probe starts from: the user's migrations (each statement on its own,
 * failures recorded), the synthetic users, then one row per user in every table. The platform (roles, `auth.*`,
 * grants) was provisioned when the sandbox was created; its fingerprint is taken before and after the migrations.
 * Everything here is best effort and reported, never fatal.
 */
export async function prepareSandbox(sandbox: Sandbox, statements: readonly SqlStatement[]): Promise<Prepared> {
  const warnings: string[] = [];

  const first = parseFingerprint(await sandbox.fingerprint());
  if (!first.ok) throw new SandboxError(`the database returned a platform fingerprint the tool could not read: ${first.error}`);
  const baseline = first.value;

  const runnable = statements.filter((s) => s.kind === "sql");
  const outcomes = await sandbox.apply(runnable.map((s) => s.text));
  const migrationErrors: StatementError[] = [];
  const accepted = new Map<string, boolean>();
  runnable.forEach((s, i) => {
    const o = outcomes[i];
    if (o) accepted.set(`${s.file}:${s.line}`, (accepted.get(`${s.file}:${s.line}`) ?? false) || o.ok);
    if (o && !o.ok) {
      migrationErrors.push({ file: s.file, line: s.line, statement: oneLine(s.text, 120), sqlstate: o.sqlstate ?? "?????", message: oneLine(o.message ?? "", 300) });
    }
  });

  const userRows = await sandbox.apply(identitySeedStatements());
  if (userRows.some((o) => !o.ok)) warnings.push("The synthetic users could not be added to auth.users; rows that reference them cannot be seeded.");

  const platformChanges = await checkPlatform(sandbox, baseline, "after the migrations");

  const parsed = parseCatalog(await sandbox.catalog());
  if (!parsed.ok) throw new SandboxError(`the database returned a catalog the tool could not read: ${parsed.error}`);
  const snapshot = parsed.value;
  const model = catalogToModel(snapshot);
  if (snapshot.truncated) warnings.push("The database holds more tables than the cap allows; only the first ones were analysed.");

  const plan = planSeed(model);
  const seedOutcomes = await sandbox.applyFirstSuccess(plan.items.map((i) => i.attempts.map((a) => a.sql)));
  const counts = await sandbox.scalars(plan.items.map((i) => i.countSql));

  const seedCounts = new Map<string, SeedCounts>();
  const problems = new Map<string, string[]>();
  plan.items.forEach((item, i) => {
    const n = counts[i];
    const rows = n && n.ok ? toNumber(n.value) : 0;
    const prev = seedCounts.get(item.table) ?? { rowsUserA: 0, rowsUserB: 0 };
    seedCounts.set(item.table, item.identity === "user-b" ? { ...prev, rowsUserB: rows } : { ...prev, rowsUserA: rows });
    const outcome = seedOutcomes[i];
    if (rows === 0) {
      const why = outcome && !outcome.ok ? `${outcome.sqlstate ?? "?????"} ${oneLine(outcome.message ?? "", 160)}` : "the insert succeeded but no row carries this user's id";
      problems.set(item.table, [...(problems.get(item.table) ?? []), `${item.identity}: ${why}`]);
    }
  });
  const skipped = new Map<string, string[]>();
  for (const s of plan.skipped) skipped.set(s.table, [...(skipped.get(s.table) ?? []), s.reason]);

  const seeding: SeedTableResult[] = model.tables.map((t) => {
    const key = qualifiedKey(t.name);
    const c = seedCounts.get(key) ?? { rowsUserA: 0, rowsUserB: 0 };
    const own = plan.items.filter((i) => i.table === key);
    const issues = [...(problems.get(key) ?? []), ...(skipped.get(key) ?? [])];
    const wanted = own.length === 0 ? 1 : own.length;
    const got = own.length === 0 ? 0 : own.filter((i) => (i.identity === "user-b" ? c.rowsUserB : c.rowsUserA) > 0).length;
    const status: SeedTableResult["status"] = own.length === 0 ? "skipped" : got === wanted ? "ok" : got === 0 ? "failed" : "partial";
    return { table: key, rowsUserA: c.rowsUserA, rowsUserB: c.rowsUserB, status, reason: status === "ok" ? null : issues.join("; ") || null };
  });

  const viewCounts = new Map<string, ViewCounts>();
  for (const view of viewsOverProtectedTables(model)) {
    const q = viewCountQueries(view, model);
    const [total, a, b] = await sandbox.scalars([q.total, q.userA ?? "SELECT NULL", q.userB ?? "SELECT NULL"]);
    const val = (r: typeof total, present: boolean): number | null => (r && r.ok && present ? toNumber(r.value) : null);
    viewCounts.set(qualifiedKey(view.name), { total: val(total, true), ownedByUserA: val(a, q.userA !== null), ownedByUserB: val(b, q.userB !== null) });
  }

  return { model, serverVersion: snapshot.serverVersion, truncated: snapshot.truncated, migrationErrors, seeding, seedCounts, viewCounts, warnings, baseline, attempts: scanForTampering(statements), outcomes: accepted, platformChanges };
}
