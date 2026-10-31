import type {
  AnalysisReport,
  AnalysisSummary,
  Cause,
  Finding,
  SubjectVerification,
} from "../../src/domain/analysis/types.js";
import { sealProof } from "../../src/domain/proof/hash.js";
import type { Proof, ProbeKind, ProbeObservation, Phase, Verdict } from "../../src/domain/proof/types.js";
import type { ClientRole, Command } from "../../src/domain/schema/model.js";

interface KindInfo {
  readonly intent: "exploit" | "legitimate";
  readonly command: Command;
  readonly actor: "anon" | "user-a";
  readonly role: ClientRole;
  readonly title: string;
}

const KINDS: Readonly<Record<ProbeKind, KindInfo>> = {
  "anon-read": { intent: "exploit", command: "select", actor: "anon", role: "anon", title: "Anonymous visitor reads rows" },
  "anon-insert": { intent: "exploit", command: "insert", actor: "anon", role: "anon", title: "Anonymous visitor inserts a row" },
  "anon-update": { intent: "exploit", command: "update", actor: "anon", role: "anon", title: "Anonymous visitor changes rows" },
  "anon-delete": { intent: "exploit", command: "delete", actor: "anon", role: "anon", title: "Anonymous visitor deletes rows" },
  "cross-read": { intent: "exploit", command: "select", actor: "user-a", role: "authenticated", title: "Signed-in user reads another user's rows" },
  "cross-insert": { intent: "exploit", command: "insert", actor: "user-a", role: "authenticated", title: "Signed-in user inserts a row for another user" },
  "null-owner-insert": { intent: "exploit", command: "insert", actor: "user-a", role: "authenticated", title: "Signed-in user inserts a row without owner" },
  "cross-update": { intent: "exploit", command: "update", actor: "user-a", role: "authenticated", title: "Signed-in user changes another user's rows" },
  "cross-delete": { intent: "exploit", command: "delete", actor: "user-a", role: "authenticated", title: "Signed-in user deletes another user's rows" },
  "reassign-owner": { intent: "exploit", command: "update", actor: "user-a", role: "authenticated", title: "Signed-in user hands own row to someone else" },
  "view-read-anon": { intent: "exploit", command: "select", actor: "anon", role: "anon", title: "Anonymous visitor reads the view" },
  "view-read-cross": { intent: "exploit", command: "select", actor: "user-a", role: "authenticated", title: "Signed-in user reads other users' rows through the view" },
  "view-read-own": { intent: "legitimate", command: "select", actor: "user-a", role: "authenticated", title: "Signed-in user reads own rows through the view" },
  "own-read": { intent: "legitimate", command: "select", actor: "user-a", role: "authenticated", title: "Signed-in user reads own rows" },
  "own-insert": { intent: "legitimate", command: "insert", actor: "user-a", role: "authenticated", title: "Signed-in user inserts own row" },
  "own-update": { intent: "legitimate", command: "update", actor: "user-a", role: "authenticated", title: "Signed-in user changes own rows" },
  "own-delete": { intent: "legitimate", command: "delete", actor: "user-a", role: "authenticated", title: "Signed-in user deletes own rows" },
};

const USER_A = "00000000-0000-4000-8000-00000000000a";

interface ProofSpec {
  readonly subject: string;
  readonly kind: ProbeKind;
  readonly sql: string;
  readonly observation: ProbeObservation;
  readonly verdict: Verdict;
  readonly reason: string;
  readonly phase?: Phase;
  readonly targetRows?: number | null;
  readonly subjectKind?: "table" | "view";
  readonly id?: string;
  readonly title?: string;
}

export function proof(spec: ProofSpec): Proof {
  const info = KINDS[spec.kind];
  return sealProof({
    id: spec.id ?? `${spec.subject}/${spec.kind}`,
    subject: spec.subject,
    subjectKind: spec.subjectKind ?? "table",
    kind: spec.kind,
    intent: info.intent,
    command: info.command,
    actor: info.actor,
    role: info.role,
    claims: info.actor === "anon" ? '{"role":"anon"}' : `{"role":"authenticated","sub":"${USER_A}"}`,
    sql: spec.sql,
    title: spec.title ?? info.title,
    targetRows: spec.targetRows ?? null,
    observation: spec.observation,
    verdict: spec.verdict,
    reason: spec.reason,
    phase: spec.phase ?? "before",
  });
}

function finding(partial: Partial<Finding> & Pick<Finding, "id" | "subject" | "tier" | "severity" | "title" | "attackerCan">): Finding {
  return {
    subjectKind: "table",
    causes: [],
    provenBy: [],
    notReproduced: [],
    inconclusive: [],
    fixStatus: "not-needed",
    fixNote: "",
    ...partial,
  };
}

const SHA_A = "a".repeat(64);
const SHA_B = "b".repeat(64);

function baseReport(over: Partial<AnalysisReport> & Pick<AnalysisReport, "summary" | "findings" | "proofs">): AnalysisReport {
  return {
    tool: { name: "proof-audit", version: "0.1.0" },
    inputs: [{ path: "supabase/migrations/001_init.sql", sha256: SHA_A, bytes: 1204 }],
    environment: { mode: "docker", image: "postgres:16.3@sha256:0123456789abcdef", postgresVersion: "16.3" },
    complete: true,
    seeding: [],
    fix: null,
    verification: null,
    audit: null,
    migrationErrors: [],
    warnings: [],
    notChecked: ["Storage bucket policies", "Edge functions and webhooks", "Anything outside the SQL you gave us"],
    ...over,
  };
}

const summary = (s: Omit<AnalysisSummary, never>): AnalysisSummary => s;

/** (a) Vulnerable app: every tier, fix plan, PARTIAL check, audit correlation, migration errors. */
export function vulnerableReport(): AnalysisReport {
  const rlsOff: Cause = { code: "rls-disabled", text: "Row level security is switched off on public.notes, so the public key can read and write every row." };
  const proofs: Proof[] = [
    proof({
      subject: "public.notes",
      kind: "anon-read",
      sql: "select * from public.notes",
      observation: { status: "rows", rows: 3 },
      targetRows: 3,
      verdict: "PROVEN_VULNERABLE",
      reason: "The anonymous role read seeded rows.",
    }),
    proof({
      subject: "public.notes",
      kind: "anon-insert",
      sql: "insert into public.notes (id, user_id, body)\nvalues (gen_random_uuid(), '00000000-0000-4000-8000-00000000000a', 'x')",
      observation: { status: "rows", rows: 1 },
      verdict: "PROVEN_VULNERABLE",
      reason: "The anonymous role inserted a row.",
    }),
    proof({
      subject: "public.notes",
      kind: "cross-delete",
      sql: "delete from public.notes where user_id = '00000000-0000-4000-8000-00000000000b'",
      observation: { status: "rows", rows: 0 },
      targetRows: 2,
      verdict: "NOT_REPRODUCED",
      reason: "No rows of the other user were deleted.",
    }),
    proof({
      subject: "public.notes",
      kind: "own-read",
      sql: "select * from public.notes where user_id = '00000000-0000-4000-8000-00000000000a'",
      observation: { status: "rows", rows: 2 },
      targetRows: 2,
      verdict: "ACCESS_OK",
      reason: "The user can read their own rows.",
    }),
    proof({
      subject: "public.profiles",
      kind: "cross-read",
      sql: "select * from public.profiles",
      observation: { status: "rows", rows: 4 },
      targetRows: 2,
      verdict: "PROVEN_VULNERABLE",
      reason: "The signed-in user read rows owned by someone else.",
    }),
    proof({
      subject: "public.profiles",
      kind: "anon-read",
      sql: "select * from public.profiles",
      observation: { status: "error", sqlstate: "42501", message: "permission denied for table profiles" },
      verdict: "NOT_REPRODUCED",
      reason: "The database refused the anonymous read.",
    }),
    proof({
      subject: "public.v_user_emails",
      subjectKind: "view",
      kind: "view-read-anon",
      sql: "select * from public.v_user_emails",
      observation: { status: "rows", rows: 2 },
      verdict: "PROVEN_VULNERABLE",
      reason: "The anonymous role read rows through the view.",
    }),
    proof({
      subject: "public.audit_log",
      kind: "anon-read",
      sql: "select * from public.audit_log",
      observation: { status: "not-run", reason: "the table could not be seeded" },
      verdict: "INCONCLUSIVE",
      reason: "No rows existed to read.",
    }),
  ];
  const after: Proof[] = [
    proof({
      subject: "public.notes",
      kind: "anon-read",
      sql: "select * from public.notes",
      observation: { status: "rows", rows: 0 },
      targetRows: 3,
      verdict: "NOT_REPRODUCED",
      reason: "The anonymous role read nothing.",
      phase: "after",
    }),
    proof({
      subject: "public.notes",
      kind: "anon-insert",
      sql: "insert into public.notes (id, user_id, body)\nvalues (gen_random_uuid(), '00000000-0000-4000-8000-00000000000a', 'x')",
      observation: { status: "error", sqlstate: "42501", message: 'new row violates row-level security policy for table "notes"' },
      verdict: "NOT_REPRODUCED",
      reason: "The database refused the insert.",
      phase: "after",
    }),
    proof({
      subject: "public.notes",
      kind: "own-read",
      sql: "select * from public.notes where user_id = '00000000-0000-4000-8000-00000000000a'",
      observation: { status: "rows", rows: 2 },
      targetRows: 2,
      verdict: "ACCESS_OK",
      reason: "The user can still read their own rows.",
      phase: "after",
    }),
    proof({
      subject: "public.profiles",
      kind: "cross-read",
      sql: "select * from public.profiles",
      observation: { status: "rows", rows: 4 },
      targetRows: 2,
      verdict: "PROVEN_VULNERABLE",
      reason: "The signed-in user still reads rows owned by someone else.",
      phase: "after",
    }),
  ];
  const subjects: SubjectVerification[] = [
    {
      subject: "public.notes",
      status: "VERIFIED",
      closed: ["public.notes/anon-read", "public.notes/anon-insert"],
      stillProven: [],
      broken: [],
      unresolved: [],
      reason: "Both attacks fail and the owner can still read their rows.",
    },
    {
      subject: "public.profiles",
      status: "STILL_VULNERABLE",
      closed: [],
      stillProven: ["public.profiles/cross-read"],
      broken: [],
      unresolved: [],
      reason: "The proposed policy does not compare the owner column.",
    },
    {
      subject: "public.v_user_emails",
      status: "NO_FIX",
      closed: [],
      stillProven: [],
      broken: [],
      unresolved: [],
      reason: "No fix was proposed for this view.",
    },
  ];
  return baseReport({
    inputs: [
      { path: "supabase/migrations/001_init.sql", sha256: SHA_A, bytes: 1204 },
      { path: "supabase/migrations/002_profiles.sql", sha256: SHA_B, bytes: 388 },
    ],
    summary: summary({ subjects: 7, proven: 3, suspected: 1, clean: 2, inconclusive: 1, probesRun: 8, probesProven: 4 }),
    findings: [
      finding({
        id: "rls:public.notes",
        subject: "public.notes",
        tier: "PROVEN",
        severity: "critical",
        title: "Notes are open to everyone",
        attackerCan: "Anyone with the public key can read, add and change every note.",
        causes: [rlsOff],
        provenBy: ["public.notes/anon-read", "public.notes/anon-insert"],
        notReproduced: ["public.notes/cross-delete"],
        fixStatus: "verified",
        fixNote: "Switch on row level security and let users touch only their own notes.",
      }),
      finding({
        id: "rls:public.profiles",
        subject: "public.profiles",
        tier: "PROVEN",
        severity: "high",
        title: "Any signed-in user can read all profiles",
        attackerCan: "Any signed-in user can read the profiles of every other user.",
        causes: [
          { code: "policy-always-true", text: 'The policy "profiles_read" allows every row.' },
          { code: "owner-not-compared", text: "No policy compares user_id with the signed-in user." },
        ],
        provenBy: ["public.profiles/cross-read"],
        notReproduced: ["public.profiles/anon-read"],
        fixStatus: "still-vulnerable",
        fixNote: "The proposed policy still lets every signed-in user read every profile.",
      }),
      finding({
        id: "rls:public.v_user_emails",
        subject: "public.v_user_emails",
        subjectKind: "view",
        tier: "PROVEN",
        severity: "medium",
        title: "A view exposes e-mail addresses",
        attackerCan: "Anyone with the public key can read e-mail addresses through the view.",
        causes: [{ code: "view-bypasses-rls", text: "The view runs with its owner's rights, so row level security does not apply." }],
        provenBy: ["public.v_user_emails/view-read-anon"],
        fixStatus: "needs-decision",
        fixNote: "Decide whether the view should run with the rights of the caller.",
      }),
      finding({
        id: "rls:public.messages",
        subject: "public.messages",
        tier: "SUSPECTED",
        severity: "medium",
        title: "Messages may be readable by other users",
        attackerCan: "A signed-in user might read messages sent to someone else.",
        causes: [{ code: "owner-not-checked", text: 'The policy "msg_read" checks only that the user is signed in.' }],
        fixStatus: "needs-decision",
        fixNote: "Decide who may read a message: sender, receiver or both.",
      }),
      finding({
        id: "rls:public.audit_log",
        subject: "public.audit_log",
        tier: "INCONCLUSIVE",
        severity: "low",
        title: "The audit log could not be tested",
        attackerCan: "Unknown: the test could not run.",
        inconclusive: [{ id: "public.audit_log/anon-read", reason: "the table could not be seeded" }],
        fixStatus: "not-proposed",
        fixNote: "Fix the seeding problem and run again.",
      }),
      finding({
        id: "rls:public.orders",
        subject: "public.orders",
        tier: "CLEAN",
        severity: "info",
        title: "Row level security on, owner checked",
        attackerCan: "Nothing found.",
      }),
      finding({
        id: "rls:public.settings",
        subject: "public.settings",
        tier: "CLEAN",
        severity: "info",
        title: "Row level security on, no public access",
        attackerCan: "Nothing found.",
      }),
    ],
    proofs,
    seeding: [{ table: "public.audit_log", rowsUserA: 0, rowsUserB: 0, status: "failed", reason: "column details has no default and is not null" }],
    fix: {
      statements: [
        "alter table public.notes enable row level security",
        'create policy "notes_owner" on public.notes for all to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id)',
      ],
      sql: [
        "-- public.notes: only the owner may touch a note",
        "alter table public.notes enable row level security;",
        'create policy "notes_owner" on public.notes',
        "  for all to authenticated",
        "  using ((select auth.uid()) = user_id)",
        "  with check ((select auth.uid()) = user_id);",
      ].join("\n"),
      covered: ["public.notes", "public.profiles"],
      needsDecision: [
        { subject: "public.messages", reason: "Only you know whether receivers may read messages." },
        { subject: "public.v_user_emails", reason: "Changing the view may break pages that rely on it." },
      ],
    },
    verification: { status: "PARTIAL", applyErrors: [], subjects, after },
    audit: {
      sourceTool: "static-auditor",
      sourceVersion: "2.1.0",
      project: "acme-app",
      findings: [
        {
          rule: "rls-disabled",
          severity: "high",
          file: "supabase/migrations/001_init.sql",
          line: 12,
          title: "Table without row level security",
          table: "public.notes",
          proofStatus: "PROVEN",
          proofIds: ["public.notes/anon-read"],
          note: "Reproduced: anonymous read returned 3 rows.",
        },
        {
          rule: "policy-true",
          severity: "medium",
          file: "supabase/migrations/002_profiles.sql",
          line: 4,
          title: "Policy that allows everything",
          table: "public.orders",
          proofStatus: "NOT_REPRODUCED",
          proofIds: [],
          note: "The database denied every attack on this table.",
        },
        {
          rule: "rls-unknown",
          severity: "low",
          file: "supabase/migrations/002_profiles.sql",
          line: 30,
          title: "Possible gap in a dynamic policy",
          table: null,
          proofStatus: "STATIC_ONLY",
          proofIds: [],
          note: "",
        },
      ],
      priorityTables: ["public.notes"],
      outOfScope: 2,
      warnings: ["one finding had no table name"],
    },
    migrationErrors: [
      {
        file: "supabase/migrations/002_profiles.sql",
        line: 18,
        statement: "create extension pg_cron",
        sqlstate: "0A000",
        message: 'extension "pg_cron" is not available',
      },
      {
        file: "supabase/migrations/002_profiles.sql",
        line: 22,
        statement: "select cron.schedule('nightly', '0 3 * * *', 'select 1')",
        sqlstate: "3F000",
        message: 'schema "cron" does not exist',
      },
    ],
    warnings: ["2 statements were skipped because they are not about row level security", "storage.objects policies were not read"],
  });
}

/** (b) Fixed app: everything CLEAN, nothing to fix. */
export function fixedReport(): AnalysisReport {
  const names = ["public.notes", "public.orders", "public.profiles"];
  const proofs = names.flatMap((subject) => [
    proof({
      subject,
      kind: "anon-read",
      sql: `select * from ${subject}`,
      observation: { status: "rows", rows: 0 },
      targetRows: 2,
      verdict: "NOT_REPRODUCED",
      reason: "The anonymous role read nothing.",
    }),
    proof({
      subject,
      kind: "own-read",
      sql: `select * from ${subject} where user_id = '${USER_A}'`,
      observation: { status: "rows", rows: 2 },
      targetRows: 2,
      verdict: "ACCESS_OK",
      reason: "The user can read their own rows.",
    }),
  ]);
  return baseReport({
    summary: summary({ subjects: 3, proven: 0, suspected: 0, clean: 3, inconclusive: 0, probesRun: 6, probesProven: 0 }),
    findings: names.map((subject) =>
      finding({ id: `rls:${subject}`, subject, tier: "CLEAN", severity: "info", title: "Row level security on, owner checked", attackerCan: "Nothing found." }),
    ),
    proofs,
  });
}

function todosProofs(phase: Phase, closed: boolean, ownReadWorks: boolean): Proof[] {
  const ownSql = `select * from public.todos where user_id = '${USER_A}'`;
  const open = phase === "before";
  return [
    proof({
      subject: "public.todos",
      kind: "anon-read",
      sql: "select * from public.todos",
      observation: open || !closed ? { status: "rows", rows: 5 } : { status: "rows", rows: 0 },
      targetRows: 5,
      verdict: open || !closed ? "PROVEN_VULNERABLE" : "NOT_REPRODUCED",
      reason: open || !closed ? "The anonymous role read seeded rows." : "The anonymous role read nothing.",
      phase,
    }),
    proof({
      subject: "public.todos",
      kind: "own-read",
      sql: ownSql,
      observation: ownReadWorks ? { status: "rows", rows: 2 } : { status: "rows", rows: 0 },
      targetRows: 2,
      verdict: ownReadWorks ? "ACCESS_OK" : "ACCESS_BROKEN",
      reason: ownReadWorks ? "The user can read their own rows." : "The user can no longer read their own rows.",
      phase,
    }),
  ];
}

function todosFinding(fixStatus: Finding["fixStatus"], fixNote: string): Finding {
  return finding({
    id: "rls:public.todos",
    subject: "public.todos",
    tier: "PROVEN",
    severity: "high",
    title: "Todos are open to everyone",
    attackerCan: "Anyone with the public key can read every todo.",
    causes: [{ code: "rls-disabled", text: "Row level security is switched off on public.todos." }],
    provenBy: ["public.todos/anon-read"],
    fixStatus,
    fixNote,
  });
}

const todosSummary = summary({ subjects: 1, proven: 1, suspected: 0, clean: 0, inconclusive: 0, probesRun: 2, probesProven: 1 });
const todosFix = (sql: string, statements: string[]) => ({ statements, sql, covered: ["public.todos"], needsDecision: [] });

/** (c) The fix works and normal use is intact: VERIFIED. */
export function verifiedReport(): AnalysisReport {
  return baseReport({
    summary: todosSummary,
    findings: [todosFinding("verified", "Switch on row level security and restrict todos to their owner.")],
    proofs: todosProofs("before", false, true),
    fix: todosFix(
      "alter table public.todos enable row level security;\ncreate policy todos_owner on public.todos for all to authenticated using ((select auth.uid()) = user_id);",
      ["alter table public.todos enable row level security", "create policy todos_owner on public.todos for all to authenticated using ((select auth.uid()) = user_id)"],
    ),
    verification: {
      status: "VERIFIED",
      applyErrors: [],
      subjects: [
        {
          subject: "public.todos",
          status: "VERIFIED",
          closed: ["public.todos/anon-read"],
          stillProven: [],
          broken: [],
          unresolved: [],
          reason: "The attack fails and the owner can still read their rows.",
        },
      ],
      after: todosProofs("after", true, true),
    },
  });
}

/** (d) The fix closes the hole but breaks normal use: must never read as verified. */
export function breaksAccessReport(): AnalysisReport {
  return baseReport({
    summary: todosSummary,
    findings: [todosFinding("breaks-access", "Enabling row level security without a policy locks everyone out, including the owners.")],
    proofs: todosProofs("before", false, true),
    fix: todosFix("alter table public.todos enable row level security;", ["alter table public.todos enable row level security"]),
    verification: {
      status: "BREAKS_ACCESS",
      applyErrors: [],
      subjects: [
        {
          subject: "public.todos",
          status: "BREAKS_ACCESS",
          closed: ["public.todos/anon-read"],
          stillProven: [],
          broken: ["public.todos/own-read"],
          unresolved: [],
          reason: "The attack fails, but the owner can no longer read their own rows.",
        },
      ],
      after: todosProofs("after", true, false),
    },
  });
}

/**
 * (e) Every input-derived field built from `h(label)`. With `h = (l) => l` it is the benign twin of the
 * hostile report: identical shape, so the markdown skeleton of both must match.
 */
export function makeInjectionReport(h: (label: string) => string, sql: (label: string) => string): AnalysisReport {
  const subject = h("subject");
  const view = h("view");
  const pid = h("probe-id");
  const pidView = h("view-probe-id");
  const pidNo = h("blocked-probe-id");
  const pidInc = h("inconclusive-probe-id");
  const hostileProof = (id: string, kind: ProbeKind, obs: ProbeObservation, verdict: Verdict, phase: Phase, subj: string): Proof =>
    sealProof({
      id,
      subject: subj,
      subjectKind: "table",
      kind,
      intent: KINDS[kind].intent,
      command: KINDS[kind].command,
      actor: KINDS[kind].actor,
      role: KINDS[kind].role,
      claims: h("claims"),
      sql: sql("proof-sql"),
      title: h("probe-title"),
      targetRows: 1,
      observation: obs,
      verdict,
      reason: h("proof-reason"),
      phase,
    });
  const proofs = [
    hostileProof(pid, "anon-read", { status: "error", sqlstate: h("sqlstate"), message: h("db-message") }, "PROVEN_VULNERABLE", "before", subject),
    hostileProof(pidNo, "cross-delete", { status: "rows", rows: 0 }, "NOT_REPRODUCED", "before", subject),
    hostileProof(pidInc, "own-read", { status: "not-run", reason: h("not-run-reason") }, "INCONCLUSIVE", "before", subject),
    hostileProof(pidView, "view-read-anon", { status: "rows", rows: 2 }, "PROVEN_VULNERABLE", "before", view),
  ];
  const after = [hostileProof(pid, "anon-read", { status: "rows", rows: 0 }, "NOT_REPRODUCED", "after", subject)];
  return {
    tool: { name: h("tool-name"), version: h("tool-version") },
    inputs: [{ path: h("input-path"), sha256: h("input-sha"), bytes: 10 }],
    environment: { mode: "docker", image: h("image"), postgresVersion: h("pg-version") },
    complete: false,
    summary: { subjects: 4, proven: 2, suspected: 1, clean: 1, inconclusive: 1, probesRun: 4, probesProven: 2 },
    findings: [
      finding({
        id: h("finding-id"),
        subject,
        tier: "PROVEN",
        severity: "critical",
        title: h("finding-title"),
        attackerCan: h("attacker-can"),
        causes: [{ code: "policy-always-true", text: h("cause-text") }],
        provenBy: [pid, h("missing-probe-id")],
        notReproduced: [pidNo],
        inconclusive: [{ id: pidInc, reason: h("inconclusive-reason") }],
        fixStatus: "unverified",
        fixNote: h("fix-note"),
      }),
      finding({
        id: h("view-finding-id"),
        subject: view,
        subjectKind: "view",
        tier: "PROVEN",
        severity: "high",
        title: h("view-title"),
        attackerCan: h("view-attacker-can"),
        provenBy: [pidView],
        fixStatus: "needs-decision",
        fixNote: h("view-fix-note"),
      }),
      finding({
        id: h("suspect-id"),
        subject: h("suspect-subject"),
        tier: "SUSPECTED",
        severity: "medium",
        title: h("suspect-title"),
        attackerCan: h("suspect-attacker-can"),
        causes: [{ code: "owner-not-checked", text: h("suspect-cause") }],
        fixStatus: "not-proposed",
        fixNote: h("suspect-fix-note"),
      }),
      finding({
        id: h("clean-id"),
        subject: h("clean-subject"),
        tier: "CLEAN",
        severity: "info",
        title: h("clean-title"),
        attackerCan: h("clean-attacker-can"),
      }),
    ],
    proofs,
    seeding: [{ table: h("seed-table"), rowsUserA: 0, rowsUserB: 0, status: "failed", reason: h("seed-reason") }],
    fix: {
      statements: [sql("fix-statement")],
      sql: sql("fix-sql"),
      covered: [subject],
      needsDecision: [{ subject: view, reason: h("decision-reason") }],
    },
    verification: {
      status: "PARTIAL",
      applyErrors: [{ statement: sql("apply-statement"), sqlstate: h("apply-sqlstate"), message: h("apply-message") }],
      subjects: [
        { subject, status: "VERIFIED", closed: [pid], stillProven: [pidView], broken: [pidNo], unresolved: [pidInc], reason: h("verification-reason") },
        { subject: view, status: "NO_FIX", closed: [], stillProven: [], broken: [], unresolved: [], reason: h("verification-reason-2") },
      ],
      after,
    },
    audit: {
      sourceTool: h("audit-tool"),
      sourceVersion: h("audit-version"),
      project: h("audit-project"),
      findings: [
        {
          rule: h("audit-rule"),
          severity: h("audit-severity"),
          file: h("audit-file"),
          line: 7,
          title: h("audit-title"),
          table: h("audit-table"),
          proofStatus: "PROVEN",
          proofIds: [pid],
          note: h("audit-note"),
        },
      ],
      priorityTables: [h("audit-table")],
      outOfScope: 1,
      warnings: [h("audit-warning")],
    },
    migrationErrors: [{ file: h("error-file"), line: 3, statement: sql("error-statement"), sqlstate: h("error-sqlstate"), message: h("error-message") }],
    warnings: [h("warning")],
    notChecked: [h("not-checked")],
  };
}

const NASTY_TAIL =
  "\u001b[31mred\u001b[0m \u001b]8;;http://evil.example\u0007link\u001b]8;;\u0007 \u202Ebidi\u202C \u200Bzero\u2060width\uFEFF \u2028sep \uD800 lone \u0000nul \u0085nel";

/** Text that tries to forge structure in every renderer. */
export function hostileString(label: string): string {
  return [
    `${label} \uD800\u202E\u200B \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\``,
    "# FORGED heading | a | b |",
    "> FORGED quote",
    "- FORGED item",
    "1. FORGED number",
    "---",
    "<script>alert(1)</script> <img src=x onerror=alert(1)> &amp; &lt;b&gt;",
    "[FORGED link](javascript:alert(1)) ![FORGED image](http://evil.example/x.png) @everyone https://evil.example www.evil.example a@evil.example",
    NASTY_TAIL,
    "A".repeat(700),
  ].join(label.length % 2 === 0 ? "\n" : "\r\n");
}

export function hostileSql(label: string): string {
  return [`select '${label}'; -- \u001b[2J\u202E\u200B\u0000`, "```", "# FORGED heading", "````sql", "<b>x</b>\tend", `${"B".repeat(700)}`].join("\n");
}

export function hostileReport(): AnalysisReport {
  return makeInjectionReport(hostileString, hostileSql);
}

export function hostileTwin(): AnalysisReport {
  return makeInjectionReport(
    (l) => l,
    (l) => `select '${l}'`,
  );
}
