import { primaryOwnerColumn } from "../schema/owner.js";
import type { SchemaModel } from "../schema/model.js";
import { qualifiedKey } from "../schema/model.js";
import type { ProbeKind, Proof } from "../proof/types.js";
import { explainTable, explainView, SUSPICIOUS } from "./causes.js";
import { SEVERITY_RANK, type Cause, type Finding, type Severity, type Tier } from "./types.js";

const ANON_PHRASE: Partial<Record<ProbeKind, (s: string) => string>> = {
  "anon-read": (s) => `read rows of ${s}`,
  "anon-insert": (s) => `add rows to ${s}`,
  "anon-update": (s) => `change rows in ${s}`,
  "anon-delete": (s) => `delete rows from ${s}`,
  "view-read-anon": (s) => `read the rows behind ${s}`,
};

const USER_PHRASE: Partial<Record<ProbeKind, string>> = {
  "cross-read": "read other users' rows",
  "cross-insert": "create rows in other users' names",
  "null-owner-insert": "create rows that belong to nobody",
  "cross-update": "change other users' rows",
  "cross-delete": "delete other users' rows",
  "reassign-owner": "give their own rows to another user",
  "view-read-cross": "read other users' rows through the view",
};

const KIND_ORDER: readonly ProbeKind[] = [
  "anon-read", "anon-insert", "anon-update", "anon-delete", "view-read-anon",
  "cross-read", "cross-insert", "null-owner-insert", "cross-update", "cross-delete", "reassign-owner", "view-read-cross",
];

function joinList(items: readonly string[]): string {
  if (items.length <= 1) return items.join("");
  return `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;
}

/** One sentence naming what the proven probes let an attacker do. */
export function attackerSentence(subject: string, proven: readonly ProbeKind[]): string {
  const anon = KIND_ORDER.filter((k) => proven.includes(k)).flatMap((k) => ANON_PHRASE[k]?.(subject) ?? []);
  const user = KIND_ORDER.filter((k) => proven.includes(k)).flatMap((k) => USER_PHRASE[k] ?? []);
  const parts: string[] = [];
  if (anon.length > 0) parts.push(`anyone with your public anon key can ${joinList(anon)}`);
  if (user.length > 0) parts.push(`any signed-in user can ${joinList(user)}${anon.length > 0 ? "" : ` in ${subject}`}`);
  const sentence = parts.join(", and ");
  return `${sentence.charAt(0).toUpperCase()}${sentence.slice(1)}.`;
}

const ANON_WRITES: readonly ProbeKind[] = ["anon-insert", "anon-update", "anon-delete"];
const USER_WRITES: readonly ProbeKind[] = ["cross-insert", "cross-update", "cross-delete", "reassign-owner"];

/** Severity of a proven problem. Writes by strangers and any anonymous read of per-user data are the worst. */
export function severityOf(proven: readonly ProbeKind[], hasOwnerColumn: boolean, subjectKind: "table" | "view"): Severity {
  if (proven.some((k) => ANON_WRITES.includes(k))) return "critical";
  if (proven.includes("anon-read") || proven.includes("view-read-anon")) return hasOwnerColumn || subjectKind === "view" ? "critical" : "medium";
  if (proven.some((k) => USER_WRITES.includes(k)) || proven.includes("cross-read") || proven.includes("view-read-cross")) return "high";
  return "medium";
}

function tierFor(exploits: readonly Proof[], causes: readonly Cause[]): Tier {
  if (exploits.some((p) => p.verdict === "PROVEN_VULNERABLE")) return "PROVEN";
  const unresolved = exploits.some((p) => p.verdict === "INCONCLUSIVE");
  const suspicious = causes.some((c) => SUSPICIOUS[c.code]);
  if (unresolved) return suspicious ? "SUSPECTED" : "INCONCLUSIVE";
  if (exploits.length > 0) return "CLEAN";
  return suspicious ? "SUSPECTED" : "INCONCLUSIVE";
}

function titleFor(tier: Tier, kind: "table" | "view", subject: string): string {
  const noun = kind === "view" ? "View" : "Table";
  switch (tier) {
    case "PROVEN":
      return `${noun} ${subject} can be accessed by people who should not see or change its rows`;
    case "SUSPECTED":
      return `${noun} ${subject} looks risky but the problem was not reproduced`;
    case "CLEAN":
      return `${noun} ${subject} refused every attack we tried`;
    case "INCONCLUSIVE":
      return `${noun} ${subject} could not be fully tested`;
  }
}

function sentenceFor(tier: Tier, subject: string, proven: readonly ProbeKind[]): string {
  switch (tier) {
    case "PROVEN":
      return attackerSentence(subject, proven);
    case "SUSPECTED":
      return `People other than the owner may be able to read or change rows of ${subject}, but this was not reproduced, so treat it as a low-confidence lead.`;
    case "CLEAN":
      return `The database refused every attack we tried against ${subject}.`;
    case "INCONCLUSIVE":
      return `Some attacks on ${subject} could not be run, so nothing is proven either way.`;
  }
}

/** What a finding becomes when the run's integrity is in doubt: nothing proven, nothing cleared. */
function quarantined(f: Finding, reason: string): Finding {
  return {
    ...f,
    tier: "INCONCLUSIVE",
    severity: "info",
    title: `${f.subjectKind === "view" ? "View" : "Table"} ${f.subject} could not be judged: the test environment was touched`,
    attackerCan: `Nothing can be concluded about ${f.subject}: the migrations touched the test environment the results depend on, so neither a problem nor its absence can be trusted (see the integrity section).`,
    causes: [],
    provenBy: [],
    notReproduced: [],
    inconclusive: [{ id: f.id, reason }],
    fixStatus: "not-needed",
    fixNote: "No fix is proposed while the results cannot be trusted.",
  };
}

/** Findings for every table and view the proofs cover, ordered PROVEN first, then by severity, then name. */
export function buildFindings(model: SchemaModel, proofs: readonly Proof[], priority: readonly string[] = [], quarantine: string | null = null): readonly Finding[] {
  const rank = (subject: string): number => { const i = priority.indexOf(subject); return i === -1 ? Number.MAX_SAFE_INTEGER : i; };
  const bySubject = new Map<string, Proof[]>();
  for (const p of proofs) bySubject.set(p.subject, [...(bySubject.get(p.subject) ?? []), p]);
  const out: Finding[] = [];
  const subjects: { key: string; kind: "table" | "view"; causes: readonly Cause[]; owner: boolean }[] = [
    ...model.tables.map((t) => ({ key: qualifiedKey(t.name), kind: "table" as const, causes: explainTable(t), owner: primaryOwnerColumn(t) !== null })),
    ...model.views.filter((v) => bySubject.has(qualifiedKey(v.name))).map((v) => ({ key: qualifiedKey(v.name), kind: "view" as const, causes: explainView(v, model), owner: true })),
  ];
  for (const s of subjects) {
    const mine = bySubject.get(s.key) ?? [];
    const exploits = mine.filter((p) => p.intent === "exploit");
    const proven = exploits.filter((p) => p.verdict === "PROVEN_VULNERABLE");
    const tier = tierFor(exploits, s.causes);
    const provenKinds = proven.map((p) => p.kind);
    out.push({
      id: `rls:${s.key}`,
      subject: s.key,
      subjectKind: s.kind,
      tier,
      severity: tier === "PROVEN" ? severityOf(provenKinds, s.owner, s.kind) : tier === "SUSPECTED" ? "low" : "info",
      title: titleFor(tier, s.kind, s.key),
      attackerCan: sentenceFor(tier, s.key, provenKinds),
      causes: tier === "CLEAN" ? [] : s.causes,
      provenBy: proven.map((p) => p.id),
      notReproduced: exploits.filter((p) => p.verdict === "NOT_REPRODUCED").map((p) => p.id),
      inconclusive: exploits.filter((p) => p.verdict === "INCONCLUSIVE").map((p) => ({ id: p.id, reason: p.reason })),
      fixStatus: tier === "PROVEN" ? "not-proposed" : "not-needed",
      fixNote: tier === "PROVEN" ? "No fix has been proposed yet." : "Nothing to fix from what was proven.",
    });
  }
  const sealed = quarantine === null ? out : out.map((f) => quarantined(f, quarantine));
  const tierRank: Record<Tier, number> = { PROVEN: 0, SUSPECTED: 1, INCONCLUSIVE: 2, CLEAN: 3 };
  return sealed.sort((a, b) => tierRank[a.tier] - tierRank[b.tier] || SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || Math.sign(rank(a.subject) - rank(b.subject)) || (a.subject < b.subject ? -1 : a.subject > b.subject ? 1 : 0));
}
