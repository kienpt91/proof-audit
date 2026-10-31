/**
 * What CHECK constraints say about a column, read from their text. Best effort: the aim is to make the
 * synthetic row pass the common constraints (enumerated strings, numeric bounds, minimum length), not to
 * solve arbitrary predicates. A row that still violates a constraint is recorded as unseeded, never forced.
 */
export interface CheckHints {
  /** String literals that appear in a constraint about the column, in order. */
  readonly literals: readonly string[];
  /** Inclusive numeric lower bound, if one was found. */
  readonly min: number | null;
  /** Inclusive numeric upper bound, if one was found. */
  readonly max: number | null;
  /** Minimum character length, if one was found. */
  readonly minLength: number | null;
}

const NO_HINTS: CheckHints = { literals: [], min: null, max: null, minLength: null };

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function checkHints(column: string, checks: readonly string[]): CheckHints {
  const name = escapeRegExp(column);
  const word = new RegExp(`(?<![\\w"])"?${name}"?(?![\\w"])`, "i");
  const literals: string[] = [];
  let min: number | null = null;
  let max: number | null = null;
  let minLength: number | null = null;
  const num = "(-?\\d+(?:\\.\\d+)?)";
  const col = `"?${name}"?(?:\\)?(?:::[a-z ]+)?\\)?)`;
  for (const check of checks) {
    if (!word.test(check)) continue;
    for (const m of check.matchAll(/'((?:[^']|'')*)'/g)) {
      const literal = (m[1] ?? "").replaceAll("''", "'");
      if (literal !== "" && !literals.includes(literal)) literals.push(literal);
    }
    const lower = (value: number): void => {
      min = min === null ? value : Math.max(min, value);
    };
    const upper = (value: number): void => {
      max = max === null ? value : Math.min(max, value);
    };
    for (const m of check.matchAll(new RegExp(`(?<![\\w"])${col}\\s*>=\\s*${num}`, "gi"))) lower(Number(m[1]));
    for (const m of check.matchAll(new RegExp(`(?<![\\w"])${col}\\s*>\\s*${num}`, "gi"))) lower(Number(m[1]) + 1);
    for (const m of check.matchAll(new RegExp(`(?<![\\w"])${col}\\s*<=\\s*${num}`, "gi"))) upper(Number(m[1]));
    for (const m of check.matchAll(new RegExp(`(?<![\\w"])${col}\\s*<\\s*${num}`, "gi"))) upper(Number(m[1]) - 1);
    for (const m of check.matchAll(new RegExp(`(?<![\\w"])${col}\\s*BETWEEN\\s*${num}\\s*AND\\s*${num}`, "gi"))) {
      lower(Number(m[1]));
      upper(Number(m[2]));
    }
    for (const m of check.matchAll(new RegExp(`(?:char_length|length)\\(\\s*${col}\\s*\\)\\s*(>=|>)\\s*(\\d+)`, "gi"))) {
      const n = Number(m[2]) + (m[1] === ">" ? 1 : 0);
      minLength = minLength === null ? n : Math.max(minLength, n);
    }
  }
  if (literals.length === 0 && min === null && max === null && minLength === null) return NO_HINTS;
  return { literals, min, max, minLength };
}
