import { err, ok, type Result } from "./result.js";

/**
 * Small strict-schema combinators for input the tool does not control (audit reports, evidence files,
 * catalog snapshots). A validator returns the typed value or one message naming the path that failed.
 * Messages never echo the offending value, only its path and expected shape, because the value may be hostile.
 */
export type Validator<T> = (value: unknown, path: string) => Result<T, string>;

const fail = (path: string, expected: string): Result<never, string> => err(`${path}: expected ${expected}`);

export function string(options: { max?: number; min?: number; pattern?: RegExp } = {}): Validator<string> {
  const max = options.max ?? 100_000;
  return (value, path) => {
    if (typeof value !== "string") return fail(path, "a string");
    if (value.length > max) return fail(path, `a string of at most ${max} characters`);
    if (options.min !== undefined && value.length < options.min) return fail(path, `a string of at least ${options.min} characters`);
    if (options.pattern && !options.pattern.test(value)) return fail(path, `a string matching ${options.pattern.source}`);
    return ok(value);
  };
}

export function integer(options: { min?: number; max?: number } = {}): Validator<number> {
  const min = options.min ?? 0;
  const max = options.max ?? Number.MAX_SAFE_INTEGER;
  return (value, path) => {
    if (typeof value !== "number" || !Number.isInteger(value)) return fail(path, "an integer");
    if (value < min || value > max) return fail(path, `an integer between ${min} and ${max}`);
    return ok(value);
  };
}

export const boolean: Validator<boolean> = (value, path) => (typeof value === "boolean" ? ok(value) : fail(path, "a boolean"));

export function literal<T extends string>(...allowed: readonly T[]): Validator<T> {
  return (value, path) => (typeof value === "string" && (allowed as readonly string[]).includes(value) ? ok(value as T) : fail(path, `one of ${allowed.join(", ")}`));
}

export function array<T>(item: Validator<T>, options: { max?: number } = {}): Validator<T[]> {
  const max = options.max ?? 10_000;
  return (value, path) => {
    if (!Array.isArray(value)) return fail(path, "an array");
    if (value.length > max) return fail(path, `an array of at most ${max} items`);
    const out: T[] = [];
    for (let i = 0; i < value.length; i++) {
      const r = item(value[i], `${path}[${i}]`);
      if (!r.ok) return r;
      out.push(r.value);
    }
    return ok(out);
  };
}

export function nullable<T>(inner: Validator<T>): Validator<T | null> {
  return (value, path) => (value === null ? ok(null) : inner(value, path));
}

type Shape<S extends Record<string, Validator<unknown>>> = { [K in keyof S]: S[K] extends Validator<infer T> ? T : never };

/** An object with exactly these keys. Unknown keys are rejected unless `allowUnknown` is set. */
export function object<S extends Record<string, Validator<unknown>>>(
  shape: S,
  options: { allowUnknown?: boolean; optional?: readonly (keyof S)[] } = {},
): Validator<Shape<S>> {
  const optional = new Set<string>((options.optional ?? []) as string[]);
  return (value, path) => {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return fail(path, "an object");
    const record = value as Record<string, unknown>;
    if (!options.allowUnknown) {
      for (const key of Object.keys(record)) {
        if (!Object.hasOwn(shape, key)) return err(`${path}: unexpected key ${JSON.stringify(key.slice(0, 40))}`);
      }
    }
    const out: Record<string, unknown> = {};
    for (const [key, validator] of Object.entries(shape)) {
      if (!Object.hasOwn(record, key) || record[key] === undefined) {
        if (optional.has(key)) continue;
        return err(`${path}.${key}: missing`);
      }
      const r = validator(record[key], `${path}.${key}`);
      if (!r.ok) return r;
      out[key] = r.value;
    }
    return ok(out as Shape<S>);
  };
}

/** Parse JSON text with a size cap, then validate. The parse error never echoes the text. */
export function parseJson<T>(text: string, validator: Validator<T>, options: { maxBytes: number; label: string }): Result<T, string> {
  if (text.length > options.maxBytes) return err(`${options.label}: larger than ${options.maxBytes} bytes`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return err(`${options.label}: not valid JSON`);
  }
  return validator(parsed, options.label);
}
