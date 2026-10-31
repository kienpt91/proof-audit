import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { describe, expect, it } from "vitest";

const SRC = resolve(import.meta.dirname, "../../src");

type Layer = "domain" | "application" | "infrastructure" | "composition" | "entry";

/** Which layers a layer may import from. The dependency rule: domain <- application <- infrastructure <- composition. */
const ALLOWED: Record<Layer, readonly Layer[]> = {
  domain: ["domain"],
  application: ["domain", "application"],
  infrastructure: ["domain", "application", "infrastructure"],
  composition: ["domain", "application", "infrastructure", "composition"],
  entry: ["domain", "application", "composition"],
};

/** Imports of packages and Node built-ins. Only the outer layers may do IO. */
const EXTERNAL_OK: Record<Layer, boolean> = { domain: false, application: false, infrastructure: true, composition: true, entry: false };

/** Sources of nondeterminism and IO that the pure layers must never touch. */
const FORBIDDEN_IN_PURE = /\bDate\.now\b|\bnew Date\b|Math\.random|performance\.now|\bprocess\.|\brequire\(|\bfetch\(|\bsetTimeout\b|\bsetInterval\b|\bglobalThis\.crypto\b|\bcrypto\.(randomUUID|getRandomValues)/;

function layerOf(file: string): Layer {
  const rel = relative(SRC, file).split(/[\\/]/);
  const first = rel[0] ?? "";
  if (first === "domain" || first === "application" || first === "infrastructure" || first === "composition") return first;
  return "entry";
}

export function importsOf(source: string): string[] {
  const out: string[] = [];
  const re = /(?:^|\n)\s*(?:import|export)\s[^'";]*?from\s*['"]([^'"]+)['"]|(?:^|\n)\s*import\s*['"]([^'"]+)['"]|\bimport\(\s*['"]([^'"]+)['"]\s*\)/g;
  for (const m of source.matchAll(re)) out.push((m[1] ?? m[2] ?? m[3]) as string);
  return out;
}

function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
}

export function violations(file: string, source: string): string[] {
  const layer = layerOf(file);
  const found: string[] = [];
  for (const spec of importsOf(stripComments(source))) {
    if (spec.startsWith(".")) {
      const target = resolve(dirname(file), spec);
      const targetLayer = layerOf(target);
      if (!ALLOWED[layer].includes(targetLayer)) found.push(`${layer} must not import ${targetLayer}: ${spec}`);
    } else if (!EXTERNAL_OK[layer]) {
      found.push(`${layer} must not import ${spec}`);
    }
  }
  if ((layer === "domain" || layer === "application") && FORBIDDEN_IN_PURE.test(stripComments(source))) {
    found.push(`${layer} touches the clock, randomness or the process`);
  }
  return found;
}

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const full = join(dir, name);
    return statSync(full).isDirectory() ? walk(full) : full.endsWith(".ts") ? [full] : [];
  });
}

describe("dependency rule over the real source tree", () => {
  const files = walk(SRC);

  it("finds the source files of every layer", () => {
    const layers = new Set(files.map(layerOf));
    expect([...layers].sort()).toEqual(["application", "composition", "domain", "entry", "infrastructure"]);
  });

  it.each(files.map((f) => [relative(SRC, f), f] as const))("%s respects the layers", (_name, file) => {
    expect(violations(file, readFileSync(file, "utf8"))).toEqual([]);
  });
});

describe("the checker itself", () => {
  const domainFile = join(SRC, "domain/x.ts");
  const appFile = join(SRC, "application/x.ts");
  const infraFile = join(SRC, "infrastructure/x.ts");

  it("flags a domain file importing the application or infrastructure layer", () => {
    expect(violations(domainFile, 'import { a } from "../application/a.js";')).toHaveLength(1);
    expect(violations(domainFile, 'export { b } from "../infrastructure/b.js";')).toHaveLength(1);
  });

  it("flags a domain file importing node built-ins or packages", () => {
    expect(violations(domainFile, 'import { readFile } from "node:fs";')).toHaveLength(1);
    expect(violations(domainFile, 'import pg from "pg";')).toHaveLength(1);
    expect(violations(domainFile, 'const m = await import("node:crypto");')).toHaveLength(1);
    expect(violations(domainFile, 'import "node:os";')).toHaveLength(1);
  });

  it("flags an application file importing infrastructure", () => {
    expect(violations(appFile, 'import { x } from "../infrastructure/x.js";')).toHaveLength(1);
  });

  it("lets infrastructure import inward and use node and packages", () => {
    expect(violations(infraFile, 'import { x } from "../domain/x.js"; import { y } from "../application/y.js"; import pg from "pg"; import { z } from "node:fs";')).toEqual([]);
  });

  it("flags infrastructure importing composition", () => {
    expect(violations(infraFile, 'import { x } from "../composition/x.js";')).toHaveLength(1);
  });

  it("flags clocks, randomness and process access in the pure layers", () => {
    expect(violations(domainFile, "const t = Date.now();")).toHaveLength(1);
    expect(violations(appFile, "const r = Math.random();")).toHaveLength(1);
    expect(violations(domainFile, "const e = process.env.X;")).toHaveLength(1);
  });

  it("ignores forbidden words that only appear in comments", () => {
    expect(violations(domainFile, "// uses Date.now() in a comment\n/* process.exit */\nconst a = 1;")).toEqual([]);
  });

  it("finds multi-line imports", () => {
    expect(importsOf('import {\n  a,\n  b,\n} from "../x.js";')).toEqual(["../x.js"]);
  });
});
