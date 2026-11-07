import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { displayPath, InputError, loadSqlInputs, readBoundedText, writeOutputs } from "../../src/infrastructure/fs/files.js";

let dir = "";
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "proof-audit-test-"));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

const write = (rel: string, content = "select 1;") => {
  const full = join(dir, rel);
  mkdirSync(join(full, ".."), { recursive: true });
  writeFileSync(full, content);
  return full;
};

describe("displayPath", () => {
  it("shows paths inside the working directory relative with forward slashes", () => {
    expect(displayPath("/work/supabase/migrations/1.sql", "/work")).toBe("supabase/migrations/1.sql");
  });

  it("keeps paths outside the working directory as given", () => {
    expect(displayPath("/elsewhere/1.sql", "/work")).toBe("/elsewhere/1.sql");
  });
});

describe("readBoundedText", () => {
  it("reads a regular file", async () => {
    expect(await readBoundedText(write("a.sql", "héllo"), 100)).toEqual({ content: "héllo", bytes: 6 });
  });

  it("refuses files over the cap", async () => {
    await expect(readBoundedText(write("big.sql", "x".repeat(50)), 10)).rejects.toThrow("larger than");
  });

  it("refuses a symbolic link", async () => {
    const target = write("real.sql");
    symlinkSync(target, join(dir, "link.sql"));
    await expect(readBoundedText(join(dir, "link.sql"), 100)).rejects.toBeInstanceOf(InputError);
  });

  it("refuses a FIFO without blocking", async () => {
    const fifo = join(dir, "pipe.sql");
    execFileSync("mkfifo", [fifo]);
    await expect(readBoundedText(fifo, 100)).rejects.toThrow("not a regular file");
  });

  it("refuses a missing file", async () => {
    await expect(readBoundedText(join(dir, "nope.sql"), 100)).rejects.toBeInstanceOf(InputError);
  });
});

describe("loadSqlInputs", () => {
  it("reads a directory recursively in name order and ignores other files", async () => {
    write("m/002_b.sql", "b");
    write("m/001_a.sql", "a");
    write("m/sub/003_c.SQL", "c");
    write("m/readme.md", "no");
    const r = await loadSqlInputs([join(dir, "m")], dir);
    expect(r.files.map((f) => f.path)).toEqual(["m/001_a.sql", "m/002_b.sql", "m/sub/003_c.SQL"]);
    expect(r.complete).toBe(true);
  });

  it("keeps explicit files in the order given and reads each once", async () => {
    const b = write("b.sql", "b");
    const a = write("a.sql", "a");
    const r = await loadSqlInputs([b, a, b], dir);
    expect(r.files.map((f) => f.path)).toEqual(["b.sql", "a.sql"]);
  });

  it("skips symbolic links inside a directory with a warning", async () => {
    write("m/1.sql");
    symlinkSync(write("outside.sql"), join(dir, "m", "2.sql"));
    const r = await loadSqlInputs([join(dir, "m")], dir);
    expect(r.files.map((f) => f.path)).toEqual(["m/1.sql"]);
    expect(r.warnings.join()).toContain("symbolic link skipped");
  });

  it("refuses a symbolic link given directly", async () => {
    symlinkSync(write("outside.sql"), join(dir, "l.sql"));
    await expect(loadSqlInputs([join(dir, "l.sql")], dir)).rejects.toThrow("symbolic links are not followed");
  });

  it("marks the run incomplete when a file is over the size cap but still reads the rest", async () => {
    write("m/1.sql", "ok");
    write("m/2.sql", "x".repeat(1024 * 1024 + 1));
    const r = await loadSqlInputs([join(dir, "m")], dir);
    expect(r.files.map((f) => f.path)).toEqual(["m/1.sql"]);
    expect(r.complete).toBe(false);
    expect(r.warnings.join()).toContain("larger than");
  });

  it("fails when nothing could be read and for a missing path", async () => {
    mkdirSync(join(dir, "empty"));
    await expect(loadSqlInputs([join(dir, "empty")], dir)).rejects.toThrow("no SQL files");
    await expect(loadSqlInputs([join(dir, "missing")], dir)).rejects.toThrow("no such file");
  });

  it("warns about directories nested too deeply", async () => {
    let rel = "d";
    for (let i = 0; i < 18; i++) rel += "/d";
    write("shallow.sql");
    write(`${rel}/deep.sql`);
    const r = await loadSqlInputs([dir], dir);
    expect(r.warnings.join()).toContain("nesting is deeper");
    expect(r.files.map((f) => f.path)).toEqual(["shallow.sql"]);
  });
});

describe("writeOutputs", () => {
  it("creates the directory and writes each file", async () => {
    await writeOutputs(join(dir, "out/run1"), { "a.txt": "A", "b.txt": "B" });
    expect(readFileSync(join(dir, "out/run1/a.txt"), "utf8")).toBe("A");
  });

  it("removes the stale names that this run did not write, and returns them", async () => {
    mkdirSync(join(dir, "out"));
    writeFileSync(join(dir, "out", "findings.json"), "[old]");
    writeFileSync(join(dir, "out", "keep.txt"), "keep");
    expect(await writeOutputs(join(dir, "out"), { "a.txt": "A" }, ["findings.json", "absent.json"])).toEqual(["findings.json"]);
    expect(existsSync(join(dir, "out", "findings.json"))).toBe(false);
    expect(readFileSync(join(dir, "out", "keep.txt"), "utf8")).toBe("keep");
  });

  it("does not remove a stale name that it just wrote", async () => {
    expect(await writeOutputs(join(dir, "out"), { "findings.json": "[]" }, ["findings.json"])).toEqual([]);
    expect(readFileSync(join(dir, "out", "findings.json"), "utf8")).toBe("[]");
  });

  it("removes a symbolic link at a stale name without touching its target, and refuses a directory", async () => {
    const victim = join(dir, "victim.txt");
    writeFileSync(victim, "keep me");
    mkdirSync(join(dir, "out"));
    symlinkSync(victim, join(dir, "out", "findings.json"));
    expect(await writeOutputs(join(dir, "out"), { "a.txt": "A" }, ["findings.json"])).toEqual(["findings.json"]);
    expect(readFileSync(victim, "utf8")).toBe("keep me");
    mkdirSync(join(dir, "out", "findings.json"));
    await expect(writeOutputs(join(dir, "out"), { "a.txt": "A" }, ["findings.json"])).rejects.toThrow("directory is in the way");
  });

  it("refuses to write through a symbolic link", async () => {
    mkdirSync(join(dir, "real"));
    symlinkSync(join(dir, "real"), join(dir, "link"));
    await expect(writeOutputs(join(dir, "link"), { "a.txt": "A" })).rejects.toThrow("real directory");
  });
});

describe("writeOutputs and symbolic links", () => {
  it("does not write through a symbolic link that already sits at an output name", async () => {
    const victim = join(dir, "victim.txt");
    writeFileSync(victim, "keep me");
    mkdirSync(join(dir, "out"));
    symlinkSync(victim, join(dir, "out", "report.md"));
    await expect(writeOutputs(join(dir, "out"), { "report.md": "overwritten" })).rejects.toThrow("symbolic link or special file");
    expect(readFileSync(victim, "utf8")).toBe("keep me");
  });

  it("does not write through a dangling symbolic link either, and creates nothing at its target", async () => {
    mkdirSync(join(dir, "out"));
    symlinkSync(join(dir, "does-not-exist.txt"), join(dir, "out", "fix.sql"));
    await expect(writeOutputs(join(dir, "out"), { "fix.sql": "x" })).rejects.toThrow();
    expect(() => readFileSync(join(dir, "does-not-exist.txt"))).toThrow();
  });

  it("does not open a FIFO left at an output name", async () => {
    mkdirSync(join(dir, "out"));
    execFileSync("mkfifo", [join(dir, "out", "proofs.jsonl")]);
    await expect(writeOutputs(join(dir, "out"), { "proofs.jsonl": "x" })).rejects.toThrow("symbolic link or special file");
  });

  it("replaces an existing regular file completely", async () => {
    mkdirSync(join(dir, "out"));
    writeFileSync(join(dir, "out", "report.md"), "a much longer previous report");
    await writeOutputs(join(dir, "out"), { "report.md": "new" });
    expect(readFileSync(join(dir, "out", "report.md"), "utf8")).toBe("new");
  });

  it("writes files readable by others but not writable by them", async () => {
    await writeOutputs(join(dir, "out2"), { "a.txt": "x" });
    expect((statSync(join(dir, "out2", "a.txt")).mode & 0o777).toString(8)).toMatch(/^6[0-4][0-4]$/);
  });
});
