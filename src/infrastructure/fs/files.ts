import { constants } from "node:fs";
import { lstat, mkdir, open, readdir } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import type { LoadedFile, LoadedFiles } from "../../application/ports.js";
import { LIMITS } from "../../domain/limits.js";

const MAX_DEPTH = 16;

export class InputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InputError";
  }
}

/** Display path: relative to `cwd` with forward slashes when inside it, otherwise as given. */
export function displayPath(path: string, cwd: string): string {
  const rel = relative(cwd, path);
  const shown = rel === "" || rel.startsWith("..") || rel.startsWith(sep) ? path : rel;
  return shown.split(sep).join("/");
}

/**
 * Read one regular file. The file is opened without following symlinks and without blocking on FIFOs, then
 * checked on the open descriptor, so a file swapped after listing cannot redirect the read.
 */
export async function readBoundedText(path: string, maxBytes: number): Promise<{ readonly content: string; readonly bytes: number }> {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch {
    throw new InputError(`cannot read ${path} (missing, unreadable or a symbolic link)`);
  }
  try {
    const info = await handle.stat();
    if (!info.isFile()) throw new InputError(`${path} is not a regular file`);
    if (info.size > maxBytes) throw new InputError(`${path} is larger than ${maxBytes} bytes`);
    const buffer = Buffer.alloc(info.size);
    let read = 0;
    while (read < info.size) {
      const { bytesRead } = await handle.read(buffer, read, info.size - read, read);
      if (bytesRead === 0) break;
      read += bytesRead;
    }
    return { content: buffer.subarray(0, read).toString("utf8"), bytes: read };
  } finally {
    await handle.close();
  }
}

async function collect(dir: string, depth: number, out: string[], warnings: string[]): Promise<void> {
  if (depth > MAX_DEPTH) {
    warnings.push(`${dir}: directory nesting is deeper than ${MAX_DEPTH}, not read`);
    return;
  }
  const entries = (await readdir(dir, { withFileTypes: true })).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isSymbolicLink()) warnings.push(`${full}: symbolic link skipped`);
    else if (entry.isDirectory()) await collect(full, depth + 1, out, warnings);
    else if (entry.isFile() && entry.name.toLowerCase().endsWith(".sql")) out.push(full);
  }
}

/** Read SQL migrations from files and directories, in the order given (directories: sorted by name), within the caps. */
export async function loadSqlInputs(paths: readonly string[], cwd: string): Promise<LoadedFiles> {
  const warnings: string[] = [];
  const candidates: string[] = [];
  for (const path of paths) {
    let info;
    try {
      info = await lstat(path);
    } catch {
      throw new InputError(`${path}: no such file or directory`);
    }
    if (info.isSymbolicLink()) throw new InputError(`${path}: symbolic links are not followed`);
    if (info.isDirectory()) {
      const found: string[] = [];
      await collect(path, 0, found, warnings);
      if (found.length === 0) warnings.push(`${path}: no .sql files found`);
      candidates.push(...found);
    } else if (info.isFile()) candidates.push(path);
    else throw new InputError(`${path}: not a regular file or directory`);
  }
  const files: LoadedFile[] = [];
  let complete = true;
  let total = 0;
  const seen = new Set<string>();
  for (const path of candidates) {
    if (seen.has(path)) continue;
    seen.add(path);
    if (files.length >= LIMITS.maxSqlFiles) {
      warnings.push(`more than ${LIMITS.maxSqlFiles} SQL files: the rest were not read`);
      complete = false;
      break;
    }
    try {
      const { content, bytes } = await readBoundedText(path, LIMITS.maxSqlFileBytes);
      if (total + bytes > LIMITS.maxSqlTotalBytes) {
        warnings.push(`${displayPath(path, cwd)}: skipped, the total size cap of ${LIMITS.maxSqlTotalBytes} bytes was reached`);
        complete = false;
        continue;
      }
      total += bytes;
      files.push({ path: displayPath(path, cwd), content, bytes });
    } catch (e) {
      warnings.push(`${displayPath(path, cwd)}: ${e instanceof Error ? e.message : "unreadable"}`);
      complete = false;
    }
  }
  if (files.length === 0) throw new InputError("no SQL files could be read from the given paths");
  return { files, warnings, complete };
}

/**
 * Write each output file without following a symbolic link or opening a FIFO that already sits at that name: the
 * directory may come from a checkout that contains `report.md -> ~/.zshrc`. Existing regular files are replaced.
 */
export async function writeOutputs(dir: string, files: Readonly<Record<string, string>>): Promise<void> {
  await mkdir(dir, { recursive: true });
  const info = await lstat(dir);
  if (info.isSymbolicLink() || !info.isDirectory()) throw new InputError(`${dir}: output must be a real directory`);
  for (const [name, content] of Object.entries(files)) {
    const target = join(dir, name);
    let handle;
    try {
      handle = await open(target, constants.O_WRONLY | constants.O_CREAT | constants.O_NOFOLLOW | constants.O_NONBLOCK, 0o644);
    } catch {
      throw new InputError(`${displayPath(target, process.cwd())}: cannot write here (a symbolic link or special file is in the way)`);
    }
    try {
      if (!(await handle.stat()).isFile()) throw new InputError(`${displayPath(target, process.cwd())}: not a regular file`);
      await handle.truncate(0);
      await handle.writeFile(content, "utf8");
    } finally {
      await handle.close();
    }
  }
}
