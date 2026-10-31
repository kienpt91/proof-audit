import { spawn } from "node:child_process";

export interface ProcessResult {
  /** Exit code, or null when the process was killed. */
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly timedOut: boolean;
  /** Output went past the cap and the process was killed. */
  readonly truncated: boolean;
}

export interface RunOptions {
  readonly stdin?: string;
  readonly timeoutMs: number;
  readonly maxOutputBytes: number;
}

/** Runs the `docker` CLI with a fixed argument vector. No shell is ever involved. */
export interface DockerRunner {
  run(argv: readonly string[], options: RunOptions): Promise<ProcessResult>;
}

export class SpawnDockerRunner implements DockerRunner {
  run(argv: readonly string[], options: RunOptions): Promise<ProcessResult> {
    return new Promise((resolve, reject) => {
      const child = spawn("docker", [...argv], { shell: false, stdio: ["pipe", "pipe", "pipe"] });
      const out: Buffer[] = [];
      const err: Buffer[] = [];
      let size = 0;
      let timedOut = false;
      let truncated = false;
      const stop = (): void => {
        child.kill("SIGKILL");
        child.stdout.destroy();
        child.stderr.destroy();
      };
      const timer = setTimeout(() => {
        timedOut = true;
        stop();
      }, options.timeoutMs);
      child.stdout.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > options.maxOutputBytes) {
          truncated = true;
          stop();
          return;
        }
        out.push(chunk);
      });
      child.stderr.on("data", (chunk: Buffer) => {
        if (err.reduce((n, b) => n + b.length, 0) < 64 * 1024) err.push(chunk);
      });
      child.on("error", (e) => {
        clearTimeout(timer);
        reject(new Error(`could not run docker: ${e.message}`));
      });
      child.on("close", (code) => {
        clearTimeout(timer);
        resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8"), timedOut, truncated });
      });
      child.stdin.on("error", () => undefined);
      child.stdin.end(options.stdin ?? "");
    });
  }
}
