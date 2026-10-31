import { err, ok, type Result } from "../result.js";

/**
 * The only kind of database endpoint the tool will ever connect to over TCP: one on this machine's
 * loopback interface. The check lives in the domain so no adapter can be handed anything else.
 *
 * The URL is read with a strict grammar instead of a general URL parser, because libpq-style parsers
 * accept ways to redirect the connection (`?host=`, `?hostaddr=`, `?service=`, several `@`, backslashes,
 * short or octal IPv4 forms) that would turn a URL which looks local into a remote connection.
 */
export interface LoopbackEndpoint {
  /** `127.x.y.z` or `::1`, never a name: `localhost` is mapped to `127.0.0.1` so DNS and hosts files are not consulted. */
  readonly host: string;
  readonly port: number;
  readonly user: string;
  readonly password: string | null;
  readonly database: string;
}

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/** True for `localhost`, a dotted-quad inside 127.0.0.0/8 (decimal only, no short forms) or `::1`. */
export function isLoopbackHost(host: string): boolean {
  const h = host.toLowerCase();
  if (h === "localhost" || h === "::1" || h === "[::1]") return true;
  const m = IPV4.exec(h);
  if (!m) return false;
  const octets = m.slice(1).map((o) => ({ text: o, value: Number(o) }));
  if (octets.some((o) => o.value > 255 || (o.text.length > 1 && o.text.startsWith("0")))) return false;
  return octets[0]?.value === 127;
}

const URL_GRAMMAR =
  /^(?:postgres|postgresql):\/\/(?:([^:@/?#\s\\]*)(?::([^@/?#\s\\]*))?@)?(\[[0-9a-fA-F:]+\]|[0-9A-Za-z.-]+)(?::(\d{1,5}))?(?:\/([^?#\s\\]*))?(\?sslmode=disable)?$/i;

function decode(part: string | undefined): string | null {
  if (part === undefined) return "";
  try {
    return decodeURIComponent(part);
  } catch {
    return null;
  }
}

export function parseLoopbackUrl(url: string): Result<LoopbackEndpoint, string> {
  if (url.length > 2048) return err("database URL is too long");
  const m = URL_GRAMMAR.exec(url);
  if (!m) return err("database URL must look like postgres://USER:PASS@127.0.0.1:5432/DB (no other options)");
  const [, userRaw, passwordRaw, hostRaw, portRaw, databaseRaw] = m;
  const host = (hostRaw ?? "").toLowerCase();
  if (!isLoopbackHost(host)) return err("refusing to connect: the database host is not a loopback address (127.0.0.0/8, ::1 or localhost)");
  const port = portRaw === undefined ? 5432 : Number(portRaw);
  if (port < 1 || port > 65535) return err("database port is out of range");
  const user = decode(userRaw);
  const password = passwordRaw === undefined ? null : decode(passwordRaw);
  const database = decode(databaseRaw);
  if (user === null || database === null || (passwordRaw !== undefined && password === null)) return err("database URL has an invalid percent-escape");
  if (/[\u0000-\u001f\u007f]/.test(user + (password ?? "") + database)) return err("database URL contains control characters");
  const normalizedHost = host === "localhost" ? "127.0.0.1" : host === "[::1]" ? "::1" : host;
  return ok({ host: normalizedHost, port, user: user === "" ? "postgres" : user, password, database: database === "" ? "postgres" : database });
}

/** Defence in depth for adapters: throws when handed a host that is not loopback. */
export function assertLoopbackHost(host: string): void {
  if (!isLoopbackHost(host)) throw new Error("refusing to connect: the database host is not a loopback address");
}
