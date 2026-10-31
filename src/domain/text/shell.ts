import { err, ok, type Result } from "../result.js";

/** Characters that need no quoting in a POSIX shell word and do nothing special to it. */
const SAFE_WORD = /^[A-Za-z0-9_@%+=:,./-]+$/;
/** Characters a plain (unquoted) word may contain: exactly the ones `shellQuote` leaves alone. */
const SAFE_CHAR = /[A-Za-z0-9_@%+=:,./-]/;

/**
 * Quote one argument for a POSIX shell. Plain words stay as they are; everything else (including the
 * empty string) is wrapped in single quotes, with each embedded single quote written as `'\''`.
 * Throws on a NUL byte, which no shell argument can contain.
 */
export function shellQuote(arg: string): string {
  if (arg.includes("\0")) throw new Error("a shell argument cannot contain a NUL byte");
  if (SAFE_WORD.test(arg)) return arg;
  return `'${arg.replaceAll("'", "'\\''")}'`;
}

/**
 * Split a command line into words, accepting only what `shellQuote` can produce: plain words made of
 * `[A-Za-z0-9_@%+=:,./-]`, single-quoted text, and the `\'` escape for a literal quote that joins two
 * quoted runs. Space and tab separate words. Anything a shell would interpret (`$ ` ; & | < > ( ) *`,
 * a newline, any other backslash, double quotes) makes the whole line invalid, so a command taken from
 * an untrusted file can be inspected before anything runs it. Errors name a position, never the text.
 */
export function splitShellWords(command: string): Result<string[], string> {
  const words: string[] = [];
  let current = "";
  let inWord = false;
  let i = 0;
  while (i < command.length) {
    const ch = command.charAt(i);
    if (ch === " " || ch === "\t") {
      if (inWord) {
        words.push(current);
        current = "";
        inWord = false;
      }
      i++;
    } else if (ch === "'") {
      const close = command.indexOf("'", i + 1);
      if (close === -1) return err(`unterminated single quote at position ${i}`);
      current += command.slice(i + 1, close);
      inWord = true;
      i = close + 1;
    } else if (ch === "\\") {
      if (command.charAt(i + 1) !== "'") return err(`unsupported backslash at position ${i}`);
      current += "'";
      inWord = true;
      i += 2;
    } else if (SAFE_CHAR.test(ch)) {
      current += ch;
      inWord = true;
      i++;
    } else {
      return err(`unsupported character at position ${i}`);
    }
  }
  if (inWord) words.push(current);
  return ok(words);
}
