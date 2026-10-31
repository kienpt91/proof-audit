import { describe, expect, it } from "vitest";
import { assertLoopbackHost, isLoopbackHost, parseLoopbackUrl } from "../../../src/domain/safety/loopback.js";

describe("isLoopbackHost", () => {
  it.each(["127.0.0.1", "127.255.255.254", "localhost", "LOCALHOST", "::1", "[::1]"])("accepts %s", (host) => {
    expect(isLoopbackHost(host)).toBe(true);
  });

  it.each([
    "0.0.0.0",
    "10.0.0.5",
    "192.168.1.1",
    "8.8.8.8",
    "128.0.0.1",
    "127.1",
    "127.0.0",
    "0177.0.0.1",
    "0x7f.0.0.1",
    "2130706433",
    "127.0.0.256",
    "127.00.0.1",
    "localhost.example.com",
    "example.com",
    "::ffff:127.0.0.1",
    "::",
    "",
    "db.internal",
  ])("refuses %s", (host) => {
    expect(isLoopbackHost(host)).toBe(false);
  });
});

describe("parseLoopbackUrl", () => {
  it("reads every part of a loopback URL", () => {
    const r = parseLoopbackUrl("postgres://tester:p%40x@127.0.0.1:55432/scratch");
    expect(r).toEqual({ ok: true, value: { host: "127.0.0.1", port: 55432, user: "tester", password: "p@x", database: "scratch" } });
  });

  it("defaults port, user and database", () => {
    const r = parseLoopbackUrl("postgresql://localhost");
    expect(r).toEqual({ ok: true, value: { host: "127.0.0.1", port: 5432, user: "postgres", password: null, database: "postgres" } });
  });

  it("maps localhost to a literal address so DNS is never consulted", () => {
    const r = parseLoopbackUrl("postgres://u@LocalHost:5433/d");
    expect(r.ok && r.value.host).toBe("127.0.0.1");
  });

  it("accepts IPv6 loopback in brackets", () => {
    const r = parseLoopbackUrl("postgres://u:p@[::1]:5432/d");
    expect(r.ok && r.value.host).toBe("::1");
  });

  it("accepts sslmode=disable as the only option", () => {
    expect(parseLoopbackUrl("postgres://u@127.0.0.1/d?sslmode=disable").ok).toBe(true);
  });

  it.each([
    "postgres://u:p@db.example.com:5432/d",
    "postgres://u:p@10.1.2.3/d",
    "postgres://127.0.0.1@evil.example/d",
    "postgres://u:p@127.0.0.1@evil.example/d",
    "postgres://u@evil.example\\@127.0.0.1/d",
    "postgres://u@127.0.0.1.evil.example/d",
    "postgres://u@localhost.evil.example/d",
    "postgres://u@127.0.0.1/d?host=evil.example",
    "postgres://u@127.0.0.1/d?hostaddr=8.8.8.8",
    "postgres://u@127.0.0.1/d?service=prod",
    "postgres://u@127.0.0.1/d?sslmode=require",
    "postgres://u@127.0.0.1/d#frag",
    "postgres:///d?host=/var/run/postgresql",
    "postgres://",
    "postgres://u@/d",
    "postgres://u@127.0.0.1:0/d",
    "postgres://u@127.0.0.1:99999/d",
    "mysql://u@127.0.0.1/d",
    "http://127.0.0.1/",
    "127.0.0.1",
    "",
  ])("refuses %s", (url) => {
    expect(parseLoopbackUrl(url).ok).toBe(false);
  });

  it("names the loopback rule when refusing a remote host", () => {
    const r = parseLoopbackUrl("postgres://u:p@db.example.com/d");
    expect(r).toEqual({ ok: false, error: expect.stringContaining("not a loopback address") });
  });

  it("never echoes the password of a refused URL", () => {
    const secret = "hunter2".repeat(2);
    const r = parseLoopbackUrl("postgres://u:" + secret + "@db.example.com/d");
    expect(JSON.stringify(r)).not.toContain("hunter2");
  });

  it("refuses control characters smuggled through percent-escapes", () => {
    expect(parseLoopbackUrl("postgres://u%0a@127.0.0.1/d").ok).toBe(false);
  });

  it("refuses bad percent-escapes", () => {
    expect(parseLoopbackUrl("postgres://u%zz@127.0.0.1/d").ok).toBe(false);
  });

  it("refuses oversized URLs", () => {
    expect(parseLoopbackUrl(`postgres://u@127.0.0.1/${"d".repeat(3000)}`).ok).toBe(false);
  });
});

describe("assertLoopbackHost", () => {
  it("throws for a remote host and passes for loopback", () => {
    expect(() => assertLoopbackHost("example.com")).toThrow(/loopback/);
    expect(() => assertLoopbackHost("127.0.0.1")).not.toThrow();
  });
});
