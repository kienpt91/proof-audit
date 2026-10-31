import { describe, expect, it } from "vitest";
import { COMMANDS } from "../../../src/domain/schema/model.js";
import { defaultPrivileges, EXPOSED_SCHEMAS } from "../../../src/domain/supabase/defaults.js";

describe("EXPOSED_SCHEMAS", () => {
  it("is just public", () => {
    expect(EXPOSED_SCHEMAS).toEqual(["public"]);
  });
});

describe("defaultPrivileges", () => {
  it("grants every command to both client roles in public", () => {
    expect(defaultPrivileges("public")).toEqual({ anon: [...COMMANDS], authenticated: [...COMMANDS] });
  });

  it.each(["auth", "storage", "private", "extensions", "Public", ""])("grants nothing in %j", (schema) => {
    expect(defaultPrivileges(schema)).toEqual({ anon: [], authenticated: [] });
  });

  it("returns fresh arrays so callers cannot corrupt the defaults", () => {
    const first = defaultPrivileges("public");
    (first.anon as string[]).length = 0;
    (first.authenticated as string[]).push("bogus");
    expect(defaultPrivileges("public")).toEqual({ anon: [...COMMANDS], authenticated: [...COMMANDS] });
    expect(defaultPrivileges("public").anon).not.toBe(defaultPrivileges("public").anon);
  });
});
