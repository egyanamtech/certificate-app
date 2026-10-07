import { hashPass, verifyPass, parseJson, CERT_COLS, DEFAULT_BRAND } from "../src/server";
import * as crypto from "crypto";

describe("hashPass", () => {
  test("returns salted scrypt hash", () => {
    const h = hashPass("admin123");
    expect(h).toMatch(/^scrypt\$[0-9a-f]{32}\$[0-9a-f]{128}$/);
  });

  test("is salted (unique per call)", () => {
    expect(hashPass("secret")).not.toBe(hashPass("secret"));
  });

  test("verifies correct password", () => {
    expect(verifyPass(hashPass("hello"), "hello")).toBe(true);
  });

  test("rejects wrong password", () => {
    expect(verifyPass(hashPass("hello"), "world")).toBe(false);
  });

  test("verifies legacy sha256 hashes and rejects wrong ones", () => {
    const legacy = crypto.createHash("sha256").update("oldpw").digest("hex");
    expect(verifyPass(legacy, "oldpw")).toBe(true);
    expect(verifyPass(legacy, "nope")).toBe(false);
  });

  test("coerces non-string input", () => {
    expect(verifyPass(hashPass(12345), 12345)).toBe(true);
  });
});

describe("parseJson", () => {
  test("returns fallback for null/undefined", () => {
    expect(parseJson(null, [])).toEqual([]);
    expect(parseJson(undefined, "fb")).toBe("fb");
  });

  test("returns object unchanged", () => {
    const obj = { a: 1 };
    expect(parseJson(obj, [])).toBe(obj);
  });

  test("parses JSON strings", () => {
    expect(parseJson('{"a":1}', {})).toEqual({ a: 1 });
    expect(parseJson("[1,2]", [])).toEqual([1, 2]);
  });

  test("returns fallback on malformed JSON", () => {
    expect(parseJson("not json", { fb: true })).toEqual({ fb: true });
  });
});

describe("CERT_COLS", () => {
  test("includes core columns", () => {
    expect(CERT_COLS).toContain("hash");
    expect(CERT_COLS).toContain("name");
    expect(CERT_COLS).toContain('"rollNumber"');
  });
});

describe("DEFAULT_BRAND", () => {
  test("has expected university default", () => {
    expect(DEFAULT_BRAND.name).toBe("XYZ University");
    expect(DEFAULT_BRAND.shortName).toBe("XYZ");
  });
});