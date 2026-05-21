import { describe, expect, test } from "bun:test";

import { fingerprint, redactSecret } from "../src/fingerprint.js";

describe("fingerprint", () => {
  test("is deterministic for same input", () => {
    const a = fingerprint({
      providerName: "gitleaks",
      ruleId: "aws-key",
      file: "src/x.ts",
      line: 42,
    });
    const b = fingerprint({
      providerName: "gitleaks",
      ruleId: "aws-key",
      file: "src/x.ts",
      line: 42,
    });
    expect(a).toBe(b);
  });

  test("differs when file or line changes", () => {
    const a = fingerprint({
      providerName: "gitleaks",
      ruleId: "aws-key",
      file: "src/x.ts",
      line: 42,
    });
    const b = fingerprint({
      providerName: "gitleaks",
      ruleId: "aws-key",
      file: "src/x.ts",
      line: 43,
    });
    const c = fingerprint({
      providerName: "gitleaks",
      ruleId: "aws-key",
      file: "src/y.ts",
      line: 42,
    });
    expect(a).not.toBe(b);
    expect(a).not.toBe(c);
  });

  test("differs across providers", () => {
    const a = fingerprint({
      providerName: "gitleaks",
      ruleId: "aws-key",
      file: "src/x.ts",
      line: 42,
    });
    const b = fingerprint({
      providerName: "trufflehog",
      ruleId: "aws-key",
      file: "src/x.ts",
      line: 42,
    });
    expect(a).not.toBe(b);
  });

  test("handles missing fields without throwing", () => {
    const fp = fingerprint({
      providerName: "syft-grype",
      ruleId: "CVE-2024-1234",
      packageName: "lodash",
    });
    expect(fp).toHaveLength(64);
  });

  test("provider name is case-insensitive", () => {
    const a = fingerprint({ providerName: "Gitleaks", ruleId: "aws-key" });
    const b = fingerprint({ providerName: "gitleaks", ruleId: "aws-key" });
    expect(a).toBe(b);
  });
});

describe("redactSecret", () => {
  test("preserves head + tail + hash but never the raw secret", () => {
    const raw = "AKIAIOSFODNN7EXAMPLE";
    const out = redactSecret(raw);
    expect(out).not.toBe(raw);
    expect(out).toContain("AKIA");
    expect(out).toContain("MPLE");
    expect(out).toContain("…");
  });

  test("two redactions of the same secret are identical", () => {
    const raw = "ghp_abcdefghijklmnop";
    expect(redactSecret(raw)).toBe(redactSecret(raw));
  });
});
