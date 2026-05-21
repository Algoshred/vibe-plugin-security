import { describe, expect, test } from "bun:test";

import {
  normalizeGrype,
  normalizeOpaDecision,
  normalizeSarif,
  summarize,
} from "../src/normalizer.js";

describe("normalizeSarif", () => {
  test("parses Gitleaks-shaped SARIF into NormalizedFinding[]", () => {
    const sarif = JSON.stringify({
      runs: [
        {
          tool: { driver: { name: "gitleaks" } },
          results: [
            {
              ruleId: "aws-access-key",
              level: "error",
              message: { text: "AWS access key leaked" },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: "apps/api/.env.example" },
                    region: {
                      startLine: 3,
                      startColumn: 1,
                      snippet: { text: "AKIAIOSFODNN7EXAMPLE" },
                    },
                  },
                },
              ],
            },
          ],
        },
      ],
    });
    const findings = normalizeSarif(sarif, "gitleaks", "secret");
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("aws-access-key");
    expect(findings[0].severity).toBe("high"); // SARIF "error" → high
    expect(findings[0].category).toBe("secret");
    expect(findings[0].file).toBe("apps/api/.env.example");
    expect(findings[0].line).toBe(3);
    expect(findings[0].redactedSample).toBeDefined();
    expect(findings[0].redactedSample).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });

  test("returns [] on malformed JSON", () => {
    expect(normalizeSarif("not json", "gitleaks", "secret")).toEqual([]);
  });

  test("honors properties.severity over level", () => {
    const sarif = JSON.stringify({
      runs: [
        {
          results: [
            {
              ruleId: "x",
              level: "warning",
              message: { text: "x" },
              properties: { severity: "critical" },
              locations: [],
            },
          ],
        },
      ],
    });
    expect(normalizeSarif(sarif, "p", "sast")[0].severity).toBe("critical");
  });
});

describe("normalizeGrype", () => {
  test("parses Grype matches[] with CVE + fixedVersion", () => {
    const raw = JSON.stringify({
      matches: [
        {
          vulnerability: {
            id: "CVE-2024-1234",
            severity: "High",
            description: "RCE in lodash",
            fix: { versions: ["4.17.21"], state: "fixed" },
          },
          artifact: {
            name: "lodash",
            version: "4.17.4",
            type: "npm",
            locations: [{ path: "package-lock.json" }],
          },
        },
      ],
    });
    const findings = normalizeGrype(raw, "syft-grype");
    expect(findings).toHaveLength(1);
    expect(findings[0].cve).toBe("CVE-2024-1234");
    expect(findings[0].severity).toBe("high");
    expect(findings[0].fixedVersion).toBe("4.17.21");
    expect(findings[0].packageName).toBe("lodash");
    expect(findings[0].remediation).toContain("Upgrade lodash");
  });
});

describe("normalizeOpaDecision", () => {
  test("maps deny[] strings into policy findings", () => {
    const raw = JSON.stringify({
      result: {
        allow: false,
        deny: ["1 critical secret finding is open", "SBOM missing for artifact digest"],
      },
    });
    const findings = normalizeOpaDecision(raw, "opa-release-gate");
    expect(findings).toHaveLength(2);
    expect(findings[0].category).toBe("policy");
    expect(findings[0].severity).toBe("high");
    expect(findings[1].title).toContain("SBOM missing");
  });

  test("handles deny[] object form with severity", () => {
    const raw = JSON.stringify({
      result: { allow: false, deny: [{ msg: "critical CVE", severity: "critical" }] },
    });
    const findings = normalizeOpaDecision(raw, "opa-release-gate");
    expect(findings[0].severity).toBe("critical");
  });
});

describe("summarize", () => {
  test("counts by severity", () => {
    const s = summarize([
      { fingerprint: "a", ruleId: "1", title: "x", severity: "critical", category: "vuln" },
      { fingerprint: "b", ruleId: "2", title: "x", severity: "high", category: "vuln" },
      { fingerprint: "c", ruleId: "3", title: "x", severity: "high", category: "vuln" },
      { fingerprint: "d", ruleId: "4", title: "x", severity: "info", category: "vuln" },
    ]);
    expect(s).toEqual({ critical: 1, high: 2, medium: 0, low: 0, info: 1 });
  });
});
