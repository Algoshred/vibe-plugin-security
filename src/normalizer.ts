/**
 * Tool-output → NormalizedFinding[] mappers.
 *
 * Each provider plugin produces its tool's native output (SARIF for
 * Gitleaks, CycloneDX JSON for Syft, JSON for Grype, OPA decision JSON
 * for the release-gate). The meta plugin normalizes everything into the
 * shared `NormalizedFinding` shape before persisting, so the backend
 * stores one consistent model regardless of which tool produced a
 * finding.
 */
import { fingerprint, redactSecret } from "./fingerprint.js";
import type { NormalizedFinding, SecurityFindingCategory, SecuritySeverity } from "./types.js";

// ── SARIF (Gitleaks, Semgrep, CodeQL) ──────────────────────────────────

interface SarifReport {
  runs?: Array<{
    tool?: { driver?: { name?: string } };
    results?: SarifResult[];
  }>;
}

interface SarifResult {
  ruleId?: string;
  level?: string;
  message?: { text?: string };
  locations?: Array<{
    physicalLocation?: {
      artifactLocation?: { uri?: string };
      region?: { startLine?: number; startColumn?: number; snippet?: { text?: string } };
    };
  }>;
  partialFingerprints?: Record<string, string>;
  properties?: { tags?: string[]; severity?: string };
}

const SARIF_LEVEL_TO_SEVERITY: Record<string, SecuritySeverity> = {
  error: "high",
  warning: "medium",
  note: "low",
  none: "info",
};

export function normalizeSarif(
  raw: string,
  providerName: string,
  defaultCategory: SecurityFindingCategory,
): NormalizedFinding[] {
  let report: SarifReport;
  try {
    report = JSON.parse(raw) as SarifReport;
  } catch {
    return [];
  }
  const out: NormalizedFinding[] = [];
  for (const run of report.runs ?? []) {
    for (const r of run.results ?? []) {
      const loc = r.locations?.[0]?.physicalLocation;
      const file = loc?.artifactLocation?.uri;
      const line = loc?.region?.startLine;
      const column = loc?.region?.startColumn;
      const snippet = loc?.region?.snippet?.text;
      const ruleId = r.ruleId ?? "unknown";
      const propSev = r.properties?.severity?.toLowerCase();
      const severity =
        (propSev as SecuritySeverity | undefined) ??
        SARIF_LEVEL_TO_SEVERITY[(r.level ?? "warning").toLowerCase()] ??
        "medium";
      const title = r.message?.text?.split("\n")[0] ?? ruleId;
      out.push({
        fingerprint: fingerprint({
          providerName,
          ruleId,
          file,
          line,
          symbol: snippet?.slice(0, 64),
        }),
        ruleId,
        title,
        description: r.message?.text,
        severity,
        category: defaultCategory,
        file,
        line,
        column,
        rawProviderRef: r.partialFingerprints ? JSON.stringify(r.partialFingerprints) : undefined,
        redactedSample: defaultCategory === "secret" && snippet ? redactSecret(snippet) : undefined,
      });
    }
  }
  return out;
}

// ── Grype JSON ─────────────────────────────────────────────────────────

interface GrypeReport {
  matches?: Array<{
    vulnerability?: {
      id?: string;
      severity?: string;
      description?: string;
      cvss?: Array<{ metrics?: { baseScore?: number } }>;
      fix?: { versions?: string[]; state?: string };
    };
    artifact?: {
      name?: string;
      version?: string;
      type?: string;
      locations?: Array<{ path?: string }>;
    };
  }>;
}

const GRYPE_SEVERITY: Record<string, SecuritySeverity> = {
  Critical: "critical",
  High: "high",
  Medium: "medium",
  Low: "low",
  Negligible: "info",
  Unknown: "info",
};

export function normalizeGrype(raw: string, providerName: string): NormalizedFinding[] {
  let report: GrypeReport;
  try {
    report = JSON.parse(raw) as GrypeReport;
  } catch {
    return [];
  }
  const out: NormalizedFinding[] = [];
  for (const m of report.matches ?? []) {
    const cve = m.vulnerability?.id;
    const pkg = m.artifact?.name;
    const ver = m.artifact?.version;
    const file = m.artifact?.locations?.[0]?.path;
    const fixed = m.vulnerability?.fix?.versions?.[0];
    const sev = GRYPE_SEVERITY[m.vulnerability?.severity ?? "Unknown"] ?? "info";
    out.push({
      fingerprint: fingerprint({
        providerName,
        ruleId: cve ?? "unknown",
        file,
        packageName: pkg,
        packageVersion: ver,
      }),
      ruleId: cve ?? "unknown",
      title: `${cve ?? "Vulnerability"} in ${pkg ?? "unknown"}@${ver ?? "?"}`,
      description: m.vulnerability?.description,
      severity: sev,
      category: "vuln",
      cve,
      file,
      packageName: pkg,
      packageVersion: ver,
      fixedVersion: fixed,
      remediation: fixed ? `Upgrade ${pkg} to ${fixed} or later.` : undefined,
    });
  }
  return out;
}

// ── OPA decision (release-gate) ────────────────────────────────────────

interface OpaDecision {
  result?: {
    allow?: boolean;
    deny?: string[] | Array<{ msg: string; severity?: string }>;
  };
}

export function normalizeOpaDecision(raw: string, providerName: string): NormalizedFinding[] {
  let report: OpaDecision;
  try {
    report = JSON.parse(raw) as OpaDecision;
  } catch {
    return [];
  }
  const denies = report.result?.deny ?? [];
  const out: NormalizedFinding[] = [];
  let i = 0;
  for (const d of denies) {
    i++;
    const msg = typeof d === "string" ? d : d.msg;
    const severityStr = (typeof d === "object" ? d.severity : undefined) ?? "high";
    out.push({
      fingerprint: fingerprint({
        providerName,
        ruleId: `policy.deny.${i}`,
        symbol: msg,
      }),
      ruleId: `policy.deny.${i}`,
      title: msg,
      description: msg,
      severity: severityStr as SecuritySeverity,
      category: "policy",
      remediation:
        "Resolve the underlying findings, request a security exception, or adjust the policy.",
    });
  }
  return out;
}

// ── Summary ────────────────────────────────────────────────────────────

export function summarize(findings: NormalizedFinding[]): {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
} {
  const s = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) s[f.severity]++;
  return s;
}
