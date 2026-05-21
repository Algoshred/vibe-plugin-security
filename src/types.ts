/**
 * Shared types for the security lifecycle. Provider plugins implement
 * `SecurityProvider` and register on the agent service registry under
 * the per-stage provider type `security.<stage>` (e.g. `security.secrets`).
 *
 * Source-of-truth contract — bumping these is a SDK-version event: every
 * provider plugin must rebuild + republish.
 */

import type { HostServices } from "@vibecontrols/plugin-sdk/contract";

// ── Lifecycle stage taxonomy ───────────────────────────────────────────

export type SecurityStage =
  | "repo.onboard"
  | "developer.local"
  | "pull_request.fast"
  | "pull_request.deep"
  | "main.merge"
  | "build"
  | "package.publish"
  | "deploy.preview"
  | "deploy.alpha"
  | "promote.prod"
  | "runtime.continuous"
  | "scheduled.rescan"
  | "incident.response"
  | "archive.offboard";

export const ALL_STAGES: readonly SecurityStage[] = [
  "repo.onboard",
  "developer.local",
  "pull_request.fast",
  "pull_request.deep",
  "main.merge",
  "build",
  "package.publish",
  "deploy.preview",
  "deploy.alpha",
  "promote.prod",
  "runtime.continuous",
  "scheduled.rescan",
  "incident.response",
  "archive.offboard",
] as const;

export type SecuritySeverity = "critical" | "high" | "medium" | "low" | "info";

export type SecurityFindingCategory =
  | "secret"
  | "vuln"
  | "sast"
  | "license"
  | "policy"
  | "config"
  | "supplychain";

export type SecurityFindingStatus = "open" | "accepted" | "fixed" | "false_positive" | "suppressed";

export type SecurityScanStatus =
  | "queued"
  | "running"
  | "succeeded"
  | "failed"
  | "errored"
  | "cancelled";

export type SecurityScanConclusion = "pass" | "warn" | "fail" | "skipped";

export type SecurityPolicyLevel = "advisory" | "warn" | "block";

export type SecurityEvidenceType =
  | "sarif"
  | "sbom-cyclonedx"
  | "sbom-spdx"
  | "grype-json"
  | "cosign-bundle"
  | "provenance"
  | "opa-decision";

// ── Provider input / output ────────────────────────────────────────────

export interface SecurityProgressEvent {
  pct: number;
  message: string;
}

export interface SecurityScanInput {
  runId: string;
  vibeId: string;
  workspaceId: string;
  repoUrl: string;
  repoLocalPath: string;
  commit: string;
  stage: SecurityStage;
  profile: {
    kind: string;
    languages: string[];
    runtimes: string[];
  };
  policyLevel: SecurityPolicyLevel;
  config: Record<string, unknown>;
  workdir: string;
  onProgress?: (event: SecurityProgressEvent) => void;
}

export interface NormalizedFinding {
  fingerprint: string;
  ruleId: string;
  title: string;
  description?: string;
  severity: SecuritySeverity;
  category: SecurityFindingCategory;
  cwe?: string[];
  cve?: string;
  file?: string;
  line?: number;
  column?: number;
  packageName?: string;
  packageVersion?: string;
  fixedVersion?: string;
  remediation?: string;
  redactedSample?: string;
  rawProviderRef?: string;
}

export interface ScanEvidenceArtifact {
  type: SecurityEvidenceType;
  localPath: string;
  sha256: string;
  sizeBytes: number;
}

export interface SecurityScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface SecurityScanResult {
  runId: string;
  status: Exclude<SecurityScanStatus, "queued" | "running">;
  findings: NormalizedFinding[];
  evidence: ScanEvidenceArtifact[];
  durationMs: number;
  summary: SecurityScanSummary;
  errorReason?: string;
}

// ── Provider interface ─────────────────────────────────────────────────

export interface SecurityProvider {
  readonly name: string;
  readonly stage: SecurityStage;
  readonly toolVersion: string;
  init(host: HostServices): Promise<void>;
  ensureToolInstalled(): Promise<void>;
  run(input: SecurityScanInput): Promise<SecurityScanResult>;
  cancel(runId: string): Promise<void>;
  metadata(): SecurityProviderMetadata;
}

export interface SecurityProviderMetadata {
  stage: SecurityStage;
  supportedProfiles: string[];
  toolVersion: string;
  description?: string;
}

// ── Service registry shape (richer than SDK base) ──────────────────────

export interface SecurityServiceRegistry {
  registerService?(pluginName: string, serviceName: string, service: unknown): void;
  getProviderByName<T>(type: string, name: string): T | undefined;
  listProvidersForType(type: string): Array<{ pluginName: string; isDefault: boolean }>;
  setProviderDefault?(type: string, name: string): void;
}

// ── Manager-facing dispatch + cache types ──────────────────────────────

export interface ScanRequest {
  vibeId: string;
  workspaceId: string;
  repoUrl: string;
  repoLocalPath: string;
  commit: string;
  stage: SecurityStage;
  providerName?: string;
  policyLevel?: SecurityPolicyLevel;
  config?: Record<string, unknown>;
  profile?: SecurityScanInput["profile"];
}

export interface ScanRunRecord {
  runId: string;
  vibeId: string;
  workspaceId: string;
  repoUrl: string;
  commit: string;
  stage: SecurityStage;
  providerName: string;
  status: SecurityScanStatus;
  conclusion?: SecurityScanConclusion;
  startedAt?: number;
  finishedAt?: number;
  durationMs?: number;
  summary: SecurityScanSummary;
  policyLevel: SecurityPolicyLevel;
  errorReason?: string;
  pushed: boolean;
}

export interface FindingRecord extends NormalizedFinding {
  vibeId: string;
  scanRunId: string;
  status: SecurityFindingStatus;
  firstSeenAt: number;
  lastSeenAt: number;
}

export interface EvidenceRecord {
  evidenceId: string;
  scanRunId: string;
  type: SecurityEvidenceType;
  localPath: string;
  sha256: string;
  sizeBytes: number;
  uploaded: boolean;
  s3Bucket?: string;
  s3Key?: string;
}

export interface ExceptionRequest {
  findingFingerprint: string;
  vibeId: string;
  reason: string;
  compensatingControls?: string;
  expiresAt: string;
}

export interface PolicyDecision {
  allow: boolean;
  denyReasons: string[];
  evaluatedAt: string;
  policyVersion?: number;
}

export const DEFAULT_PROVIDER_CONFIG_KEY = (stage: SecurityStage): string =>
  `provider:default:security.${stage}`;

export const PROVIDER_TYPE_FOR_STAGE = (stage: SecurityStage): string => {
  // Per-stage provider types let each stage have an independent default.
  switch (stage) {
    case "pull_request.fast":
    case "pull_request.deep":
    case "developer.local":
      return "security.secrets";
    case "build":
    case "package.publish":
      return "security.sbom";
    case "promote.prod":
    case "deploy.alpha":
    case "deploy.preview":
      return "security.release";
    case "runtime.continuous":
    case "scheduled.rescan":
      return "security.runtime";
    case "repo.onboard":
      return "security.onboard";
    case "main.merge":
      return "security.scorecard";
    case "incident.response":
      return "security.incident";
    case "archive.offboard":
      return "security.archive";
  }
};
