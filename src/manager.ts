/**
 * SecurityManager — the orchestrator.
 *
 *   user                                 backend
 *    │  REST + SSE                            ▲
 *    ▼                                        │
 *   routes.ts ──► SecurityManager ──► dispatcher ──► provider.run()
 *                       │                            (in-process)
 *                       ├── agent-store (SQLite)
 *                       ├── normalizer
 *                       ├── evidence-uploader ──► backend presign + S3 PUT
 *                       └── workspaceQuery ──► pushSecurityScanRun mutation
 */
import { randomUUID } from "node:crypto";
import { promises as fs } from "node:fs";
import { homedir, tmpdir } from "node:os";
import * as path from "node:path";

import { BoundLogger } from "@vibecontrols/plugin-sdk";
import type { HostServices } from "@vibecontrols/plugin-sdk/contract";

import { AgentSecurityStore } from "./agent-store.js";
import { SecurityDispatcher } from "./dispatcher.js";
import { uploadEvidence } from "./evidence-uploader.js";
import { summarize } from "./normalizer.js";
import { evaluatePolicy } from "./policy-client.js";
import {
  type ExceptionRequest,
  type FindingRecord,
  type NormalizedFinding,
  type PolicyDecision,
  type ScanRequest,
  type ScanRunRecord,
  type SecurityScanConclusion,
  type SecurityScanInput,
  type SecurityScanResult,
  type SecurityStage,
} from "./types.js";

const LOG_SOURCE = "security-manager";

const PUSH_RUN_MUTATION = `
  mutation PushSecurityScanRun($input: PushSecurityScanRunInput!) {
    pushSecurityScanRun(input: $input) {
      id
      status
      conclusion
    }
  }
`;

const GET_CONFIG_QUERY = `
  query RepositorySecurityConfig($vibeId: ID!) {
    repositorySecurityConfig(vibeId: $vibeId) {
      enabledStages
      pluginAssignments
      policyLevel
      configYamlEquivalent
    }
  }
`;

const CREATE_EXCEPTION_MUTATION = `
  mutation CreateSecurityException($input: CreateSecurityExceptionInput!) {
    createSecurityException(input: $input) {
      id
      status
      expiresAt
    }
  }
`;

export class SecurityManager {
  readonly store = new AgentSecurityStore();
  readonly dispatcher = new SecurityDispatcher();
  private host?: HostServices;
  private log = new BoundLogger(undefined, LOG_SOURCE);
  private dataDir?: string;

  async init(host: HostServices): Promise<void> {
    this.host = host;
    this.log = new BoundLogger(host.logger, LOG_SOURCE);
    this.dataDir = host.getDataDir?.() ?? path.join(homedir(), ".boff/vibecontrols");
    await this.store.init(this.dataDir);
    this.dispatcher.init(host);
    void this.retryUnpushed();
  }

  async stop(): Promise<void> {
    this.store.close();
  }

  // ── Public surface ─────────────────────────────────────────────────

  async startScan(req: ScanRequest): Promise<ScanRunRecord> {
    const runId = randomUUID();
    const now = Date.now();
    const workdir = await this.createWorkdir(runId);

    const initial: ScanRunRecord = {
      runId,
      vibeId: req.vibeId,
      workspaceId: req.workspaceId,
      repoUrl: req.repoUrl,
      commit: req.commit,
      stage: req.stage,
      providerName: req.providerName ?? "(default)",
      status: "queued",
      summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      policyLevel: req.policyLevel ?? "warn",
      pushed: false,
    };
    this.store.insertRun(initial);

    void this.executeScan(runId, req, workdir, now).catch((err) => {
      this.log.error?.(`scan ${runId} crashed`, { error: String(err) });
      this.store.updateRunStatus(runId, "errored", {
        finishedAt: Date.now(),
        durationMs: Date.now() - now,
        errorReason: String(err),
      });
      this.host?.broadcast?.("security.scan.errored", { runId, reason: String(err) });
    });

    return initial;
  }

  getRun(runId: string): ScanRunRecord | undefined {
    return this.store.getRun(runId);
  }

  listFindings(filter: {
    vibeId?: string;
    severity?: string;
    status?: string;
    limit?: number;
  }): FindingRecord[] {
    return this.store.listFindings(filter);
  }

  listProvidersForStage(stage: SecurityStage): Array<{ name: string; isDefault: boolean }> {
    return this.dispatcher.listProvidersForStage(stage);
  }

  async setDefaultProvider(stage: SecurityStage, providerName: string): Promise<void> {
    await this.dispatcher.setDefault(stage, providerName);
  }

  async cancelScan(runId: string): Promise<boolean> {
    const ok = await this.dispatcher.cancel(runId);
    if (ok) {
      this.store.updateRunStatus(runId, "cancelled", {
        finishedAt: Date.now(),
      });
      this.host?.broadcast?.("security.scan.cancelled", { runId });
    }
    return ok;
  }

  async evaluatePolicy(scanRunId: string): Promise<PolicyDecision> {
    if (!this.host) throw new Error("manager not initialized");
    return evaluatePolicy(this.host, scanRunId);
  }

  async createException(req: ExceptionRequest): Promise<{ id: string }> {
    if (!this.host?.workspaceQuery) {
      throw new Error("manager: workspaceQuery unavailable");
    }
    const res = await this.host.workspaceQuery<{
      createSecurityException: { id: string };
    }>(CREATE_EXCEPTION_MUTATION, {
      input: {
        findingFingerprint: req.findingFingerprint,
        vibeId: req.vibeId,
        reason: req.reason,
        compensatingControls: req.compensatingControls,
        expiresAt: req.expiresAt,
      },
    });
    if (res.errors && res.errors.length > 0) {
      throw new Error(res.errors.map((e) => e.message).join("; "));
    }
    return { id: res.data?.createSecurityException.id ?? "" };
  }

  // ── Internal flow ──────────────────────────────────────────────────

  private async executeScan(
    runId: string,
    req: ScanRequest,
    workdir: string,
    queuedAt: number,
  ): Promise<void> {
    const provider = await this.dispatcher.resolveProvider(req.stage, req.providerName);
    this.store.updateRunStatus(runId, "running", {
      startedAt: Date.now(),
    });
    this.host?.broadcast?.("security.scan.started", {
      runId,
      stage: req.stage,
      provider: provider.name,
    });

    await provider.ensureToolInstalled();

    const cfg = await this.fetchVibeConfig(req.vibeId);
    const enrichedConfig = this.enrichStageConfig(
      req.stage,
      req.vibeId,
      req.config ?? cfg?.stageConfig ?? {},
    );

    const input: SecurityScanInput = {
      runId,
      vibeId: req.vibeId,
      workspaceId: req.workspaceId,
      repoUrl: req.repoUrl,
      repoLocalPath: req.repoLocalPath,
      commit: req.commit,
      stage: req.stage,
      profile: req.profile ?? cfg?.profile ?? { kind: "unknown", languages: [], runtimes: [] },
      policyLevel: req.policyLevel ?? cfg?.policyLevel ?? "warn",
      config: enrichedConfig,
      workdir,
      onProgress: ({ pct, message }) =>
        this.host?.broadcast?.("security.scan.progress", { runId, pct, message }),
    };

    const result = await this.dispatcher.runWithTimeout(provider, input);
    const finishedAt = Date.now();
    const durationMs = finishedAt - queuedAt;
    const summary = summarize(result.findings);
    const conclusion = this.deriveConclusion(result, input.policyLevel);

    this.store.updateRunStatus(runId, result.status, {
      conclusion,
      finishedAt,
      durationMs,
      summary,
      errorReason: result.errorReason,
    });

    // Persist findings locally.
    for (const f of result.findings) {
      this.upsertFinding(req.vibeId, runId, f, finishedAt);
    }

    this.host?.broadcast?.("security.scan.completed", {
      runId,
      status: result.status,
      conclusion,
      summary,
    });

    void this.pushRunToBackend(runId, result, summary, conclusion).catch((err) => {
      this.log.warn?.(`pushRunToBackend ${runId} failed; will retry on reconnect`, {
        error: String(err),
      });
    });
  }

  private upsertFinding(
    vibeId: string,
    scanRunId: string,
    f: NormalizedFinding,
    now: number,
  ): void {
    this.store.upsertFinding({
      ...f,
      vibeId,
      scanRunId,
      status: "open",
      firstSeenAt: now,
      lastSeenAt: now,
    });
  }

  private deriveConclusion(
    result: SecurityScanResult,
    policyLevel: ScanRunRecord["policyLevel"],
  ): SecurityScanConclusion {
    if (result.status === "cancelled" || result.status === "errored") return "skipped";
    const { critical, high } = summarize(result.findings);
    if (policyLevel === "advisory") return critical + high > 0 ? "warn" : "pass";
    if (policyLevel === "warn") return critical > 0 ? "fail" : high > 0 ? "warn" : "pass";
    return critical + high > 0 ? "fail" : "pass";
  }

  /**
   * Enrich the scan input config for stages that need cross-run context.
   *
   * For `promote.prod` we look up the upstream scan run (typically the
   * preceding `build` stage SBOM scan) and inject its findings + summary
   * into config so the release-gate provider can evaluate the policy
   * locally without round-tripping to a backend. The caller is expected
   * to set `config.upstreamScanRunId` to the build run's id.
   */
  private enrichStageConfig(
    stage: SecurityStage,
    vibeId: string,
    incoming: Record<string, unknown>,
  ): Record<string, unknown> {
    if (stage !== "promote.prod") return incoming;
    const upstreamScanRunId = incoming.upstreamScanRunId as string | undefined;
    if (!upstreamScanRunId) return incoming;
    const upstreamRun = this.store.getRun(upstreamScanRunId);
    const upstreamFindings = this.store
      .listFindings({ vibeId })
      .filter((f) => f.scanRunId === upstreamScanRunId)
      .map((f) => ({
        fingerprint: f.fingerprint,
        ruleId: f.ruleId,
        title: f.title,
        severity: f.severity,
        category: f.category,
        status: f.status,
        cve: f.cve,
        packageName: f.packageName,
      }));
    return {
      ...incoming,
      upstreamFindings,
      upstreamSummary: upstreamRun?.summary,
    };
  }

  private async fetchVibeConfig(vibeId: string): Promise<
    | {
        profile?: SecurityScanInput["profile"];
        policyLevel?: ScanRunRecord["policyLevel"];
        stageConfig?: Record<string, unknown>;
      }
    | undefined
  > {
    if (!this.host?.workspaceQuery) return undefined;
    try {
      const res = await this.host.workspaceQuery<{
        repositorySecurityConfig?: {
          policyLevel?: ScanRunRecord["policyLevel"];
          configYamlEquivalent?: {
            profile?: SecurityScanInput["profile"];
            stages?: Record<string, { config?: Record<string, unknown> }>;
          };
        };
      }>(GET_CONFIG_QUERY, { vibeId });
      const cfg = res.data?.repositorySecurityConfig;
      if (!cfg) return undefined;
      return {
        profile: cfg.configYamlEquivalent?.profile,
        policyLevel: cfg.policyLevel,
      };
    } catch (err) {
      this.log.warn?.(`fetchVibeConfig(${vibeId}) failed`, { error: String(err) });
      return undefined;
    }
  }

  private async pushRunToBackend(
    runId: string,
    result: SecurityScanResult,
    summary: ScanRunRecord["summary"],
    conclusion: SecurityScanConclusion,
  ): Promise<void> {
    if (!this.host?.workspaceQuery) {
      this.log.warn?.(`workspaceQuery unavailable; deferring push for ${runId}`);
      return;
    }
    const run = this.store.getRun(runId);
    if (!run) return;

    // Upload evidence first so we can reference IDs in the push.
    const evidenceRefs: Array<{
      evidenceId: string;
      type: string;
      sha256: string;
      sizeBytes: number;
    }> = [];
    for (const artifact of result.evidence) {
      const evidenceId = randomUUID();
      this.store.upsertEvidence({
        evidenceId,
        scanRunId: runId,
        type: artifact.type,
        localPath: artifact.localPath,
        sha256: artifact.sha256,
        sizeBytes: artifact.sizeBytes,
        uploaded: false,
      });
      try {
        const uploaded = await uploadEvidence(this.host, runId, artifact);
        this.store.upsertEvidence({
          evidenceId: uploaded.evidenceId,
          scanRunId: runId,
          type: artifact.type,
          localPath: artifact.localPath,
          sha256: artifact.sha256,
          sizeBytes: artifact.sizeBytes,
          uploaded: true,
          s3Bucket: uploaded.s3Bucket,
          s3Key: uploaded.s3Key,
        });
        evidenceRefs.push({
          evidenceId: uploaded.evidenceId,
          type: GQL_EVIDENCE_TYPES[artifact.type],
          sha256: artifact.sha256,
          sizeBytes: artifact.sizeBytes,
        });
      } catch (err) {
        this.log.warn?.(`evidence upload failed for ${runId}`, {
          error: String(err),
          type: artifact.type,
        });
      }
    }

    const findings = result.findings.map((f) => ({
      fingerprint: f.fingerprint,
      ruleId: f.ruleId,
      title: f.title,
      description: f.description,
      severity: f.severity.toUpperCase(),
      category: f.category.toUpperCase(),
      cwe: f.cwe ?? [],
      cve: f.cve,
      file: f.file,
      line: f.line,
      column: f.column,
      packageName: f.packageName,
      packageVersion: f.packageVersion,
      fixedVersion: f.fixedVersion,
      remediation: f.remediation,
      redactedSample: f.redactedSample,
      rawProviderRef: f.rawProviderRef,
    }));

    const pushRes = await this.host.workspaceQuery<{
      pushSecurityScanRun: { id: string; status: string; conclusion: string };
    }>(PUSH_RUN_MUTATION, {
      input: {
        runId,
        vibeId: run.vibeId,
        repoUrl: run.repoUrl,
        commit: run.commit,
        stage: GQL_STAGES[run.stage],
        providerName: run.providerName,
        status: run.status.toUpperCase(),
        conclusion: conclusion.toUpperCase(),
        startedAt: run.startedAt ? new Date(run.startedAt).toISOString() : null,
        finishedAt: run.finishedAt ? new Date(run.finishedAt).toISOString() : null,
        durationMs: run.durationMs ?? null,
        summary,
        policyLevel: run.policyLevel.toUpperCase(),
        errorReason: run.errorReason,
        findings,
        evidenceRefs,
      },
    });
    if (pushRes.errors && pushRes.errors.length > 0) {
      throw new Error(pushRes.errors.map((e) => e.message).join("; "));
    }
    this.store.updateRunStatus(runId, run.status, { pushed: true });
  }

  private async retryUnpushed(): Promise<void> {
    const unpushed = this.store.listUnpushedRuns();
    for (const run of unpushed) {
      this.log.info?.(`retrying push for unpushed run ${run.runId}`);
      // We don't have the original SecurityScanResult anymore; reconstruct
      // a minimal one from the cache so backend stays consistent.
      try {
        if (!this.host?.workspaceQuery) return;
        await this.host.workspaceQuery(PUSH_RUN_MUTATION, {
          input: {
            runId: run.runId,
            vibeId: run.vibeId,
            repoUrl: run.repoUrl,
            commit: run.commit,
            stage: GQL_STAGES[run.stage],
            providerName: run.providerName,
            status: run.status.toUpperCase(),
            conclusion: run.conclusion?.toUpperCase(),
            startedAt: run.startedAt ? new Date(run.startedAt).toISOString() : null,
            finishedAt: run.finishedAt ? new Date(run.finishedAt).toISOString() : null,
            durationMs: run.durationMs ?? null,
            summary: run.summary,
            policyLevel: run.policyLevel.toUpperCase(),
            errorReason: run.errorReason,
            findings: this.store
              .listFindings({ vibeId: run.vibeId })
              .filter((f) => f.scanRunId === run.runId)
              .map((f) => ({
                fingerprint: f.fingerprint,
                ruleId: f.ruleId,
                title: f.title,
                description: f.description,
                severity: f.severity.toUpperCase(),
                category: f.category.toUpperCase(),
                cwe: f.cwe ?? [],
                cve: f.cve,
                file: f.file,
                line: f.line,
                column: f.column,
                packageName: f.packageName,
                packageVersion: f.packageVersion,
                fixedVersion: f.fixedVersion,
                remediation: f.remediation,
                redactedSample: f.redactedSample,
                rawProviderRef: f.rawProviderRef,
              })),
            evidenceRefs: [],
          },
        });
        this.store.updateRunStatus(run.runId, run.status, { pushed: true });
      } catch (err) {
        this.log.warn?.(`retry push failed for ${run.runId}`, { error: String(err) });
      }
    }
  }

  private async createWorkdir(runId: string): Promise<string> {
    const dir = path.join(this.dataDir ?? tmpdir(), "security", "runs", runId);
    await fs.mkdir(dir, { recursive: true });
    return dir;
  }
}

// GQL enum value mappings — match server-side SecurityStage/Type enums.
const GQL_STAGES: Record<SecurityStage, string> = {
  "repo.onboard": "REPO_ONBOARD",
  "developer.local": "DEVELOPER_LOCAL",
  "pull_request.fast": "PULL_REQUEST_FAST",
  "pull_request.deep": "PULL_REQUEST_DEEP",
  "main.merge": "MAIN_MERGE",
  build: "BUILD",
  "package.publish": "PACKAGE_PUBLISH",
  "deploy.preview": "DEPLOY_PREVIEW",
  "deploy.alpha": "DEPLOY_ALPHA",
  "promote.prod": "PROMOTE_PROD",
  "runtime.continuous": "RUNTIME_CONTINUOUS",
  "scheduled.rescan": "SCHEDULED_RESCAN",
  "incident.response": "INCIDENT_RESPONSE",
  "archive.offboard": "ARCHIVE_OFFBOARD",
};

const GQL_EVIDENCE_TYPES: Record<string, string> = {
  sarif: "SARIF",
  "sbom-cyclonedx": "SBOM_CYCLONEDX",
  "sbom-spdx": "SBOM_SPDX",
  "grype-json": "GRYPE_JSON",
  "cosign-bundle": "COSIGN_BUNDLE",
  provenance: "PROVENANCE",
  "opa-decision": "OPA_DECISION",
};
