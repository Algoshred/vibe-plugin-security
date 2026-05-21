/**
 * Agent-side SQLite cache for scan runs, findings, evidence.
 *
 * Findings live primarily in the backend (Prisma), but the agent keeps
 * a local cache so the UI is responsive without round-tripping every
 * query, and so failed pushes are retried on reconnect (rows with
 * `pushed=false`).
 */
import { Database } from "bun:sqlite";
import * as path from "node:path";
import { promises as fs } from "node:fs";

import type { EvidenceRecord, FindingRecord, ScanRunRecord, SecurityScanStatus } from "./types.js";

type Bindable = string | number | bigint | boolean | null | Uint8Array;

export class AgentSecurityStore {
  private db?: Database;

  async init(dataDir: string): Promise<void> {
    const dir = path.join(dataDir, "security");
    await fs.mkdir(dir, { recursive: true });
    this.db = new Database(path.join(dir, "security.sqlite"));
    this.db.exec(SCHEMA_SQL);
  }

  close(): void {
    this.db?.close();
    this.db = undefined;
  }

  // ── Scan runs ────────────────────────────────────────────────────────

  insertRun(run: ScanRunRecord): void {
    this.requireDb()
      .prepare(
        `INSERT OR REPLACE INTO security_scan_runs
         (run_id, vibe_id, workspace_id, repo_url, commit_sha, stage, provider_name,
          status, conclusion, started_at, finished_at, duration_ms, summary_json,
          policy_level, error_reason, pushed)
         VALUES ($run_id, $vibe_id, $workspace_id, $repo_url, $commit_sha, $stage,
          $provider_name, $status, $conclusion, $started_at, $finished_at,
          $duration_ms, $summary_json, $policy_level, $error_reason, $pushed)`,
      )
      .run({
        $run_id: run.runId,
        $vibe_id: run.vibeId,
        $workspace_id: run.workspaceId,
        $repo_url: run.repoUrl,
        $commit_sha: run.commit,
        $stage: run.stage,
        $provider_name: run.providerName,
        $status: run.status,
        $conclusion: run.conclusion ?? null,
        $started_at: run.startedAt ?? null,
        $finished_at: run.finishedAt ?? null,
        $duration_ms: run.durationMs ?? null,
        $summary_json: JSON.stringify(run.summary),
        $policy_level: run.policyLevel,
        $error_reason: run.errorReason ?? null,
        $pushed: run.pushed ? 1 : 0,
      });
  }

  updateRunStatus(
    runId: string,
    status: SecurityScanStatus,
    extra: Partial<ScanRunRecord> = {},
  ): void {
    const db = this.requireDb();
    const set: string[] = ["status = $status"];
    const params: Record<string, Bindable> = { $status: status, $run_id: runId };
    if (extra.conclusion !== undefined) {
      set.push("conclusion = $conclusion");
      params.$conclusion = extra.conclusion;
    }
    if (extra.startedAt !== undefined) {
      set.push("started_at = $started_at");
      params.$started_at = extra.startedAt;
    }
    if (extra.finishedAt !== undefined) {
      set.push("finished_at = $finished_at");
      params.$finished_at = extra.finishedAt;
    }
    if (extra.durationMs !== undefined) {
      set.push("duration_ms = $duration_ms");
      params.$duration_ms = extra.durationMs;
    }
    if (extra.summary !== undefined) {
      set.push("summary_json = $summary_json");
      params.$summary_json = JSON.stringify(extra.summary);
    }
    if (extra.errorReason !== undefined) {
      set.push("error_reason = $error_reason");
      params.$error_reason = extra.errorReason;
    }
    if (extra.pushed !== undefined) {
      set.push("pushed = $pushed");
      params.$pushed = extra.pushed ? 1 : 0;
    }
    db.prepare(`UPDATE security_scan_runs SET ${set.join(", ")} WHERE run_id = $run_id`).run(
      params,
    );
  }

  getRun(runId: string): ScanRunRecord | undefined {
    const row = this.requireDb()
      .prepare(`SELECT * FROM security_scan_runs WHERE run_id = ?`)
      .get(runId) as Record<string, unknown> | null;
    return row ? rowToRunRecord(row) : undefined;
  }

  listUnpushedRuns(): ScanRunRecord[] {
    const rows = this.requireDb()
      .prepare(`SELECT * FROM security_scan_runs WHERE pushed = 0`)
      .all() as Array<Record<string, unknown>>;
    return rows.map(rowToRunRecord);
  }

  // ── Findings ─────────────────────────────────────────────────────────

  upsertFinding(f: FindingRecord): void {
    this.requireDb()
      .prepare(
        `INSERT OR REPLACE INTO security_findings
         (fingerprint, vibe_id, scan_run_id, rule_id, title, description, severity, category,
          cwe_json, cve, file, line, col, package_name, package_version, fixed_version,
          remediation, status, raw_provider_ref, redacted_sample, first_seen_at, last_seen_at)
         VALUES ($fingerprint, $vibe_id, $scan_run_id, $rule_id, $title, $description,
          $severity, $category, $cwe_json, $cve, $file, $line, $col, $package_name,
          $package_version, $fixed_version, $remediation, $status, $raw_provider_ref,
          $redacted_sample, $first_seen_at, $last_seen_at)`,
      )
      .run({
        $fingerprint: f.fingerprint,
        $vibe_id: f.vibeId,
        $scan_run_id: f.scanRunId,
        $rule_id: f.ruleId,
        $title: f.title,
        $description: f.description ?? null,
        $severity: f.severity,
        $category: f.category,
        $cwe_json: f.cwe ? JSON.stringify(f.cwe) : null,
        $cve: f.cve ?? null,
        $file: f.file ?? null,
        $line: f.line ?? null,
        $col: f.column ?? null,
        $package_name: f.packageName ?? null,
        $package_version: f.packageVersion ?? null,
        $fixed_version: f.fixedVersion ?? null,
        $remediation: f.remediation ?? null,
        $status: f.status,
        $raw_provider_ref: f.rawProviderRef ?? null,
        $redacted_sample: f.redactedSample ?? null,
        $first_seen_at: f.firstSeenAt,
        $last_seen_at: f.lastSeenAt,
      });
  }

  listFindings(filter: {
    vibeId?: string;
    severity?: string;
    status?: string;
    limit?: number;
  }): FindingRecord[] {
    const where: string[] = [];
    const params: Record<string, Bindable> = {};
    if (filter.vibeId) {
      where.push("vibe_id = $vibe_id");
      params.$vibe_id = filter.vibeId;
    }
    if (filter.severity) {
      where.push("severity = $severity");
      params.$severity = filter.severity;
    }
    if (filter.status) {
      where.push("status = $status");
      params.$status = filter.status;
    }
    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const limit = Math.min(filter.limit ?? 200, 1000);
    const rows = this.requireDb()
      .prepare(
        `SELECT * FROM security_findings ${whereSql} ORDER BY last_seen_at DESC LIMIT ${limit}`,
      )
      .all(params) as Array<Record<string, unknown>>;
    return rows.map(rowToFindingRecord);
  }

  // ── Evidence ─────────────────────────────────────────────────────────

  upsertEvidence(e: EvidenceRecord): void {
    this.requireDb()
      .prepare(
        `INSERT OR REPLACE INTO security_evidence
         (evidence_id, scan_run_id, type, local_path, sha256, size_bytes, uploaded, s3_bucket, s3_key)
         VALUES ($evidence_id, $scan_run_id, $type, $local_path, $sha256, $size_bytes, $uploaded, $s3_bucket, $s3_key)`,
      )
      .run({
        $evidence_id: e.evidenceId,
        $scan_run_id: e.scanRunId,
        $type: e.type,
        $local_path: e.localPath,
        $sha256: e.sha256,
        $size_bytes: e.sizeBytes,
        $uploaded: e.uploaded ? 1 : 0,
        $s3_bucket: e.s3Bucket ?? null,
        $s3_key: e.s3Key ?? null,
      });
  }

  // ── Helpers ──────────────────────────────────────────────────────────

  private requireDb(): Database {
    if (!this.db) throw new Error("Agent security store not initialized");
    return this.db;
  }
}

const SCHEMA_SQL = `
  CREATE TABLE IF NOT EXISTS security_scan_runs (
    run_id        TEXT PRIMARY KEY,
    vibe_id       TEXT NOT NULL,
    workspace_id  TEXT NOT NULL,
    repo_url      TEXT NOT NULL,
    commit_sha    TEXT NOT NULL,
    stage         TEXT NOT NULL,
    provider_name TEXT NOT NULL,
    status        TEXT NOT NULL,
    conclusion    TEXT,
    started_at    INTEGER,
    finished_at   INTEGER,
    duration_ms   INTEGER,
    summary_json  TEXT NOT NULL DEFAULT '{}',
    policy_level  TEXT NOT NULL,
    error_reason  TEXT,
    pushed        INTEGER NOT NULL DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS idx_security_scan_runs_vibe_stage ON security_scan_runs(vibe_id, stage);
  CREATE INDEX IF NOT EXISTS idx_security_scan_runs_pushed ON security_scan_runs(pushed);

  CREATE TABLE IF NOT EXISTS security_findings (
    fingerprint        TEXT NOT NULL,
    vibe_id            TEXT NOT NULL,
    scan_run_id        TEXT NOT NULL,
    rule_id            TEXT NOT NULL,
    title              TEXT NOT NULL,
    description        TEXT,
    severity           TEXT NOT NULL,
    category           TEXT NOT NULL,
    cwe_json           TEXT,
    cve                TEXT,
    file               TEXT,
    line               INTEGER,
    col                INTEGER,
    package_name       TEXT,
    package_version    TEXT,
    fixed_version      TEXT,
    remediation        TEXT,
    status             TEXT NOT NULL DEFAULT 'open',
    raw_provider_ref   TEXT,
    redacted_sample    TEXT,
    first_seen_at      INTEGER NOT NULL,
    last_seen_at       INTEGER NOT NULL,
    PRIMARY KEY (fingerprint, vibe_id)
  );
  CREATE INDEX IF NOT EXISTS idx_security_findings_vibe ON security_findings(vibe_id, severity, status);
  CREATE INDEX IF NOT EXISTS idx_security_findings_scan ON security_findings(scan_run_id);

  CREATE TABLE IF NOT EXISTS security_evidence (
    evidence_id   TEXT PRIMARY KEY,
    scan_run_id   TEXT NOT NULL,
    type          TEXT NOT NULL,
    local_path    TEXT NOT NULL,
    sha256        TEXT NOT NULL,
    size_bytes    INTEGER NOT NULL,
    uploaded      INTEGER NOT NULL DEFAULT 0,
    s3_bucket     TEXT,
    s3_key        TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_security_evidence_scan ON security_evidence(scan_run_id);
`;

function rowToRunRecord(row: Record<string, unknown>): ScanRunRecord {
  return {
    runId: row.run_id as string,
    vibeId: row.vibe_id as string,
    workspaceId: row.workspace_id as string,
    repoUrl: row.repo_url as string,
    commit: row.commit_sha as string,
    stage: row.stage as ScanRunRecord["stage"],
    providerName: row.provider_name as string,
    status: row.status as ScanRunRecord["status"],
    conclusion: (row.conclusion as ScanRunRecord["conclusion"]) ?? undefined,
    startedAt: (row.started_at as number) ?? undefined,
    finishedAt: (row.finished_at as number) ?? undefined,
    durationMs: (row.duration_ms as number) ?? undefined,
    summary: JSON.parse((row.summary_json as string) || "{}") as ScanRunRecord["summary"],
    policyLevel: row.policy_level as ScanRunRecord["policyLevel"],
    errorReason: (row.error_reason as string) ?? undefined,
    pushed: Boolean(row.pushed),
  };
}

function rowToFindingRecord(row: Record<string, unknown>): FindingRecord {
  return {
    fingerprint: row.fingerprint as string,
    vibeId: row.vibe_id as string,
    scanRunId: row.scan_run_id as string,
    ruleId: row.rule_id as string,
    title: row.title as string,
    description: (row.description as string) ?? undefined,
    severity: row.severity as FindingRecord["severity"],
    category: row.category as FindingRecord["category"],
    cwe: row.cwe_json ? (JSON.parse(row.cwe_json as string) as string[]) : undefined,
    cve: (row.cve as string) ?? undefined,
    file: (row.file as string) ?? undefined,
    line: (row.line as number) ?? undefined,
    column: (row.col as number) ?? undefined,
    packageName: (row.package_name as string) ?? undefined,
    packageVersion: (row.package_version as string) ?? undefined,
    fixedVersion: (row.fixed_version as string) ?? undefined,
    remediation: (row.remediation as string) ?? undefined,
    status: row.status as FindingRecord["status"],
    rawProviderRef: (row.raw_provider_ref as string) ?? undefined,
    redactedSample: (row.redacted_sample as string) ?? undefined,
    firstSeenAt: row.first_seen_at as number,
    lastSeenAt: row.last_seen_at as number,
  };
}
