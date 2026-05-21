import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";

import { AgentSecurityStore } from "../src/agent-store.js";

describe("AgentSecurityStore", () => {
  let store: AgentSecurityStore;
  let dir: string;

  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(tmpdir(), "vibe-security-test-"));
    store = new AgentSecurityStore();
    await store.init(dir);
  });

  afterEach(async () => {
    store.close();
    await fs.rm(dir, { recursive: true, force: true });
  });

  test("insertRun + getRun round-trip", () => {
    store.insertRun({
      runId: "r1",
      vibeId: "v1",
      workspaceId: "w1",
      repoUrl: "git@github.com:foo/bar.git",
      commit: "abc123",
      stage: "pull_request.fast",
      providerName: "gitleaks",
      status: "queued",
      summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      policyLevel: "warn",
      pushed: false,
    });
    const r = store.getRun("r1");
    expect(r).toBeDefined();
    expect(r?.providerName).toBe("gitleaks");
    expect(r?.pushed).toBe(false);
  });

  test("updateRunStatus updates targeted fields", () => {
    store.insertRun({
      runId: "r2",
      vibeId: "v1",
      workspaceId: "w1",
      repoUrl: "git@github.com:foo/bar.git",
      commit: "abc",
      stage: "build",
      providerName: "syft-grype",
      status: "queued",
      summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      policyLevel: "warn",
      pushed: false,
    });
    store.updateRunStatus("r2", "succeeded", {
      conclusion: "pass",
      finishedAt: 100,
      durationMs: 50,
      summary: { critical: 0, high: 0, medium: 2, low: 1, info: 0 },
    });
    const r = store.getRun("r2");
    expect(r?.status).toBe("succeeded");
    expect(r?.conclusion).toBe("pass");
    expect(r?.summary.medium).toBe(2);
  });

  test("listUnpushedRuns returns only pushed=false rows", () => {
    store.insertRun({
      runId: "r3",
      vibeId: "v1",
      workspaceId: "w1",
      repoUrl: "x",
      commit: "x",
      stage: "build",
      providerName: "p",
      status: "succeeded",
      summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      policyLevel: "warn",
      pushed: false,
    });
    store.insertRun({
      runId: "r4",
      vibeId: "v1",
      workspaceId: "w1",
      repoUrl: "x",
      commit: "x",
      stage: "build",
      providerName: "p",
      status: "succeeded",
      summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      policyLevel: "warn",
      pushed: true,
    });
    const unpushed = store.listUnpushedRuns();
    const ids = unpushed.map((r) => r.runId);
    expect(ids).toContain("r3");
    expect(ids).not.toContain("r4");
  });

  test("upsertFinding + listFindings filters", () => {
    const now = Date.now();
    store.upsertFinding({
      fingerprint: "fp1",
      vibeId: "v1",
      scanRunId: "r1",
      ruleId: "rule-1",
      title: "secret leaked",
      severity: "critical",
      category: "secret",
      status: "open",
      firstSeenAt: now,
      lastSeenAt: now,
    });
    store.upsertFinding({
      fingerprint: "fp2",
      vibeId: "v1",
      scanRunId: "r1",
      ruleId: "rule-2",
      title: "cve",
      severity: "low",
      category: "vuln",
      status: "open",
      firstSeenAt: now,
      lastSeenAt: now,
    });
    const crit = store.listFindings({ vibeId: "v1", severity: "critical" });
    expect(crit).toHaveLength(1);
    expect(crit[0].fingerprint).toBe("fp1");
  });

  test("upsertEvidence persists", () => {
    store.upsertEvidence({
      evidenceId: "e1",
      scanRunId: "r1",
      type: "sarif",
      localPath: "/tmp/sarif.json",
      sha256: "abc",
      sizeBytes: 100,
      uploaded: false,
    });
    // Re-upserting the same evidenceId should not throw.
    store.upsertEvidence({
      evidenceId: "e1",
      scanRunId: "r1",
      type: "sarif",
      localPath: "/tmp/sarif.json",
      sha256: "abc",
      sizeBytes: 100,
      uploaded: true,
      s3Bucket: "b",
      s3Key: "k",
    });
  });
});
