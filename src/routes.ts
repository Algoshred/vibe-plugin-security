/**
 * HTTP + SSE routes for the security meta plugin. Mounted under
 * `/api/security` via the plugin's `apiPrefix`. The agent's path-utils
 * surfaces this under `/api/profiles/<profile>/agent/security` at
 * runtime; the Elysia instance only knows the relative path.
 */
import { Elysia, t } from "elysia";

import type { SecurityManager } from "./manager.js";
import { ALL_STAGES, type SecurityStage } from "./types.js";

export function createSecurityRoutes(manager: SecurityManager) {
  return (
    new Elysia()

      // ── Providers ──────────────────────────────────────────────────
      .get("/providers", () => {
        const byStage: Record<string, Array<{ name: string; isDefault: boolean }>> = {};
        for (const stage of ALL_STAGES) {
          byStage[stage] = manager.listProvidersForStage(stage);
        }
        return { stages: byStage };
      })
      .post(
        "/providers/default",
        async ({ body, set }) => {
          try {
            await manager.setDefaultProvider(body.stage as SecurityStage, body.providerName);
            return { success: true };
          } catch (err) {
            set.status = 400;
            return { error: String(err) };
          }
        },
        {
          body: t.Object({ stage: t.String(), providerName: t.String() }),
        },
      )

      // ── Scans ──────────────────────────────────────────────────────
      .post(
        "/scan",
        async ({ body, set }) => {
          try {
            const run = await manager.startScan({
              vibeId: body.vibeId,
              workspaceId: body.workspaceId,
              repoUrl: body.repoUrl,
              repoLocalPath: body.repoLocalPath,
              commit: body.commit,
              stage: body.stage as SecurityStage,
              providerName: body.providerName,
              policyLevel: body.policyLevel,
              config: body.config,
              profile: body.profile,
            });
            return { runId: run.runId, status: run.status };
          } catch (err) {
            set.status = 400;
            return { error: String(err) };
          }
        },
        {
          body: t.Object({
            vibeId: t.String(),
            workspaceId: t.String(),
            repoUrl: t.String(),
            repoLocalPath: t.String(),
            commit: t.String(),
            stage: t.String(),
            providerName: t.Optional(t.String()),
            policyLevel: t.Optional(
              t.Union([t.Literal("advisory"), t.Literal("warn"), t.Literal("block")]),
            ),
            config: t.Optional(t.Any()),
            profile: t.Optional(
              t.Object({
                kind: t.String(),
                languages: t.Array(t.String()),
                runtimes: t.Array(t.String()),
              }),
            ),
          }),
        },
      )
      .get("/scan/:runId", ({ params, set }) => {
        const run = manager.getRun(params.runId);
        if (!run) {
          set.status = 404;
          return { error: "Scan run not found" };
        }
        return { run };
      })
      .post("/scan/:runId/cancel", async ({ params }) => {
        const ok = await manager.cancelScan(params.runId);
        return { cancelled: ok };
      })
      .get("/scan/:runId/stream", ({ params, set }) => {
        // The agent runtime upgrades this path to its broadcast bus when a
        // request reaches it (the websocket handler is registered by the
        // agent core, not Elysia). Returning here is mainly to short-circuit
        // misrouted requests with a 200 + hint.
        set.headers["content-type"] = "text/plain";
        return `Connect via WebSocket to receive progress events for run ${params.runId}. Channels: security.scan.{started,progress,completed,errored,cancelled}.`;
      })

      // ── Findings ───────────────────────────────────────────────────
      .get("/findings", ({ query }) => {
        const findings = manager.listFindings({
          vibeId: query.vibeId,
          severity: query.severity,
          status: query.status,
          limit: query.limit ? Number(query.limit) : undefined,
        });
        return { findings, total: findings.length };
      })

      // ── Exceptions ─────────────────────────────────────────────────
      .post(
        "/exceptions",
        async ({ body, set }) => {
          try {
            const exc = await manager.createException({
              findingFingerprint: body.findingFingerprint,
              vibeId: body.vibeId,
              reason: body.reason,
              compensatingControls: body.compensatingControls,
              expiresAt: body.expiresAt,
            });
            return { id: exc.id };
          } catch (err) {
            set.status = 400;
            return { error: String(err) };
          }
        },
        {
          body: t.Object({
            findingFingerprint: t.String(),
            vibeId: t.String(),
            reason: t.String(),
            compensatingControls: t.Optional(t.String()),
            expiresAt: t.String(),
          }),
        },
      )

      // ── Policy ─────────────────────────────────────────────────────
      .get("/policy/evaluate", async ({ query, set }) => {
        if (!query.scanRunId) {
          set.status = 400;
          return { error: "scanRunId required" };
        }
        try {
          return await manager.evaluatePolicy(query.scanRunId);
        } catch (err) {
          set.status = 500;
          return { error: String(err) };
        }
      })

      // ── Health ─────────────────────────────────────────────────────
      .get("/health", () => ({ manager: "ok", stages: ALL_STAGES.length }))
  );
}
