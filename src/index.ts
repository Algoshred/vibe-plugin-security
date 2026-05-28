/**
 * @vibecontrols/vibe-plugin-security
 *
 * Security lifecycle orchestrator. Owns `/api/security/*` on the agent
 * and dispatches scans to concrete providers registered in the service
 * registry under per-stage provider types (`security.secrets`,
 * `security.sbom`, `security.release`, ...). This plugin does NOT scan
 * anything itself — it normalizes results, persists findings + evidence,
 * pushes them to the backend, and gates releases via the OPA-backed
 * policy decision.
 */
import { createLifecycleHooks, TelemetryEmitter } from "@vibecontrols/plugin-sdk";
import type {
  HostServices,
  ProfileContext,
  VibePlugin,
  VibePluginFactory,
} from "@vibecontrols/plugin-sdk/contract";

import { registerSecurityCommands } from "./commands.js";
import { SecurityManager } from "./manager.js";
import { createSecurityRoutes } from "./routes.js";

const PLUGIN_NAME = "security";
const PLUGIN_VERSION = "2026.527.1";

/**
 * Per-profile state (the `SecurityManager` instance) lives in this
 * closure so concurrent profiles can't share manager/SQLite handles.
 */
export const createPlugin: VibePluginFactory = (_ctx: ProfileContext): VibePlugin => {
  const manager = new SecurityManager();
  const telemetry = new TelemetryEmitter(PLUGIN_NAME, PLUGIN_VERSION);

  const lifecycle = createLifecycleHooks({
    name: PLUGIN_NAME,
    telemetryEventName: "security.meta.ready",
    onInit: async (host: HostServices) => {
      await manager.init(host);
      telemetry.emit("security.manager.ready");
    },
    onShutdown: async () => {
      await manager.stop();
    },
  });

  return {
    name: PLUGIN_NAME,
    version: PLUGIN_VERSION,
    description: "Security lifecycle orchestrator — dispatches to per-stage security providers.",
    tags: ["backend", "cli", "integration"],
    cliCommand: "security",
    apiPrefix: "/api/security",
    capabilities: {
      storage: "rw",
      broadcast: true,
      audit: true,
      telemetry: true,
      gateway: true,
    },
    createRoutes: () => createSecurityRoutes(manager),
    onServerStart: lifecycle.onServerStart,
    onServerStop: lifecycle.onServerStop,
    onCliSetup: (program: unknown, host: HostServices) => {
      registerSecurityCommands(program as Parameters<typeof registerSecurityCommands>[0], host);
    },
  };
};

export default createPlugin;

export { SecurityManager } from "./manager.js";
export type * from "./types.js";
