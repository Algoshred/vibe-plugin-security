/**
 * Provider resolver + timeout + retry + broadcast.
 *
 * Looks up the right provider for a stage (explicit `providerName` or
 * the configured default via the agent host's `getConfig`). Wraps
 * `provider.run()` in a per-stage timeout. Streams progress via
 * `hostServices.broadcast`.
 */
import { BoundLogger } from "@vibecontrols/plugin-sdk";
import type { HostServices } from "@vibecontrols/plugin-sdk/contract";

import {
  DEFAULT_PROVIDER_CONFIG_KEY,
  PROVIDER_TYPE_FOR_STAGE,
  type SecurityProvider,
  type SecurityScanInput,
  type SecurityScanResult,
  type SecurityServiceRegistry,
  type SecurityStage,
} from "./types.js";

const STAGE_TIMEOUTS_MS: Record<SecurityStage, number> = {
  "repo.onboard": 5 * 60_000,
  "developer.local": 2 * 60_000,
  "pull_request.fast": 5 * 60_000,
  "pull_request.deep": 15 * 60_000,
  "main.merge": 15 * 60_000,
  build: 15 * 60_000,
  "package.publish": 10 * 60_000,
  "deploy.preview": 20 * 60_000,
  "deploy.alpha": 20 * 60_000,
  "promote.prod": 2 * 60_000,
  "runtime.continuous": 5 * 60_000,
  "scheduled.rescan": 30 * 60_000,
  "incident.response": 30 * 60_000,
  "archive.offboard": 5 * 60_000,
};

const LOG_SOURCE = "security-dispatcher";

export class SecurityDispatcher {
  private registry?: SecurityServiceRegistry;
  private host?: HostServices;
  private log = new BoundLogger(undefined, LOG_SOURCE);
  private activeRuns = new Map<string, SecurityProvider>();

  init(host: HostServices): void {
    this.host = host;
    this.registry = host.serviceRegistry as unknown as SecurityServiceRegistry | undefined;
    this.log = new BoundLogger(host.logger, LOG_SOURCE);
  }

  async resolveProvider(stage: SecurityStage, explicit?: string): Promise<SecurityProvider> {
    if (!this.registry) {
      throw new Error("security-dispatcher: service registry unavailable");
    }
    const type = PROVIDER_TYPE_FOR_STAGE(stage);

    const name = explicit ?? (await this.defaultProviderName(stage));
    if (!name) {
      throw new Error(`security-dispatcher: no provider configured for stage ${stage}`);
    }
    const provider = this.registry.getProviderByName<SecurityProvider>(type, name);
    if (!provider) {
      throw new Error(`security-dispatcher: provider '${name}' not registered for type '${type}'`);
    }
    return provider;
  }

  async defaultProviderName(stage: SecurityStage): Promise<string | undefined> {
    const fromConfig = await this.host?.getConfig?.(DEFAULT_PROVIDER_CONFIG_KEY(stage));
    if (fromConfig) return fromConfig;

    const type = PROVIDER_TYPE_FOR_STAGE(stage);
    const entries = this.registry?.listProvidersForType(type) ?? [];
    const flagged = entries.find((e) => e.isDefault);
    if (flagged) return flagged.pluginName;
    if (entries.length === 1) return entries[0]?.pluginName;
    return undefined;
  }

  listProvidersForStage(stage: SecurityStage): Array<{ name: string; isDefault: boolean }> {
    const type = PROVIDER_TYPE_FOR_STAGE(stage);
    return (this.registry?.listProvidersForType(type) ?? []).map((e) => ({
      name: e.pluginName,
      isDefault: e.isDefault,
    }));
  }

  async setDefault(stage: SecurityStage, providerName: string): Promise<void> {
    // Verify the provider exists.
    await this.resolveProvider(stage, providerName);
    if (this.registry?.setProviderDefault) {
      this.registry.setProviderDefault(PROVIDER_TYPE_FOR_STAGE(stage), providerName);
    }
    const hostWithSet = this.host as
      | (HostServices & {
          setConfig?: (key: string, value: string) => Promise<void>;
        })
      | undefined;
    if (hostWithSet?.setConfig) {
      await hostWithSet.setConfig(DEFAULT_PROVIDER_CONFIG_KEY(stage), providerName);
    }
  }

  async runWithTimeout(
    provider: SecurityProvider,
    input: SecurityScanInput,
  ): Promise<SecurityScanResult> {
    this.activeRuns.set(input.runId, provider);
    const timeoutMs = STAGE_TIMEOUTS_MS[input.stage];
    try {
      const result = await Promise.race([
        provider.run(input),
        new Promise<SecurityScanResult>((_, reject) =>
          setTimeout(
            () =>
              reject(
                new Error(
                  `security-dispatcher: stage ${input.stage} exceeded timeout ${timeoutMs}ms`,
                ),
              ),
            timeoutMs,
          ),
        ),
      ]);
      return result;
    } finally {
      this.activeRuns.delete(input.runId);
    }
  }

  async cancel(runId: string): Promise<boolean> {
    const provider = this.activeRuns.get(runId);
    if (!provider) return false;
    try {
      await provider.cancel(runId);
      return true;
    } catch (err) {
      this.log.warn?.(`cancel(${runId}) failed`, { error: String(err) });
      return false;
    }
  }
}
