# @vibecontrols/vibe-plugin-security

Security lifecycle orchestrator for the [VibeControls](https://vibecontrols.com) agent. Owns `/api/security/*`, the `vibe security` CLI, the SQLite cache of scan runs and findings, the evidence uploader, and the dispatcher that resolves which security provider to invoke per lifecycle stage.

This plugin does **not** scan anything by itself. It dispatches to concrete provider plugins registered on the agent's service registry under the per-stage provider types `security.secrets`, `security.sbom`, `security.release` (and future per-stage types). The user selects a default provider per stage; the meta plugin handles the rest.

## Install

```bash
vibe plugin install @vibecontrols/vibe-plugin-security
```

Then install one or more provider plugins for the stages you want to cover, e.g.:

```bash
vibe plugin install @vibecontrols/vibe-plugin-security-secrets-pr   # Gitleaks at pull_request.fast
vibe plugin install @vibecontrols/vibe-plugin-security-sbom-build   # Syft + Grype at build
vibe plugin install @vibecontrols/vibe-plugin-security-release-gate # OPA Rego at promote.prod
```

## Capabilities

| Capability  | Value  | Why                                                        |
| ----------- | ------ | ---------------------------------------------------------- |
| `storage`   | `rw`   | SQLite cache of scan runs / findings / evidence            |
| `broadcast` | `true` | Real-time WebSocket progress events                        |
| `audit`     | `true` | Audit log every scan, finding, exception                   |
| `telemetry` | `true` | Scan duration, finding count, conclusion                   |
| `gateway`   | `true` | Pushes findings + evidence to backend via `workspaceQuery` |

## REST surface

Mounted under `/api/profiles/<profile>/agent/security`:

```
POST   /api/security/scan                  { vibeId, repoUrl, commit, stage, providerName? }
GET    /api/security/scan/:runId
GET    /api/security/scan/:runId/stream    (SSE: progress, finding, evidence, done, error)
POST   /api/security/scan/:runId/cancel
GET    /api/security/findings?vibeId&severity&status
POST   /api/security/exceptions
GET    /api/security/policy/evaluate?scanRunId
GET    /api/security/providers
POST   /api/security/providers/default     { stage, providerName }
```

## CLI surface

```
vibe security scan      [--stage <stage>] [--provider <name>] [--vibe <id>]
vibe security status    [--vibe <id>]
vibe security providers [list | set-default --stage <stage> --provider <name>]
vibe security findings  [--severity <level>] [--status <state>] [--vibe <id>]
```

## Authoring a provider plugin

```ts
import { ProviderRegistry, createLifecycleHooks } from "@vibecontrols/plugin-sdk";
import type { VibePluginFactory, HostServices } from "@vibecontrols/plugin-sdk/contract";
import type { SecurityProvider } from "@vibecontrols/vibe-plugin-security/types";
import { ensureToolInstalled } from "@vibecontrols/vibe-plugin-security/tool-installer";

class MyProvider implements SecurityProvider {
  readonly name = "my-provider";
  readonly stage = "pull_request.fast";
  readonly toolVersion = "1.0.0";
  async init(_host: HostServices) {}
  async ensureToolInstalled() {
    /* download via tool-installer */
  }
  async run(input) {
    /* invoke tool, return SecurityScanResult */
  }
  async cancel(_runId: string) {}
  metadata() {
    return { stage: this.stage, supportedProfiles: ["backend"], toolVersion: this.toolVersion };
  }
}

export const createPlugin: VibePluginFactory = (ctx) => {
  const provider = new MyProvider();
  const lifecycle = createLifecycleHooks({
    name: "my-plugin",
    telemetryEventName: "my-plugin.ready",
    onInit: async (host) => {
      await provider.init(host);
      new ProviderRegistry(host).registerProvider(
        "security.secrets",
        "my-provider",
        () => provider,
      );
    },
  });
  return {
    name: "my-plugin",
    version: "2026.521.1",
    tags: ["backend", "provider", "integration"],
    capabilities: { storage: "rw", subprocess: true, audit: true, telemetry: true },
    onServerStart: lifecycle.onServerStart,
    onServerStop: lifecycle.onServerStop,
  };
};
export default createPlugin;
```

## License

Proprietary — Burdenoff Consultancy Services Pvt. Ltd.
