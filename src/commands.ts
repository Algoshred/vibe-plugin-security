/**
 * `vibe security ...` CLI surface. Implementation talks to the agent's
 * REST API rather than calling the manager directly so a remote operator
 * can drive scans against an agent on another machine.
 */
import type { HostServices } from "@vibecontrols/plugin-sdk/contract";

interface CommanderLike {
  command(name: string): CommanderLike;
  description(text: string): CommanderLike;
  option(flag: string, description: string, defaultValue?: unknown): CommanderLike;
  // Action callbacks are duck-typed by Commander; accept anything and
  // cast inside the callback to keep the SDK happy.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  action(fn: (...args: any[]) => void | Promise<void>): CommanderLike;
}

export function registerSecurityCommands(program: CommanderLike, host: HostServices): void {
  const baseUrl = () => host.getAgentBaseUrl?.() ?? "http://localhost:3005";
  const profile = process.env.VIBECONTROLS_PROFILE ?? "default";
  const path = (suffix: string) =>
    `${baseUrl()}/api/profiles/${encodeURIComponent(profile)}/agent/security${suffix}`;

  program.command("security").description("Security lifecycle orchestrator commands");

  program
    .command("security:scan")
    .description("Trigger a security scan for a vibe + stage")
    .option("--vibe <id>", "Vibe id")
    .option("--repo <url>", "Repo URL")
    .option("--repo-path <path>", "Local repo path")
    .option("--commit <sha>", "Commit SHA")
    .option("--stage <stage>", "Lifecycle stage")
    .option("--provider <name>", "Provider name (overrides default)")
    .option("--workspace <id>", "Workspace id")
    .action(async (opts: Record<string, string>) => {
      const res = await fetch(path("/scan"), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          vibeId: opts.vibe,
          workspaceId: opts.workspace ?? "",
          repoUrl: opts.repo,
          repoLocalPath: opts.repoPath,
          commit: opts.commit,
          stage: opts.stage,
          providerName: opts.provider,
        }),
      });
      const body = await res.json();
      console.log(JSON.stringify(body, null, 2));
    });

  program
    .command("security:status")
    .description("Look up a scan run by id")
    .option("--run <id>", "Scan run id")
    .action(async (opts: Record<string, string>) => {
      const res = await fetch(path(`/scan/${encodeURIComponent(opts.run)}`));
      console.log(JSON.stringify(await res.json(), null, 2));
    });

  program
    .command("security:findings")
    .description("List findings")
    .option("--vibe <id>", "Vibe id")
    .option("--severity <level>", "Filter by severity")
    .option("--status <state>", "Filter by status")
    .action(async (opts: Record<string, string>) => {
      const q = new URLSearchParams();
      if (opts.vibe) q.set("vibeId", opts.vibe);
      if (opts.severity) q.set("severity", opts.severity);
      if (opts.status) q.set("status", opts.status);
      const res = await fetch(path(`/findings?${q.toString()}`));
      console.log(JSON.stringify(await res.json(), null, 2));
    });

  program
    .command("security:providers")
    .description("List registered security providers per stage")
    .action(async () => {
      const res = await fetch(path("/providers"));
      console.log(JSON.stringify(await res.json(), null, 2));
    });

  program
    .command("security:providers:set-default")
    .description("Set the default provider for a stage")
    .option("--stage <stage>", "Lifecycle stage")
    .option("--provider <name>", "Provider name")
    .action(async (opts: Record<string, string>) => {
      const res = await fetch(path("/providers/default"), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ stage: opts.stage, providerName: opts.provider }),
      });
      console.log(JSON.stringify(await res.json(), null, 2));
    });
}
