/**
 * Backend policy client.
 *
 * The release-gate provider doesn't run OPA in-process. It asks the
 * backend's `securityPolicyDecision(scanRunId)` resolver, which loads
 * the scan + open findings + active exceptions, POSTs to the existing
 * `opa-wspace:8181` sidecar with the appropriate Rego bundle, caches
 * the decision for 5 minutes keyed by `(scanRunId, policyVersion)`,
 * and returns `{ allow, deny }`.
 */
import type { HostServices } from "@vibecontrols/plugin-sdk/contract";
import type { PolicyDecision } from "./types.js";

const QUERY = `
  query SecurityPolicyDecision($scanRunId: ID!) {
    securityPolicyDecision(scanRunId: $scanRunId) {
      allow
      denyReasons
      evaluatedAt
      policyVersion
    }
  }
`;

export async function evaluatePolicy(
  host: HostServices,
  scanRunId: string,
): Promise<PolicyDecision> {
  if (!host.workspaceQuery) {
    throw new Error("policy-client: workspaceQuery not available on host");
  }
  const res = await host.workspaceQuery<{ securityPolicyDecision: PolicyDecision }>(QUERY, {
    scanRunId,
  });
  if (res.errors && res.errors.length > 0) {
    throw new Error(
      `policy-client: backend errors — ${res.errors.map((e) => e.message).join("; ")}`,
    );
  }
  if (!res.data?.securityPolicyDecision) {
    throw new Error("policy-client: missing securityPolicyDecision in response");
  }
  return res.data.securityPolicyDecision;
}
