/**
 * Deterministic finding fingerprint. Two scans of the same code at the
 * same commit must produce identical fingerprints so the backend can
 * de-duplicate findings across runs and stages.
 *
 * Format: sha256(<provider>|<ruleId>|<file>|<line>|<symbol>).
 * Missing fields collapse to an empty string — order is stable.
 */
import { createHash } from "node:crypto";

export interface FingerprintInput {
  providerName: string;
  ruleId: string;
  file?: string;
  line?: number;
  symbol?: string;
  packageName?: string;
  packageVersion?: string;
}

export function fingerprint(input: FingerprintInput): string {
  const parts = [
    input.providerName.toLowerCase(),
    input.ruleId,
    input.file ?? "",
    input.line == null ? "" : String(input.line),
    input.symbol ?? "",
    input.packageName ?? "",
    input.packageVersion ?? "",
  ];
  return createHash("sha256").update(parts.join("|")).digest("hex");
}

/**
 * Redact a secret value for safe persistence. Returns a fingerprint of
 * the raw value plus the first 4 and last 4 characters of the original
 * — enough to help an investigator identify the leaked secret without
 * persisting the raw token.
 */
export function redactSecret(raw: string): string {
  const hash = createHash("sha256").update(raw).digest("hex").slice(0, 12);
  const head = raw.slice(0, 4);
  const tail = raw.slice(-4);
  return `${head}…${hash}…${tail}`;
}
