/**
 * Evidence uploader.
 *
 * For each evidence artifact produced by a scan, asks the backend for
 * a presigned PUT (15min TTL, SSE-S3, Content-SHA256 header enforced)
 * to the `burdenoff-aws-{env}-vibecontrols-evidence` bucket, then PUTs
 * the file directly. The backend creates the `SecurityEvidence` row
 * in PENDING state during presign; once the PUT succeeds we mark it
 * `uploaded=true` locally and reference its ID when pushing the run.
 */
import { promises as fs } from "node:fs";
import type { HostServices } from "@vibecontrols/plugin-sdk/contract";

import type { ScanEvidenceArtifact, SecurityEvidenceType } from "./types.js";

const PRESIGN_MUTATION = `
  mutation PresignSecurityEvidence(
    $scanRunId: ID!
    $type: SecurityEvidenceType!
    $sha256: String!
    $sizeBytes: Int!
  ) {
    presignSecurityEvidence(
      scanRunId: $scanRunId
      type: $type
      sha256: $sha256
      sizeBytes: $sizeBytes
    ) {
      evidenceId
      uploadUrl
      method
      expiresAt
      requiredHeaders
      s3Bucket
      s3Key
    }
  }
`;

export interface UploadedEvidence {
  evidenceId: string;
  type: SecurityEvidenceType;
  sha256: string;
  sizeBytes: number;
  s3Bucket: string;
  s3Key: string;
}

export async function uploadEvidence(
  host: HostServices,
  scanRunId: string,
  artifact: ScanEvidenceArtifact,
): Promise<UploadedEvidence> {
  if (!host.workspaceQuery) {
    throw new Error("evidence-uploader: workspaceQuery not available");
  }
  const presignRes = await host.workspaceQuery<{
    presignSecurityEvidence: {
      evidenceId: string;
      uploadUrl: string;
      method: string;
      expiresAt: string;
      requiredHeaders: Record<string, string>;
      s3Bucket: string;
      s3Key: string;
    };
  }>(PRESIGN_MUTATION, {
    scanRunId,
    type: GQL_TYPE_MAP[artifact.type],
    sha256: artifact.sha256,
    sizeBytes: artifact.sizeBytes,
  });
  if (presignRes.errors && presignRes.errors.length > 0) {
    throw new Error(
      `evidence-uploader: presign errors — ${presignRes.errors.map((e) => e.message).join("; ")}`,
    );
  }
  const presign = presignRes.data?.presignSecurityEvidence;
  if (!presign) throw new Error("evidence-uploader: missing presign result");

  const body = await fs.readFile(artifact.localPath);
  const putRes = await fetch(presign.uploadUrl, {
    method: presign.method.toUpperCase(),
    headers: presign.requiredHeaders,
    body,
  });
  if (!putRes.ok) {
    throw new Error(`evidence-uploader: PUT failed ${putRes.status} ${putRes.statusText}`);
  }
  return {
    evidenceId: presign.evidenceId,
    type: artifact.type,
    sha256: artifact.sha256,
    sizeBytes: artifact.sizeBytes,
    s3Bucket: presign.s3Bucket,
    s3Key: presign.s3Key,
  };
}

const GQL_TYPE_MAP: Record<SecurityEvidenceType, string> = {
  sarif: "SARIF",
  "sbom-cyclonedx": "SBOM_CYCLONEDX",
  "sbom-spdx": "SBOM_SPDX",
  "grype-json": "GRYPE_JSON",
  "cosign-bundle": "COSIGN_BUNDLE",
  provenance: "PROVENANCE",
  "opa-decision": "OPA_DECISION",
};
