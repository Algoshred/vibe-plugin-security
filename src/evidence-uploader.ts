/**
 * Evidence uploader.
 *
 * Evidence files are stored in the workspace file library (wspace-files-svc)
 * on behalf of the signed-in user; the agent never talks to object storage
 * with credentials of its own. For each artifact of a pushed scan run:
 *
 *   1. `presignSecurityEvidence` opens an upload for the run and returns
 *      either one presigned PUT (`DIRECT`, with the headers it is signed for)
 *      or one presigned PUT per part (`MULTIPART`, files over 5 MiB).
 *   2. The agent PUTs the bytes (each part's ETag is kept).
 *   3. `completeSecurityEvidenceUpload` hands the ETags back; the backend
 *      verifies the declared size and SHA-256 and the evidence becomes
 *      UPLOADED.
 *
 * The scan run must already be pushed: presigning names the backend's run id.
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
      uploadType
      uploadUrl
      method
      expiresAt
      requiredHeaders
      parts {
        partNumber
        url
        offset
        length
      }
    }
  }
`;

const COMPLETE_MUTATION = `
  mutation CompleteSecurityEvidenceUpload(
    $evidenceId: ID!
    $parts: [SecurityEvidenceUploadedPartInput!]
  ) {
    completeSecurityEvidenceUpload(evidenceId: $evidenceId, parts: $parts) {
      id
      status
      fileId
    }
  }
`;

interface EvidenceUploadPart {
  partNumber: number;
  url: string;
  offset: number;
  length: number;
}

interface EvidencePresign {
  evidenceId: string;
  uploadType: "DIRECT" | "MULTIPART";
  uploadUrl: string | null;
  method: string;
  expiresAt: string;
  requiredHeaders: Record<string, string>;
  parts: EvidenceUploadPart[];
}

export interface UploadedEvidence {
  evidenceId: string;
  type: SecurityEvidenceType;
  sha256: string;
  sizeBytes: number;
  /** wspace-files-svc File id of the stored evidence. */
  fileId: string;
}

type WorkspaceQuery = NonNullable<HostServices["workspaceQuery"]>;

function errorsOf(response: { errors?: Array<{ message: string }> }): string | null {
  return response.errors && response.errors.length > 0
    ? response.errors.map((e) => e.message).join("; ")
    : null;
}

async function put(
  url: string,
  method: string,
  headers: Record<string, string>,
  body: Uint8Array,
  label: string,
): Promise<Response> {
  const response = await fetch(url, { method, headers, body });
  if (!response.ok) {
    throw new Error(
      `evidence-uploader: ${label} PUT failed ${response.status} ${response.statusText}`,
    );
  }
  return response;
}

async function putParts(
  presign: EvidencePresign,
  body: Uint8Array,
): Promise<Array<{ partNumber: number; etag: string }>> {
  if (presign.parts.length === 0) {
    throw new Error("evidence-uploader: multipart upload without parts");
  }
  const uploaded: Array<{ partNumber: number; etag: string }> = [];
  for (const part of presign.parts) {
    const end = part.offset + part.length;
    if (part.offset < 0 || part.length <= 0 || end > body.byteLength) {
      throw new Error(`evidence-uploader: part ${part.partNumber} is outside the file`);
    }
    const response = await put(
      part.url,
      "PUT",
      {},
      body.subarray(part.offset, end),
      `part ${part.partNumber}`,
    );
    const etag = response.headers.get("etag");
    if (!etag) {
      throw new Error(`evidence-uploader: part ${part.partNumber} returned no ETag`);
    }
    uploaded.push({ partNumber: part.partNumber, etag });
  }
  return uploaded;
}

export async function uploadEvidence(
  host: HostServices,
  scanRunId: string,
  artifact: ScanEvidenceArtifact,
): Promise<UploadedEvidence> {
  if (!host.workspaceQuery) {
    throw new Error("evidence-uploader: workspaceQuery not available");
  }
  const query: WorkspaceQuery = host.workspaceQuery.bind(host);

  const presignRes = await query<{ presignSecurityEvidence: EvidencePresign }>(PRESIGN_MUTATION, {
    scanRunId,
    type: GQL_TYPE_MAP[artifact.type],
    sha256: artifact.sha256,
    sizeBytes: artifact.sizeBytes,
  });
  const presignErrors = errorsOf(presignRes);
  if (presignErrors) {
    throw new Error(`evidence-uploader: presign errors — ${presignErrors}`);
  }
  const presign = presignRes.data?.presignSecurityEvidence;
  if (!presign) throw new Error("evidence-uploader: missing presign result");

  const body = new Uint8Array(await fs.readFile(artifact.localPath));
  if (body.byteLength !== artifact.sizeBytes) {
    throw new Error(
      `evidence-uploader: ${artifact.localPath} is ${body.byteLength} bytes, declared ${artifact.sizeBytes}`,
    );
  }

  let parts: Array<{ partNumber: number; etag: string }> | null = null;
  if (presign.uploadType === "MULTIPART") {
    parts = await putParts(presign, body);
  } else {
    if (!presign.uploadUrl) {
      throw new Error("evidence-uploader: direct upload without a URL");
    }
    await put(
      presign.uploadUrl,
      presign.method.toUpperCase(),
      presign.requiredHeaders,
      body,
      "evidence",
    );
  }

  const completeRes = await query<{
    completeSecurityEvidenceUpload: {
      id: string;
      status: string;
      fileId: string | null;
    };
  }>(COMPLETE_MUTATION, { evidenceId: presign.evidenceId, parts });
  const completeErrors = errorsOf(completeRes);
  if (completeErrors) {
    throw new Error(`evidence-uploader: complete errors — ${completeErrors}`);
  }
  const completed = completeRes.data?.completeSecurityEvidenceUpload;
  if (!completed || completed.status !== "UPLOADED" || !completed.fileId) {
    throw new Error("evidence-uploader: the upload did not complete");
  }

  return {
    evidenceId: presign.evidenceId,
    type: artifact.type,
    sha256: artifact.sha256,
    sizeBytes: artifact.sizeBytes,
    fileId: completed.fileId,
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
