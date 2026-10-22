import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import type { HostServices } from "@vibecontrols/plugin-sdk/contract";

import { uploadEvidence } from "../src/evidence-uploader.js";

interface Put {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: Uint8Array;
}

type Answer = { data?: unknown; errors?: Array<{ message: string }> };

function hostAnswering(answers: Record<string, Answer>) {
  const calls: Array<{ operation: string; variables: Record<string, unknown> }> = [];
  const workspaceQuery = async (query: string, variables?: Record<string, unknown>) => {
    const operation = /mutation\s+(\w+)/.exec(query)?.[1] ?? "unknown";
    calls.push({ operation, variables: variables ?? {} });
    return answers[operation] ?? { errors: [{ message: `unexpected ${operation}` }] };
  };
  // The host contract is generic over the response type; the fake answers untyped JSON like the real host.
  const host = { workspaceQuery } as unknown as HostServices;
  return { host, calls };
}

describe("uploadEvidence", () => {
  const realFetch = globalThis.fetch;
  let dir: string;
  let file: string;
  let puts: Put[];
  let respond: (put: Put) => Response;

  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(tmpdir(), "vibe-evidence-"));
    file = path.join(dir, "scan.sarif.json");
    await fs.writeFile(file, "0123456789");
    puts = [];
    respond = () => new Response(null, { status: 200, headers: { etag: '"e"' } });
    globalThis.fetch = (async (url: string, init?: RequestInit) => {
      const put: Put = {
        url,
        method: init?.method ?? "GET",
        headers: Object.fromEntries(new Headers(init?.headers).entries()),
        body: new Uint8Array(init?.body as Uint8Array),
      };
      puts.push(put);
      return respond(put);
    }) as typeof fetch;
  });

  afterEach(async () => {
    globalThis.fetch = realFetch;
    await fs.rm(dir, { recursive: true, force: true });
  });

  const artifact = () => ({
    type: "sarif" as const,
    localPath: file,
    sha256: "a".repeat(64),
    sizeBytes: 10,
  });

  test("PUTs a DIRECT upload with the signed headers and completes it", async () => {
    const { host, calls } = hostAnswering({
      PresignSecurityEvidence: {
        data: {
          presignSecurityEvidence: {
            evidenceId: "ev-1",
            uploadType: "DIRECT",
            uploadUrl: "https://bucket/put?sig=1",
            method: "put",
            expiresAt: "2026-10-22T10:00:00Z",
            requiredHeaders: { "Content-Type": "application/sarif+json" },
            parts: [],
          },
        },
      },
      CompleteSecurityEvidenceUpload: {
        data: {
          completeSecurityEvidenceUpload: { id: "ev-1", status: "UPLOADED", fileId: "file-1" },
        },
      },
    });

    const uploaded = await uploadEvidence(host, "run-1", artifact());

    expect(uploaded).toEqual({
      evidenceId: "ev-1",
      type: "sarif",
      sha256: "a".repeat(64),
      sizeBytes: 10,
      fileId: "file-1",
    });
    expect(calls[0]).toEqual({
      operation: "PresignSecurityEvidence",
      variables: { scanRunId: "run-1", type: "SARIF", sha256: "a".repeat(64), sizeBytes: 10 },
    });
    expect(puts).toHaveLength(1);
    expect(puts[0]?.method).toBe("PUT");
    expect(puts[0]?.headers["content-type"]).toBe("application/sarif+json");
    expect(calls[1]).toEqual({
      operation: "CompleteSecurityEvidenceUpload",
      variables: { evidenceId: "ev-1", parts: null },
    });
  });

  test("PUTs every MULTIPART part and hands back the ETags", async () => {
    respond = (put) =>
      new Response(null, { status: 200, headers: { etag: `"${put.url.slice(-1)}"` } });
    const { host, calls } = hostAnswering({
      PresignSecurityEvidence: {
        data: {
          presignSecurityEvidence: {
            evidenceId: "ev-2",
            uploadType: "MULTIPART",
            uploadUrl: null,
            method: "PUT",
            expiresAt: "2026-10-22T10:00:00Z",
            requiredHeaders: {},
            parts: [
              { partNumber: 1, url: "https://bucket/p?n=1", offset: 0, length: 6 },
              { partNumber: 2, url: "https://bucket/p?n=2", offset: 6, length: 4 },
            ],
          },
        },
      },
      CompleteSecurityEvidenceUpload: {
        data: {
          completeSecurityEvidenceUpload: { id: "ev-2", status: "UPLOADED", fileId: "file-2" },
        },
      },
    });

    await uploadEvidence(host, "run-1", artifact());

    expect(puts.map((put) => new TextDecoder().decode(put.body))).toEqual(["012345", "6789"]);
    expect(calls[1]?.variables).toEqual({
      evidenceId: "ev-2",
      parts: [
        { partNumber: 1, etag: '"1"' },
        { partNumber: 2, etag: '"2"' },
      ],
    });
  });

  test("fails on presign errors, a failed PUT, a size mismatch or an incomplete upload", async () => {
    const direct = {
      data: {
        presignSecurityEvidence: {
          evidenceId: "ev-3",
          uploadType: "DIRECT",
          uploadUrl: "https://bucket/put",
          method: "PUT",
          expiresAt: "x",
          requiredHeaders: {},
          parts: [],
        },
      },
    };
    await expect(
      uploadEvidence(
        hostAnswering({
          PresignSecurityEvidence: { errors: [{ message: "Security scan not found" }] },
        }).host,
        "r",
        artifact(),
      ),
    ).rejects.toThrow("Security scan not found");

    await expect(
      uploadEvidence(hostAnswering({ PresignSecurityEvidence: direct }).host, "r", {
        ...artifact(),
        sizeBytes: 11,
      }),
    ).rejects.toThrow("declared 11");

    respond = () => new Response(null, { status: 403, statusText: "Forbidden" });
    await expect(
      uploadEvidence(hostAnswering({ PresignSecurityEvidence: direct }).host, "r", artifact()),
    ).rejects.toThrow("PUT failed 403");

    respond = () => new Response(null, { status: 200 });
    await expect(
      uploadEvidence(
        hostAnswering({
          PresignSecurityEvidence: direct,
          CompleteSecurityEvidenceUpload: {
            errors: [{ message: "does not match the declared size or SHA-256" }],
          },
        }).host,
        "r",
        artifact(),
      ),
    ).rejects.toThrow("does not match");

    await expect(
      uploadEvidence(
        hostAnswering({
          PresignSecurityEvidence: direct,
          CompleteSecurityEvidenceUpload: {
            data: {
              completeSecurityEvidenceUpload: { id: "ev-3", status: "PENDING", fileId: null },
            },
          },
        }).host,
        "r",
        artifact(),
      ),
    ).rejects.toThrow("did not complete");
  });

  test("rejects a host without workspaceQuery and malformed multipart plans", async () => {
    await expect(uploadEvidence({} as HostServices, "r", artifact())).rejects.toThrow(
      "workspaceQuery not available",
    );

    const multipart = (parts: unknown[]) =>
      hostAnswering({
        PresignSecurityEvidence: {
          data: {
            presignSecurityEvidence: {
              evidenceId: "ev-4",
              uploadType: "MULTIPART",
              uploadUrl: null,
              method: "PUT",
              expiresAt: "x",
              requiredHeaders: {},
              parts,
            },
          },
        },
      }).host;
    await expect(uploadEvidence(multipart([]), "r", artifact())).rejects.toThrow("without parts");
    await expect(
      uploadEvidence(
        multipart([{ partNumber: 1, url: "https://b/p", offset: 4, length: 10 }]),
        "r",
        artifact(),
      ),
    ).rejects.toThrow("outside the file");
    respond = () => new Response(null, { status: 200 });
    await expect(
      uploadEvidence(
        multipart([{ partNumber: 1, url: "https://b/p", offset: 0, length: 10 }]),
        "r",
        artifact(),
      ),
    ).rejects.toThrow("no ETag");
  });
});
