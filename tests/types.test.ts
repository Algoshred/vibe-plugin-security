import { describe, expect, test } from "bun:test";

import {
  ALL_STAGES,
  DEFAULT_PROVIDER_CONFIG_KEY,
  PROVIDER_TYPE_FOR_STAGE,
  type SecurityStage,
} from "../src/types.js";

describe("types", () => {
  test("ALL_STAGES has 14 lifecycle stages", () => {
    expect(ALL_STAGES.length).toBe(14);
  });

  test("PROVIDER_TYPE_FOR_STAGE maps PR-fast to security.secrets", () => {
    expect(PROVIDER_TYPE_FOR_STAGE("pull_request.fast")).toBe("security.secrets");
  });

  test("PROVIDER_TYPE_FOR_STAGE maps build to security.sbom", () => {
    expect(PROVIDER_TYPE_FOR_STAGE("build")).toBe("security.sbom");
  });

  test("PROVIDER_TYPE_FOR_STAGE maps promote.prod to security.release", () => {
    expect(PROVIDER_TYPE_FOR_STAGE("promote.prod")).toBe("security.release");
  });

  test("DEFAULT_PROVIDER_CONFIG_KEY namespaces by stage", () => {
    const key = DEFAULT_PROVIDER_CONFIG_KEY("build" as SecurityStage);
    expect(key).toBe("provider:default:security.build");
  });

  test("every stage has a provider type", () => {
    for (const s of ALL_STAGES) {
      expect(PROVIDER_TYPE_FOR_STAGE(s)).toMatch(/^security\./);
    }
  });
});
