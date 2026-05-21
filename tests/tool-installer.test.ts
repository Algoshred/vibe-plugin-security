import { describe, expect, test } from "bun:test";

import { currentPlatform, type ToolPlatform } from "../src/tool-installer.js";

describe("tool-installer", () => {
  test("currentPlatform returns a known tuple", () => {
    const p = currentPlatform();
    const valid: ToolPlatform[] = ["linux-x64", "linux-arm64", "darwin-x64", "darwin-arm64"];
    expect(valid).toContain(p);
  });
});
