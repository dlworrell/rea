import { expect, it } from "vitest";
import { err, ok } from "../../../src/domain/result.js";
import { GhidraSessionError } from "../../../src/ghidra/GhidraSessionError.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";
import { connectGhidraMcp } from "./ghidraMcpHarness.js";

it.each(["compact", "full"] as const)(
  "identifies the invalid Ghidra regex field and permits correction (%s)",
  async (profile) => {
    const message =
      "Invalid regex pattern [: Unclosed character class at index 0";
    const harness = await connectGhidraMcp(
      "ghidra-regex-diagnostic",
      (operation, input) =>
        Promise.resolve(
          input.pattern === "["
            ? err(
                new GhidraSessionError(
                  "remote",
                  message,
                  {},
                  { remoteCode: "invalid_regex_pattern" },
                ),
              )
            : ok([]),
        ),
      { environment: { REA_MCP_OUTPUT_SCHEMA_PROFILE: profile } },
    );
    try {
      for (const operation of [
        "search_strings",
        "search_procedures",
      ] as const) {
        const rejected = await harness.mcp.callTool({
          name: operation,
          arguments: { pattern: "[", mode: "regex" },
        });
        const error = parseMcpToolError(rejected).error;
        expect(error).toMatchObject({
          code: "invalid_request",
          message,
          remediation: {
            action: expect.stringMatching(/pattern.*mode literal/u),
          },
          details: {
            issues: [{ path: ["pattern"], reason: "invalid_format", message }],
          },
        });
        expect(error.recovery).toMatchObject({
          kind: "inspect_input_contract",
          operation,
        });
        const corrected = await harness.mcp.callTool({
          name: operation,
          arguments: { pattern: "valid", mode: "regex" },
        });
        expect(corrected.isError).not.toBe(true);
      }
    } finally {
      await harness.close();
    }
  },
);

it.each(["compact", "full"] as const)(
  "reports the isolated regex deadline and accepts the corrected search (%s)",
  async (profile) => {
    const harness = await connectGhidraMcp(
      "ghidra-regex-timeout",
      (_operation, input) =>
        Promise.resolve(
          input.pattern === "(a+)+$"
            ? err(
                new GhidraSessionError(
                  "remote",
                  "Ghidra regex search exceeded its 5000 ms deadline",
                  { remote_code: "regex_timeout" },
                  { remoteCode: "regex_timeout" },
                ),
              )
            : ok([]),
        ),
      { environment: { REA_MCP_OUTPUT_SCHEMA_PROFILE: profile } },
    );
    try {
      for (const operation of [
        "search_strings",
        "search_procedures",
      ] as const) {
        const error = parseMcpToolError(
          await harness.mcp.callTool({
            name: operation,
            arguments: { pattern: "(a+)+$", mode: "regex" },
          }),
        ).error;
        expect(error).toMatchObject({
          code: "provider_timeout",
          recovery: { kind: "inspect_timeout_state", timeout_ms: 5000 },
          details: {
            limit: {
              setting: "regex.matching_deadline_ms",
              effective_value: 5000,
              source: "default",
              minimum: 1,
              maximum: 2147483647,
              applies_at: "next_operation",
              scope: "rea-runtime",
            },
          },
        });
        expect(error.message).toContain("annotations remain available");
        expect(error.remediation.action).toContain("update_analysis_settings");
        expect(
          (
            await harness.mcp.callTool({
              name: operation,
              arguments: { pattern: "safe", mode: "regex" },
            })
          ).isError,
        ).not.toBe(true);
      }
    } finally {
      await harness.close();
    }
  },
);
