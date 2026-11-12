import { mkdir, rename, rm, symlink, unlink } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { DecompileExport } from "./exportTree.js";
import { execFileOutput } from "../../process/ExecFileOutput.js";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";

// The resume journal is opened first, with
// O_NOFOLLOW | O_NONBLOCK, and checked on its descriptor. These cases cover
// what resume reports for each journal shape.

const identity = {
  targetSha256: "ab".repeat(32),
  provider: { id: "fixture", name: "Fixture", version: "1" },
  analysisProfileDigest: "cd".repeat(32),
  layout: "address" as const,
};

const MISSING =
  "Resume requires decompile-journal.jsonl in the output directory. An export stopped before its journal was written has no functions to keep; choose a new output directory, or remove this one if it is yours.";
const UNREADABLE = "The decompile journal could not be read.";

/** A closed export with a valid journal, ready to be resumed. */
const createdExport = async (
  prefix: string,
): Promise<{ root: string; journal: string }> => {
  const parent = await createTestTempDirectory(prefix);
  const root = join(parent, "out");
  const created = await DecompileExport.open({
    placement: { mode: "create", root },
    identity,
  });
  expect(created.ok).toBe(true);
  if (created.ok) expect((await created.value.close()).ok).toBe(true);
  return { root, journal: join(root, "decompile-journal.jsonl") };
};

const resumeRefusal = async (root: string): Promise<string | undefined> => {
  const resumed = await DecompileExport.open({
    placement: { mode: "resume", root },
    identity,
  });
  if (resumed.ok) {
    expect((await resumed.value.close()).ok).toBe(true);
    return undefined;
  }
  expect(resumed.error._tag).toBe("AnalysisInputError");
  return resumed.error.userMessage;
};

describe("decompile journal resume admission", () => {
  it("resumes from a regular journal", async () => {
    const { root } = await createdExport("rea-journal-regular-");
    expect(await resumeRefusal(root)).toBeUndefined();
  });

  it("reports a missing journal as missing", async () => {
    const { root, journal } = await createdExport("rea-journal-missing-");
    await unlink(journal);
    expect(await resumeRefusal(root)).toBe(MISSING);
  });

  it("refuses a directory in place of the journal", async () => {
    const { root, journal } = await createdExport("rea-journal-directory-");
    await unlink(journal);
    await mkdir(journal);
    expect(await resumeRefusal(root)).toBe(UNREADABLE);
    await rm(journal, { recursive: true });
  });

  it.skipIf(process.platform === "win32")(
    "refuses a symlinked journal, even to a valid journal",
    async () => {
      const { root, journal } = await createdExport("rea-journal-symlink-");
      const target = join(root, "..", "real-journal.jsonl");
      await rename(journal, target);
      await symlink(target, journal);
      expect(await resumeRefusal(root)).toBe(UNREADABLE);
    },
  );

  it.skipIf(process.platform === "win32")(
    "refuses a FIFO journal without blocking on it",
    async () => {
      const { root, journal } = await createdExport("rea-journal-fifo-");
      await unlink(journal);
      await execFileOutput("mkfifo", [journal], { maxBuffer: 1024 });
      // A blocking open of a FIFO with no writer would never return; the
      // test timeout turns that regression into a failure.
      expect(await resumeRefusal(root)).toBe(UNREADABLE);
    },
    10_000,
  );
});
