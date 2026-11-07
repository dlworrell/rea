import { mkdir, readdir, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { readStaticCheckpointFile } from "./JavaScriptAnalysisWorker.js";
import { execFileOutput } from "../../process/ExecFileOutput.js";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";

// The static checkpoint is opened with
// O_NOFOLLOW | O_NONBLOCK, refused when its descriptor is not a regular file
// or over budget, and read through that same descriptor. These cases cover
// each refusal and check that the descriptor is closed afterwards.

const NOT_REGULAR = "JavaScript static checkpoint is not a regular file";
const OVER_BUDGET =
  "JavaScript static checkpoint byte count exceeds or differs from its declared budget";

/** Open descriptors of this test process (Linux only; the adapters project runs each file in its own fork). */
const openDescriptors = async (): Promise<number> =>
  (await readdir("/proc/self/fd")).length;

const refusal = async (
  path: string,
  maximumBytes = 1024,
  expectedBytes?: number,
  admit: (bytes: number) => void = () => undefined,
): Promise<unknown> => {
  try {
    await readStaticCheckpointFile(path, maximumBytes, expectedBytes, admit);
  } catch (error: unknown) {
    return error;
  }
  throw new Error("expected the checkpoint read to be refused");
};

const isLinux = process.platform === "linux";

describe("static checkpoint admission", () => {
  it("reads a checkpoint within its budget and reports its size first", async () => {
    const folder = await createTestTempDirectory("rea-checkpoint-valid-");
    const path = join(folder, "a.static.json");
    await writeFile(path, '{"ok":true}');
    const admitted: number[] = [];
    const read = await readStaticCheckpointFile(path, 1024, 11, (bytes) => {
      admitted.push(bytes);
    });
    expect(read.bytes).toBe(11);
    expect(read.checkpoint.toString()).toBe('{"ok":true}');
    expect(admitted).toEqual([11]);
  });

  it("refuses a checkpoint over the budget or of an unexpected size", async () => {
    const folder = await createTestTempDirectory("rea-checkpoint-size-");
    const path = join(folder, "a.static.json");
    await writeFile(path, "x".repeat(33));
    for (const [maximum, expected] of [
      [32, undefined],
      [1024, 32],
    ] as const) {
      const error = await refusal(path, maximum, expected);
      expect(error).toMatchObject({ _tag: "AnalysisOutputError" });
      expect((error as Error).message).toContain(OVER_BUDGET);
    }
  });

  it("does not read a checkpoint that admission refuses", async () => {
    const folder = await createTestTempDirectory("rea-checkpoint-admit-");
    const path = join(folder, "a.static.json");
    await writeFile(path, "{}");
    const refused = new Error("heap");
    expect(
      await refusal(path, 1024, undefined, () => {
        throw refused;
      }),
    ).toBe(refused);
  });

  it("refuses a directory as not a regular file", async () => {
    const folder = await createTestTempDirectory("rea-checkpoint-directory-");
    const path = join(folder, "a.static.json");
    await mkdir(path);
    const error = await refusal(path);
    expect(error).toMatchObject({ _tag: "AnalysisOutputError" });
    expect((error as Error).message).toContain(NOT_REGULAR);
  });

  it.skipIf(process.platform === "win32")(
    "refuses a FIFO without blocking on it",
    async () => {
      const folder = await createTestTempDirectory("rea-checkpoint-fifo-");
      const path = join(folder, "a.static.json");
      await execFileOutput("mkfifo", [path], { maxBuffer: 1024 });
      // A blocking open of a FIFO with no writer would never return; the test
      // timeout turns that regression into a failure.
      const error = await refusal(path);
      expect(error).toMatchObject({ _tag: "AnalysisOutputError" });
      expect((error as Error).message).toContain(NOT_REGULAR);
    },
    10_000,
  );

  it.skipIf(process.platform === "win32")(
    "refuses a symlink, even to a valid checkpoint",
    async () => {
      const folder = await createTestTempDirectory("rea-checkpoint-symlink-");
      const target = join(folder, "real.static.json");
      await writeFile(target, "{}");
      const path = join(folder, "a.static.json");
      await symlink(target, path);
      // O_NOFOLLOW makes the open itself fail.
      expect(await refusal(path)).toMatchObject({ code: "ELOOP" });
    },
  );

  it.skipIf(!isLinux)(
    "closes the descriptor on every refusal after the open",
    async () => {
      const folder = await createTestTempDirectory("rea-checkpoint-close-");
      const large = join(folder, "large.static.json");
      await writeFile(large, "x".repeat(64));
      const directory = join(folder, "dir.static.json");
      await mkdir(directory);
      const before = await openDescriptors();
      await refusal(large, 32);
      await refusal(directory);
      await refusal(large, 1024, undefined, () => {
        throw new Error("heap");
      });
      expect(await openDescriptors()).toBe(before);
    },
  );
});
