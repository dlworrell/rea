import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { MAX_KEY_BYTES, readAptKey } from "./DesktopBuildBundle.js";
import { execFileOutput } from "../../process/ExecFileOutput.js";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";

// readAptKey reads the key through
// readHostFile, which checks type and size on the open descriptor. These
// cases pin each outcome's user message.

const NOT_A_KEY = `is not a readable regular file of at most ${String(MAX_KEY_BYTES)} bytes, as a signing key is.`;

const refusal = async (path: string): Promise<string | undefined> => {
  try {
    await readAptKey(path);
    return undefined;
  } catch (error: unknown) {
    expect((error as { _tag?: string })._tag).toBe("AnalysisInputError");
    return (error as { userMessage?: string }).userMessage;
  }
};

describe("apt key file admission", () => {
  it("reads a regular key file", async () => {
    const folder = await createTestTempDirectory("rea-apt-key-valid-");
    const path = join(folder, "key.asc");
    await writeFile(path, "-----BEGIN PGP PUBLIC KEY BLOCK-----\n");
    expect((await readAptKey(path)).toString()).toBe(
      "-----BEGIN PGP PUBLIC KEY BLOCK-----\n",
    );
  });

  it("reads a key of exactly the size limit", async () => {
    const folder = await createTestTempDirectory("rea-apt-key-limit-");
    const path = join(folder, "key.gpg");
    await writeFile(path, Buffer.alloc(MAX_KEY_BYTES, 1));
    expect((await readAptKey(path)).length).toBe(MAX_KEY_BYTES);
  });

  it("refuses a missing key file", async () => {
    const folder = await createTestTempDirectory("rea-apt-key-missing-");
    const path = join(folder, "absent.asc");
    expect(await refusal(path)).toBe(
      `The apt key file ${path} cannot be read.`,
    );
  });

  it("refuses a directory", async () => {
    const folder = await createTestTempDirectory("rea-apt-key-directory-");
    const path = join(folder, "keys");
    await mkdir(path);
    expect(await refusal(path)).toBe(`The apt key file ${path} ${NOT_A_KEY}`);
  });

  it("refuses a key larger than the limit", async () => {
    const folder = await createTestTempDirectory("rea-apt-key-large-");
    const path = join(folder, "key.gpg");
    await writeFile(path, Buffer.alloc(MAX_KEY_BYTES + 1, 1));
    expect(await refusal(path)).toBe(`The apt key file ${path} ${NOT_A_KEY}`);
  });

  it.skipIf(process.platform === "win32")(
    "refuses a FIFO without blocking on it",
    async () => {
      const folder = await createTestTempDirectory("rea-apt-key-fifo-");
      const path = join(folder, "key.fifo");
      await execFileOutput("mkfifo", [path], { maxBuffer: 1024 });
      // A blocking open of a FIFO with no writer would never return; the test
      // timeout turns that regression into a failure.
      expect(await refusal(path)).toBe(`The apt key file ${path} ${NOT_A_KEY}`);
    },
    10_000,
  );
});
