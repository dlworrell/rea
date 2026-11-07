import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { runInNewContext } from "node:vm";
import { describe, expect, it, vi } from "vitest";

// Execute the build script's exact download boundary without invoking MinGW,
// making network requests, or writing to the developer's shared build cache.
const source = await readFile(
  new URL("../../scripts/build-windows-native.mjs", import.meta.url),
  "utf8",
);
const start = source.indexOf("const verifiedDownload = ");
const end = source.indexOf("\nconst cachedHeaders = ", start);
if (start === -1 || end === -1)
  throw new Error("Windows native download boundary was not found");
const downloadSource = `${source.slice(start, end)}\nverifiedDownload;`;
const bytes = Buffer.from("Node headers fixture");
const checksum = createHash("sha256").update(bytes).digest("hex");
const name = "node-headers.tar.gz";
const path = "/fixture/cache/node-headers.tar.gz";

const fixture = (cached: boolean, checksums: string) => {
  const fetchBytes = vi.fn(async () => bytes);
  const readFile = vi.fn(async () => bytes);
  const writeFile = vi.fn(async () => undefined);
  const download = runInNewContext(downloadSource, {
    checksums,
    createHash,
    exists: async () => cached,
    fetchBytes,
    readFile,
    writeFile,
  }) as (name: string, path: string) => Promise<void>;
  return { download, fetchBytes, readFile, writeFile };
};

describe("Windows native prerequisite download", () => {
  it("caches a verified fresh download", async () => {
    const run = fixture(false, `${checksum}  ${name}\n`);
    await run.download(name, path);
    expect(run.fetchBytes).toHaveBeenCalledWith(name);
    expect(run.readFile).not.toHaveBeenCalled();
    expect(run.writeFile).toHaveBeenCalledExactlyOnceWith(path, bytes);
  });

  it.each(["mismatch", "missing"])(
    "does not cache a download with a %s checksum",
    async (kind) => {
      const run = fixture(
        false,
        kind === "missing" ? "" : `${"0".repeat(64)}  ${name}\n`,
      );
      await expect(run.download(name, path)).rejects.toThrow(
        "Node build prerequisite SHA-256 mismatch",
      );
      expect(run.writeFile).not.toHaveBeenCalled();
    },
  );

  it("revalidates a valid cache entry without fetching or rewriting it", async () => {
    const run = fixture(true, `${checksum}  ${name}\n`);
    await run.download(name, path);
    expect(run.readFile).toHaveBeenCalledWith(path);
    expect(run.fetchBytes).not.toHaveBeenCalled();
    expect(run.writeFile).not.toHaveBeenCalled();
  });

  it("rejects a mismatched cache entry without fetching or rewriting it", async () => {
    const run = fixture(true, `${"0".repeat(64)}  ${name}\n`);
    await expect(run.download(name, path)).rejects.toThrow(
      "Node build prerequisite SHA-256 mismatch",
    );
    expect(run.fetchBytes).not.toHaveBeenCalled();
    expect(run.writeFile).not.toHaveBeenCalled();
  });
});
