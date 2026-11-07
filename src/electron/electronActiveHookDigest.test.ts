import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";

import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";

// The shipped Electron hook hashes a native
// add-on through one descriptor, in 64 KiB chunks, up to 16 MiB. These cases
// pin the boundary and the refusals through the real patch, with
// process.dlopen stubbed so nothing is loaded.

interface RuntimeRecord {
  readonly phase: string;
  readonly details: { readonly artifact_sha256?: string | null };
}

interface BoundaryPatches {
  readonly patchNativeAddonLoading: () => void;
}

const load = createRequire(import.meta.url);
const { createElectronActiveBoundaryPatches } = load(
  "../../scripts/electron-active-hook-boundaries.cjs",
) as {
  readonly createElectronActiveBoundaryPatches: (
    context: Readonly<Record<string, unknown>>,
  ) => BoundaryPatches;
};

const LIMIT = 16 * 1024 * 1024;

/** The digest the patched dlopen records for a path, with loading stubbed out. */
const recordedDigest = (path: string): string | null | undefined => {
  const records: RuntimeRecord[] = [];
  const original = process.dlopen;
  process.dlopen = () => undefined;
  try {
    createElectronActiveBoundaryPatches({
      identity: () => "id",
      patchEmitter: () => undefined,
      processType: () => "main",
      recordIpc: () => undefined,
      recordRuntime: (
        _kind: string,
        _method: string,
        phase: string,
        details: RuntimeRecord["details"],
      ) => {
        records.push({ phase, details });
      },
      shape: (value: unknown) => value,
    }).patchNativeAddonLoading();
    process.dlopen({ exports: {} }, path);
  } finally {
    process.dlopen = original;
  }
  return records.find((record) => record.phase === "attempted")?.details
    .artifact_sha256;
};

const sha256 = (bytes: Buffer): string =>
  createHash("sha256").update(bytes).digest("hex");

describe("Electron hook native add-on digest", () => {
  it("hashes a small add-on", async () => {
    const folder = await createTestTempDirectory("rea-hook-digest-small-");
    const path = join(folder, "small.node");
    const bytes = Buffer.from("small native add-on");
    await writeFile(path, bytes);
    expect(recordedDigest(path)).toBe(sha256(bytes));
  });

  it("hashes an add-on of exactly the 16 MiB limit", async () => {
    const folder = await createTestTempDirectory("rea-hook-digest-limit-");
    const path = join(folder, "limit.node");
    const bytes = Buffer.alloc(LIMIT, 7);
    await writeFile(path, bytes);
    expect(recordedDigest(path)).toBe(sha256(bytes));
  });

  it("records no digest one byte over the limit", async () => {
    const folder = await createTestTempDirectory("rea-hook-digest-over-");
    const path = join(folder, "over.node");
    await writeFile(path, Buffer.alloc(LIMIT + 1, 7));
    expect(recordedDigest(path)).toBeNull();
  });

  it("bounds a file that grows after the descriptor type check", async () => {
    const folder = await createTestTempDirectory("rea-hook-digest-growth-");
    const path = join(folder, "growing.node");
    await writeFile(path, Buffer.from("small add-on"));
    const fs = load("node:fs") as typeof import("node:fs");
    const initialStat = fs.statSync(path);
    const grow = () => {
      fs.truncateSync(path, LIMIT + 1);
      return initialStat;
    };
    // Exercise both admission methods so this case also reproduces the old
    // stat-then-readFile race rather than relying on the new implementation.
    const stat = vi.spyOn(fs, "statSync").mockImplementationOnce(grow);
    const fstat = vi.spyOn(fs, "fstatSync").mockImplementationOnce(grow);
    try {
      expect(recordedDigest(path)).toBeNull();
    } finally {
      stat.mockRestore();
      fstat.mockRestore();
    }
  });

  it("records no digest for a directory or a missing path", async () => {
    const folder = await createTestTempDirectory("rea-hook-digest-shapes-");
    const directory = join(folder, "addon.node");
    await mkdir(directory);
    expect(recordedDigest(directory)).toBeNull();
    expect(recordedDigest(join(folder, "missing.node"))).toBeNull();
  });
});
