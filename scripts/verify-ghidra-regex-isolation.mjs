#!/usr/bin/env node
// Compile and execute the production Java regex subprocess owner without a
// Ghidra installation. This does not replace real-provider session verification.
import { spawnSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const java = process.env.JAVA_HOME
  ? join(
      process.env.JAVA_HOME,
      "bin",
      process.platform === "win32" ? "java.exe" : "java",
    )
  : "java";
const scratch = await mkdtemp(join(tmpdir(), "rea-regex-verify-"));
try {
  // Ghidra requires a JDK. Calling its compiler module also works when a host
  // has not put a separate javac launcher on PATH.
  run([
    "com.sun.tools.javac.Main",
    "-Xlint:all",
    "-source",
    "21",
    "-target",
    "21",
    "-encoding",
    "UTF-8",
    "-d",
    scratch,
    "bridge/ghidra/ReaGhidraRegexWorker.java",
    "bridge/ghidra/ReaGhidraRegexSearch.java",
    "tests/fixtures/ghidra/ReaGhidraRegexSearchTest.java",
  ]);
  run(["-Xmx128m", "-cp", scratch, "ReaGhidraRegexSearchTest"]);
} finally {
  await rm(scratch, { recursive: true, force: true });
}

function run(args) {
  const result = spawnSync(java, args, {
    cwd: root,
    encoding: "utf8",
    timeout: 30_000,
    maxBuffer: 1024 * 1024,
  });
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  if (result.error || result.status !== 0)
    throw (
      result.error ??
      new Error(`Java regex verification exited ${result.status}`)
    );
}
