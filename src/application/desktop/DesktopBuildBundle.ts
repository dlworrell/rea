import { copyFile, mkdir, stat, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join } from "node:path";

import {
  renderBuildBundle,
  type BuildRequest,
  type ReaPayload,
} from "../../domain/desktop/appBuild.js";
import {
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
} from "../../domain/analysisErrorCore.js";
import { AGENTENV_PROVIDER } from "../../desktop/AgentEnvComputerHelper.js";
import { readHostFile } from "../../desktop/HostFileRead.js";
import { PrivateRuntimeRoot } from "../../process/PrivateRuntimeRoot.js";

const START = "start_build_computer";
const MAX_KEY_BYTES = 1024 * 1024;

/** The archive the build layer unpacks REA from, as the operator configured it. */
const reaPayload = async (
  environment: Readonly<NodeJS.ProcessEnv>,
): Promise<ReaPayload> => {
  const path = environment.REA_BUILD_COMPUTER_REA_ARCHIVE;
  const reason =
    "A build computer from a request needs REA_BUILD_COMPUTER_REA_ARCHIVE, the absolute path of a tar archive of a runnable REA whose one top folder holds scripts/rea.mjs.";
  if (
    path === undefined ||
    !isAbsolute(path) ||
    !(await stat(path).then(
      (entry) => entry.isFile(),
      () => false,
    ))
  )
    throw new AnalysisCapabilityUnavailableError(
      AGENTENV_PROVIDER,
      START,
      reason,
      {
        userMessage: reason,
        remediationAction:
          "Pack a built REA with its production dependencies, set REA_BUILD_COMPUTER_REA_ARCHIVE to the archive and restart REA, or start from an exported bundle folder.",
      },
    );
  return { kind: "file", path };
};

/**
 * An apt repository's key file. Its type and size are checked on the open
 * descriptor and the read is bounded, so a path swapped after a check cannot
 * bypass the size limit or block on a FIFO (CodeQL js/file-system-race).
 */
const readAptKey = async (path: string): Promise<Buffer> => {
  const refuse = (reason: string, cause?: unknown) =>
    new AnalysisInputError(START, {
      userMessage: `The apt key file ${path} ${reason}.`,
      conformsToInputContract: true,
      ...(cause === undefined ? {} : { cause }),
    });
  const bytes = await readHostFile(path, MAX_KEY_BYTES, undefined).catch(
    (cause: unknown) => {
      throw refuse("cannot be read", cause);
    },
  );
  if (bytes === "missing") throw refuse("cannot be read");
  if (bytes === "unreadable")
    throw refuse(
      `is not a readable regular file of at most ${String(MAX_KEY_BYTES)} bytes, as a signing key is`,
    );
  return bytes;
};

/** Write the request's build bundle into a private folder, which the computer's owner removes on close. */
const writeBuildBundle = async (
  request: BuildRequest,
  payload: ReaPayload,
): Promise<{
  readonly workspace: PrivateRuntimeRoot;
  readonly bundle: string;
  readonly name: string;
}> => {
  const key =
    request.install.kind === "apt_repository"
      ? await readAptKey(request.install.key_file)
      : undefined;
  const { name, files } = renderBuildBundle(request, payload, key);
  const workspace = await PrivateRuntimeRoot.create({
    prefix: "rea-build-computer-",
  });
  try {
    const bundle = join(workspace.path, "bundle");
    for (const file of files) {
      const target = join(bundle, file.path);
      await mkdir(dirname(target), { recursive: true });
      if (
        typeof file.content === "string" ||
        file.content instanceof Uint8Array
      )
        await writeFile(target, file.content);
      else await copyFile(file.content.copyFrom, target);
    }
    return { workspace, bundle, name };
  } catch (cause: unknown) {
    await workspace.close();
    throw cause;
  }
};

/**
 * Render a request's build bundle, with REA's payload from the operator's
 * configuration, into a private folder the caller owns and removes.
 */
export const writeRequestBundle = async (
  request: BuildRequest,
  environment: Readonly<NodeJS.ProcessEnv>,
) => writeBuildBundle(request, await reaPayload(environment));
