/** Required packaged sources, selected by their runtime role rather than order. */
export const GHIDRA_BRIDGE_SOURCES = Object.freeze({
  bridge: "ReaGhidraBridge.java",
  regexWorker: "ReaGhidraRegexWorker.java",
  regexSearch: "ReaGhidraRegexSearch.java",
  bundleActivator: "ReaGhidraBundleActivator.java",
  extensions: "ReaGhidraExtensions.java",
  prepareCom: "ReaGhidraPrepareCom.java",
  prepareRaw: "ReaGhidraPrepareRaw.java",
  prepareDol: "ReaGhidraPrepareDol.java",
  applySeeds: "ReaGhidraApplySeeds.java",
  analysisOptions: "ReaGhidraAnalysisOptions.java",
  noReturnFix: "ReaGhidraNoReturnFix.java",
  mipsSoftFloat: "ReaGhidraMipsSoftFloat.java",
  riscvCallingConvention: "ReaGhidraRiscvCallingConvention.java",
} as const);
