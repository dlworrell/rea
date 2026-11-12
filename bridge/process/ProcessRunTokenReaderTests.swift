// Tests for the KERN_PROCARGS2 parser, the
// observation rules and the process-table retry in ProcessRunTokenReader.swift.
// Build with ProcessRunTokenReader.swift only (not ...Main.swift):
//   xcrun swiftc ProcessRunTokenReader.swift ProcessRunTokenReaderTests.swift -o tests
// The program prints one line per check and exits 1 if any check fails.

import Darwin
import Foundation

/** A KERN_PROCARGS2 buffer: argc, executable path, zero padding, argv, then the trailing region. */
func procargs(
  argc: Int32? = nil,
  path: String = "/usr/local/bin/tool",
  pointerSize: Int = 8,
  arguments: [String] = ["tool"],
  trailing: [UInt8]
) -> [UInt8] {
  var bytes: [UInt8] = []
  let count = argc ?? Int32(arguments.count)
  withUnsafeBytes(of: count.littleEndian) { bytes.append(contentsOf: $0) }
  bytes.append(contentsOf: Array(path.utf8))
  bytes.append(0)
  let record = Array("executable_path=".utf8).count + path.utf8.count + 1
  bytes.append(contentsOf: [UInt8](repeating: 0, count: (pointerSize - record % pointerSize) % pointerSize))
  for argument in arguments {
    bytes.append(contentsOf: Array(argument.utf8))
    bytes.append(0)
  }
  return bytes + trailing
}

/** NUL-terminated entries. */
func entries(_ values: [String]) -> [UInt8] {
  values.flatMap { Array($0.utf8) + [0] }
}

/** libc clears the first Apple-vector record (`pfz=...`) to zeros after startup. */
let zeroedAppleVector: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0] + entries(["ptr_munge=", "main_stack="])
let intactAppleVector = entries(["pfz=0x1", "ptr_munge="])

func describe(_ error: RunTokenReadError) -> String {
  switch error {
  case .invalidBuffer: return "invalidBuffer"
  case .invalidBufferAt(let stage): return "invalidBufferAt.\(stage.rawValue)"
  case .duplicateToken: return "duplicateToken"
  case .invalidTokenEncoding: return "invalidTokenEncoding"
  case .environmentUnavailable: return "environmentUnavailable"
  case .appleVectorUnavailable: return "appleVectorUnavailable"
  case .ambiguousEnvironmentBoundary: return "ambiguousEnvironmentBoundary"
  }
}

func parse(_ bytes: [UInt8], pointerSize: Int = 8) -> Result<ParsedRunToken, RunTokenReadError> {
  do {
    return .success(try parseProcessEnvironment(in: bytes, pointerSize: pointerSize))
  } catch let error as RunTokenReadError {
    return .failure(error)
  } catch {
    return .failure(.invalidBuffer)
  }
}

/** "token=<id|nil> entries=<n>" for a parse, or the error name. */
func outcome(_ result: Result<ParsedRunToken, RunTokenReadError>) -> String {
  switch result {
  case .success(let parsed): return "token=\(parsed.runId ?? "nil") entries=\(parsed.environmentEntryCount)"
  case .failure(let error): return describe(error)
  }
}

final class Checks {
  private(set) var failures = 0

  func expect(_ name: String, _ actual: String, _ expected: String) {
    if actual == expected {
      print("ok   \(name)")
    } else {
      failures += 1
      print("FAIL \(name): expected \(expected), got \(actual)")
    }
  }
}

func parserChecks(_ checks: Checks) {
  let token = "REA_PROCESS_RUN_ID=run-1"
  checks.expect("intact pfz= boundary finds the token",
    outcome(parse(procargs(trailing: entries(["HOME=/x", token]) + intactAppleVector))),
    "token=run-1 entries=2")
  checks.expect("zeroed pfz= boundary finds the token",
    outcome(parse(procargs(trailing: entries([token, "PATH=/bin"]) + zeroedAppleVector))),
    "token=run-1 entries=2")
  checks.expect("caller-set pfz before a zeroed vector: the zeroed boundary wins",
    outcome(parse(procargs(trailing: entries(["pfz=user", token]) + zeroedAppleVector))),
    "token=run-1 entries=2")
  checks.expect("environment without the token",
    outcome(parse(procargs(trailing: entries(["HOME=/x"]) + intactAppleVector))),
    "token=nil entries=1")
  checks.expect("32-bit padding",
    outcome(parse(procargs(path: "/a", pointerSize: 4, trailing: entries([token]) + intactAppleVector), pointerSize: 4)),
    "token=run-1 entries=1")
  checks.expect("no Apple vector",
    outcome(parse(procargs(trailing: entries(["HOME=/x", token])))),
    "appleVectorUnavailable")
  checks.expect("token in argv is ambiguous",
    outcome(parse(procargs(arguments: ["tool", token], trailing: entries(["HOME=/x"]) + intactAppleVector))),
    "ambiguousEnvironmentBoundary")
  checks.expect("token after the Apple vector is ambiguous",
    outcome(parse(procargs(trailing: entries(["HOME=/x"]) + intactAppleVector + entries([token])))),
    "ambiguousEnvironmentBoundary")
  checks.expect("duplicate token",
    outcome(parse(procargs(trailing: entries([token, "REA_PROCESS_RUN_ID=run-2"]) + intactAppleVector))),
    "duplicateToken")
  checks.expect("token that is not UTF-8",
    outcome(parse(procargs(trailing: Array("REA_PROCESS_RUN_ID=".utf8) + [0xFF, 0xFE, 0] + intactAppleVector))),
    "invalidTokenEncoding")
  checks.expect("argv ends the buffer: environment unavailable",
    outcome(parse(procargs(trailing: []))),
    "environmentUnavailable")
}

func malformedChecks(_ checks: Checks) {
  let valid = entries(["HOME=/x"]) + intactAppleVector
  checks.expect("stage header", outcome(parse([1, 0])), "invalidBufferAt.header")
  checks.expect("stage argument_count",
    outcome(parse(procargs(argc: -1, trailing: valid))), "invalidBufferAt.argument_count")
  var noPathTerminator: [UInt8] = []
  withUnsafeBytes(of: Int32(0).littleEndian) { noPathTerminator.append(contentsOf: $0) }
  noPathTerminator.append(contentsOf: Array("/no/terminator".utf8))
  checks.expect("stage executable_path", outcome(parse(noPathTerminator)), "invalidBufferAt.executable_path")
  checks.expect("stage pointer_size",
    outcome(parse(procargs(trailing: valid), pointerSize: 3)), "invalidBufferAt.pointer_size")
  var badPadding = procargs(path: "ab", trailing: valid)
  badPadding[4 + 3] = 1  // the first padding byte after "ab\0"
  checks.expect("stage path_padding", outcome(parse(badPadding)), "invalidBufferAt.path_padding")
  checks.expect("stage arguments",
    outcome(parse(procargs(argc: 9, trailing: []))), "invalidBufferAt.arguments")
  checks.expect("stage terminator",
    outcome(parse(procargs(trailing: valid + [0x41]))), "invalidBufferAt.terminator")
  // trailing_entries cannot be reached: the terminator check guarantees a final
  // NUL, so every non-empty trailing entry has an end.
}

func observationChecks(_ checks: Checks) {
  let restrict: UInt32 = 0x0000_0800
  let platform: UInt32 = 0x0400_0000
  func observe(_ parse: Result<ParsedRunToken, RunTokenReadError>, flags: UInt32?) -> String {
    let o = processRunTokenObservation(pid: 42, parse: parse, codeSigningFlags: { flags })
    return "\(o.state) run_id=\(o.run_id ?? "nil") reason=\(o.reason ?? "nil")"
  }
  let token = ParsedRunToken(runId: "run-1", environmentEntryCount: 3)
  let unrelated = ParsedRunToken(runId: nil, environmentEntryCount: 2)
  let empty = ParsedRunToken(runId: nil, environmentEntryCount: 0)
  checks.expect("token is readable", observe(.success(token), flags: restrict),
    "readable run_id=run-1 reason=nil")
  checks.expect("CS_RESTRICT does not hide a readable unrelated environment",
    observe(.success(unrelated), flags: restrict), "readable run_id=nil reason=nil")
  checks.expect("empty environment with CS_RESTRICT is withheld",
    observe(.success(empty), flags: restrict),
    "unavailable run_id=nil reason=restricted_process_environment_withheld")
  checks.expect("platform binary is withheld",
    observe(.failure(.environmentUnavailable), flags: platform),
    "unavailable run_id=nil reason=platform_binary_environment_withheld")
  checks.expect("unknown flags keep the parser's reason",
    observe(.failure(.invalidBufferAt(.terminator)), flags: nil),
    "unavailable run_id=nil reason=malformed_procargs_terminator")
  checks.expect("a duplicate token is never reported as withheld",
    observe(.failure(.duplicateToken), flags: restrict),
    "unavailable run_id=nil reason=duplicate_run_token")
}

func snapshotChecks(_ checks: Checks) {
  let stride = MemoryLayout<kinfo_proc>.stride
  func snapshot(failingFills: Int) -> (ProcessSnapshot, Int) {
    var fills = 0
    let result = readProcessSnapshot { _, output, size in
      if output == nil {
        size = 2 * stride
        return 0
      }
      fills += 1
      if fills <= failingFills {
        errno = ENOMEM
        return -1
      }
      size = 2 * stride
      return 0
    }
    return (result, fills)
  }
  let (exhausted, attempts) = snapshot(failingFills: 3)
  checks.expect("ENOMEM three times gives up after three attempts",
    "\(exhausted.failure ?? "nil") attempts=\(attempts)", "process_table_failed_\(ENOMEM) attempts=3")
  let (recovered, retries) = snapshot(failingFills: 2)
  checks.expect("ENOMEM twice, then success",
    "\(recovered.failure ?? "nil") attempts=\(retries) processes=\(recovered.metadata.count)",
    "nil attempts=3 processes=1")
}

@main
struct ProcessRunTokenReaderTests {
  static func main() {
    let checks = Checks()
    parserChecks(checks)
    malformedChecks(checks)
    observationChecks(checks)
    snapshotChecks(checks)
    print(checks.failures == 0 ? "all checks passed" : "\(checks.failures) check(s) failed")
    exit(checks.failures == 0 ? 0 : 1)
  }
}
