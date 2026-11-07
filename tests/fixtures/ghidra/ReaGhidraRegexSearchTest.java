import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;

/** Tests the production subprocess owner without requiring a Ghidra SDK. */
public final class ReaGhidraRegexSearchTest {
    private static int checks;

    public static void main(String[] arguments) throws Exception {
        Path root = Files.createTempDirectory("rea-regex-test-");
        try {
            semantics(root, "abc", true, new String[] {"xabcx", "ab", "ABC"},
                new boolean[] {true, false, false});
            semantics(root, "(?<=prefix)name", true, new String[] {"prefixname", "name"},
                new boolean[] {true, false});
            semantics(root, "^(a+)\\1$", true, new String[] {"aaaa", "aaa"},
                new boolean[] {true, false});
            semantics(root, "^\\p{IsGreek}+$", true, new String[] {"λΩ", "latin"},
                new boolean[] {true, false});
            semantics(root, "k", false, new String[] {"K", "\u212a", "x"},
                new boolean[] {true, true, false});
            semantics(root, "😀", true, new String[] {"x😀y", "other"},
                new boolean[] {true, false});
            semantics(root, "\ud800", true, new String[] {"x\ud800y", "x"},
                new boolean[] {true, false});
            semantics(root, "", true, new String[] {"", "a"},
                new boolean[] {true, true});
            semantics(root, "a", true, new String[0], new boolean[0]);
            invalidPattern(root);
            longPatternDiagnostic(root);
            stackExhaustion(root);
            pathologicalTimeout(root);
            sharedDeadline(root);
            finishDeadline(root);
            cleanupRetry(root);
            abnormalExit(root);
            interruptedWait(root);
            blockedWrite(root);
            closeBeforeStart(root);
            largeCandidateBatch(root);
            sourceResourceLaunch(root);
            requireEmpty(root);
            System.out.println("PASS " + checks + " production-owner checks");
        } finally {
            Files.delete(root);
        }
    }

    private static void semantics(Path root, String expression, boolean sensitive,
            String[] values, boolean[] expected) {
        ReaGhidraRegexSearch search = new ReaGhidraRegexSearch(root, 5_000);
        try {
            search.start(expression, sensitive);
            for (int index = 0; index < values.length; index++)
                check(search.matches(values[index]) == expected[index], "Matching semantics changed");
            search.finish();
        } finally {
            search.close();
        }
        check(search.isClosed() && !search.workerAlive(), "Successful worker was not reaped");
    }

    private static void invalidPattern(Path root) {
        ReaGhidraRegexSearch search = new ReaGhidraRegexSearch(root, 5_000);
        try {
            expect("invalid_regex_pattern", () -> search.start("[", true));
        } finally {
            search.close();
        }
        check(search.isClosed(), "Invalid-pattern cleanup incomplete");
    }

    private static void pathologicalTimeout(Path root) {
        ReaGhidraRegexSearch search = new ReaGhidraRegexSearch(root, 500);
        long began = System.nanoTime();
        try {
            search.start("^(a+)+$", true);
            check(search.matches("a"), "Control candidate did not match");
            expect("regex_timeout", () -> search.matches("a".repeat(100_000) + "!"));
        } finally {
            search.close();
        }
        check(search.isClosed() && !search.workerAlive(), "Timed-out worker was not reaped");
        check(System.nanoTime() - began < 5_000_000_000L, "Timeout cleanup exceeded bound");
        semantics(root, "a", true, new String[] {"a"}, new boolean[] {true});
    }

    private static void longPatternDiagnostic(Path root) {
        ReaGhidraRegexSearch search = new ReaGhidraRegexSearch(root, 5_000);
        try {
            expect("invalid_regex_pattern", () -> search.start("\\p{" + "A".repeat(5000) + "}", true));
        } finally { search.close(); }
        check(search.isClosed(), "Long pattern diagnostic cleanup failed");
    }

    private static void stackExhaustion(Path root) {
        ReaGhidraRegexSearch search = new ReaGhidraRegexSearch(root, 5_000);
        try {
            String expression = "(".repeat(20_000) + "a" + ")".repeat(20_000);
            try {
                search.start(expression, true);
                throw new AssertionError("Deep pattern compilation unexpectedly succeeded");
            } catch (ReaGhidraRegexSearch.Failure failure) {
                check(failure.code().equals("regex_stack_exhausted"), "Compile stack failure misclassified");
                check(failure.getMessage().contains("stack while compiling pattern"), "Stack stage lost");
            }
        } finally { search.close(); }
        check(search.isClosed() && !search.workerAlive(), "Compile failure cleanup incomplete");
    }

    private static void sharedDeadline(Path root) throws InterruptedException {
        ReaGhidraRegexSearch search = new ReaGhidraRegexSearch(root, 200);
        try {
            search.start("a", true);
            check(search.matches("a"), "First search failed");
            Thread.sleep(250);
            expect("regex_timeout", () -> search.matches("a"));
        } finally {
            search.close();
        }
        check(search.isClosed(), "Shared deadline cleanup failed");
    }

    private static void finishDeadline(Path root) throws InterruptedException {
        ReaGhidraRegexSearch search = new ReaGhidraRegexSearch(root, 200);
        try {
            search.start("a", true);
            check(search.matches("a"), "First search failed");
            Thread.sleep(250);
            expect("regex_timeout", search::finish);
        } finally {
            search.close();
        }
        check(search.isClosed(), "Completion timeout cleanup failed");
    }

    private static void cleanupRetry(Path root) throws Exception {
        ReaGhidraRegexSearch search = new ReaGhidraRegexSearch(root, 5_000);
        search.start("a", true);
        search.matches("a");
        search.finish();
        Field field = ReaGhidraRegexSearch.class.getDeclaredField("directory");
        field.setAccessible(true);
        Path directory = (Path) field.get(search);
        // Deterministic retained-file cleanup failure; no process or permissions
        // are mocked, and the exact original owner performs the later retry.
        Path retained = Files.writeString(directory.resolve("retained-test-file"), "test");
        try {
            expect("regex_worker_cleanup_failed", search::close);
            check(!search.isClosed(), "Failed cleanup discarded ownership");
            check(!search.workerAlive(), "Cleanup did not stop child first");
        } finally {
            Files.delete(retained);
            search.close();
        }
        check(search.isClosed(), "Cleanup retry did not release original owner");
        search.close();
    }

    private static void closeBeforeStart(Path root) {
        ReaGhidraRegexSearch search = new ReaGhidraRegexSearch(root, 5_000);
        search.close();
        check(search.isClosed(), "Unstarted owner did not close");
        try {
            search.start("a", true);
            throw new AssertionError("Closed owner was reused");
        } catch (IllegalStateException expected) { checks++; }
    }

    private static Process worker(ReaGhidraRegexSearch search) throws Exception {
        Field field = ReaGhidraRegexSearch.class.getDeclaredField("process");
        field.setAccessible(true);
        return (Process) field.get(search);
    }

    private static void abnormalExit(Path root) throws Exception {
        ReaGhidraRegexSearch search = new ReaGhidraRegexSearch(root, 5_000);
        try {
            search.start("a", true);
            Process worker = worker(search);
            worker.destroyForcibly().waitFor();
            expect("regex_worker_failed", () -> search.matches("a"));
        } finally { search.close(); }
        check(search.isClosed() && !search.workerAlive(), "Abnormal exit cleanup failed");
        semantics(root, "a", true, new String[] {"a"}, new boolean[] {true});
    }

    private static void interruptedWait(Path root) {
        ReaGhidraRegexSearch search = new ReaGhidraRegexSearch(root, 5_000);
        try {
            search.start("a", true);
            Thread.currentThread().interrupt();
            expect("regex_worker_failed", () -> search.matches("a"));
        } finally {
            search.close();
            check(Thread.interrupted(), "Cleanup lost the caller's interrupt flag");
        }
        check(search.isClosed() && !search.workerAlive(), "Interrupted cleanup failed");
    }

    private static void blockedWrite(Path root) throws Exception {
        if (System.getProperty("os.name", "").startsWith("Windows")) {
            System.out.println("SKIP suspended-worker blocked-write check: POSIX signal required");
            return;
        }
        ReaGhidraRegexSearch search = new ReaGhidraRegexSearch(root, 500);
        try {
            search.start("a", true);
            // Stop only this test-owned child after READY. A value larger than
            // pipe capacity then exercises a blocked writer, not only a reader.
            Process stopped = new ProcessBuilder("kill", "-STOP", Long.toString(worker(search).pid())).start();
            check(stopped.waitFor() == 0, "Cannot suspend owned worker fixture");
            expect("regex_timeout", () -> search.matches("a".repeat(5_000_000)));
        } finally { search.close(); }
        check(search.isClosed() && !search.workerAlive(), "Blocked writer cleanup failed");
    }

    private static void largeCandidateBatch(Path root) {
        ReaGhidraRegexSearch search = new ReaGhidraRegexSearch(root, 5_000);
        long start = System.nanoTime();
        try {
            search.start("(?:func|alias)_\\d+", true);
            for (int index = 0; index < 10_000; index++)
                check(search.matches("namespace::func_" + index), "Batch candidate mismatch");
            search.finish();
        } finally { search.close(); }
        System.out.println("10,000 simple candidates: " + ((System.nanoTime() - start) / 1_000_000) + " ms");
    }

    private static void sourceResourceLaunch(Path root) throws Exception {
        // Child classpath is only the private extracted-class directory, not
        // this test's classpath; successful matching proves that packaging path.
        semantics(root, "packaged", true, new String[] {"packaged"}, new boolean[] {true});
        requireEmpty(root);
    }

    private static void requireEmpty(Path root) throws Exception {
        try (var files = Files.list(root)) {
            check(files.findAny().isEmpty(), "Private worker files leaked");
        }
    }

    private static void expect(String code, Runnable operation) {
        try {
            operation.run();
            throw new AssertionError("Expected " + code);
        } catch (ReaGhidraRegexSearch.Failure failure) {
            check(failure.code().equals(code), "Expected " + code + "; got " + failure.code());
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
