import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/** Owns one killable Java regex process; never owns the Ghidra Program. */
public final class ReaGhidraRegexSearch implements AutoCloseable {
    private static final long CLEANUP_MILLIS = 2_000;
    private static final String WORKER = "ReaGhidraRegexWorker";
    private final Path privateParent;
    private final int deadlineMillis;
    private final long heapBytes;
    private Path directory;
    private Path workerClass;
    private Process process;
    private ExecutorService io;
    private DataOutputStream input;
    private DataInputStream output;
    private long deadlineNanos;
    private int ordinal;
    private boolean started;
    private boolean finished;
    private boolean closed;
    private Failure primary;
    private String expression;

    /** Callers retain this owner before start and until isClosed() is true. */
    public ReaGhidraRegexSearch(Path privateParent, int deadlineMillis) {
        if (deadlineMillis < 1)
            throw new IllegalArgumentException("Regex deadline must be positive");
        this.privateParent = privateParent;
        this.deadlineMillis = deadlineMillis;
        // Preserve the admitted Ghidra JVM's heap ceiling rather than inventing
        // a smaller pattern limit or repurposing V8's old-generation setting.
        this.heapBytes = Runtime.getRuntime().maxMemory();
    }

    public void start(String expression, boolean caseSensitive) {
        if (started || closed) throw new IllegalStateException("Search already started or closed");
        started = true;
        this.expression = expression;
        deadlineNanos = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(deadlineMillis);
        try {
            directory = Files.createTempDirectory(privateParent, "regex-");
            workerClass = directory.resolve(WORKER + ".class");
            // Ghidra loads scripts in an OSGi bundle, not java.class.path.
            // This JDK-only worker consists of one class with no inner classes.
            try (InputStream compiled = ReaGhidraRegexWorker.class
                    .getResourceAsStream(WORKER + ".class")) {
                if (compiled == null) throw new IOException("Packaged regex worker class is unavailable");
                try (var target = Files.newOutputStream(workerClass,
                        StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                    compiled.transferTo(target);
                }
            }
            String executable = System.getProperty("os.name", "").startsWith("Windows")
                ? "java.exe" : "java";
            Path java = Path.of(System.getProperty("java.home"), "bin", executable);
            remaining();
            process = new ProcessBuilder(java.toString(), "-Xms" + Math.min(heapBytes, 16L * 1024 * 1024),
                "-Xmx" + heapBytes, "-cp", directory.toString(), WORKER)
                // The protocol carries classified failures. Never retain an
                // unbounded stderr stream or put user values in argv/files.
                .redirectError(ProcessBuilder.Redirect.DISCARD).start();
            input = new DataOutputStream(new BufferedOutputStream(process.getOutputStream()));
            output = new DataInputStream(new BufferedInputStream(process.getInputStream()));
            io = Executors.newSingleThreadExecutor(task -> {
                Thread thread = new Thread(task, "rea-regex-io");
                thread.setDaemon(true);
                return thread;
            });
            exchange(() -> {
                input.writeInt(ReaGhidraRegexWorker.MAGIC);
                input.writeByte(caseSensitive ? 1 : 0);
                writeString(expression);
                input.flush();
                if (output.readInt() != ReaGhidraRegexWorker.MAGIC)
                    throw protocolFailure();
                requireFrame(ReaGhidraRegexWorker.READY);
                return null;
            });
        } catch (Failure failure) {
            primary = failure;
            throw failure;
        } catch (IOException failure) {
            throw remember(new Failure("regex_worker_failed", "Cannot start the isolated Java regex worker", failure));
        }
    }

    public boolean matches(String value) {
        if (!started || finished || closed || primary != null)
            throw new IllegalStateException("Regex search is not active");
        if (ordinal == Integer.MAX_VALUE)
            throw remember(protocolFailure());
        return exchange(() -> {
            input.writeByte(ReaGhidraRegexWorker.VALUE);
            writeString(value);
            input.flush();
            requireFrame(ReaGhidraRegexWorker.MATCH);
            if (output.readInt() != ordinal) throw protocolFailure();
            int matched = output.readUnsignedByte();
            if (matched != 0 && matched != 1) throw protocolFailure();
            ordinal++;
            return matched == 1;
        });
    }

    /** Validate exact completion before publishing any accumulated result. */
    public void finish() {
        if (!started || finished || closed || primary != null)
            throw new IllegalStateException("Regex search is not active");
        exchange(() -> {
            input.writeByte(ReaGhidraRegexWorker.END);
            input.close();
            requireFrame(ReaGhidraRegexWorker.DONE);
            if (output.readInt() != ordinal || output.read() != -1)
                throw protocolFailure();
            if (!process.waitFor(remaining(), TimeUnit.NANOSECONDS)) throw timeout();
            if (process.exitValue() != 0) throw protocolFailure();
            return null;
        });
        finished = true;
    }

    public boolean isClosed() { return closed; }

    /** Test/diagnostic observation; this Process object remains the owner. */
    boolean workerAlive() { return process != null && process.isAlive(); }

    @Override
    public void close() {
        if (closed) return;
        boolean interrupted = Thread.interrupted();
        try {
            if (process != null) {
                process.destroyForcibly();
                if (!process.waitFor(CLEANUP_MILLIS, TimeUnit.MILLISECONDS))
                    throw cleanupFailure("The owned regex process did not exit");
            }
            // Closing streams before stopping the process can block on the IO
            // thread's BufferedInputStream lock. Positive exit comes first.
            if (io != null) {
                io.shutdownNow();
                if (!io.awaitTermination(CLEANUP_MILLIS, TimeUnit.MILLISECONDS))
                    throw cleanupFailure("The regex IO owner did not stop");
            }
            // A broken pipe after confirmed process/IO exit is not a retained
            // resource. In particular, a cancelled buffered write can fail flush.
            if (input != null) try { input.close(); } catch (IOException ignored) {}
            if (output != null) try { output.close(); } catch (IOException ignored) {}
            if (workerClass != null) Files.deleteIfExists(workerClass);
            if (directory != null) Files.deleteIfExists(directory);
            closed = true;
        } catch (InterruptedException failure) {
            interrupted = true;
            throw cleanupFailure("Regex cleanup was interrupted");
        } catch (IOException | SecurityException failure) {
            throw new Failure("regex_worker_cleanup_failed",
                "Regex worker cleanup remains incomplete; retry retained cleanup before another regex search", failure);
        } finally {
            if (interrupted) Thread.currentThread().interrupt();
        }
    }

    private <T> T exchange(Callable<T> action) {
        Future<T> pending = io.submit(action);
        try {
            return pending.get(remaining(), TimeUnit.NANOSECONDS);
        } catch (TimeoutException failure) {
            pending.cancel(true);
            throw remember(timeout());
        } catch (InterruptedException failure) {
            pending.cancel(true);
            Thread.currentThread().interrupt();
            throw remember(new Failure("regex_worker_failed", "Regex search was interrupted", failure));
        } catch (ExecutionException failure) {
            Throwable cause = failure.getCause();
            throw remember(cause instanceof Failure classified ? classified
                : new Failure("regex_worker_failed", "Isolated Java regex worker failed before complete results", cause));
        } catch (Failure failure) {
            pending.cancel(true);
            throw remember(failure);
        }
    }

    private long remaining() {
        long value = deadlineNanos - System.nanoTime();
        if (value <= 0) throw timeout();
        return value;
    }

    private void requireFrame(int expected) throws IOException {
        int frame = output.readUnsignedByte();
        if (frame == expected) return;
        if (frame == ReaGhidraRegexWorker.INVALID_PATTERN) {
            int index = output.readInt();
            int units = output.readInt();
            // Java can include a caller-provided property/group name in its
            // diagnostic. Bound framing without truncating such valid errors.
            if (units < 0 || (long) units > (long) expression.length() + 4096)
                throw protocolFailure();
            StringBuilder reason = new StringBuilder(units);
            for (int item = 0; item < units; item++) reason.append(output.readChar());
            throw new Failure("invalid_regex_pattern", "Invalid regex pattern " + expression + ": " + reason + " at index " + index);
        }
        if (frame == ReaGhidraRegexWorker.STACK_EXHAUSTED) {
            int stage = output.readUnsignedByte();
            if (stage != 0 && stage != 1) throw protocolFailure();
            throw stackExhausted(expression, stage == 0 ? "compiling" : "matching");
        }
        if (frame == ReaGhidraRegexWorker.MEMORY_EXHAUSTED)
            throw new Failure("regex_worker_memory_exhausted",
                "Isolated Java regex worker exhausted its " + heapBytes + " byte heap ceiling inherited from the Ghidra JVM");
        throw protocolFailure();
    }

    private void writeString(String value) throws IOException {
        input.writeInt(value.length());
        for (int index = 0; index < value.length(); index++) input.writeChar(value.charAt(index));
    }

    private Failure remember(Failure failure) { primary = failure; return failure; }
    private static Failure stackExhausted(String expression, String stage) {
        return new Failure("regex_stack_exhausted",
            "Ghidra's isolated Java regex engine exhausted its stack while " + stage +
            " pattern " + expression + ".");
    }
    private Failure timeout() {
        return new Failure("regex_timeout", "Ghidra regex search exceeded its " + deadlineMillis + " ms deadline");
    }
    private static Failure protocolFailure() {
        return new Failure("regex_worker_failed", "Isolated Java regex worker returned an incomplete or invalid response");
    }
    private static Failure cleanupFailure(String reason) {
        return new Failure("regex_worker_cleanup_failed", reason + "; retry retained cleanup before another regex search");
    }

    public static final class Failure extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final String code;
        Failure(String code, String message) { super(message); this.code = code; }
        Failure(String code, String message, Throwable cause) { super(message, cause); this.code = code; }
        public String code() { return code; }
    }
}
