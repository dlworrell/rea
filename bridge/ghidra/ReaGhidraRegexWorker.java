import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Isolated regex worker. Owns no Ghidra API or Program.
 * The supervisor must enforce one deadline, terminate/reap this process, bound
 * its heap and transport, and publish matches only after the DONE frame.
 * UTF-16 units preserve Java String semantics, including unpaired surrogates.
 */
public final class ReaGhidraRegexWorker {
    static final int MAGIC = 0x52475831; // RGX1, protocol version 1
    static final int READY = 0;
    static final int MATCH = 1;
    static final int DONE = 2;
    static final int INVALID_PATTERN = 3;
    static final int STACK_EXHAUSTED = 4;
    static final int INVALID_PROTOCOL = 5;
    static final int MEMORY_EXHAUSTED = 6;
    static final int VALUE = 1;
    static final int END = 0;

    private ReaGhidraRegexWorker() {}

    public static void main(String[] arguments) throws IOException {
        try (DataInputStream input = new DataInputStream(
                 new BufferedInputStream(System.in));
             DataOutputStream output = new DataOutputStream(
                 new BufferedOutputStream(System.out))) {
            output.writeInt(MAGIC);
            output.flush();
            boolean compiling = true;
            try {
                if (arguments.length != 0 || input.readInt() != MAGIC)
                    throw new IOException("Invalid worker header");
                int sensitive = input.readUnsignedByte();
                if (sensitive != 0 && sensitive != 1)
                    throw new IOException("Invalid case flag");
                String expression = readString(input);
                Pattern pattern = Pattern.compile(expression, sensitive == 1
                    ? 0 : Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
                compiling = false;
                output.writeByte(READY);
                output.flush();
                int ordinal = 0;
                for (;;) {
                    int command = input.readUnsignedByte();
                    if (command == END) {
                        // Exact completion frame; EOF/truncation is not success.
                        if (input.read() != -1)
                            throw new IOException("Trailing request data");
                        output.writeByte(DONE);
                        output.writeInt(ordinal);
                        output.flush();
                        return;
                    }
                    if (command != VALUE || ordinal == Integer.MAX_VALUE)
                        throw new IOException("Invalid worker command");
                    boolean matched = pattern.matcher(readString(input)).find();
                    output.writeByte(MATCH);
                    output.writeInt(ordinal++);
                    output.writeBoolean(matched);
                    output.flush();
                }
            } catch (PatternSyntaxException failure) {
                if ("Stack overflow during pattern compilation"
                        .equals(failure.getDescription())) {
                    output.writeByte(STACK_EXHAUSTED);
                    output.writeByte(0);
                } else {
                    output.writeByte(INVALID_PATTERN);
                    output.writeInt(failure.getIndex());
                    writeString(output, failure.getDescription());
                }
                output.flush();
            } catch (StackOverflowError failure) {
                output.writeByte(STACK_EXHAUSTED);
                output.writeByte(compiling ? 0 : 1);
                output.flush();
            } catch (OutOfMemoryError failure) {
                // Best effort only; abnormal exit remains a failed operation.
                output.writeByte(MEMORY_EXHAUSTED);
                output.flush();
            } catch (IOException failure) {
                output.writeByte(INVALID_PROTOCOL);
                output.flush();
            }
        }
    }

    private static String readString(DataInputStream input) throws IOException {
        int units = input.readInt();
        if (units < 0) throw new IOException("Negative string length");
        // No semantic pattern-length cap. Allocation is confined to the child
        // heap and supervised transport; an OOME/abnormal exit is not a match.
        StringBuilder value = new StringBuilder(Math.min(units, 8192));
        for (int index = 0; index < units; index++) value.append(input.readChar());
        return value.toString();
    }

    private static void writeString(DataOutputStream output, String value)
            throws IOException {
        output.writeInt(value.length());
        for (int index = 0; index < value.length(); index++)
            output.writeChar(value.charAt(index));
    }
}
