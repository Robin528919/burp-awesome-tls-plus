package burp.control;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Write-ahead record of an in-flight settings change.
 * <p>
 * Settings live in two stores that cannot be written atomically together — Burp's preferences and
 * {@code rules.json} — so a crash between the two would otherwise leave a configuration that is
 * half of one version and half of another, with nothing on disk saying which. ADR-0001 section 11
 * fixes that by writing the intent first: every phase transition is durable, and each records the
 * digest each store is expected to hold before and after, so startup can tell a partial write from
 * an external edit and refuse to guess between them.
 * <p>
 * Not final only so that {@link SettingsControlCheck} can subclass it to make a write fail at a
 * chosen phase. Those failures are the whole point of the design and cannot be provoked any other
 * way, so there has to be a seam for them.
 * <p>
 * The single most important property is that exactly one phase is the commit decision. Before
 * {@link Phase#COMMIT_DECIDED} a crash rolls back; at or after it, a crash rolls <em>forward</em>,
 * and never the other way. A change the user approved and that was durably decided must not be
 * silently undone by a later failure to update a phase marker or refresh a UI.
 */
public class TransactionJournal {
    public static final int FORMAT_VERSION = 1;

    public static final String FILE_NAME = "transaction.json";

    /**
     * Where a transaction had got to. The ordering is the ordering of ADR-0001 section 11.
     */
    public enum Phase {
        /** Intent recorded. Nothing has been written to either store. */
        PREPARED,
        /** The audit trail has accepted the pending mutation. Still nothing written. */
        AUDIT_PREPARED,
        /** Preferences hold the candidate; rules do not yet. */
        PREFERENCES_WRITTEN,
        /** Both stores hold the candidate, but nothing has decided to keep it. */
        RULES_WRITTEN,
        /** Both stores verified against the candidate digests. Still reversible. */
        COMMIT_READY,
        /** The decision. From here the change is kept, whatever else fails. */
        COMMIT_DECIDED,
        /** The runtime snapshot and matcher have been published. */
        RUNTIME_PUBLISHED,
        /** Everything done; only cleanup remains. */
        COMPLETE;

        /**
         * @return whether reaching this phase means the change has been committed.
         */
        public boolean afterDecision() {
            return ordinal() >= COMMIT_DECIDED.ordinal();
        }
    }

    /**
     * What kind of change this was, for the audit trail and for the UI's recovery message.
     */
    public enum Source {UI_SAVE, RULES_AUTOSAVE, IMPORT, AI_APPLY, AI_REVERT, MIGRATION, RECOVERY}

    /**
     * The digests one store is expected to hold on each side of the change.
     *
     * @param before what it held when the candidate was built; null means "no file".
     * @param after  what it must hold once written.
     */
    public record Participant(String before, String after) {
        JsonObject toJson() {
            var json = new JsonObject();
            json.add("before", before == null ? com.google.gson.JsonNull.INSTANCE
                    : new com.google.gson.JsonPrimitive(before));
            json.addProperty("after", after);
            return json;
        }

        static Participant fromJson(JsonObject json) {
            var before = json.get("before");
            return new Participant(
                    before == null || before.isJsonNull() ? null : before.getAsString(),
                    json.get("after").getAsString());
        }
    }

    /**
     * One transaction's durable state.
     *
     * @param auditEnabled whether full audit was on when this transaction started. Recovery must
     *                     use the transaction's own setting, not today's: a transaction started
     *                     with audit on is only decided by a matching audit event, and looking for
     *                     one that was never meant to exist would block recovery forever.
     * @param oldDocument  the canonical document to roll back to.
     * @param newDocument  the canonical document to roll forward to.
     */
    public record Record(
            int formatVersion,
            String transactionId,
            Source source,
            boolean auditEnabled,
            Phase phase,
            String baseRevision,
            String candidateRevision,
            Participant preferences,
            Participant rules,
            String auditEventDigest,
            JsonObject oldDocument,
            JsonObject newDocument) {

        public Record withPhase(Phase next) {
            return new Record(formatVersion, transactionId, source, auditEnabled, next, baseRevision,
                    candidateRevision, preferences, rules, auditEventDigest, oldDocument, newDocument);
        }

        public JsonObject toJson() {
            var json = new JsonObject();
            json.addProperty("formatVersion", formatVersion);
            json.addProperty("transactionId", transactionId);
            json.addProperty("source", source.name());
            json.addProperty("auditEnabled", auditEnabled);
            json.addProperty("phase", phase.name());
            json.addProperty("baseRevision", baseRevision);
            json.addProperty("candidateRevision", candidateRevision);
            json.add("preferences", preferences.toJson());
            json.add("rules", rules.toJson());
            if (auditEventDigest != null) {
                json.addProperty("auditEventDigest", auditEventDigest);
            }
            json.add("oldDocument", oldDocument);
            json.add("newDocument", newDocument);
            return json;
        }

        static Record fromJson(JsonObject json) {
            var version = json.get("formatVersion").getAsInt();
            if (version != FORMAT_VERSION) {
                // A journal this version cannot read must block, not be discarded: it describes a
                // change that may be half-written right now.
                throw new IllegalStateException(
                        "transaction journal format " + version + " is not supported by this version");
            }
            return new Record(
                    version,
                    json.get("transactionId").getAsString(),
                    Source.valueOf(json.get("source").getAsString()),
                    json.get("auditEnabled").getAsBoolean(),
                    Phase.valueOf(json.get("phase").getAsString()),
                    json.get("baseRevision").getAsString(),
                    json.get("candidateRevision").getAsString(),
                    Participant.fromJson(json.getAsJsonObject("preferences")),
                    Participant.fromJson(json.getAsJsonObject("rules")),
                    json.has("auditEventDigest") ? json.get("auditEventDigest").getAsString() : null,
                    json.getAsJsonObject("oldDocument"),
                    json.getAsJsonObject("newDocument"));
        }
    }

    private static final SecureRandom RANDOM = new SecureRandom();

    private final Path file;

    public TransactionJournal(Path file) {
        this.file = file;
    }

    public Path path() {
        return file;
    }

    public static String newTransactionId() {
        var bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    /**
     * @return the unfinished transaction, or null if there is none.
     * @throws IOException if a journal exists but cannot be understood. Deliberately not swallowed:
     *                     an unreadable journal is the one case where continuing could overwrite a
     *                     half-written change.
     */
    public Record read() throws IOException {
        String text;
        try {
            text = Files.readString(file, StandardCharsets.UTF_8);
        } catch (NoSuchFileException e) {
            return null;
        }
        if (text.isBlank()) {
            // A zero-length journal is a crash during the very first write, before any store was
            // touched. Nothing to recover, but say so rather than pretending it was never there.
            return null;
        }
        try {
            JsonElement root = JsonParser.parseString(text);
            if (!root.isJsonObject()) {
                throw new IOException("transaction journal at " + file + " is not an object");
            }
            return Record.fromJson(root.getAsJsonObject());
        } catch (RuntimeException e) {
            throw new IOException("transaction journal at " + file + " is unreadable: " + e.getMessage(), e);
        }
    }

    /**
     * Writes {@code record} and does not return until it is on the platter.
     */
    public void write(Record record) throws IOException {
        Files.createDirectories(file.getParent());

        var temp = Files.createTempFile(file.getParent(), "transaction", ".tmp");
        try {
            var bytes = Jcs.bytes(record.toJson());
            Files.write(temp, bytes, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
            fsync(temp);
            try {
                Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (java.nio.file.AtomicMoveNotSupportedException e) {
                Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
            }
            fsyncDirectory(file.getParent());
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    /**
     * Moves a transaction to its next phase durably.
     *
     * @return the updated record, so the caller keeps working from what is actually on disk.
     */
    public Record advance(Record record, Phase next) throws IOException {
        var updated = record.withPhase(next);
        write(updated);
        return updated;
    }

    /**
     * Removes the journal once a transaction is fully done. Failing here is harmless: a leftover
     * {@code COMPLETE} journal is re-examined at startup and cleaned up then.
     */
    public void clear() throws IOException {
        Files.deleteIfExists(file);
        if (Files.isDirectory(file.getParent())) {
            fsyncDirectory(file.getParent());
        }
    }

    public boolean exists() {
        return Files.isRegularFile(file);
    }

    static void fsync(Path path) throws IOException {
        try (var channel = FileChannel.open(path, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            channel.force(true);
        }
    }

    /**
     * A rename is only durable once the directory entry is. Not every platform lets a directory be
     * opened for this, so a failure here is tolerated rather than fatal.
     */
    static void fsyncDirectory(Path directory) {
        try (var channel = FileChannel.open(directory, StandardOpenOption.READ)) {
            channel.force(true);
        } catch (IOException | UnsupportedOperationException ignored) {
            // Windows in particular refuses; the atomic rename is still the important half.
        }
    }

    /**
     * Self-check.
     * Run with: {@code java -ea -cp build/classes/java/main:<gson.jar> burp.control.TransactionJournal}
     */
    public static void main(String[] args) throws Exception {
        var dir = Files.createTempDirectory("awesome-tls-journal");
        var journal = new TransactionJournal(dir.resolve(FILE_NAME));

        check(journal.read() == null, "no journal means no unfinished transaction");
        check(!journal.exists(), "and no file");

        var old = SettingsSnapshot.empty();
        var candidate = SettingsSnapshot.of(BusinessSettings.defaults().withHttpTimeout(45), java.util.List.of());
        var record = new Record(FORMAT_VERSION, newTransactionId(), Source.AI_APPLY, true, Phase.PREPARED,
                old.revision(), candidate.revision(),
                new Participant(old.settings().canonicalDigest(), candidate.settings().canonicalDigest()),
                new Participant(null, "sha256:" + "a".repeat(64)),
                "sha256:" + "b".repeat(64),
                old.canonicalDocument(), candidate.canonicalDocument());

        journal.write(record);
        var read = journal.read();
        check(read != null, "a written journal is read back");
        check(read.transactionId().equals(record.transactionId()), "the transaction id survives");
        check(read.phase() == Phase.PREPARED, "the phase survives");
        check(read.auditEnabled(), "the transaction's own audit mode survives");
        check(read.rules().before() == null, "an absent rules file round trips as null");
        check(read.candidateRevision().equals(candidate.revision()), "the candidate revision survives");
        check(Jcs.digest(read.newDocument()).equals(candidate.revision()),
                "the stored candidate document still hashes to its revision");

        var advanced = journal.advance(read, Phase.COMMIT_DECIDED);
        check(advanced.phase() == Phase.COMMIT_DECIDED, "advance returns the new state");
        check(journal.read().phase() == Phase.COMMIT_DECIDED, "and it is what is on disk");
        check(journal.read().transactionId().equals(record.transactionId()),
                "advancing does not disturb the rest of the record");

        // The decision boundary is the whole point of the phase list.
        for (var phase : Phase.values()) {
            var expected = phase.ordinal() >= Phase.COMMIT_DECIDED.ordinal();
            check(phase.afterDecision() == expected, phase + " is on the right side of the decision");
        }
        check(!Phase.COMMIT_READY.afterDecision(), "COMMIT_READY is still reversible");
        check(Phase.COMMIT_DECIDED.afterDecision(), "COMMIT_DECIDED is not");

        journal.clear();
        check(journal.read() == null && !journal.exists(), "clearing removes it");
        journal.clear();
        check(true, "clearing twice is harmless");

        // A journal from a future version must block rather than be ignored: it describes a change
        // that may be sitting half-written in the stores right now.
        var future = record.toJson();
        future.addProperty("formatVersion", FORMAT_VERSION + 1);
        Files.writeString(journal.path(), Jcs.string(future));
        try {
            journal.read();
            check(false, "a future journal format is refused");
        } catch (IOException expected) {
            check(expected.getMessage().contains("not supported"), "and says why");
        }

        Files.writeString(journal.path(), "{ truncated");
        try {
            journal.read();
            check(false, "a truncated journal is refused");
        } catch (IOException expected) {
            check(true, "a truncated journal is refused");
        }

        // A zero-length file is a crash before the first byte, which is recoverable by doing nothing.
        Files.writeString(journal.path(), "");
        check(journal.read() == null, "an empty journal means nothing happened yet");

        System.out.println("TransactionJournal self-check passed (" + dir + ")");
    }

    private static void check(boolean condition, String what) {
        if (!condition) throw new AssertionError("failed: " + what);
    }
}
