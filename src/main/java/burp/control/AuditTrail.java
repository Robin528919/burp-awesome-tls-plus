package burp.control;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * Append-only record of everything AI Control does, when full audit is switched on.
 * <p>
 * Two jobs, and the second is the one that constrains the design. The obvious job is a trail a
 * user can read. The load-bearing job is that a durable {@code MUTATION_COMMITTED} event <em>is</em>
 * the commit decision for an audited transaction: ADR-0001 section 11 makes recovery ask this file
 * whether a change was committed, so "I cannot tell" has to be a distinct answer from "no". A
 * truncated last line must never read as "not committed", because that would roll back a change
 * the user approved and that may already be live.
 * <p>
 * Not final only so that {@link SettingsControlCheck} can subclass it to make an append fail, or
 * fail after having written. Recovery is defined entirely in terms of those cases.
 * <p>
 * Contents are plaintext and unredacted, credentials included. That is a deliberate, disclosed
 * risk: section 14.3 requires the enable warning and the audit settings to say so, because any
 * process, user or backup tool with access to the directory can read them.
 */
public class AuditTrail {
    public static final int FORMAT_VERSION = 1;

    static final String DIR_NAME = "audit";
    static final String EVENTS_FILE = "events.jsonl";
    static final String SNAPSHOT_DIR = "snapshots";

    /** ADR-0001 section 14.3 retention ceilings; whichever is reached first rotates. */
    static final Duration MAX_AGE = Duration.ofDays(30);
    static final int MAX_EVENTS = 1000;
    static final long MAX_BYTES = 100L * 1024 * 1024;

    /** There is no authentication, so there is only ever one actor. */
    public static final String ACTOR = "unauthenticated-local";

    /**
     * Whether a particular durable event can be proven to exist.
     * <p>
     * The third state is the point. Collapsing {@code INDETERMINATE} into {@code ABSENT} is what
     * would turn a torn write into a silent rollback of an approved change.
     */
    public enum Evidence {FOUND, ABSENT, INDETERMINATE}

    private final Path directory;

    /**
     * Serializes appends. Everything that reaches the trail is already serialized by the settings
     * coordinator, but MCP request threads log too, and two interleaved appends would corrupt a
     * line — which under the rule above is indistinguishable from a crash.
     */
    private final Object lock = new Object();

    public AuditTrail(Path directory) {
        this.directory = directory;
    }

    public Path directory() {
        return directory;
    }

    public Path eventsPath() {
        return directory.resolve(EVENTS_FILE);
    }

    /**
     * Appends an event and does not return until it is durable.
     *
     * @param body the event's stable content. A digest is taken over exactly this, so it must not
     *             contain a timestamp, sequence number or anything else that varies between the
     *             moment a transaction plans an event and the moment it writes one.
     * @return the digest of {@code body}, which is how recovery finds this event again.
     * @throws IOException if the event could not be made durable. Callers must treat this as a
     *                     hard failure; ADR-0001 section 14.2 is fail-closed.
     */
    public String append(String type, JsonObject body) throws IOException {
        var content = withType(type, body);
        var digest = Jcs.digest(content);

        var event = new JsonObject();
        event.addProperty("formatVersion", FORMAT_VERSION);
        event.addProperty("at", Instant.now().toString());
        event.addProperty("actor", ACTOR);
        event.addProperty("eventDigest", digest);
        event.add("event", content);

        var line = Jcs.string(event) + "\n";
        synchronized (lock) {
            Files.createDirectories(directory);
            Files.writeString(eventsPath(), line, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            TransactionJournal.fsync(eventsPath());
        }
        return digest;
    }

    /**
     * @return the digest {@link #append} would produce for this event, without writing anything.
     * A transaction records this in its journal before the event exists, so that recovery can look
     * for exactly the event that was intended rather than any event that looks similar.
     */
    public static String digestOf(String type, JsonObject body) {
        return Jcs.digest(withType(type, body));
    }

    private static JsonObject withType(String type, JsonObject body) {
        var content = body == null ? new JsonObject() : body.deepCopy();
        content.addProperty("type", type);
        return content;
    }

    /**
     * The evidence that decides an audited transaction: is there a durable, intact, matching
     * {@code MUTATION_COMMITTED}?
     * <p>
     * Every line in every audit file must parse for the answer to be {@link Evidence#ABSENT}. One
     * unreadable line anywhere means the file cannot rule the event out, and recovery must block
     * rather than roll back.
     */
    public Evidence probeCommitted(String transactionId, String expectedDigest) {
        var intact = true;
        for (var file : eventFiles()) {
            List<String> lines;
            try {
                lines = Files.readAllLines(file, StandardCharsets.UTF_8);
            } catch (IOException e) {
                return Evidence.INDETERMINATE;
            }
            for (var line : lines) {
                if (line.isBlank()) {
                    // A blank line is a torn append: something was allocated but not written.
                    intact = false;
                    continue;
                }
                JsonObject event;
                try {
                    var parsed = JsonParser.parseString(line);
                    if (!parsed.isJsonObject()) {
                        intact = false;
                        continue;
                    }
                    event = parsed.getAsJsonObject();
                } catch (RuntimeException e) {
                    intact = false;
                    continue;
                }
                if (!matchesCommitted(event, transactionId, expectedDigest)) {
                    continue;
                }
                // Re-derive the digest instead of trusting the recorded one, so a truncated and
                // then re-appended line cannot masquerade as a decision that never happened.
                if (!Jcs.digest(event.getAsJsonObject("event")).equals(expectedDigest)) {
                    intact = false;
                    continue;
                }
                return Evidence.FOUND;
            }
        }
        return intact ? Evidence.ABSENT : Evidence.INDETERMINATE;
    }

    private static boolean matchesCommitted(JsonObject event, String transactionId, String expectedDigest) {
        if (!event.has("eventDigest") || !event.has("event")) {
            return false;
        }
        if (!expectedDigest.equals(event.get("eventDigest").getAsString())) {
            return false;
        }
        var body = event.get("event");
        if (!body.isJsonObject()) {
            return false;
        }
        var inner = body.getAsJsonObject();
        return inner.has("type")
                && "MUTATION_COMMITTED".equals(inner.get("type").getAsString())
                && inner.has("transactionId")
                && transactionId.equals(inner.get("transactionId").getAsString());
    }

    /**
     * Stores one full settings document per revision, referenced by digest, so a run of events
     * that all describe the same configuration does not store it a thousand times.
     *
     * @return the revision, which is how events refer to it.
     */
    public String recordSnapshot(SettingsSnapshot snapshot) throws IOException {
        var revision = snapshot.revision();
        var file = snapshotPath(revision);
        synchronized (lock) {
            if (Files.isRegularFile(file)) {
                return revision;
            }
            Files.createDirectories(file.getParent());
            Files.write(file, Jcs.bytes(snapshot.canonicalDocument()),
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
            TransactionJournal.fsync(file);
        }
        return revision;
    }

    Path snapshotPath(String revision) {
        // The digest is hex after a fixed prefix, so it is already a safe file name.
        return directory.resolve(SNAPSHOT_DIR).resolve(revision.replace(':', '-') + ".json");
    }

    /**
     * @return the most recent events, newest first, for the UI.
     */
    public List<JsonObject> recent(int limit) {
        var out = new ArrayList<JsonObject>();
        var files = eventFiles();
        for (var i = files.size() - 1; i >= 0 && out.size() < limit; i--) {
            List<String> lines;
            try {
                lines = Files.readAllLines(files.get(i), StandardCharsets.UTF_8);
            } catch (IOException e) {
                continue;
            }
            for (var j = lines.size() - 1; j >= 0 && out.size() < limit; j--) {
                var line = lines.get(j);
                if (line.isBlank()) continue;
                try {
                    var parsed = JsonParser.parseString(line);
                    if (parsed.isJsonObject()) {
                        out.add(parsed.getAsJsonObject());
                    }
                } catch (RuntimeException ignored) {
                    // A damaged line is not worth failing the whole view over; probeCommitted is
                    // the path where it matters, and that one already refuses to guess.
                }
            }
        }
        return List.copyOf(out);
    }

    /**
     * Rotates and prunes to the section 14.3 ceilings. Best-effort by design: losing old history is
     * never a reason to stop recording new history.
     */
    public void enforceRetention() {
        try {
            var events = eventsPath();
            if (Files.isRegularFile(events)) {
                var size = Files.size(events);
                var count = countLines(events);
                if (size >= MAX_BYTES || count >= MAX_EVENTS) {
                    synchronized (lock) {
                        var archived = directory.resolve("events-" + Instant.now().toEpochMilli() + ".jsonl");
                        Files.move(events, archived);
                    }
                }
            }

            var cutoff = Instant.now().minus(MAX_AGE);
            for (var file : archives()) {
                if (Files.getLastModifiedTime(file).toInstant().isBefore(cutoff)) {
                    Files.deleteIfExists(file);
                }
            }

            // Then trim by total size, oldest archive first.
            var archives = archives();
            var total = 0L;
            for (var file : archives) {
                total += Files.size(file);
            }
            for (var file : archives) {
                if (total < MAX_BYTES) break;
                total -= Files.size(file);
                Files.deleteIfExists(file);
            }
        } catch (IOException ignored) {
            // Retention is housekeeping. A failure here must not turn into a failure to audit.
        }
    }

    private long countLines(Path file) throws IOException {
        try (var lines = Files.lines(file, StandardCharsets.UTF_8)) {
            return lines.count();
        }
    }

    /**
     * @return archives oldest first, excluding the live file.
     */
    private List<Path> archives() {
        if (!Files.isDirectory(directory)) {
            return List.of();
        }
        try (var stream = Files.list(directory)) {
            return stream
                    .filter(Files::isRegularFile)
                    .filter(p -> {
                        var name = p.getFileName().toString().toLowerCase(Locale.ROOT);
                        return name.startsWith("events-") && name.endsWith(".jsonl");
                    })
                    .sorted(Comparator.comparing(Path::getFileName))
                    .toList();
        } catch (IOException e) {
            return List.of();
        }
    }

    /**
     * @return every file that could hold an event, oldest first.
     */
    private List<Path> eventFiles() {
        var files = new ArrayList<>(archives());
        if (Files.isRegularFile(eventsPath())) {
            files.add(eventsPath());
        }
        return files;
    }

    /**
     * Self-check.
     * Run with: {@code java -ea -cp build/classes/java/main:<gson.jar> burp.control.AuditTrail}
     */
    public static void main(String[] args) throws Exception {
        var dir = Files.createTempDirectory("awesome-tls-audit");
        var trail = new AuditTrail(dir.resolve(DIR_NAME));

        var body = commitBody("tx1", "sha256:" + "0".repeat(64), "sha256:" + "1".repeat(64));
        var planned = digestOf("MUTATION_COMMITTED", body);

        check(trail.probeCommitted("tx1", planned) == Evidence.ABSENT,
                "with no file at all, the event is provably absent");

        var written = trail.append("MUTATION_COMMITTED", body);
        check(written.equals(planned), "the digest matches what was planned before the write");
        check(trail.probeCommitted("tx1", planned) == Evidence.FOUND, "and the event is found");
        check(trail.probeCommitted("tx2", planned) == Evidence.ABSENT, "another transaction is not");
        check(trail.probeCommitted("tx1", "sha256:" + "f".repeat(64)) == Evidence.ABSENT,
                "a different expected digest is not");

        // Unrelated traffic must not confuse the search.
        trail.append("MCP_CALL", jsonOf("tool", "awesome_tls.settings.inspect"));
        trail.append("LISTENER_STARTED", jsonOf("endpoint", "http://127.0.0.1:8885/mcp"));
        check(trail.probeCommitted("tx1", planned) == Evidence.FOUND, "surrounding events do not hide it");

        // The whole reason the third state exists.
        Files.writeString(trail.eventsPath(), "{ truncated line without a newline",
                StandardCharsets.UTF_8, StandardOpenOption.APPEND);
        check(trail.probeCommitted("tx2", digestOf("MUTATION_COMMITTED", commitBody("tx2", "a", "b")))
                == Evidence.INDETERMINATE, "a damaged line makes absence unprovable");
        check(trail.probeCommitted("tx1", planned) == Evidence.FOUND,
                "but an intact matching event is still proof");

        checkTamperedDigest(dir);
        checkSnapshotDeduplication(dir);
        checkRotation(dir);

        System.out.println("AuditTrail self-check passed (" + dir + ")");
    }

    /**
     * The recorded digest is a convenience for reading; the content is the truth.
     */
    private static void checkTamperedDigest(Path dir) throws Exception {
        var trail = new AuditTrail(dir.resolve("tampered"));
        var body = commitBody("tx", "sha256:" + "0".repeat(64), "sha256:" + "1".repeat(64));
        var digest = digestOf("MUTATION_COMMITTED", body);
        trail.append("MUTATION_COMMITTED", body);

        var lines = Files.readAllLines(trail.eventsPath());
        var event = JsonParser.parseString(lines.get(0)).getAsJsonObject();
        event.getAsJsonObject("event").addProperty("candidateRevision", "sha256:" + "9".repeat(64));
        Files.writeString(trail.eventsPath(), Jcs.string(event) + "\n");

        check(trail.probeCommitted("tx", digest) == Evidence.INDETERMINATE,
                "an event whose content no longer hashes to its digest is not proof");
    }

    private static void checkSnapshotDeduplication(Path dir) throws Exception {
        var trail = new AuditTrail(dir.resolve("snap"));
        var snapshot = SettingsSnapshot.empty();

        var revision = trail.recordSnapshot(snapshot);
        check(revision.equals(snapshot.revision()), "a snapshot is referenced by its revision");
        var file = trail.snapshotPath(revision);
        check(Files.isRegularFile(file), "and stored once");

        var firstWrite = Files.getLastModifiedTime(file);
        Thread.sleep(10);
        trail.recordSnapshot(SettingsSnapshot.empty());
        check(Files.getLastModifiedTime(file).equals(firstWrite), "storing the same revision again is a no-op");

        trail.recordSnapshot(SettingsSnapshot.of(BusinessSettings.defaults().withHttpTimeout(99), List.of()));
        try (var stream = Files.list(file.getParent())) {
            check(stream.count() == 2, "a different revision gets its own file");
        }

        check(Jcs.digestOfBytes(Files.readAllBytes(file)) != null, "the stored snapshot is readable");
        check(Jcs.digest(JsonParser.parseString(Files.readString(file))).equals(revision),
                "and still hashes to its revision");
    }

    private static void checkRotation(Path dir) throws Exception {
        var trail = new AuditTrail(dir.resolve("rotate"));
        for (var i = 0; i < 5; i++) {
            trail.append("MCP_CALL", jsonOf("n", String.valueOf(i)));
        }
        var body = commitBody("keep", "a", "b");
        var digest = digestOf("MUTATION_COMMITTED", body);
        trail.append("MUTATION_COMMITTED", body);

        // Force a rotation by moving the live file aside the way retention would.
        Files.move(trail.eventsPath(), trail.directory().resolve("events-1.jsonl"));
        trail.append("MCP_CALL", jsonOf("n", "after"));

        check(trail.probeCommitted("keep", digest) == Evidence.FOUND,
                "evidence in a rotated archive still counts");
        check(trail.recent(100).size() == 7, "the UI sees events across the rotation");
        check(trail.recent(2).size() == 2, "and can ask for fewer");

        trail.enforceRetention();
        check(trail.probeCommitted("keep", digest) != Evidence.INDETERMINATE,
                "retention leaves the trail readable");
    }

    private static JsonObject commitBody(String transactionId, String base, String candidate) {
        var body = new JsonObject();
        body.addProperty("transactionId", transactionId);
        body.addProperty("baseRevision", base);
        body.addProperty("candidateRevision", candidate);
        return body;
    }

    private static JsonObject jsonOf(String key, String value) {
        var json = new JsonObject();
        json.addProperty(key, value);
        return json;
    }

    private static void check(boolean condition, String what) {
        if (!condition) throw new AssertionError("failed: " + what);
    }
}
