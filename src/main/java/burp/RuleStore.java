package burp;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import burp.control.Jcs;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.Consumer;

/**
 * Reads and writes the domain rules as a JSON file on disk.
 * <p>
 * Burp's own preference store is backed by the Java preference store, which caps a single value
 * at 8192 characters. A couple of rules carrying a full ClientHello hex stream already exceed
 * that, so the rules live in a plain file instead: no size ceiling, and it can be edited by
 * hand, diffed, and shared.
 * <p>
 * Parsing is strict, and deliberately so. ADR-0001 section 7 replaces the previous lenient
 * behaviour, under which a blank file, a null row or an unknown field were quietly treated as
 * "no rules" or dropped. That was tolerable when the file only fed a table a user was looking at;
 * it is not tolerable once the same file is the base for a three-way merge and a content hash,
 * because "we could not read your rules" and "you have no rules" would become the same answer, and
 * an AI proposal would be merged against an empty baseline.
 * <p>
 * Deliberately free of Burp API types so {@link #main} can exercise it without Burp.
 */
public final class RuleStore {
    /**
     * Bumped only when the on-disk shape changes in a way older readers cannot handle.
     */
    public static final int FORMAT_VERSION = 1;

    public static final String FILE_NAME = "rules.json";

    /**
     * The directory the extension keeps its state in, named after the repository.
     * {@link #LEGACY_DIR_NAME} is what setups predating the {@code -plus} rename used.
     */
    public static final String DIR_NAME = "burp-awesome-tls-plus";

    static final String LEGACY_DIR_NAME = "burp-awesome-tls";

    /** The only keys the wrapper object may carry. */
    private static final Set<String> WRAPPER_FIELDS = Set.of("version", "rules");

    /** The only keys a rule object may carry. */
    private static final Set<String> RULE_FIELDS = Set.of(
            "hostPattern", "fingerprint", "hexClientHello", "externalProxyUrl", "httpTimeout", "enabled");

    private final Path file;
    private final Consumer<String> errorLog;

    public RuleStore(Path file, Consumer<String> errorLog) {
        this.file = file;
        this.errorLog = errorLog;
    }

    /**
     * The same directory the Go side keeps its CA in, so all of the extension's state lives
     * together. Java has no equivalent of Go's os.UserConfigDir, so its behaviour is reproduced
     * here: %AppData% on Windows, ~/Library/Application Support on macOS, $XDG_CONFIG_HOME or
     * ~/.config elsewhere.
     */
    public static Path configDir() {
        return configBase().resolve(DIR_NAME);
    }

    /**
     * Where a setup predating the {@code -plus} rename keeps its rules.
     */
    public static Path legacyConfigDir() {
        return configBase().resolve(LEGACY_DIR_NAME);
    }

    private static Path configBase() {
        var os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        var home = System.getProperty("user.home", ".");

        String base;
        if (os.contains("win")) {
            base = System.getenv("AppData");
        } else if (os.contains("mac") || os.contains("darwin")) {
            base = home + "/Library/Application Support";
        } else {
            base = System.getenv("XDG_CONFIG_HOME");
            if (base == null || base.isBlank()) {
                base = home + "/.config";
            }
        }

        if (base == null || base.isBlank()) {
            base = home;
        }

        return Path.of(base);
    }

    /**
     * A store for the current config directory, with no side effects.
     * <p>
     * Adopting a pre-rename directory is deliberately <em>not</em> done here. Startup has to
     * finish transaction-journal recovery before anything moves files around, or a migration
     * could overwrite the state recovery is about to restore; see {@link #adoptFrom} and
     * ADR-0001 section 11.
     */
    public static RuleStore inConfigDir(Consumer<String> errorLog) {
        return new RuleStore(configDir().resolve(FILE_NAME), errorLog);
    }

    /**
     * Moves the rules of a setup predating the {@code -plus} rename into the current directory, so
     * upgrading does not silently start from an empty rule list.
     * <p>
     * Keyed on the rules file rather than on the directory: the Go side creates the new directory
     * for its CA as soon as the server starts, which may well happen before this runs.
     *
     * @return true if anything was moved.
     */
    public boolean adoptFrom(Path legacyDir) {
        if (exists() || legacyDir.equals(file.getParent())) {
            return false;
        }

        var legacy = legacyDir.resolve(FILE_NAME);
        if (!Files.isRegularFile(legacy)) {
            return false;
        }

        try {
            Files.createDirectories(file.getParent());
            Files.move(legacy, file);

            var legacyBackup = legacyDir.resolve(backupPath().getFileName());
            if (Files.isRegularFile(legacyBackup)) {
                Files.move(legacyBackup, backupPath(), StandardCopyOption.REPLACE_EXISTING);
            }
            return true;
        } catch (IOException e) {
            errorLog.accept("Could not move " + legacy + " to " + file + ": " + e);
            return false;
        }
    }

    public Path path() {
        return file;
    }

    public boolean exists() {
        return Files.isRegularFile(file);
    }

    public Path backupPath() {
        return file.resolveSibling(file.getFileName() + ".bak");
    }

    public Path corruptPath() {
        return file.resolveSibling(file.getFileName() + ".corrupt");
    }

    // ------------------------------------------------------------------ reading

    /**
     * The outcome of a read that changed nothing on disk.
     */
    public sealed interface Probe {
        /**
         * No file. Distinct from an unreadable one: only this means "you have no rules".
         */
        record Missing() implements Probe {
        }

        /**
         * @param rules     the parsed rows, in storage order, exactly as written.
         * @param rawDigest {@code sha256:<hex>} over the file's bytes, for {@link #saveIfUnchanged}.
         */
        record Loaded(List<FingerprintRule> rules, String rawDigest) implements Probe {
        }

        /**
         * The file exists but cannot be trusted. Nothing is moved, renamed or rewritten; the
         * caller is expected to block and offer a repair, not to invent an empty baseline.
         *
         * @param rawDigest the digest of whatever is there, or null if it could not even be read.
         */
        record Invalid(String reason, String rawDigest) implements Probe {
        }
    }

    /**
     * Reads the file without touching it, in any way, ever.
     * <p>
     * This is the only read that inspect, propose, approval and startup recovery may use.
     * {@link #load()} exists for the settings table and quarantines on failure, which would
     * destroy the very bytes a conflict check needs to compare against.
     */
    public Probe probe() {
        byte[] raw;
        try {
            raw = Files.readAllBytes(file);
        } catch (NoSuchFileException e) {
            return new Probe.Missing();
        } catch (IOException e) {
            return new Probe.Invalid("could not be read: " + e, null);
        }

        var digest = Jcs.digestOfBytes(raw);
        try {
            return new Probe.Loaded(parse(new String(raw, StandardCharsets.UTF_8)), digest);
        } catch (RuleFileException e) {
            return new Probe.Invalid(e.getMessage(), digest);
        }
    }

    /**
     * @return the stored rules, or an empty list if the file is missing or unreadable.
     * @deprecated prefer {@link #probe()}, which distinguishes "no rules" from "unreadable" and
     * has no side effects. Kept for the settings table's own load path.
     */
    @Deprecated
    public List<FingerprintRule> load() {
        var probe = probe();
        if (probe instanceof Probe.Loaded loaded) {
            return loaded.rules();
        }
        if (probe instanceof Probe.Invalid invalid) {
            errorLog.accept("Could not read " + file + ": " + invalid.reason());
        }
        return List.of();
    }

    /**
     * Raised when the file's shape is not one this version understands. Distinct from a row that
     * is merely incomplete: those are kept, and simply never match.
     */
    public static final class RuleFileException extends RuntimeException {
        public RuleFileException(String message) {
            super(message);
        }
    }

    /**
     * Parses the file format, tolerating a bare JSON array so a hand-written or exported list
     * without the wrapper still imports.
     * <p>
     * Shape is checked on the JSON tree before anything is mapped to a rule, because letting Gson
     * bind directly would silently drop a misspelled field — and a misspelled field in a rules
     * file is a rule that does not do what its author believes it does.
     *
     * @throws RuleFileException if the content is not a rules file this version can read.
     */
    public static List<FingerprintRule> parse(String json) {
        if (json == null) {
            throw new RuleFileException("is empty; delete it to start from no rules");
        }
        // A blank file used to mean "no rules". It now means "something truncated this", because
        // an empty baseline is the one answer that silently discards every rule on a merge.
        if (json.isBlank()) {
            throw new RuleFileException("is empty; delete it to start from no rules");
        }

        JsonElement root;
        try {
            root = JsonParser.parseString(json);
        } catch (JsonSyntaxException e) {
            throw new RuleFileException("is not valid JSON: " + rootCause(e));
        }

        JsonArray rows;
        if (root.isJsonArray()) {
            // Legacy bare array, still accepted so an exported or hand-written list imports.
            rows = root.getAsJsonArray();
        } else if (root.isJsonObject()) {
            var wrapper = root.getAsJsonObject();
            for (var key : wrapper.keySet()) {
                if (!WRAPPER_FIELDS.contains(key)) {
                    throw new RuleFileException("has an unknown top-level field \"" + key + "\"");
                }
            }

            var version = FORMAT_VERSION;
            if (wrapper.has("version")) {
                version = intOf(wrapper.get("version"), "version");
                if (version < 0) {
                    throw new RuleFileException("has a negative format version (" + version + ")");
                }
                // 0 or missing is the legacy wrapper, which this version reads unchanged.
                if (version > FORMAT_VERSION) {
                    throw new RuleFileException(
                            "was written by a newer version of the extension (format " + version + ")");
                }
            }

            if (!wrapper.has("rules") || wrapper.get("rules").isJsonNull()) {
                rows = new JsonArray();
            } else if (wrapper.get("rules").isJsonArray()) {
                rows = wrapper.getAsJsonArray("rules");
            } else {
                throw new RuleFileException("has a \"rules\" field that is not an array");
            }
        } else {
            throw new RuleFileException("is not a rules file: expected an object or an array");
        }

        var out = new ArrayList<FingerprintRule>(rows.size());
        for (var i = 0; i < rows.size(); i++) {
            out.add(parseRule(rows.get(i), i));
        }
        return List.copyOf(out);
    }

    private static FingerprintRule parseRule(JsonElement element, int index) {
        var at = "rule " + (index + 1);
        if (!element.isJsonObject()) {
            throw new RuleFileException("has " + at + " that is not an object");
        }
        var object = element.getAsJsonObject();
        for (var key : object.keySet()) {
            if (!RULE_FIELDS.contains(key)) {
                throw new RuleFileException("has an unknown field \"" + key + "\" in " + at);
            }
        }

        var rule = new FingerprintRule();
        rule.hostPattern = stringOf(object, "hostPattern", at);
        rule.fingerprint = stringOf(object, "fingerprint", at);
        rule.hexClientHello = stringOf(object, "hexClientHello", at);
        rule.externalProxyUrl = stringOf(object, "externalProxyUrl", at);

        if (object.has("httpTimeout") && !object.get("httpTimeout").isJsonNull()) {
            rule.httpTimeout = intOf(object.get("httpTimeout"), at + "'s httpTimeout");
        }
        if (object.has("enabled") && !object.get("enabled").isJsonNull()) {
            var value = object.get("enabled");
            if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isBoolean()) {
                throw new RuleFileException("has a non-boolean \"enabled\" in " + at);
            }
            rule.enabled = value.getAsBoolean();
        }
        return rule;
    }

    /**
     * A missing or null string materializes as empty, which is what every earlier version wrote
     * for "inherit". A number or object in its place is a mistake, not a value.
     */
    private static String stringOf(JsonObject object, String field, String at) {
        if (!object.has(field) || object.get(field).isJsonNull()) {
            return "";
        }
        var value = object.get(field);
        if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) {
            throw new RuleFileException("has a non-string \"" + field + "\" in " + at);
        }
        return value.getAsString();
    }

    private static int intOf(JsonElement element, String what) {
        if (!element.isJsonPrimitive() || !element.getAsJsonPrimitive().isNumber()) {
            throw new RuleFileException("has a non-numeric \"" + what + "\"");
        }
        var text = element.getAsString();
        try {
            return Integer.parseInt(text);
        } catch (NumberFormatException e) {
            throw new RuleFileException("has a non-integer \"" + what + "\" (" + text + ")");
        }
    }

    private static String rootCause(Throwable e) {
        var cause = e;
        while (cause.getCause() != null) {
            cause = cause.getCause();
        }
        return cause.getMessage() == null ? e.toString() : cause.getMessage();
    }

    public static String serialize(List<FingerprintRule> rules) {
        var wrapper = new RuleFile();
        wrapper.version = FORMAT_VERSION;
        wrapper.rules = rules;
        return new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(wrapper) + "\n";
    }

    // ------------------------------------------------------------------ writing

    /**
     * Raised when the file changed underneath a write that expected a particular version.
     */
    public static final class ConflictException extends IOException {
        private final String actualDigest;

        ConflictException(String message, String actualDigest) {
            super(message);
            this.actualDigest = actualDigest;
        }

        public String actualDigest() {
            return actualDigest;
        }
    }

    /**
     * Writes via a temporary file and a rename, so an interrupted write cannot leave a truncated
     * rules file behind. The previous contents are kept as {@code .bak}, because rules are saved
     * automatically and there is no undo.
     */
    public void save(List<FingerprintRule> rules) throws IOException {
        write(rules);
    }

    /**
     * Replaces the file only if its current bytes still hash to {@code expectedDigest}.
     * <p>
     * A plain filesystem offers no compare-and-swap against an uncooperative editor, so this is a
     * narrowed window rather than mutual exclusion: the digest is re-checked immediately before
     * the rename, and the previous contents are kept as {@code .bak}. ADR-0001 section 10 requires
     * that the residual race be reported rather than papered over, which is what
     * {@link ConflictException} is for.
     *
     * @param expectedDigest the digest observed when the candidate was built, or null when the
     *                       file is expected not to exist yet.
     */
    public void saveIfUnchanged(String expectedDigest, List<FingerprintRule> rules) throws IOException {
        var current = currentDigest();
        if (!java.util.Objects.equals(current, expectedDigest)) {
            throw new ConflictException(file + " changed on disk since it was read", current);
        }
        write(rules);
    }

    /**
     * @return {@code sha256:<hex>} over the file's bytes, or null when there is no file.
     */
    public String currentDigest() throws IOException {
        try {
            return Jcs.digestOfBytes(Files.readAllBytes(file));
        } catch (NoSuchFileException e) {
            return null;
        }
    }

    private void write(List<FingerprintRule> rules) throws IOException {
        Files.createDirectories(file.getParent());

        if (exists()) {
            try {
                Files.copy(file, backupPath(), StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException e) {
                errorLog.accept("Could not back up " + file + ": " + e);
            }
        }

        var temp = Files.createTempFile(file.getParent(), "rules", ".tmp");
        try {
            Files.writeString(temp, serialize(rules), StandardCharsets.UTF_8);
            try {
                Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                // Some filesystems (and Windows in places) refuse an atomic move; the plain one
                // is still better than writing the destination in place.
                Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    /**
     * Moves an unreadable file aside so a fresh one can be written.
     * <p>
     * Only ever called from an explicit user action. Doing this automatically on a parse failure —
     * which is what this class used to do — destroys the evidence needed to work out what went
     * wrong, and does it at exactly the moment the user most needs their rules back.
     */
    public void quarantine() throws IOException {
        Files.move(file, corruptPath(), StandardCopyOption.REPLACE_EXISTING);
    }

    /**
     * Restores the {@code .bak} written before the last save.
     */
    public void restoreBackup() throws IOException {
        Files.copy(backupPath(), file, StandardCopyOption.REPLACE_EXISTING);
    }

    private static final class RuleFile {
        int version;
        List<FingerprintRule> rules;
    }

    /**
     * Self-check for the on-disk behaviour, which is easy to break without noticing.
     * Run with: {@code java -ea -cp build/classes/java/main:<gson.jar> burp.RuleStore}
     */
    public static void main(String[] args) throws Exception {
        var dir = Files.createTempDirectory("awesome-tls-store");
        var file = dir.resolve(FILE_NAME);
        var errors = new ArrayList<String>();
        var store = new RuleStore(file, errors::add);

        check(store.probe() instanceof Probe.Missing, "a missing file probes as missing, not as empty");
        check(!store.exists(), "a missing file does not report as existing");

        var rules = List.of(
                new FingerprintRule("example.com", "chrome", "", "", 60, true),
                new FingerprintRule("*.api.example.com", "", "aabb", "socks5://127.0.0.1:1080", null, false));
        store.save(rules);

        var loaded = ((Probe.Loaded) store.probe()).rules();
        check(loaded.size() == 2, "both rules survive a round trip");
        check(loaded.get(0).hostPattern.equals("example.com") && loaded.get(0).httpTimeout == 60,
                "scalar fields survive a round trip");
        check(loaded.get(1).hexClientHello.equals("aabb") && !loaded.get(1).enabled,
                "hex and the enabled flag survive a round trip");
        check(loaded.get(1).httpTimeout == null, "an absent timeout stays absent");

        // Rewriting must leave the previous version recoverable, since saves are automatic.
        store.save(List.of(new FingerprintRule("only.com", "firefox", "", "", null, true)));
        check(((Probe.Loaded) store.probe()).rules().size() == 1, "a rewrite replaces the previous contents");
        check(Files.exists(store.backupPath()), "a rewrite leaves a .bak behind");
        check(parse(Files.readString(store.backupPath())).size() == 2, "the .bak holds the previous rules");

        checkStrictParsing();
        checkDigestGuardedWrites(dir);
        checkProbeHasNoSideEffects(dir);
        checkLegacyAdoption(dir, errors);

        check(configDir().endsWith(DIR_NAME), "the config dir is namespaced");
        check(configDir().isAbsolute(), "the config dir is absolute");
        check(legacyConfigDir().equals(configDir().resolveSibling(LEGACY_DIR_NAME)),
                "the pre-rename dir sits beside the current one");

        System.out.println("RuleStore self-check passed (" + dir + ")");
    }

    /**
     * The parser is the boundary between "these are your rules" and "we cannot tell". Everything
     * ambiguous has to land on the second answer.
     */
    private static void checkStrictParsing() {
        // A hand-edited or exported bare array is still accepted.
        check(parse("[{\"hostPattern\":\"bare.com\"}]").size() == 1, "a bare JSON array parses");
        check(parse("{\"version\":1,\"rules\":[]}").isEmpty(), "an explicitly empty rule list parses");
        check(parse("{\"version\":1}").isEmpty(), "a wrapper without rules parses as no rules");
        check(parse("{\"rules\":[]}").isEmpty(), "a wrapper without a version is the legacy shape");
        check(parse("{\"version\":0,\"rules\":[]}").isEmpty(), "version 0 is the legacy shape");
        check(parse("[{\"hostPattern\":\"x.com\"}]").get(0).fingerprint.isEmpty(),
                "absent strings materialize as empty, never null");
        check(parse("[{\"hostPattern\":\"x.com\",\"fingerprint\":null}]").get(0).fingerprint.isEmpty(),
                "explicit nulls materialize as empty too");
        check(parse("[{\"hostPattern\":\"x.com\"}]").get(0).enabled, "an absent enabled flag defaults to on");

        // Everything below used to be silently accepted, and each one turned "unreadable" into
        // "you have no rules" or "that field does not exist".
        rejects("", "a blank file");
        rejects("   \n ", "a whitespace-only file");
        rejects("{ this is not json", "malformed JSON");
        rejects("\"just a string\"", "a JSON string at the root");
        rejects("42", "a JSON number at the root");
        rejects("null", "a JSON null at the root");
        rejects("{\"version\":" + (FORMAT_VERSION + 1) + ",\"rules\":[]}", "a newer format version");
        rejects("{\"version\":1,\"rules\":[],\"extra\":1}", "an unknown top-level field");
        rejects("{\"version\":1,\"rules\":{}}", "a rules field that is not an array");
        rejects("{\"version\":1,\"rules\":[null]}", "a null row");
        rejects("{\"version\":1,\"rules\":[[]]}", "a non-object row");
        rejects("{\"version\":1,\"rules\":[{\"hostPatern\":\"typo.com\"}]}", "a misspelled field");
        rejects("{\"version\":1,\"rules\":[{\"hostPattern\":123}]}", "a non-string host pattern");
        rejects("{\"version\":1,\"rules\":[{\"httpTimeout\":\"60\"}]}", "a stringly-typed timeout");
        rejects("{\"version\":1,\"rules\":[{\"httpTimeout\":1.5}]}", "a fractional timeout");
        rejects("{\"version\":1,\"rules\":[{\"enabled\":\"yes\"}]}", "a stringly-typed enabled flag");
        rejects("{\"version\":\"1\",\"rules\":[]}", "a stringly-typed version");
    }

    private static void checkDigestGuardedWrites(Path dir) throws Exception {
        var file = dir.resolve("guarded.json");
        var store = new RuleStore(file, s -> {
        });

        check(store.currentDigest() == null, "a missing file has no digest");
        store.saveIfUnchanged(null, List.of(new FingerprintRule("a.com", "", "", "", null, true)));
        check(store.exists(), "a guarded write creates the file when none was expected");

        var digest = store.currentDigest();
        store.saveIfUnchanged(digest, List.of(new FingerprintRule("b.com", "", "", "", null, true)));
        check(((Probe.Loaded) store.probe()).rules().get(0).hostPattern.equals("b.com"),
                "a matching digest lets the write through");

        // Someone else edited the file between read and write.
        var stale = store.currentDigest();
        Files.writeString(file, serialize(List.of(new FingerprintRule("external.com", "", "", "", null, true))));
        try {
            store.saveIfUnchanged(stale, List.of(new FingerprintRule("c.com", "", "", "", null, true)));
            check(false, "a stale digest is refused");
        } catch (ConflictException expected) {
            check(expected.actualDigest() != null, "the conflict reports what is actually there");
        }
        check(((Probe.Loaded) store.probe()).rules().get(0).hostPattern.equals("external.com"),
                "and the external edit survives untouched");

        check(Files.exists(store.backupPath()), "guarded writes keep a backup too");
    }

    /**
     * A probe runs while the user may be looking at a broken file and deciding what to do. It must
     * not be the thing that moves it.
     */
    private static void checkProbeHasNoSideEffects(Path dir) throws Exception {
        var file = dir.resolve("broken.json");
        Files.writeString(file, "{ not json");
        var before = Files.readAllBytes(file);
        var store = new RuleStore(file, s -> {
        });

        var probe = store.probe();
        check(probe instanceof Probe.Invalid, "a broken file probes as invalid");
        check(((Probe.Invalid) probe).rawDigest() != null, "an invalid probe still reports a digest");
        check(java.util.Arrays.equals(before, Files.readAllBytes(file)), "the bytes are untouched");
        check(!Files.exists(store.corruptPath()), "nothing was quarantined");
        check(!Files.exists(store.backupPath()), "nothing was backed up");
        check(Files.list(dir.getParent() == null ? dir : file.getParent())
                .noneMatch(p -> p.getFileName().toString().endsWith(".tmp")), "nothing was written");

        // Quarantine is available, but only when asked for.
        store.quarantine();
        check(Files.exists(store.corruptPath()) && !store.exists(), "an explicit quarantine moves the file");
    }

    private static void checkLegacyAdoption(Path dir, List<String> errors) throws Exception {
        var legacyDir = Files.createDirectory(dir.resolve(LEGACY_DIR_NAME));
        var currentDir = Files.createDirectory(dir.resolve(DIR_NAME));
        var legacyStore = new RuleStore(legacyDir.resolve(FILE_NAME), errors::add);
        legacyStore.save(List.of(new FingerprintRule("old.com", "chrome", "", "", null, true)));
        legacyStore.save(List.of(new FingerprintRule("new.com", "firefox", "", "", null, true)));

        var adopted = new RuleStore(currentDir.resolve(FILE_NAME), errors::add);
        check(adopted.adoptFrom(legacyDir), "adoption reports that it moved something");
        var moved = ((Probe.Loaded) adopted.probe()).rules();
        check(moved.size() == 1 && moved.get(0).hostPattern.equals("new.com"),
                "rules move across from the pre-rename dir");
        check(parse(Files.readString(adopted.backupPath())).get(0).hostPattern.equals("old.com"),
                "the .bak moves across with them");
        check(!legacyStore.exists(), "the pre-rename file is not left behind to diverge");

        // Whatever is in the current directory always wins; a second run must not resurrect old rules.
        legacyStore.save(List.of(
                new FingerprintRule("a.com", "chrome", "", "", null, true),
                new FingerprintRule("b.com", "chrome", "", "", null, true)));
        check(!adopted.adoptFrom(legacyDir), "a second adoption does nothing");
        check(((Probe.Loaded) adopted.probe()).rules().size() == 1,
                "an existing file is never overwritten by the pre-rename one");

        // inConfigDir must no longer adopt on its own; startup orders that after journal recovery.
        check(RuleStore.inConfigDir(errors::add).path().equals(configDir().resolve(FILE_NAME)),
                "inConfigDir points at the current directory without side effects");
    }

    private static void rejects(String json, String what) {
        try {
            parse(json);
            throw new AssertionError("failed: " + what + " must be refused");
        } catch (RuleFileException expected) {
            check(expected.getMessage() != null && !expected.getMessage().isBlank(),
                    what + " is refused with a reason");
        }
    }

    private static void check(boolean condition, String what) {
        if (!condition) throw new AssertionError("failed: " + what);
    }
}
