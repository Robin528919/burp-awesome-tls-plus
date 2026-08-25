package burp.control;

import burp.FingerprintRule;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * The one settings validator. ADR-0001 section 7 requires the UI, import, MCP and the pre-commit
 * recheck to run the same checks and differ only in {@link Policy}; letting each caller carry its
 * own near-copy is how a value the table accepts becomes a value a proposal rejects, or worse,
 * the reverse.
 * <p>
 * Field- and set-level only. Whether a change is ambiguous, needs an acknowledgement, or collides
 * with a hidden row depends on what is already committed, so those live with the patch.
 */
public final class Validation {
    /**
     * Who is asking, which decides both the check set and whether a problem is fatal.
     */
    public enum Policy {
        /**
         * The rules table's 500 ms autosave. Historically it has to be able to store a row the
         * user is still typing, so problems here mark a row inactive rather than refusing the save.
         */
        UI_DRAFT,
        /** Importing a file: the whole batch is vetted before anything is accepted. */
        IMPORT,
        /** An AI patch: strict, and with the extra restrictions in section 7. */
        AI_PROPOSAL,
        /** The final recheck of a candidate before it is persisted. */
        COMMIT;

        /**
         * @return whether a problem must block the operation rather than merely disable a row.
         */
        public boolean blocking() {
            return this != UI_DRAFT;
        }
    }

    /**
     * @param path    output locator, e.g. {@code /settings/fingerprint}. Never a writable patch path.
     * @param reason  stable machine-readable token, safe to switch on.
     * @param message one sentence a user can act on.
     */
    public record Problem(String path, String reason, String message) {
    }

    private Validation() {
    }

    // ------------------------------------------------------------------ paths

    /** RFC 6901: {@code ~} and {@code /} are the only characters a token must escape. */
    public static String escapeToken(String token) {
        return token.replace("~", "~0").replace("/", "~1");
    }

    public static String settingsPath(String field) {
        return "/settings/" + escapeToken(field);
    }

    public static String rulePath(String normalizedKey, String field) {
        return "/domainRules/byHost/" + escapeToken(normalizedKey) + "/" + escapeToken(field);
    }

    // ------------------------------------------------------------------ fields

    /**
     * @return why {@code value} is not a {@code host:port} listen address, or null.
     */
    public static String addressProblem(String value, String label) {
        var address = value == null ? "" : value.trim();
        var separator = address.lastIndexOf(':');
        if (separator <= 0 || separator == address.length() - 1) {
            return label + " must be in host:port form, e.g. 127.0.0.1:8887.";
        }

        var host = address.substring(0, separator);
        if (host.isBlank() || host.contains(" ")) {
            return label + " must be in host:port form, e.g. 127.0.0.1:8887.";
        }

        try {
            var port = Integer.parseInt(address.substring(separator + 1));
            if (port < 1 || port > 65535) {
                return label + " port must be between 1 and 65535.";
            }
        } catch (NumberFormatException e) {
            return label + " port must be a number.";
        }
        return null;
    }

    /**
     * @return why {@code value} is not a ClientHello hex stream, or null. Empty means "inherit".
     */
    public static String hexProblem(String value) {
        var hex = value == null ? "" : value.trim();
        if (hex.isEmpty()) {
            return null;
        }
        if (hex.length() % 2 != 0) {
            return "Hex ClientHello must have an even number of characters.";
        }
        for (var i = 0; i < hex.length(); i++) {
            if (Character.digit(hex.charAt(i), 16) < 0) {
                return "Hex ClientHello must contain hexadecimal characters only.";
            }
        }
        return null;
    }

    public static String timeoutProblem(Integer value, boolean inheritable) {
        if (value == null) {
            return inheritable ? null : "Timeout is required.";
        }
        if (value < BusinessSettings.MIN_HTTP_TIMEOUT || value > BusinessSettings.MAX_HTTP_TIMEOUT) {
            return "Timeout must be between " + BusinessSettings.MIN_HTTP_TIMEOUT + " and "
                    + BusinessSettings.MAX_HTTP_TIMEOUT + " seconds"
                    + (inheritable ? ", or empty to inherit." : ".");
        }
        return null;
    }

    /**
     * @param catalog the fingerprints the Go library currently offers. Empty means the catalog is
     *                unavailable, in which case the name is not second-guessed — refusing every
     *                fingerprint because the native library has not answered yet would be worse
     *                than accepting one the Go side will reject with a clear message.
     */
    public static String fingerprintProblem(String value, Set<String> catalog, boolean inheritable) {
        var name = value == null ? "" : value.trim();
        if (name.isEmpty()) {
            return inheritable ? null : "Fingerprint is required.";
        }
        if (catalog == null || catalog.isEmpty()) {
            return null;
        }
        if (!catalog.contains(name)) {
            return "Unknown fingerprint \"" + name + "\".";
        }
        return null;
    }

    // ------------------------------------------------------------------ settings

    public static List<Problem> settings(BusinessSettings settings, Set<String> catalog, Policy policy) {
        var problems = new ArrayList<Problem>();
        var value = settings.normalized();

        add(problems, "spoofProxyAddress",
                addressProblem(value.spoofProxyAddress(), "Listen address"), "invalid_address");
        add(problems, "interceptProxyAddress",
                addressProblem(value.interceptProxyAddress(), "Intercept proxy address"), "invalid_address");
        add(problems, "burpProxyAddress",
                addressProblem(value.burpProxyAddress(), "Burp proxy address"), "invalid_address");
        add(problems, "hexClientHello", hexProblem(value.hexClientHello()), "invalid_hex");
        add(problems, "httpTimeout", timeoutProblem(value.httpTimeout(), false), "timeout_out_of_range");
        add(problems, "externalProxyUrl", prefixed("External proxy URL", ProxyUrl.problem(value.externalProxyUrl())),
                "invalid_proxy_url");

        // The global fingerprint is not inheritable: something has to be selected.
        add(problems, "fingerprint", fingerprintProblem(value.fingerprint(), catalog, false), "unknown_fingerprint");

        return List.copyOf(problems);
    }

    // ------------------------------------------------------------------ rules

    /**
     * Field-level checks for a single rule, keyed by the normalized host when there is one.
     *
     * @param index   storage position, used to locate a row whose host pattern is itself unusable.
     * @param catalog the fingerprint names to check against, or null to skip that check.
     */
    public static List<Problem> rule(FingerprintRule rule, int index, Set<String> catalog, Policy policy) {
        var problems = new ArrayList<Problem>(structuralRule(rule, index));
        if (catalog != null) {
            var value = rule.normalized();
            var host = HostKey.normalize(value.hostPattern, HostKey.Mode.RULE_KEY);
            addRule(problems, host.ok() ? host.key() : "#" + index, "fingerprint",
                    fingerprintProblem(value.fingerprint, catalog, true), "unknown_fingerprint");
        }
        return List.copyOf(problems);
    }

    /**
     * The checks that depend only on the stored value, never on runtime state.
     * <p>
     * The split matters: these decide whether a row is usable, and therefore whether it is
     * canonicalized or preserved verbatim, and therefore the settings revision. The fingerprint
     * catalog comes from the loaded Go library, so folding it in here would make the revision
     * change when the native library fails to load — turning every {@code expectedRevision} an AI
     * client holds into a conflict for a reason nothing in the settings explains. An unrecognized
     * fingerprint is still refused, but by {@link #rule}, at the point a patch introduces one.
     */
    public static List<Problem> structuralRule(FingerprintRule rule, int index) {
        var problems = new ArrayList<Problem>();
        var value = rule.normalized();

        var host = HostKey.normalize(value.hostPattern, HostKey.Mode.RULE_KEY);
        var key = host.ok() ? host.key() : "#" + index;

        if (!host.ok()) {
            problems.add(new Problem(rulePath(key, "hostPattern"), "invalid_host_pattern",
                    "Host pattern " + host.problem() + "; use example.com or *.example.com."));
        }

        addRule(problems, key, "hexClientHello", hexProblem(value.hexClientHello), "invalid_hex");
        addRule(problems, key, "externalProxyUrl",
                prefixed("External proxy URL", ProxyUrl.problem(value.externalProxyUrl)), "invalid_proxy_url");
        addRule(problems, key, "httpTimeout", timeoutProblem(value.httpTimeout, true), "timeout_out_of_range");

        return List.copyOf(problems);
    }

    /**
     * Whole-set checks: everything {@link #rule} finds, plus duplicate normalized keys.
     * <p>
     * Two rows that normalize to the same key are both reported. ADR-0001 section 8.1 forbids
     * picking a winner, because "the last one wins" is exactly the silent behaviour that makes a
     * duplicate look harmless right up until the wrong rule is the one applied.
     */
    public static List<Problem> ruleSet(List<FingerprintRule> rules, Set<String> catalog, Policy policy) {
        var problems = new ArrayList<Problem>();
        var firstSeenAt = new HashMap<String, Integer>();
        var reported = new java.util.HashSet<String>();

        for (var i = 0; i < rules.size(); i++) {
            var rule = rules.get(i);
            if (rule == null) {
                problems.add(new Problem("/domainRules/byHost/#" + i, "null_rule", "Rule " + (i + 1) + " is empty."));
                continue;
            }
            problems.addAll(rule(rule, i, catalog, policy));

            var host = HostKey.normalize(rule.normalized().hostPattern, HostKey.Mode.RULE_KEY);
            if (!host.ok()) {
                continue;
            }
            var previous = firstSeenAt.putIfAbsent(host.key(), i);
            if (previous == null) {
                continue;
            }
            // Report the original row once as well, so the UI can highlight both halves.
            if (reported.add(host.key())) {
                problems.add(duplicate(host.key(), previous));
            }
            problems.add(duplicate(host.key(), i));
        }

        return List.copyOf(problems);
    }

    private static Problem duplicate(String key, int index) {
        return new Problem(rulePath(key, "hostPattern"), "duplicate_host_pattern",
                "Rule " + (index + 1) + " repeats host pattern \"" + key
                        + "\"; remove one, because a duplicate never applies.");
    }

    // ------------------------------------------------------------------ helpers

    private static String prefixed(String label, String problem) {
        return problem == null ? null : label + " " + problem + ".";
    }

    private static void add(List<Problem> into, String field, String message, String reason) {
        if (message != null) {
            into.add(new Problem(settingsPath(field), reason, message));
        }
    }

    private static void addRule(List<Problem> into, String key, String field, String message, String reason) {
        if (message != null) {
            into.add(new Problem(rulePath(key, field), reason, message));
        }
    }

    /**
     * Self-check.
     * Run with: {@code java -ea -cp build/classes/java/main:<gson.jar> burp.control.Validation}
     */
    public static void main(String[] args) {
        var catalog = Set.of("chrome", "firefox", "default");

        check(settings(BusinessSettings.defaults(), catalog, Policy.COMMIT).isEmpty(),
                "the shipped defaults validate cleanly");

        check(addressProblem("127.0.0.1:8887", "x") == null, "a host:port address passes");
        for (var bad : new String[]{"", "127.0.0.1", ":8080", "127.0.0.1:", "127.0.0.1:0",
                "127.0.0.1:65536", "127.0.0.1:abc", " :1"}) {
            check(addressProblem(bad, "x") != null, "address rejected: \"" + bad + "\"");
        }

        check(hexProblem("") == null && hexProblem(null) == null, "an empty hex value inherits");
        check(hexProblem("aabb") == null && hexProblem("AABB") == null, "hex is case-insensitive");
        check(hexProblem("abc") != null, "odd-length hex is rejected");
        check(hexProblem("zz") != null, "non-hex is rejected");

        check(timeoutProblem(null, true) == null, "an inheritable timeout may be absent");
        check(timeoutProblem(null, false) != null, "the global timeout may not be absent");
        check(timeoutProblem(0, true) != null && timeoutProblem(3601, true) != null, "the range is 1..3600");
        check(timeoutProblem(1, true) == null && timeoutProblem(3600, true) == null, "the bounds are inclusive");

        check(fingerprintProblem("chrome", catalog, false) == null, "a known fingerprint passes");
        check(fingerprintProblem("nope", catalog, false) != null, "an unknown fingerprint is rejected");
        check(fingerprintProblem("nope", Set.of(), false) == null,
                "an unavailable catalog does not reject every name");
        check(fingerprintProblem("", catalog, true) == null, "a rule may inherit the fingerprint");
        check(fingerprintProblem("", catalog, false) != null, "the global fingerprint is required");

        var broken = BusinessSettings.defaults()
                .withSpoofProxyAddress("nope")
                .withHexClientHello("xyz")
                .withExternalProxyUrl("ftp://h:1")
                .withFingerprint("unknown");
        var found = settings(broken, catalog, Policy.COMMIT);
        check(found.size() == 4, "every broken field is reported, not just the first");
        check(found.stream().anyMatch(p -> p.path().equals("/settings/externalProxyUrl")), "paths locate the field");

        // Duplicates must implicate both rows, and both spellings of a wildcard are one key.
        var dupes = List.of(
                new FingerprintRule("a.com", "", "", "", null, true),
                new FingerprintRule("*.b.com", "", "", "", null, true),
                new FingerprintRule(".b.com", "", "", "", null, true),
                new FingerprintRule("A.COM", "", "", "", null, true));
        var dupProblems = ruleSet(dupes, catalog, Policy.AI_PROPOSAL);
        check(dupProblems.stream().filter(p -> p.reason().equals("duplicate_host_pattern")).count() == 4,
                "both halves of each duplicate pair are reported");

        var draft = List.of(new FingerprintRule("", "", "", "", null, true));
        check(!ruleSet(draft, catalog, Policy.UI_DRAFT).isEmpty(), "an incomplete row is still reported");
        check(!Policy.UI_DRAFT.blocking(), "but autosave is not blocked by it");
        check(Policy.AI_PROPOSAL.blocking() && Policy.IMPORT.blocking() && Policy.COMMIT.blocking(),
                "every other caller is blocked by it");

        // An unknown fingerprint must not make a row structurally invalid, or losing the native
        // library would silently rewrite the revision.
        var unknownFp = new FingerprintRule("a.com", "nope", "", "", null, true);
        check(structuralRule(unknownFp, 0).isEmpty(), "an unknown fingerprint is not a structural problem");
        check(!rule(unknownFp, 0, catalog, Policy.AI_PROPOSAL).isEmpty(), "but a patch introducing one is refused");
        check(rule(unknownFp, 0, null, Policy.AI_PROPOSAL).isEmpty(), "a null catalog skips the check");
        check(!structuralRule(new FingerprintRule("a.com", "", "zz", "", null, true), 0).isEmpty(),
                "bad hex is a structural problem");

        check(escapeToken("a/b~c").equals("a~1b~0c"), "RFC 6901 tokens are escaped");
        check(rulePath("*.example.com", "fingerprint").equals("/domainRules/byHost/*.example.com/fingerprint"),
                "rule paths locate a field by host key");

        System.out.println("Validation self-check passed");
    }

    private static void check(boolean condition, String what) {
        if (!condition) throw new AssertionError("failed: " + what);
    }
}
