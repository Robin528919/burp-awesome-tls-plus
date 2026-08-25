package burp.control;

import java.net.IDN;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * The one host-pattern normalizer. ADR-0001 section 6.2 requires the request hot path,
 * effective-config queries, the UI, AI patches, revisioning and the matcher to share this
 * implementation and only switch {@link Mode}; approximate per-adapter copies are what let
 * {@code Example.COM} and {@code example.com} become two rules that disagree about which wins.
 * <p>
 * Deliberately free of Burp and Gson types so {@link #main} can exercise it without either.
 */
public final class HostKey {
    /**
     * A rule key may carry the leftmost {@code *.}; an exact query never may.
     */
    public enum Mode {RULE_KEY, EXACT_QUERY}

    /** RFC 1035: a single label is at most 63 bytes, a full name at most 253. */
    private static final int MAX_LABEL_BYTES = 63;
    private static final int MAX_HOST_BYTES = 253;

    /** {@code *.} makes a rule pattern two bytes longer than the host it can match. */
    public static final int MAX_PATTERN_BYTES = MAX_HOST_BYTES + 2;

    public static final String WILDCARD_PREFIX = "*.";

    private HostKey() {
    }

    /**
     * The outcome of normalizing one pattern: either a canonical key or the reason it was refused.
     */
    public record Result(String key, boolean wildcard, String problem) {
        public boolean ok() {
            return problem == null;
        }

        static Result bad(String problem) {
            return new Result(null, false, problem);
        }

        /**
         * @return the suffix a wildcard matches, e.g. {@code .example.com} for {@code *.example.com}.
         * Deliberately excludes the apex.
         */
        public String wildcardSuffix() {
            return wildcard ? key.substring(1) : null;
        }
    }

    /**
     * @return the canonical key for {@code raw}, or a Result carrying a human-readable problem.
     */
    public static Result normalize(String raw, Mode mode) {
        if (raw == null) {
            return Result.bad("must not be empty");
        }

        // Trim first, matching what the settings table has always done with pasted values.
        var value = raw.trim();
        if (value.isEmpty()) {
            return Result.bad("must not be empty");
        }

        if (value.length() > 4096) {
            return Result.bad("is unreasonably long");
        }

        for (var i = 0; i < value.length(); i++) {
            var c = value.charAt(i);
            if (Character.isWhitespace(c) || c == ' ') {
                return Result.bad("must not contain whitespace");
            }
        }

        if (value.contains("/") || value.contains("\\")) {
            return Result.bad("must be a bare hostname, without a scheme or path");
        }
        if (value.contains(":")) {
            // Catches both "example.com:443" and IPv6 literals, neither of which is a rule key.
            return Result.bad("must be a bare hostname, without a port");
        }
        if (value.startsWith("[") || value.endsWith("]")) {
            return Result.bad("IPv6 literals are not supported");
        }
        if (value.contains("@") || value.contains("?") || value.contains("#")) {
            return Result.bad("must be a bare hostname");
        }

        var wildcard = false;
        var body = value;

        // A leading dot has always been accepted as a synonym for "*."; canonicalize to one form
        // so the two spellings can never coexist as separate rules.
        if (body.startsWith(WILDCARD_PREFIX)) {
            wildcard = true;
            body = body.substring(2);
        } else if (body.startsWith(".")) {
            wildcard = true;
            body = body.substring(1);
        }

        if (wildcard && mode == Mode.EXACT_QUERY) {
            return Result.bad("must be an exact hostname, not a wildcard");
        }

        if (body.indexOf('*') >= 0) {
            return Result.bad("only a single leading \"*.\" wildcard is supported");
        }
        if (body.isEmpty()) {
            return Result.bad("must name a domain after the wildcard");
        }
        if (body.endsWith(".")) {
            return Result.bad("must not end with a dot");
        }
        if (body.startsWith(".") || body.contains("..")) {
            return Result.bad("must not contain an empty label");
        }

        String ascii;
        try {
            // STD3 rules reject underscores and the other characters that are legal in DNS but
            // not in a hostname, which is the stricter reading a rule key wants.
            ascii = IDN.toASCII(body, IDN.USE_STD3_ASCII_RULES);
        } catch (IllegalArgumentException e) {
            var detail = e.getMessage() == null ? "" : " (" + e.getMessage() + ")";
            return Result.bad("is not a valid hostname" + detail);
        }
        if (ascii.isEmpty()) {
            return Result.bad("is not a valid hostname");
        }

        ascii = ascii.toLowerCase(Locale.ROOT);

        for (var label : ascii.split("\\.", -1)) {
            if (label.isEmpty()) {
                return Result.bad("must not contain an empty label");
            }
            if (label.getBytes(StandardCharsets.UTF_8).length > MAX_LABEL_BYTES) {
                return Result.bad("has a label longer than " + MAX_LABEL_BYTES + " bytes");
            }
        }

        if (ascii.getBytes(StandardCharsets.UTF_8).length > MAX_HOST_BYTES) {
            return Result.bad("is longer than " + MAX_HOST_BYTES + " bytes");
        }

        return new Result(wildcard ? WILDCARD_PREFIX + ascii : ascii, wildcard, null);
    }

    /**
     * @return the canonical key, or null when {@code raw} is not a usable pattern.
     */
    public static String keyOrNull(String raw, Mode mode) {
        var result = normalize(raw, mode);
        return result.ok() ? result.key() : null;
    }

    /**
     * Self-check for normalization, which several other invariants are defined in terms of.
     * Run with: {@code java -ea -cp build/classes/java/main burp.control.HostKey}
     */
    public static void main(String[] args) {
        check(key("example.com").equals("example.com"), "a plain hostname passes through");
        check(key("  EXAMPLE.com  ").equals("example.com"), "trimmed and lowercased");
        check(key("*.example.com").equals("*.example.com"), "a wildcard keeps its prefix");
        check(key(".example.com").equals("*.example.com"), "a leading dot canonicalizes to \"*.\"");
        check(key("127.0.0.1").equals("127.0.0.1"), "an IPv4 literal is a valid exact key");

        // The leading-dot alias must collide with the "*." spelling, not sit beside it.
        check(key(".a.com").equals(key("*.a.com")), "both wildcard spellings share one key");

        check(normalize("*.example.com", Mode.RULE_KEY).wildcard(), "wildcards are flagged");
        check(normalize("*.example.com", Mode.RULE_KEY).wildcardSuffix().equals(".example.com"),
                "the wildcard suffix excludes the apex");

        check(normalize("*.example.com", Mode.EXACT_QUERY).problem() != null, "an exact query rejects wildcards");
        check(normalize(".example.com", Mode.EXACT_QUERY).problem() != null, "an exact query rejects leading dots");
        check(normalize("example.com", Mode.EXACT_QUERY).ok(), "an exact query accepts a hostname");

        // Everything that is not a bare hostname.
        for (var bad : new String[]{"", "   ", null, "http://example.com", "example.com:443", "example.com/p",
                "ex ample.com", "example..com", "example.com.", ".", "*", "*.", "a.*.com", "ex*mple.com",
                "[::1]", "::1", "user@example.com", "example.com?q", "under_score.com"}) {
            check(normalize(bad, Mode.RULE_KEY).problem() != null, "rejected: " + bad);
        }

        // IDN must resolve to A-labels so the matcher compares like with like.
        check(key("bücher.de").equals("xn--bcher-kva.de"), "an IDN becomes its A-label form");
        check(key("BÜCHER.de").equals("xn--bcher-kva.de"), "IDN casing is normalized too");

        check(normalize("a".repeat(64) + ".com", Mode.RULE_KEY).problem() != null, "an over-long label is rejected");
        check(normalize("a".repeat(63) + ".com", Mode.RULE_KEY).ok(), "a 63-byte label is allowed");

        var longHost = ("a".repeat(63) + ".").repeat(4) + "com";
        check(normalize(longHost, Mode.RULE_KEY).problem() != null, "an over-long hostname is rejected");

        check(keyOrNull("nope!/", Mode.RULE_KEY) == null, "keyOrNull returns null for junk");

        System.out.println("HostKey self-check passed");
    }

    private static String key(String raw) {
        var r = normalize(raw, Mode.RULE_KEY);
        if (!r.ok()) throw new AssertionError(raw + ": " + r.problem());
        return r.key();
    }

    private static void check(boolean condition, String what) {
        if (!condition) throw new AssertionError("failed: " + what);
    }
}
