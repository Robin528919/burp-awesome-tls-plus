package burp;

import burp.control.HostKey;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Resolves a hostname to the most specific matching {@link FingerprintRule}.
 * <p>
 * Rules are indexed once at construction, so matching costs an O(1) hash lookup plus a scan
 * over the wildcard rules only. This runs on every proxied request, so it must not touch
 * Burp's preference store or re-parse JSON.
 * <p>
 * Precedence: an exact hostname always beats a wildcard; among wildcards the longest
 * (most specific) suffix wins, independent of the order rules appear in the UI.
 * <p>
 * Host patterns go through {@link HostKey}, the same normalizer the settings UI, the revision and
 * AI patches use, so a rule cannot be stored under one spelling and looked up under another.
 * Rows whose patterns collide after normalization are dropped rather than resolved: ADR-0001
 * section 7 replaces the previous "the last one wins" behaviour, under which a duplicate looked
 * harmless right up until the wrong rule was the one that applied.
 */
public final class RuleMatcher {
    /**
     * Empty matcher, used before any rules are configured.
     */
    public static final RuleMatcher EMPTY = new RuleMatcher(List.of());

    private final Map<String, FingerprintRule> exact;

    /**
     * Wildcard rules paired with their suffix (e.g. ".example.com"), longest suffix first.
     */
    private final List<Object[]> wildcards;

    public RuleMatcher(List<FingerprintRule> rules) {
        // Two passes, because a duplicate disqualifies every row claiming that key, including the
        // one already indexed.
        var contested = new HashSet<String>();
        var claimed = new HashSet<String>();
        for (var raw : rules) {
            var key = keyOf(raw);
            if (key != null && !claimed.add(key)) {
                contested.add(key);
            }
        }

        var exact = new HashMap<String, FingerprintRule>();
        var wildcards = new ArrayList<Object[]>();
        for (var raw : rules) {
            var key = keyOf(raw);
            if (key == null || contested.contains(key)) continue;

            var rule = raw.normalized();
            if (!rule.enabled) continue;

            if (key.startsWith(HostKey.WILDCARD_PREFIX)) {
                // ".example.com": matches any subdomain, deliberately not the apex.
                wildcards.add(new Object[]{key.substring(1), rule});
            } else {
                exact.put(key, rule);
            }
        }

        wildcards.sort(Comparator.comparingInt((Object[] w) -> ((String) w[0]).length()).reversed());

        this.exact = Map.copyOf(exact);
        this.wildcards = List.copyOf(wildcards);
    }

    /**
     * @return the normalized key a row claims, or null when the row is not usable at all. A
     * disabled row still claims its key, so disabling one half of a duplicate pair does not
     * quietly promote the other.
     */
    private static String keyOf(FingerprintRule raw) {
        if (raw == null) return null;
        return HostKey.keyOrNull(raw.normalized().hostPattern, HostKey.Mode.RULE_KEY);
    }

    public boolean isEmpty() {
        return exact.isEmpty() && wildcards.isEmpty();
    }

    /**
     * @return the most specific rule for {@code host}, or null if none applies.
     */
    public FingerprintRule match(String host) {
        if (host == null || host.isEmpty()) return null;

        // The request hot path asks in exact-query mode: a request is for one host, never a
        // pattern, so "*.example.com" arriving as a Host header must not match anything.
        var normalized = HostKey.keyOrNull(host, HostKey.Mode.EXACT_QUERY);
        if (normalized == null) return null;

        var hit = exact.get(normalized);
        if (hit != null) return hit;

        for (var wildcard : wildcards) {
            // "*.example.com" matches "a.example.com" but deliberately not "example.com".
            if (normalized.endsWith((String) wildcard[0])) {
                return (FingerprintRule) wildcard[1];
            }
        }

        return null;
    }

    /**
     * Standalone self-check for the matching rules, which are easy to break silently.
     * Run with: {@code java -ea -cp build/classes/java/main burp.RuleMatcher}
     */
    public static void main(String[] args) {
        var exact = rule("example.com", "chrome");
        var wildcard = rule("*.example.com", "firefox");
        var deepWildcard = rule("*.api.example.com", "safari");
        var dotted = rule(".dotted.com", "okhttp");
        var disabled = rule("off.com", "chrome");
        disabled.enabled = false;

        var m = new RuleMatcher(List.of(exact, wildcard, deepWildcard, dotted, disabled));

        // Each rule carries a distinct fingerprint, so comparing that identifies which one matched.
        check(hit(m, "example.com", "chrome"), "exact match wins");
        check(hit(m, "EXAMPLE.COM", "chrome"), "host matching is case-insensitive");
        check(hit(m, "www.example.com", "firefox"), "wildcard matches a subdomain");
        check(hit(m, "v1.api.example.com", "safari"), "longest suffix wins over a shorter one");
        check(hit(m, "a.example.com", "firefox"), "shorter wildcard still matches outside the deeper zone");
        check(hit(m, "x.dotted.com", "okhttp"), "leading-dot pattern behaves like a wildcard");
        check(hit(m, "dotted.com", null), "wildcard does not match the bare domain");
        check(hit(m, "other.com", null), "unmatched host falls through to the defaults");
        check(hit(m, "off.com", null), "disabled rules never match");
        check(hit(m, null, null) && hit(m, "", null), "null and empty hosts are safe");

        // Order in the list must not affect the outcome.
        var reversed = new RuleMatcher(List.of(disabled, dotted, deepWildcard, wildcard, exact));
        check(hit(reversed, "v1.api.example.com", "safari"), "precedence is independent of list order");

        check(RuleMatcher.EMPTY.isEmpty() && hit(RuleMatcher.EMPTY, "example.com", null), "empty matcher matches nothing");

        checkDuplicatesNeverMatch();
        checkUnusableRowsNeverMatch();

        checkOverrides();

        // Rules deserialized by Gson can carry null strings; they must not blow up.
        var fromJson = new FingerprintRule();
        fromJson.hostPattern = null;
        check(hit(new RuleMatcher(List.of(fromJson)), "example.com", null), "null pattern is ignored");

        // Matched rules are normalized, so callers never have to null-check their fields.
        var untrimmed = new FingerprintRule();
        untrimmed.hostPattern = "  spacey.com  ";
        untrimmed.fingerprint = null;
        var normalizedHit = new RuleMatcher(List.of(untrimmed)).match("spacey.com");
        check(normalizedHit != null && normalizedHit.fingerprint.isEmpty(), "matched rules have non-null fields");

        System.out.println("RuleMatcher self-check passed");
    }

    /**
     * A duplicated pattern must disable both rows, not silently pick one. This is the regression
     * ADR-0001 section 7 asks for: the old behaviour let the last exact row overwrite the first,
     * so which of two contradictory rules applied depended on table order.
     */
    private static void checkDuplicatesNeverMatch() {
        var first = rule("dup.com", "chrome");
        var second = rule("dup.com", "firefox");
        check(hit(new RuleMatcher(List.of(first, second)), "dup.com", null), "a duplicate exact key matches nothing");
        check(hit(new RuleMatcher(List.of(second, first)), "dup.com", null), "in either order");

        // The two wildcard spellings are the same key, so they collide too.
        check(hit(new RuleMatcher(List.of(rule("*.w.com", "chrome"), rule(".w.com", "firefox"))), "a.w.com", null),
                "\"*.x\" and \".x\" are one key and collide");

        // Case and whitespace do not create a second rule either.
        check(hit(new RuleMatcher(List.of(rule("Dup.com", "chrome"), rule(" dup.COM ", "firefox"))), "dup.com", null),
                "spelling differences do not escape the duplicate check");

        // Disabling one half must not promote the other; the pattern is still ambiguous on disk.
        var disabled = rule("dup.com", "firefox");
        disabled.enabled = false;
        check(hit(new RuleMatcher(List.of(first, disabled)), "dup.com", null),
                "disabling one half of a duplicate does not promote the other");

        // A duplicate must not take unrelated rules down with it.
        var matcher = new RuleMatcher(List.of(first, second, rule("fine.com", "safari")));
        check(hit(matcher, "fine.com", "safari"), "an unrelated rule still matches");
    }

    /**
     * Rows the settings table tolerates while they are being typed must never reach a request.
     */
    private static void checkUnusableRowsNeverMatch() {
        var junk = List.of(
                rule("", "chrome"),
                rule("   ", "chrome"),
                rule("http://x.com", "chrome"),
                rule("x.com:443", "chrome"),
                rule("a.*.com", "chrome"),
                rule("x..com", "chrome"));
        var matcher = new RuleMatcher(junk);
        check(matcher.isEmpty(), "no unusable row is indexed");
        for (var host : new String[]{"x.com", "a.x.com", "com", ""}) {
            check(matcher.match(host) == null, "unusable rows match nothing, including \"" + host + "\"");
        }

        // A wildcard arriving as a request host is a lookup, not a pattern.
        var wild = new RuleMatcher(List.of(rule("*.example.com", "firefox")));
        check(wild.match("*.example.com") == null, "a wildcard is not itself a matchable host");
        check(wild.match("a.example.com") != null, "but it still matches a subdomain");
    }

    /**
     * Checks how a matched rule is layered onto the global defaults.
     */
    private static void checkOverrides() {
        var inherited = apply(new FingerprintRule());
        check("chrome".equals(inherited.Fingerprint) && "aabb".equals(inherited.HexClientHello)
                        && "http://global".equals(inherited.ExternalProxyUrl) && inherited.HttpTimeout == 30,
                "an empty rule inherits every default");

        // The Go side prefers HexClientHello, so overriding one of the pair must clear the other.
        var byFingerprint = apply(new FingerprintRule("x.com", "firefox", "", "", null, true));
        check("firefox".equals(byFingerprint.Fingerprint) && byFingerprint.HexClientHello.isEmpty(),
                "a fingerprint override clears the inherited hex ClientHello");

        var byHex = apply(new FingerprintRule("x.com", "", "ccdd", "", null, true));
        check("ccdd".equals(byHex.HexClientHello) && byHex.Fingerprint.isEmpty(),
                "a hex override clears the inherited fingerprint");

        var both = apply(new FingerprintRule("x.com", "firefox", "ccdd", "", null, true));
        check("ccdd".equals(both.HexClientHello) && both.Fingerprint.isEmpty(),
                "hex wins over fingerprint within a single rule, matching the Go precedence");

        var proxied = apply(new FingerprintRule("x.com", "", "", "http://rule", 60, true));
        check("http://rule".equals(proxied.ExternalProxyUrl) && proxied.HttpTimeout == 60,
                "proxy and timeout are overridden independently");
        check("chrome".equals(proxied.Fingerprint) && "aabb".equals(proxied.HexClientHello),
                "overriding only the proxy leaves the fingerprint pair untouched");

        var zeroTimeout = apply(new FingerprintRule("x.com", "", "", "", 0, true));
        check(zeroTimeout.HttpTimeout == 30, "a non-positive timeout inherits instead of disabling the timeout");
    }

    /**
     * @return the defaults with {@code rule} layered on top.
     */
    private static TransportConfig apply(FingerprintRule rule) {
        var config = new TransportConfig();
        config.Fingerprint = "chrome";
        config.HexClientHello = "aabb";
        config.ExternalProxyUrl = "http://global";
        config.HttpTimeout = 30;

        rule.normalized().applyTo(config);
        return config;
    }

    private static FingerprintRule rule(String pattern, String fingerprint) {
        return new FingerprintRule(pattern, fingerprint, "", "", null, true);
    }

    /**
     * @return true if matching {@code host} selected the rule carrying {@code expectedFingerprint}
     * (or matched nothing, when that is null).
     */
    private static boolean hit(RuleMatcher matcher, String host, String expectedFingerprint) {
        var match = matcher.match(host);
        return expectedFingerprint == null ? match == null : match != null && expectedFingerprint.equals(match.fingerprint);
    }

    private static void check(boolean condition, String what) {
        if (!condition) throw new AssertionError("failed: " + what);
    }
}
