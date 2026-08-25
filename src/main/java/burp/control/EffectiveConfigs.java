package burp.control;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

/**
 * Answers "what would a request to this host actually use?", entirely from what is already in
 * memory.
 * <p>
 * The whole point is that it answers without touching the network. ADR-0001 sections 2 and 5
 * require inspect to resolve no DNS, open no connection and send nothing through either proxy, so
 * this is pure lookup against the committed snapshot's matcher — the same matcher the request path
 * uses, so the answer cannot drift from what really happens.
 * <p>
 * It also reports where each value came from and which configured values are being suppressed,
 * because the fingerprint/hex precedence means a setting can be present, correct, and completely
 * unused, with nothing in the settings screen saying so.
 */
public final class EffectiveConfigs {
    /** At most this many hosts per inspect call, so one query cannot become a bulk export. */
    public static final int MAX_HOSTS = 20;

    private static final String GLOBAL = "GLOBAL_DEFAULT";

    private EffectiveConfigs() {
    }

    /**
     * @param host a bare hostname. Wildcards are refused: a request is for one host, and asking
     *             what {@code *.example.com} resolves to has no answer.
     * @return the resolution, or null if {@code host} is not a usable exact hostname.
     */
    public static Wire.EffectiveConfig resolve(SettingsSnapshot snapshot, String host) {
        var normalized = HostKey.normalize(host, HostKey.Mode.EXACT_QUERY);
        if (!normalized.ok()) {
            return null;
        }

        var globals = snapshot.settings();
        var rule = snapshot.matcher().match(normalized.key());
        var matchedKey = rule == null ? null : HostKey.keyOrNull(rule.hostPattern, HostKey.Mode.RULE_KEY);
        var from = matchedKey == null ? null : "RULE:" + matchedKey;

        var sources = new LinkedHashMap<String, String>();
        var suppressed = new ArrayList<String>();

        var fingerprint = globals.fingerprint();
        var hex = globals.hexClientHello();
        sources.put("fingerprint", GLOBAL);
        sources.put("hexClientHello", GLOBAL);

        if (rule != null && !rule.hexClientHello.isEmpty()) {
            // The rule's hex replaces the pair: the Go side always prefers hex, so leaving an
            // inherited fingerprint in place would describe a value that is not used.
            hex = rule.hexClientHello;
            fingerprint = "";
            sources.put("hexClientHello", from);
            sources.put("fingerprint", from);
            if (!globals.fingerprint().isEmpty()) {
                suppressed.add(Validation.settingsPath("fingerprint"));
            }
            if (!rule.fingerprint.isEmpty()) {
                suppressed.add(Validation.rulePath(matchedKey, "fingerprint"));
            }
        } else if (rule != null && !rule.fingerprint.isEmpty()) {
            fingerprint = rule.fingerprint;
            hex = "";
            sources.put("fingerprint", from);
            sources.put("hexClientHello", from);
            if (!globals.hexClientHello().isEmpty()) {
                // Still configured globally, still stored, and not used for this host.
                suppressed.add(Validation.settingsPath("hexClientHello"));
            }
        } else if (!globals.hexClientHello().isEmpty() && !globals.fingerprint().isEmpty()) {
            suppressed.add(Validation.settingsPath("fingerprint"));
        }

        var proxy = globals.externalProxyUrl();
        sources.put("externalProxyUrl", GLOBAL);
        if (rule != null && !rule.externalProxyUrl.isEmpty()) {
            proxy = rule.externalProxyUrl;
            sources.put("externalProxyUrl", from);
        }

        var timeout = globals.httpTimeout();
        sources.put("httpTimeout", GLOBAL);
        // A non-positive stored timeout inherits rather than disabling the timeout, matching
        // FingerprintRule#applyTo.
        if (rule != null && rule.httpTimeout != null && rule.httpTimeout > 0) {
            timeout = rule.httpTimeout;
            sources.put("httpTimeout", from);
        }

        // These three are global by construction; a rule can never carry them.
        sources.put("useInterceptedFingerprint", GLOBAL);
        sources.put("interceptProxyAddress", GLOBAL);
        sources.put("burpProxyAddress", GLOBAL);

        String staticMode;
        String selectedPath;
        if (!hex.isEmpty()) {
            staticMode = "HEX_CLIENT_HELLO";
            selectedPath = GLOBAL.equals(sources.get("hexClientHello"))
                    ? Validation.settingsPath("hexClientHello")
                    : Validation.rulePath(matchedKey, "hexClientHello");
        } else if (!fingerprint.isEmpty()) {
            staticMode = "FINGERPRINT";
            selectedPath = GLOBAL.equals(sources.get("fingerprint"))
                    ? Validation.settingsPath("fingerprint")
                    : Validation.rulePath(matchedKey, "fingerprint");
        } else {
            // Neither set: the Go client falls back to its own default profile.
            staticMode = "LIBRARY_DEFAULT";
            selectedPath = null;
        }

        // With the intercept flag on, Go overrides the static choice only when it has actually
        // captured a ClientHello. Whether it has cannot be known without sending traffic, so this
        // reports the conditional rather than inventing an answer.
        var runtimeMode = globals.useInterceptedFingerprint()
                ? "INTERCEPTED_IF_AVAILABLE_ELSE_STATIC" : "STATIC";

        var transport = new BusinessSettings(
                // Not part of a request's transport config; carried only to satisfy the record.
                "",
                globals.interceptProxyAddress(),
                globals.burpProxyAddress(),
                fingerprint,
                hex,
                globals.useInterceptedFingerprint(),
                timeout,
                proxy);

        return new Wire.EffectiveConfig(normalized.key(), matchedKey, transport,
                java.util.Collections.unmodifiableMap(sources), staticMode, runtimeMode,
                selectedPath, List.copyOf(suppressed));
    }

    /**
     * @return one resolution per host, in the order asked, or an error detail for the first host
     * that is not a bare hostname.
     */
    public static List<Wire.EffectiveConfig> resolveAll(SettingsSnapshot snapshot, List<String> hosts) {
        var out = new ArrayList<Wire.EffectiveConfig>(hosts.size());
        for (var host : hosts) {
            var resolved = resolve(snapshot, host);
            if (resolved == null) {
                return null;
            }
            out.add(resolved);
        }
        return List.copyOf(out);
    }

    /**
     * @return why {@code hosts} cannot be resolved, or null.
     */
    public static Wire.ErrorDetail hostsProblem(List<String> hosts) {
        if (hosts == null || hosts.isEmpty()) {
            return Wire.ErrorDetail.of("/hosts", "no_hosts_given");
        }
        if (hosts.size() > MAX_HOSTS) {
            return Wire.ErrorDetail.mismatch("/hosts", "too_many_hosts", MAX_HOSTS, hosts.size());
        }
        for (var i = 0; i < hosts.size(); i++) {
            var normalized = HostKey.normalize(hosts.get(i), HostKey.Mode.EXACT_QUERY);
            if (!normalized.ok()) {
                return Wire.ErrorDetail.of("/hosts/" + i, "invalid_host");
            }
        }
        return null;
    }

    /**
     * Self-check.
     * Run with: {@code java -ea -cp build/classes/java/main:<gson.jar> burp.control.EffectiveConfigs}
     */
    public static void main(String[] args) {
        var globals = BusinessSettings.defaults().withFingerprint("chrome").withHttpTimeout(30);
        var snapshot = SettingsSnapshot.of(globals, List.of(
                new burp.FingerprintRule("plain.com", "firefox", "", "", null, true),
                new burp.FingerprintRule("hexed.com", "", "aabb", "", null, true),
                new burp.FingerprintRule("*.wild.com", "safari", "", "socks5://127.0.0.1:1080", 90, true),
                new burp.FingerprintRule("off.com", "opera", "", "", null, false)));

        var unmatched = resolve(snapshot, "nothing.com");
        check(unmatched.matchedRuleHostPattern() == null, "an unmatched host reports no rule");
        check(unmatched.transport().fingerprint().equals("chrome"), "and inherits the global fingerprint");
        check(unmatched.sources().get("fingerprint").equals(GLOBAL), "sourced from the globals");
        check(unmatched.staticMode().equals("FINGERPRINT"), "with a named profile selected");
        check(unmatched.runtimeMode().equals("STATIC"), "and no interception");

        var plain = resolve(snapshot, "PLAIN.com");
        check(plain.transport().fingerprint().equals("firefox"), "a rule fingerprint wins");
        check(plain.sources().get("fingerprint").equals("RULE:plain.com"), "and is sourced to the rule");
        check(plain.transport().httpTimeout() == 30, "unset rule fields still inherit");

        var hexed = resolve(snapshot, "hexed.com");
        check(hexed.transport().hexClientHello().equals("aabb"), "a rule hex wins");
        check(hexed.transport().fingerprint().isEmpty(), "and clears the inherited fingerprint");
        check(hexed.staticMode().equals("HEX_CLIENT_HELLO"), "hex is the selected mode");
        check(hexed.suppressedPaths().contains("/settings/fingerprint"),
                "the suppressed global fingerprint is named");

        var wild = resolve(snapshot, "a.wild.com");
        check(wild.matchedRuleHostPattern().equals("*.wild.com"), "a wildcard matches a subdomain");
        check(wild.transport().httpTimeout() == 90 && wild.transport().externalProxyUrl().contains("socks5"),
                "proxy and timeout come from the rule");
        check(wild.sources().get("httpTimeout").equals("RULE:*.wild.com"), "and are sourced to it");
        check(resolve(snapshot, "wild.com").matchedRuleHostPattern() == null,
                "but the apex is not covered by the wildcard");

        check(resolve(snapshot, "off.com").matchedRuleHostPattern() == null, "a disabled rule does not apply");

        // A global hex outranks a global fingerprint, and the fingerprint must be shown as unused.
        var hexGlobal = SettingsSnapshot.of(globals.withHexClientHello("ccdd"), List.of(
                new burp.FingerprintRule("fp.com", "safari", "", "", null, true)));
        var inherited = resolve(hexGlobal, "other.com");
        check(inherited.staticMode().equals("HEX_CLIENT_HELLO"), "the global hex is selected");
        check(inherited.suppressedPaths().contains("/settings/fingerprint"),
                "and the global fingerprint is listed as suppressed");

        // A rule fingerprint suppresses the inherited global hex for that host, without clearing it.
        var overridden = resolve(hexGlobal, "fp.com");
        check(overridden.staticMode().equals("FINGERPRINT") && overridden.transport().hexClientHello().isEmpty(),
                "a rule fingerprint suppresses the inherited hex");
        check(overridden.suppressedPaths().contains("/settings/hexClientHello"),
                "and says which value it is suppressing");
        check(hexGlobal.settings().hexClientHello().equals("ccdd"), "while the global value stays stored");

        // Neither set anywhere.
        var bare = resolve(SettingsSnapshot.of(BusinessSettings.defaults().withFingerprint(""), List.of()), "x.com");
        check(bare.staticMode().equals("LIBRARY_DEFAULT") && bare.selectedPath() == null,
                "with neither set, the library default applies");

        var intercepting = resolve(SettingsSnapshot.of(globals.withUseInterceptedFingerprint(true), List.of()),
                "x.com");
        check(intercepting.runtimeMode().equals("INTERCEPTED_IF_AVAILABLE_ELSE_STATIC"),
                "interception is reported as conditional, not as a captured value");

        // Queries are exact; a pattern is not a host.
        check(resolve(snapshot, "*.wild.com") == null, "a wildcard is not a resolvable host");
        check(resolve(snapshot, "http://x.com") == null, "a URL is not a host");
        check(resolve(snapshot, "") == null, "an empty host resolves to nothing");

        check(hostsProblem(List.of()) != null, "an empty host list is refused");
        check(hostsProblem(java.util.Collections.nCopies(MAX_HOSTS + 1, "a.com")) != null,
                "more than " + MAX_HOSTS + " hosts is refused");
        check(hostsProblem(java.util.Collections.nCopies(MAX_HOSTS, "a.com")) == null,
                "exactly " + MAX_HOSTS + " is allowed");
        check(hostsProblem(List.of("a.com", "*.b.com")) != null, "a wildcard in the list is refused");
        check(hostsProblem(List.of("a.com")) == null, "a bare hostname is accepted");

        System.out.println("EffectiveConfigs self-check passed");
    }

    private static void check(boolean condition, String what) {
        if (!condition) throw new AssertionError("failed: " + what);
    }
}
