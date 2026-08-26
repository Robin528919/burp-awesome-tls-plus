package burp.control;

import burp.FingerprintRule;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

/**
 * Turns "before" and "after" into the three things a person needs before approving a change:
 * what exactly differs, which differences are dangerous, and when each takes effect.
 * <p>
 * The last one is the part a settings screen normally gets wrong. ADR-0001 section 12 requires
 * configured and active to be reported separately, because several of these settings do not apply
 * until something restarts — and the spoof listener address in particular, if treated as live the
 * moment it is saved, sends every subsequent request to a port nothing is listening on.
 */
public final class Analysis {
    /** Changing this many rules at once is treated as high risk regardless of what changed. */
    static final int BULK_RULE_THRESHOLD = 10;

    private Analysis() {
    }

    // ------------------------------------------------------------------ diff

    /**
     * @return every differing leaf field, as add, replace or remove. A rule that changes host is a
     * set of removes under the old key and a set of adds under the new one, because the key is the
     * rule's identity.
     */
    public static List<Wire.FieldChange> diff(SettingsSnapshot base, SettingsSnapshot candidate) {
        var changes = new ArrayList<Wire.FieldChange>();

        for (var field : BusinessSettings.FIELDS) {
            var before = base.settings().get(field);
            var after = candidate.settings().get(field);
            if (!java.util.Objects.equals(before, after)) {
                changes.add(Wire.FieldChange.replace(Validation.settingsPath(field), before, after));
            }
        }

        var keys = new LinkedHashSet<String>();
        keys.addAll(base.indexByKey().keySet());
        keys.addAll(candidate.indexByKey().keySet());

        for (var key : keys) {
            var before = base.ruleByKey(key);
            var after = candidate.ruleByKey(key);
            if (before == null && after == null) {
                continue;
            }
            for (var field : FingerprintRule.FIELDS) {
                var path = Validation.rulePath(key, field);
                if (before == null) {
                    changes.add(Wire.FieldChange.add(path, after.get(field)));
                } else if (after == null) {
                    changes.add(Wire.FieldChange.remove(path, before.get(field)));
                } else if (!java.util.Objects.equals(before.get(field), after.get(field))) {
                    changes.add(Wire.FieldChange.replace(path, before.get(field), after.get(field)));
                }
            }
        }

        return changes.stream().sorted(Wire.FieldChange.ORDER).toList();
    }

    // ------------------------------------------------------------------ risk

    /**
     * @return what about this change deserves a second look. Section 9 fixes the high-risk set;
     * a proposal carrying any of it needs a second confirmation in Burp before it is applied.
     */
    public static List<Wire.RiskFlag> risks(SettingsSnapshot base, SettingsSnapshot candidate,
                                            List<Wire.FieldChange> diff) {
        var flags = new ArrayList<Wire.RiskFlag>();

        addIfChanged(flags, diff, "LISTENER_ADDRESS_CHANGED", "HIGH",
                "Changing where a listener binds can leave traffic pointed at a port nothing is "
                        + "serving until the extension is reloaded.",
                Validation.settingsPath("spoofProxyAddress"),
                Validation.settingsPath("interceptProxyAddress"),
                Validation.settingsPath("burpProxyAddress"));

        // Every proxy URL, global or per-rule: it decides where traffic goes and may carry
        // credentials in the same string.
        //
        // Only when a proxy is actually involved, though. Creating a rule materializes all six of
        // its fields, so a proposal that sets nothing but a fingerprint still produces an "add" of
        // an empty externalProxyUrl. Flagging that as high risk marks the proposal as needing a
        // second confirmation for a change that touches no proxy at all — and a confirmation
        // dialog that cries wolf is one that stops being read.
        var proxyPaths = diff.stream()
                .filter(change -> change.path().endsWith("/externalProxyUrl"))
                .filter(change -> !isBlank(change.before()) || !isBlank(change.after()))
                .map(Wire.FieldChange::path)
                .toList();
        if (!proxyPaths.isEmpty()) {
            flags.add(new Wire.RiskFlag("EXTERNAL_PROXY_CHANGED", "HIGH", proxyPaths,
                    "An upstream proxy change redirects traffic, and the URL may carry credentials."));
        }

        addIfChanged(flags, diff, "GLOBAL_TLS_IDENTITY_CHANGED", "HIGH",
                "The global TLS fingerprint or ClientHello decides how every unmatched host sees you.",
                Validation.settingsPath("fingerprint"),
                Validation.settingsPath("hexClientHello"));

        addIfChanged(flags, diff, "INTERCEPT_TOGGLE_CHANGED", "HIGH",
                "Switching intercepted fingerprints on or off starts or stops a shared proxy for "
                        + "all traffic at once.",
                Validation.settingsPath("useInterceptedFingerprint"));

        var deleted = new ArrayList<String>();
        for (var key : base.indexByKey().keySet()) {
            if (!candidate.indexByKey().containsKey(key)) {
                deleted.add(Validation.rulePath(key, "hostPattern"));
            }
        }
        if (!deleted.isEmpty()) {
            flags.add(new Wire.RiskFlag("RULE_DELETED", "HIGH", deleted,
                    deleted.size() + " domain rule(s) would be deleted; there is no undo beyond the "
                            + "single most recent AI change."));
        }

        var touched = touchedRuleKeys(diff);
        if (touched.size() >= BULK_RULE_THRESHOLD) {
            flags.add(new Wire.RiskFlag("BULK_RULE_CHANGE", "HIGH",
                    touched.stream().map(k -> Validation.rulePath(k, "hostPattern")).toList(),
                    touched.size() + " domain rules change at once; review the full diff before applying."));
        }

        // Not high risk, but worth saying: the value is stored and simply will not be used.
        if (!candidate.settings().hexClientHello().isEmpty()
                && !candidate.settings().fingerprint().isEmpty()) {
            flags.add(new Wire.RiskFlag("FINGERPRINT_SUPPRESSED_BY_HEX", "MEDIUM",
                    List.of(Validation.settingsPath("fingerprint"), Validation.settingsPath("hexClientHello")),
                    "The global hex ClientHello takes precedence, so the global fingerprint "
                            + "\"" + candidate.settings().fingerprint() + "\" will not be used."));
        }

        return flags.stream().sorted(Wire.RiskFlag.ORDER).toList();
    }

    /**
     * @return whether a value is absent or an empty string, which for these settings both mean
     * "nothing configured".
     */
    private static boolean isBlank(Object value) {
        return value == null || (value instanceof String text && text.isBlank());
    }

    private static void addIfChanged(List<Wire.RiskFlag> into, List<Wire.FieldChange> diff,
                                     String code, String severity, String message, String... paths) {
        var hit = new ArrayList<String>();
        for (var path : paths) {
            if (diff.stream().anyMatch(c -> c.path().equals(path))) {
                hit.add(path);
            }
        }
        if (!hit.isEmpty()) {
            into.add(new Wire.RiskFlag(code, severity, hit, message));
        }
    }

    private static List<String> touchedRuleKeys(List<Wire.FieldChange> diff) {
        var keys = new LinkedHashSet<String>();
        for (var change : diff) {
            var key = ruleKeyOf(change.path());
            if (key != null) {
                keys.add(key);
            }
        }
        return List.copyOf(keys);
    }

    private static final String RULE_PREFIX = "/domainRules/byHost/";

    private static String ruleKeyOf(String path) {
        if (!path.startsWith(RULE_PREFIX)) {
            return null;
        }
        var rest = path.substring(RULE_PREFIX.length());
        var slash = rest.lastIndexOf('/');
        if (slash < 0) {
            return null;
        }
        return rest.substring(0, slash).replace("~1", "/").replace("~0", "~");
    }

    /**
     * @return whether this change needs the second confirmation described in section 9.
     */
    public static boolean highRisk(List<Wire.RiskFlag> flags) {
        return flags.stream().anyMatch(Wire.RiskFlag::high);
    }

    // ------------------------------------------------------------------ runtime impact

    /**
     * @param status what the Go side reports it is doing, which decides whether an address change
     *               is merely "next start" or an actual reload the user has to perform.
     */
    public static List<Wire.RuntimeImpact> impact(List<Wire.FieldChange> diff, RuntimeStatus status) {
        var impacts = new ArrayList<Wire.RuntimeImpact>();
        var interceptRunning = status != null && status.intercept() != null && status.intercept().running();

        for (var change : diff) {
            var path = change.path();
            if (path.equals(Validation.settingsPath("spoofProxyAddress"))) {
                // The running Go server keeps its current address, and requests keep going there.
                // Reporting this as live would be the single most damaging lie on this screen.
                impacts.add(new Wire.RuntimeImpact(path, "NEXT_START", true,
                        "The Go server keeps listening on its current address. Requests continue to "
                                + "use it until the extension is reloaded."));
            } else if (path.equals(Validation.settingsPath("interceptProxyAddress"))
                    || path.equals(Validation.settingsPath("burpProxyAddress"))) {
                impacts.add(interceptRunning
                        ? new Wire.RuntimeImpact(path, "RELOAD_REQUIRED", true,
                        "The intercept proxy is running on the previous address; it has to be "
                                + "stopped and started for this to take effect.")
                        : new Wire.RuntimeImpact(path, "NEXT_START", false,
                        "The intercept proxy is not running; it will use this when it next starts."));
            } else if (path.equals(Validation.settingsPath("useInterceptedFingerprint"))) {
                impacts.add(new Wire.RuntimeImpact(path, "NEXT_REQUEST", false,
                        "The next request starts or stops the shared intercept proxy accordingly."));
            } else {
                impacts.add(new Wire.RuntimeImpact(path, "NEXT_REQUEST", false,
                        // Neutral on purpose: with auto-apply armed there is no approval step,
                        // and a message promising one would be wrong half the time.
                        "Applies to requests sent after this takes effect."));
            }
        }
        return impacts.stream().sorted(Wire.RuntimeImpact.ORDER).toList();
    }

    /**
     * Configured versus active, for the inspect result and the UI.
     */
    public static List<Wire.RuntimeState> runtimeStates(SettingsSnapshot snapshot, RuntimeStatus status) {
        var states = new ArrayList<Wire.RuntimeState>();
        var settings = snapshot.settings();
        var spoof = status == null ? null : status.spoof();
        var intercept = status == null ? null : status.intercept();

        states.add(new Wire.RuntimeState(Validation.settingsPath("spoofProxyAddress"),
                settings.spoofProxyAddress(),
                spoof == null ? null : spoof.actualAddress(),
                spoof != null && spoof.running()
                        && settings.spoofProxyAddress().equals(spoof.actualAddress())
                        ? "ACTIVE_NOW" : "NEXT_START"));

        states.add(new Wire.RuntimeState(Validation.settingsPath("interceptProxyAddress"),
                settings.interceptProxyAddress(),
                intercept == null ? null : intercept.actualAddress(),
                intercept != null && intercept.running()
                        && settings.interceptProxyAddress().equals(intercept.actualAddress())
                        ? "ACTIVE_NOW" : "NEXT_START"));

        // Burp's proxy listener does not expose the interface it is bound to through the Montoya
        // API, so the active value is whatever Go reports it is dialling, and null when even that
        // is unknown. Substituting the configured value here would be a guess presented as a fact.
        states.add(new Wire.RuntimeState(Validation.settingsPath("burpProxyAddress"),
                settings.burpProxyAddress(),
                status == null ? null : status.burpUpstreamEndpoint(),
                "NEXT_START"));

        states.add(new Wire.RuntimeState(Validation.settingsPath("useInterceptedFingerprint"),
                settings.useInterceptedFingerprint(),
                intercept != null && intercept.running(),
                "NEXT_REQUEST"));

        for (var field : List.of("fingerprint", "hexClientHello", "externalProxyUrl", "httpTimeout")) {
            var value = settings.get(field);
            states.add(new Wire.RuntimeState(Validation.settingsPath(field), value, value, "NEXT_REQUEST"));
        }

        return List.copyOf(states);
    }

    /**
     * Self-check.
     * Run with: {@code java -ea -cp build/classes/java/main:<gson.jar> burp.control.Analysis}
     */
    public static void main(String[] args) {
        var base = SettingsSnapshot.of(BusinessSettings.defaults(), List.of(
                new FingerprintRule("keep.com", "chrome", "", "", null, true),
                new FingerprintRule("gone.com", "firefox", "", "", null, true)));
        var candidate = SettingsSnapshot.of(BusinessSettings.defaults().withHttpTimeout(45), List.of(
                new FingerprintRule("keep.com", "safari", "", "", null, true),
                new FingerprintRule("new.com", "chrome", "", "", null, true)));

        var diff = diff(base, candidate);
        check(diff.stream().anyMatch(c -> c.path().equals("/settings/httpTimeout")
                && c.operation().equals("replace") && c.after().equals(45)), "a scalar change is a replace");
        check(diff.stream().anyMatch(c -> c.path().equals("/domainRules/byHost/keep.com/fingerprint")
                && "chrome".equals(c.before()) && "safari".equals(c.after())), "a rule field change is a replace");
        check(diff.stream().anyMatch(c -> c.path().startsWith("/domainRules/byHost/gone.com/")
                && c.operation().equals("remove")), "a deleted rule is removes");
        check(diff.stream().anyMatch(c -> c.path().startsWith("/domainRules/byHost/new.com/")
                && c.operation().equals("add")), "a new rule is adds");
        check(diff.stream().noneMatch(c -> c.path().contains("byHost/keep.com/hostPattern")),
                "unchanged fields are not in the diff");

        var sorted = diff.stream().sorted(Wire.FieldChange.ORDER).toList();
        check(sorted.equals(diff), "the diff comes out already sorted, so the digest is stable");

        check(diff(base, base).isEmpty(), "no change means no diff");

        checkRisks();
        checkImpact();

        System.out.println("Analysis self-check passed");
    }

    private static void checkRisks() {
        var base = SettingsSnapshot.of(BusinessSettings.defaults(),
                List.of(new FingerprintRule("a.com", "chrome", "", "", null, true)));

        check(highRisk(risksBetween(base, base.withSettings(
                        BusinessSettings.defaults().withSpoofProxyAddress("127.0.0.1:9999")))),
                "a listener address change is high risk");
        check(highRisk(risksBetween(base, base.withSettings(
                        BusinessSettings.defaults().withExternalProxyUrl("http://127.0.0.1:8080")))),
                "an external proxy change is high risk");
        check(highRisk(risksBetween(base, base.withSettings(
                        BusinessSettings.defaults().withFingerprint("firefox")))),
                "a global fingerprint change is high risk");
        check(highRisk(risksBetween(base, base.withSettings(
                        BusinessSettings.defaults().withUseInterceptedFingerprint(true)))),
                "the intercept toggle is high risk");
        check(highRisk(risksBetween(base, base.withRules(List.of()))), "deleting a rule is high risk");

        // A timeout change on its own is not.
        check(!highRisk(risksBetween(base, base.withSettings(BusinessSettings.defaults().withHttpTimeout(45)))),
                "a timeout change alone is not high risk");

        // Volume alone is enough.
        var many = new ArrayList<FingerprintRule>();
        for (var i = 0; i < BULK_RULE_THRESHOLD; i++) {
            many.add(new FingerprintRule("h" + i + ".com", "chrome", "", "", null, true));
        }
        var bulk = risksBetween(SettingsSnapshot.of(BusinessSettings.defaults(), List.of()),
                SettingsSnapshot.of(BusinessSettings.defaults(), many));
        check(bulk.stream().anyMatch(f -> f.code().equals("BULK_RULE_CHANGE")),
                BULK_RULE_THRESHOLD + " rules at once is high risk on volume alone");

        var nine = new ArrayList<>(many.subList(0, BULK_RULE_THRESHOLD - 1));
        var justUnder = risksBetween(SettingsSnapshot.of(BusinessSettings.defaults(), List.of()),
                SettingsSnapshot.of(BusinessSettings.defaults(), nine));
        check(justUnder.stream().noneMatch(f -> f.code().equals("BULK_RULE_CHANGE")),
                "one fewer is not");

        // Creating a rule writes every field, most of them empty. Those are not changes to
        // anything and must not drag the proposal into the high-risk path.
        var newRule = risksBetween(SettingsSnapshot.of(BusinessSettings.defaults(), List.of()),
                SettingsSnapshot.of(BusinessSettings.defaults(),
                        List.of(new FingerprintRule("a.com", "chrome", "", "", null, true))));
        check(newRule.stream().noneMatch(f -> f.code().equals("EXTERNAL_PROXY_CHANGED")),
                "adding a rule with no proxy is not an external proxy change");
        check(!highRisk(newRule), "and adding one plain rule is not high risk at all");

        // Clearing a proxy that was set is still a proxy change.
        var cleared = risksBetween(
                SettingsSnapshot.of(BusinessSettings.defaults().withExternalProxyUrl("http://127.0.0.1:8080"),
                        List.of()),
                SettingsSnapshot.of(BusinessSettings.defaults(), List.of()));
        check(cleared.stream().anyMatch(f -> f.code().equals("EXTERNAL_PROXY_CHANGED")),
                "removing a proxy is still an external proxy change");

        // And a rule that does set one still is.
        var ruleProxy = risksBetween(SettingsSnapshot.of(BusinessSettings.defaults(), List.of()),
                SettingsSnapshot.of(BusinessSettings.defaults(), List.of(
                        new FingerprintRule("a.com", "", "", "socks5://127.0.0.1:1080", null, true))));
        check(ruleProxy.stream().anyMatch(f -> f.code().equals("EXTERNAL_PROXY_CHANGED")),
                "a rule that sets a proxy is an external proxy change");

        // A stored value that will never be used has to be said out loud.
        var suppressed = risksBetween(base, base.withSettings(BusinessSettings.defaults()
                .withFingerprint("chrome").withHexClientHello("aabb")));
        check(suppressed.stream().anyMatch(f -> f.code().equals("FINGERPRINT_SUPPRESSED_BY_HEX")),
                "a fingerprint that hex will override is flagged");
    }

    private static void checkImpact() {
        var base = SettingsSnapshot.empty();
        var moved = base.withSettings(BusinessSettings.defaults().withSpoofProxyAddress("127.0.0.1:9999"));
        var running = new RuntimeStatus(
                new RuntimeStatus.Listener(RuntimeStatus.State.RUNNING, "127.0.0.1:8887", null),
                new RuntimeStatus.Listener(RuntimeStatus.State.RUNNING, "127.0.0.1:8886", null),
                null, null);

        var spoofImpact = impact(diff(base, moved), running).get(0);
        check(spoofImpact.effect().equals("NEXT_START") && spoofImpact.requiresUserAction(),
                "moving the spoof listener is not live until reload, and says so");

        var interceptMoved = base.withSettings(BusinessSettings.defaults().withInterceptProxyAddress("127.0.0.1:1"));
        check(impact(diff(base, interceptMoved), running).get(0).effect().equals("RELOAD_REQUIRED"),
                "moving a running intercept proxy needs a reload");

        var stopped = new RuntimeStatus(running.spoof(), RuntimeStatus.Listener.stopped(), null, null);
        check(impact(diff(base, interceptMoved), stopped).get(0).effect().equals("NEXT_START"),
                "moving a stopped one does not");

        var retimed = base.withSettings(BusinessSettings.defaults().withHttpTimeout(45));
        check(impact(diff(base, retimed), running).get(0).effect().equals("NEXT_REQUEST"),
                "a timeout applies to the next request");

        var states = runtimeStates(base, running);
        var spoofState = states.stream()
                .filter(s -> s.path().equals("/settings/spoofProxyAddress")).findFirst().orElseThrow();
        check(spoofState.effect().equals("ACTIVE_NOW"), "a listener on its configured address is active");

        var mismatched = runtimeStates(moved, running);
        check(mismatched.stream().filter(s -> s.path().equals("/settings/spoofProxyAddress"))
                        .findFirst().orElseThrow().effect().equals("NEXT_START"),
                "a listener on a different address is not");
        check(mismatched.stream().filter(s -> s.path().equals("/settings/spoofProxyAddress"))
                        .findFirst().orElseThrow().active().equals("127.0.0.1:8887"),
                "and the active value is the real one, not the configured one");

        // Burp's own bind interface is not knowable, so it must not be invented.
        var burpState = runtimeStates(base, running).stream()
                .filter(s -> s.path().equals("/settings/burpProxyAddress")).findFirst().orElseThrow();
        check(burpState.active() == null, "Burp's actual proxy endpoint is reported as unavailable");
    }

    private static List<Wire.RiskFlag> risksBetween(SettingsSnapshot base, SettingsSnapshot candidate) {
        return risks(base, candidate, diff(base, candidate));
    }

    private static void check(boolean condition, String what) {
        if (!condition) throw new AssertionError("failed: " + what);
    }
}
