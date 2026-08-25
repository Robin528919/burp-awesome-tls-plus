package burp.control;

import burp.FingerprintRule;
import burp.RuleMatcher;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * One committed configuration, and the matcher that goes with it.
 * <p>
 * ADR-0001 section 3 requires the snapshot and its {@link RuleMatcher} to be published together in
 * a single reference, so a request thread only ever sees a complete old version or a complete new
 * one. Building the matcher in the constructor is what makes that possible: there is no window in
 * which the settings have changed but the matcher has not.
 * <p>
 * Rules are kept exactly as stored, in storage order, including rows the matcher will not use.
 * Section 7 is explicit that an unusable row stays on disk and stays visible in the table — it is
 * a row someone is midway through typing — but never participates in matching, and is not shown to
 * an AI client, which would otherwise be able to delete it without anyone seeing the change.
 */
public final class SettingsSnapshot {
    /** The canonical document's own version, independent of the wire and journal versions. */
    public static final int SCHEMA_VERSION = 1;

    private final BusinessSettings settings;
    private final List<FingerprintRule> storedRules;
    private final List<FingerprintRule> validRules;
    private final Map<String, Integer> indexByKey;
    private final List<Integer> hiddenIndexes;
    private final RuleMatcher matcher;
    private final String revision;

    private SettingsSnapshot(BusinessSettings settings, List<FingerprintRule> storedRules) {
        this.settings = settings.normalized();

        var stored = new ArrayList<FingerprintRule>(storedRules.size());
        for (var rule : storedRules) {
            // A hand-edited file can contain a null entry; treat it as an unusable row rather
            // than letting it reach anything that dereferences it.
            stored.add(rule == null ? new FingerprintRule() : rule.materialized());
        }
        this.storedRules = List.copyOf(stored);

        // Pass one: which rows are structurally usable, and what key does each claim?
        var keyOf = new String[stored.size()];
        var claims = new HashMap<String, Integer>();
        var contested = new HashSet<String>();
        for (var i = 0; i < stored.size(); i++) {
            if (!Validation.structuralRule(stored.get(i), i).isEmpty()) {
                continue;
            }
            var host = HostKey.normalize(stored.get(i).normalized().hostPattern, HostKey.Mode.RULE_KEY);
            if (!host.ok()) {
                continue;
            }
            keyOf[i] = host.key();
            if (claims.putIfAbsent(host.key(), i) != null) {
                // Neither row wins. "The last one wins" is the behaviour that lets a duplicate
                // look harmless until the wrong rule is the one that applies.
                contested.add(host.key());
            }
        }

        // Pass two: everything not contested becomes a valid rule, in storage order.
        var valid = new ArrayList<FingerprintRule>();
        var index = new LinkedHashMap<String, Integer>();
        var hidden = new ArrayList<Integer>();
        for (var i = 0; i < stored.size(); i++) {
            var key = keyOf[i];
            if (key == null || contested.contains(key)) {
                hidden.add(i);
                continue;
            }
            index.put(key, i);
            valid.add(canonicalRule(stored.get(i), key));
        }

        this.validRules = List.copyOf(valid);
        this.indexByKey = Collections.unmodifiableMap(index);
        this.hiddenIndexes = List.copyOf(hidden);
        this.matcher = new RuleMatcher(this.validRules);
        this.revision = Jcs.digest(canonicalDocument());
    }

    public static SettingsSnapshot of(BusinessSettings settings, List<FingerprintRule> storedRules) {
        return new SettingsSnapshot(settings, storedRules == null ? List.of() : storedRules);
    }

    public static SettingsSnapshot empty() {
        return of(BusinessSettings.defaults(), List.of());
    }

    // ------------------------------------------------------------------ accessors

    public BusinessSettings settings() {
        return settings;
    }

    /**
     * @return every rule as stored, in storage order, including unusable ones. This is what the
     * table shows and what is written back to disk.
     */
    public List<FingerprintRule> storedRules() {
        return storedRules;
    }

    /**
     * @return the usable rules, canonicalized, in storage order. This is what an AI client sees
     * and what the matcher was built from.
     */
    public List<FingerprintRule> validRules() {
        return validRules;
    }

    /**
     * @return storage index by normalized host key, for locating the row a patch names.
     */
    public Map<String, Integer> indexByKey() {
        return indexByKey;
    }

    public FingerprintRule ruleByKey(String normalizedKey) {
        var at = indexByKey.get(normalizedKey);
        return at == null ? null : canonicalRule(storedRules.get(at), normalizedKey);
    }

    /**
     * @return storage indexes of rows that are on disk and in the table but never match. Their
     * count is all an AI client is told; their contents are not exposed, so a patch cannot
     * silently rewrite a row the user has not finished.
     */
    public List<Integer> hiddenIndexes() {
        return hiddenIndexes;
    }

    public int hiddenInvalidRuleCount() {
        return hiddenIndexes.size();
    }

    public RuleMatcher matcher() {
        return matcher;
    }

    /**
     * @return {@code sha256:<hex>} over the canonical document. Content identity, not a counter:
     * two histories that arrive at the same settings are the same revision.
     */
    public String revision() {
        return revision;
    }

    // ------------------------------------------------------------------ canonical form

    /**
     * The logical document the revision is taken over. See ADR-0001 section 8.1.
     */
    public JsonObject canonicalDocument() {
        var root = new JsonObject();
        root.addProperty("schemaVersion", SCHEMA_VERSION);
        settings.writeCanonical(root);

        var rules = new JsonArray();
        var hidden = new HashSet<>(hiddenIndexes);
        for (var i = 0; i < storedRules.size(); i++) {
            var stored = storedRules.get(i);
            if (hidden.contains(i)) {
                // Verbatim, so that fixing whitespace in an unusable row is still a change.
                rules.add(ruleJson(stored));
            } else {
                var key = HostKey.keyOrNull(stored.normalized().hostPattern, HostKey.Mode.RULE_KEY);
                rules.add(ruleJson(canonicalRule(stored, key)));
            }
        }
        root.add("rules", rules);
        return root;
    }

    private static JsonObject ruleJson(FingerprintRule rule) {
        var json = new JsonObject();
        json.addProperty("hostPattern", rule.hostPattern);
        json.addProperty("enabled", rule.enabled);
        json.addProperty("fingerprint", rule.fingerprint);
        json.addProperty("hexClientHello", rule.hexClientHello);
        json.addProperty("externalProxyUrl", rule.externalProxyUrl);
        if (rule.httpTimeout == null) {
            json.add("httpTimeout", com.google.gson.JsonNull.INSTANCE);
        } else {
            json.addProperty("httpTimeout", rule.httpTimeout);
        }
        return json;
    }

    /**
     * A usable row in the same normalized form everywhere it is compared, hashed or matched.
     */
    private static FingerprintRule canonicalRule(FingerprintRule stored, String key) {
        var normalized = stored.normalized();
        return new FingerprintRule(
                key,
                normalized.fingerprint,
                normalized.hexClientHello.toLowerCase(java.util.Locale.ROOT),
                normalized.externalProxyUrl,
                normalized.httpTimeout,
                normalized.enabled);
    }

    /**
     * @return this snapshot with a different rule list, sharing the settings.
     */
    public SettingsSnapshot withRules(List<FingerprintRule> rules) {
        return of(settings, rules);
    }

    public SettingsSnapshot withSettings(BusinessSettings replacement) {
        return of(replacement, storedRules);
    }

    /**
     * Self-check.
     * Run with: {@code java -ea -cp build/classes/java/main:<gson.jar> burp.control.SettingsSnapshot}
     */
    public static void main(String[] args) {
        var empty = SettingsSnapshot.empty();
        check(empty.revision().equals("sha256:3e3e681a6422f5cd90d4c3d6bb226e4ba6713a19efb43f5a9706b0eb8046f2b3"),
                "the empty snapshot matches the ADR golden revision");
        check(empty.hiddenInvalidRuleCount() == 0 && empty.validRules().isEmpty(), "no rules means no rules");

        var one = SettingsSnapshot.of(BusinessSettings.defaults(),
                List.of(new FingerprintRule("Example.COM", "chrome", "AABB", "", 60, true)));
        check(one.validRules().size() == 1, "a usable row is valid");
        check(one.validRules().get(0).hostPattern.equals("example.com"), "the host key is canonical");
        check(one.validRules().get(0).hexClientHello.equals("aabb"), "hex is lowercased");
        check(one.storedRules().get(0).hostPattern.equals("Example.COM"), "the stored spelling is untouched");
        check(one.matcher().match("EXAMPLE.com") != null, "the matcher was built from it");

        // Both wildcard spellings are one rule, so writing both hides both.
        var dupes = SettingsSnapshot.of(BusinessSettings.defaults(), List.of(
                new FingerprintRule("*.b.com", "chrome", "", "", null, true),
                new FingerprintRule(".b.com", "firefox", "", "", null, true)));
        check(dupes.validRules().isEmpty(), "a contested key produces no valid rule");
        check(dupes.hiddenInvalidRuleCount() == 2, "both halves of the duplicate are hidden");
        check(dupes.matcher().match("x.b.com") == null, "and neither reaches the request path");
        check(dupes.storedRules().size() == 2, "but both stay on disk");

        // An unusable row must not take the whole file down with it.
        var mixed = SettingsSnapshot.of(BusinessSettings.defaults(), List.of(
                new FingerprintRule("good.com", "chrome", "", "", null, true),
                new FingerprintRule("", "", "", "", null, true),
                new FingerprintRule("also-good.com", "firefox", "", "", null, true)));
        check(mixed.validRules().size() == 2 && mixed.hiddenInvalidRuleCount() == 1,
                "an incomplete row is hidden and the rest still work");
        check(mixed.matcher().match("good.com") != null && mixed.matcher().match("also-good.com") != null,
                "the usable rows still match");

        // Revision is content identity, not a counter.
        var a = SettingsSnapshot.of(BusinessSettings.defaults(),
                List.of(new FingerprintRule("a.com", "chrome", "", "", null, true)));
        var b = SettingsSnapshot.of(BusinessSettings.defaults(),
                List.of(new FingerprintRule("  A.com  ", "chrome", "", "", null, true)));
        check(a.revision().equals(b.revision()), "spelling differences in a usable row do not change the revision");

        var reordered = SettingsSnapshot.of(BusinessSettings.defaults(), List.of(
                new FingerprintRule("b.com", "chrome", "", "", null, true),
                new FingerprintRule("a.com", "chrome", "", "", null, true)));
        var ordered = SettingsSnapshot.of(BusinessSettings.defaults(), List.of(
                new FingerprintRule("a.com", "chrome", "", "", null, true),
                new FingerprintRule("b.com", "chrome", "", "", null, true)));
        check(!reordered.revision().equals(ordered.revision()), "storage order is part of the revision");

        // A hidden row is hashed verbatim, so fixing its whitespace is a real change.
        var raw1 = SettingsSnapshot.of(BusinessSettings.defaults(),
                List.of(new FingerprintRule("  ", "chrome", "", "", null, true)));
        var raw2 = SettingsSnapshot.of(BusinessSettings.defaults(),
                List.of(new FingerprintRule("    ", "chrome", "", "", null, true)));
        check(!raw1.revision().equals(raw2.revision()), "a hidden row's exact contents are part of the revision");

        var changed = SettingsSnapshot.of(BusinessSettings.defaults().withHttpTimeout(45), List.of());
        check(!changed.revision().equals(empty.revision()), "a scalar change moves the revision");

        check(one.ruleByKey("example.com") != null, "a rule can be found by its key");
        check(one.ruleByKey("nope.com") == null, "an absent key returns nothing");
        check(one.indexByKey().get("example.com") == 0, "keys map back to storage positions");

        // Nulls from a hand-edited file must not escape.
        var withNull = SettingsSnapshot.of(BusinessSettings.defaults(),
                java.util.Arrays.asList(null, new FingerprintRule("ok.com", "", "", "", null, true)));
        check(withNull.validRules().size() == 1 && withNull.hiddenInvalidRuleCount() == 1,
                "a null entry becomes a hidden row rather than an exception");

        System.out.println("SettingsSnapshot self-check passed");
    }

    private static void check(boolean condition, String what) {
        if (!condition) throw new AssertionError("failed: " + what);
    }
}
