package burp.control;

import burp.FingerprintRule;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A semantic change to the settings: which named fields to set, and which rules to add, update or
 * remove, keyed by host.
 * <p>
 * Deliberately not a JSON Patch. ADR-0001 section 6 refuses array indices, wholesale array
 * replacement and arbitrary paths, because all three let a caller change something it never named:
 * an index shifts when a row is inserted, and "replace the rules array" silently deletes every rule
 * the caller did not know about — including the half-typed ones the table is holding for the user.
 * Everything here addresses a rule by its normalized host, which is stable.
 * <p>
 * Applying a patch never touches storage. It produces a candidate snapshot; whether that candidate
 * is ever committed is decided by a person, in Burp.
 */
public final class SettingsPatch {
    /** Total rule operations one proposal may carry. */
    public static final int MAX_RULE_CHANGES = 100;

    /**
     * Consequences a caller must state out loud before a patch that has them is accepted.
     * <p>
     * These exist because the fingerprint/hex precedence is invisible in the field being edited.
     * Setting a hex ClientHello quietly stops the configured fingerprint from doing anything, and
     * the settings screen would still show the fingerprint. Requiring the words makes the caller
     * demonstrate it knows, rather than discovering it from a traffic capture.
     */
    public enum Ack {
        /** A global hex ClientHello will take precedence over the global fingerprint. */
        GLOBAL_HEX_OVERRIDES_FINGERPRINT,
        /** A rule's hex ClientHello will take precedence over any fingerprint for that host. */
        RULE_HEX_OVERRIDES_FINGERPRINT,
        /** A rule's fingerprint will suppress the global hex ClientHello for that host. */
        RULE_FINGERPRINT_SUPPRESSES_INHERITED_HEX
    }

    /** Fields a settings patch may name. Anything else is refused rather than ignored. */
    static final Set<String> SETTINGS_FIELDS = Set.of(
            "spoofProxyAddress", "interceptProxyAddress", "burpProxyAddress", "fingerprint",
            "hexClientHello", "useInterceptedFingerprint", "httpTimeout", "externalProxyUrl");

    /** Fields that may be cleared by an explicit null. The rest are required to have a value. */
    static final Set<String> CLEARABLE_SETTINGS = Set.of("hexClientHello", "externalProxyUrl");

    /** Fields a rule upsert may name. */
    static final Set<String> RULE_FIELDS = Set.of(
            "hostPattern", "enabled", "fingerprint", "hexClientHello", "externalProxyUrl", "httpTimeout",
            "note");

    /**
     * Settings that only exist globally.
     * <p>
     * The intercept flag and the two proxy addresses drive a single shared Go proxy that is started
     * and stopped from whichever request arrives. Per-host values would make it rebind constantly
     * and cut live connections, so they are refused inside a rule rather than accepted and ignored.
     */
    static final Set<String> GLOBAL_ONLY = Set.of(
            "useInterceptedFingerprint", "interceptProxyAddress", "burpProxyAddress", "spoofProxyAddress");

    /**
     * One rule to create or update.
     *
     * @param key    the normalized host, which is the identity.
     * @param fields the named changes; a present key with a null value means "clear".
     */
    public record RuleUpsert(String rawHostPattern, String key, Map<String, Object> fields) {
        public RuleUpsert {
            // Same reason as above: a null field value means "clear it", so the map cannot go
            // through Map.copyOf.
            fields = java.util.Collections.unmodifiableMap(new LinkedHashMap<>(fields));
        }
    }

    private final Map<String, Object> settings;
    private final List<RuleUpsert> upserts;
    private final List<String> removeKeys;
    private final Set<Ack> acknowledgements;

    private SettingsPatch(Map<String, Object> settings, List<RuleUpsert> upserts,
                          List<String> removeKeys, Set<Ack> acknowledgements) {
        // Not Map.copyOf: a null value here is the instruction to clear a field, and
        // Map.copyOf rejects nulls outright.
        this.settings = mapWithNulls(settings);
        this.upserts = List.copyOf(upserts);
        this.removeKeys = List.copyOf(removeKeys);
        this.acknowledgements = acknowledgements.isEmpty()
                ? EnumSet.noneOf(Ack.class) : EnumSet.copyOf(acknowledgements);
    }

    /**
     * {@link Map#copyOf} rejects null values, but a null here is the instruction to clear a field,
     * so the map is wrapped rather than copied.
     */
    private static Map<String, Object> mapWithNulls(Map<String, Object> source) {
        var copy = new LinkedHashMap<String, Object>();
        // LinkedHashMap tolerates nulls; the caller's map is not retained.
        source.forEach(copy::put);
        return java.util.Collections.unmodifiableMap(copy);
    }

    public Map<String, Object> settings() {
        return settings;
    }

    public List<RuleUpsert> upserts() {
        return upserts;
    }

    public List<String> removeKeys() {
        return removeKeys;
    }

    public Set<Ack> acknowledgements() {
        return acknowledgements;
    }

    public boolean isEmpty() {
        return settings.isEmpty() && upserts.isEmpty() && removeKeys.isEmpty();
    }

    // ------------------------------------------------------------------ parsing

    /**
     * Either a usable patch or the reason there is not one.
     */
    public sealed interface Parsed {
        record Ok(SettingsPatch patch) implements Parsed {
        }

        record Failed(Wire.Code code, String message, List<Wire.ErrorDetail> details) implements Parsed {
        }
    }

    private static Parsed fail(Wire.Code code, String message, List<Wire.ErrorDetail> details) {
        return new Parsed.Failed(code, message, details);
    }

    private static Parsed reject(String path, String reason, String message) {
        return fail(Wire.Code.VALIDATION_FAILED, message, List.of(Wire.ErrorDetail.of(path, reason)));
    }

    /**
     * Reads the {@code patch} and {@code acknowledgements} arguments of a propose call.
     * <p>
     * Structure only. Whether a fingerprint exists, whether a host collides with a hidden row, and
     * whether the revision still matches all depend on what is currently committed, so they are
     * checked later, against a snapshot.
     */
    public static Parsed parse(JsonObject patchJson, List<String> acknowledgementNames) {
        if (patchJson == null || patchJson.size() == 0) {
            return reject("/patch", "empty_patch", "The patch must change something.");
        }
        for (var key : patchJson.keySet()) {
            if (!key.equals("settings") && !key.equals("domainRules")) {
                return reject("/patch/" + Validation.escapeToken(key), "unknown_field",
                        "Unknown patch section \"" + key + "\".");
            }
        }

        var acks = EnumSet.noneOf(Ack.class);
        for (var name : acknowledgementNames == null ? List.<String>of() : acknowledgementNames) {
            try {
                acks.add(Ack.valueOf(name));
            } catch (IllegalArgumentException e) {
                return reject("/acknowledgements", "unknown_acknowledgement",
                        "Unknown acknowledgement \"" + name + "\".");
            }
        }

        var settings = new LinkedHashMap<String, Object>();
        if (patchJson.has("settings")) {
            var problem = readSettings(patchJson.get("settings"), settings);
            if (problem != null) {
                return problem;
            }
        }

        var upserts = new ArrayList<RuleUpsert>();
        var removes = new ArrayList<String>();
        if (patchJson.has("domainRules")) {
            var problem = readRules(patchJson.get("domainRules"), upserts, removes);
            if (problem != null) {
                return problem;
            }
        }

        if (settings.isEmpty() && upserts.isEmpty() && removes.isEmpty()) {
            return reject("/patch", "empty_patch", "The patch must change something.");
        }
        if (upserts.size() + removes.size() > MAX_RULE_CHANGES) {
            return fail(Wire.Code.VALIDATION_FAILED,
                    "A proposal may change at most " + MAX_RULE_CHANGES + " rules; this one changes "
                            + (upserts.size() + removes.size()) + ".",
                    List.of(Wire.ErrorDetail.mismatch("/patch/domainRules", "too_many_rule_changes",
                            MAX_RULE_CHANGES, upserts.size() + removes.size())));
        }

        return new Parsed.Ok(new SettingsPatch(settings, upserts, removes, acks));
    }

    private static Parsed readSettings(JsonElement element, Map<String, Object> into) {
        if (!element.isJsonObject()) {
            return reject("/patch/settings", "not_an_object", "The settings patch must be an object.");
        }
        var object = element.getAsJsonObject();
        if (object.size() == 0) {
            return reject("/patch/settings", "empty_patch", "The settings patch must change something.");
        }

        for (var field : object.keySet()) {
            var path = "/patch/settings/" + Validation.escapeToken(field);
            if (!SETTINGS_FIELDS.contains(field)) {
                // Names the caller might reasonably reach for, and why they are not settings.
                if (field.equals("Host") || field.equals("Scheme") || field.equals("HeaderOrder")) {
                    return reject(path, "request_only_field",
                            "\"" + field + "\" belongs to a single request, not to the settings.");
                }
                return reject(path, "unknown_field", "Unknown setting \"" + field + "\".");
            }

            var value = object.get(field);
            if (value.isJsonNull()) {
                if (!CLEARABLE_SETTINGS.contains(field)) {
                    return reject(path, "not_clearable",
                            "\"" + field + "\" always has a value; null cannot clear it.");
                }
                into.put(field, null);
                continue;
            }
            if (!value.isJsonPrimitive()) {
                return reject(path, "not_a_scalar", "\"" + field + "\" must be a scalar value.");
            }

            var primitive = value.getAsJsonPrimitive();
            switch (field) {
                case "useInterceptedFingerprint" -> {
                    if (!primitive.isBoolean()) {
                        return reject(path, "not_a_boolean", "\"" + field + "\" must be true or false.");
                    }
                    into.put(field, primitive.getAsBoolean());
                }
                case "httpTimeout" -> {
                    if (!primitive.isNumber()) {
                        return reject(path, "not_an_integer", "\"" + field + "\" must be a whole number of seconds.");
                    }
                    try {
                        into.put(field, Integer.parseInt(primitive.getAsString()));
                    } catch (NumberFormatException e) {
                        return reject(path, "not_an_integer", "\"" + field + "\" must be a whole number of seconds.");
                    }
                }
                default -> {
                    if (!primitive.isString()) {
                        return reject(path, "not_a_string", "\"" + field + "\" must be a string.");
                    }
                    into.put(field, primitive.getAsString());
                }
            }
        }
        return null;
    }

    private static Parsed readRules(JsonElement element, List<RuleUpsert> upserts, List<String> removes) {
        if (!element.isJsonObject()) {
            return reject("/patch/domainRules", "not_an_object", "The domain rule patch must be an object.");
        }
        var object = element.getAsJsonObject();
        for (var key : object.keySet()) {
            if (!key.equals("upsert") && !key.equals("remove")) {
                if (key.equals("replaceAll") || key.equals("rules")) {
                    return reject("/patch/domainRules/" + Validation.escapeToken(key), "unsupported_operation",
                            "Rules are changed one host at a time; there is no wholesale replacement, "
                                    + "because it would delete rules the caller never saw.");
                }
                return reject("/patch/domainRules/" + Validation.escapeToken(key), "unknown_field",
                        "Unknown domain rule operation \"" + key + "\".");
            }
        }
        if (object.size() == 0) {
            return reject("/patch/domainRules", "empty_patch", "The domain rule patch must change something.");
        }

        // One key may appear once, in one operation. Two instructions for the same host in one
        // proposal have no defined order, so there is no safe way to apply both.
        var claimed = new HashSet<String>();

        if (object.has("upsert")) {
            var array = object.get("upsert");
            if (!array.isJsonArray()) {
                return reject("/patch/domainRules/upsert", "not_an_array", "\"upsert\" must be an array.");
            }
            for (var i = 0; i < array.getAsJsonArray().size(); i++) {
                var problem = readUpsert(array.getAsJsonArray().get(i), i, claimed, upserts);
                if (problem != null) {
                    return problem;
                }
            }
        }

        if (object.has("remove")) {
            var array = object.get("remove");
            if (!array.isJsonArray()) {
                return reject("/patch/domainRules/remove", "not_an_array", "\"remove\" must be an array.");
            }
            for (var i = 0; i < array.getAsJsonArray().size(); i++) {
                var path = "/patch/domainRules/remove/" + i;
                var value = array.getAsJsonArray().get(i);
                if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) {
                    return reject(path, "not_a_string", "Each removed host pattern must be a string.");
                }
                var host = HostKey.normalize(value.getAsString(), HostKey.Mode.RULE_KEY);
                if (!host.ok()) {
                    return reject(path, "invalid_host_pattern", "Host pattern " + host.problem() + ".");
                }
                if (!claimed.add(host.key())) {
                    return reject(path, "conflicting_rule_change",
                            "\"" + host.key() + "\" is changed more than once in this proposal.");
                }
                removes.add(host.key());
            }
        }
        return null;
    }

    private static Parsed readUpsert(JsonElement element, int index, Set<String> claimed, List<RuleUpsert> into) {
        var at = "/patch/domainRules/upsert/" + index;
        if (!element.isJsonObject()) {
            return reject(at, "not_an_object", "Each upsert must be an object.");
        }
        var object = element.getAsJsonObject();

        for (var field : object.keySet()) {
            if (RULE_FIELDS.contains(field)) {
                continue;
            }
            if (GLOBAL_ONLY.contains(field)) {
                return reject(at + "/" + Validation.escapeToken(field), "global_only_field",
                        "\"" + field + "\" is a global setting; it cannot vary per host.");
            }
            return reject(at + "/" + Validation.escapeToken(field), "unknown_field",
                    "Unknown rule field \"" + field + "\".");
        }

        if (!object.has("hostPattern") || object.get("hostPattern").isJsonNull()
                || !object.get("hostPattern").isJsonPrimitive()
                || !object.get("hostPattern").getAsJsonPrimitive().isString()) {
            return reject(at + "/hostPattern", "missing_host_pattern", "Each upsert must name a host pattern.");
        }
        var raw = object.get("hostPattern").getAsString();
        var host = HostKey.normalize(raw, HostKey.Mode.RULE_KEY);
        if (!host.ok()) {
            return reject(at + "/hostPattern", "invalid_host_pattern", "Host pattern " + host.problem() + ".");
        }
        if (!claimed.add(host.key())) {
            return reject(at + "/hostPattern", "conflicting_rule_change",
                    "\"" + host.key() + "\" is changed more than once in this proposal.");
        }

        var fields = new LinkedHashMap<String, Object>();
        for (var field : object.keySet()) {
            if (field.equals("hostPattern")) {
                continue;
            }
            var path = at + "/" + Validation.escapeToken(field);
            var value = object.get(field);
            if (value.isJsonNull()) {
                if (field.equals("enabled")) {
                    return reject(path, "not_clearable", "\"enabled\" is always true or false.");
                }
                fields.put(field, null);
                continue;
            }
            if (!value.isJsonPrimitive()) {
                return reject(path, "not_a_scalar", "\"" + field + "\" must be a scalar value.");
            }
            var primitive = value.getAsJsonPrimitive();
            switch (field) {
                case "enabled" -> {
                    if (!primitive.isBoolean()) {
                        return reject(path, "not_a_boolean", "\"enabled\" must be true or false.");
                    }
                    fields.put(field, primitive.getAsBoolean());
                }
                case "httpTimeout" -> {
                    if (!primitive.isNumber()) {
                        return reject(path, "not_an_integer", "\"httpTimeout\" must be a whole number of seconds.");
                    }
                    try {
                        fields.put(field, Integer.parseInt(primitive.getAsString()));
                    } catch (NumberFormatException e) {
                        return reject(path, "not_an_integer", "\"httpTimeout\" must be a whole number of seconds.");
                    }
                }
                default -> {
                    if (!primitive.isString()) {
                        return reject(path, "not_a_string", "\"" + field + "\" must be a string.");
                    }
                    fields.put(field, primitive.getAsString());
                }
            }
        }

        if (fields.isEmpty()) {
            return reject(at, "no_change", "An upsert must change at least one field besides the host pattern.");
        }

        into.add(new RuleUpsert(raw, host.key(), fields));
        return null;
    }

    // ------------------------------------------------------------------ applying

    /**
     * @return {@code base} with this patch applied, or null if a removal names a host that is not
     * there. Nothing is written; this is a candidate for review.
     */
    public SettingsSnapshot applyTo(SettingsSnapshot base) {
        var settingsValue = base.settings();
        for (var entry : settings.entrySet()) {
            settingsValue = applySetting(settingsValue, entry.getKey(), entry.getValue());
        }

        // Rules keep their position and their stored spelling; only named fields move. A rewrite
        // that reordered or re-spelled untouched rows would show up in the file as a change nobody
        // asked for, and in a three-way merge as a conflict with whoever edited it by hand.
        var rules = new ArrayList<FingerprintRule>(base.storedRules());
        var removed = new LinkedHashSet<>(removeKeys);

        for (var upsert : upserts) {
            var at = base.indexByKey().get(upsert.key());
            if (at == null) {
                var created = new FingerprintRule(upsert.key(), "", "", "", null, true);
                rules.add(applyRuleFields(created, upsert.fields()));
            } else {
                rules.set(at, applyRuleFields(rules.get(at), upsert.fields()));
            }
        }

        if (!removed.isEmpty()) {
            var kept = new ArrayList<FingerprintRule>(rules.size());
            for (var i = 0; i < rules.size(); i++) {
                var key = i < base.storedRules().size() ? keyAt(base, i) : null;
                if (key != null && removed.contains(key)) {
                    continue;
                }
                kept.add(rules.get(i));
            }
            rules = kept;
        }

        return SettingsSnapshot.of(settingsValue, rules);
    }

    private static String keyAt(SettingsSnapshot base, int index) {
        for (var entry : base.indexByKey().entrySet()) {
            if (entry.getValue() == index) {
                return entry.getKey();
            }
        }
        return null;
    }

    private static BusinessSettings applySetting(BusinessSettings settings, String field, Object value) {
        return switch (field) {
            case "spoofProxyAddress" -> settings.withSpoofProxyAddress((String) value);
            case "interceptProxyAddress" -> settings.withInterceptProxyAddress((String) value);
            case "burpProxyAddress" -> settings.withBurpProxyAddress((String) value);
            case "fingerprint" -> settings.withFingerprint((String) value);
            case "hexClientHello" -> settings.withHexClientHello(value == null ? "" : (String) value);
            case "useInterceptedFingerprint" -> settings.withUseInterceptedFingerprint((Boolean) value);
            case "httpTimeout" -> settings.withHttpTimeout((Integer) value);
            case "externalProxyUrl" -> settings.withExternalProxyUrl(value == null ? "" : (String) value);
            default -> throw new IllegalStateException("unreachable: unknown setting " + field);
        };
    }

    private static FingerprintRule applyRuleFields(FingerprintRule rule, Map<String, Object> fields) {
        var updated = rule.materialized();
        for (var entry : fields.entrySet()) {
            var value = entry.getValue();
            switch (entry.getKey()) {
                case "enabled" -> updated.enabled = (Boolean) value;
                case "fingerprint" -> updated.fingerprint = value == null ? "" : (String) value;
                case "hexClientHello" -> updated.hexClientHello = value == null ? "" : (String) value;
                case "externalProxyUrl" -> updated.externalProxyUrl = value == null ? "" : (String) value;
                case "note" -> updated.note = value == null ? "" : (String) value;
                case "httpTimeout" -> updated.httpTimeout = (Integer) value;
                default -> throw new IllegalStateException("unreachable: unknown rule field " + entry.getKey());
            }
        }
        return updated;
    }

    /**
     * @return the hosts this patch removes that are not in {@code base}.
     */
    public List<String> missingRemovals(SettingsSnapshot base) {
        return removeKeys.stream().filter(key -> !base.indexByKey().containsKey(key)).toList();
    }

    /**
     * @return hosts this patch names that collide with a row the matcher already refuses.
     * <p>
     * Those rows are invisible to the caller, so an upsert would either resurrect one or overwrite
     * a half-typed edit. Section 7 requires the user to resolve it in Burp first.
     */
    public List<String> hiddenRuleConflicts(SettingsSnapshot base) {
        var hidden = new LinkedHashSet<String>();
        for (var index : base.hiddenIndexes()) {
            var key = HostKey.keyOrNull(base.storedRules().get(index).normalized().hostPattern,
                    HostKey.Mode.RULE_KEY);
            if (key != null) {
                hidden.add(key);
            }
        }
        var conflicts = new ArrayList<String>();
        for (var upsert : upserts) {
            if (hidden.contains(upsert.key())) {
                conflicts.add(upsert.key());
            }
        }
        for (var key : removeKeys) {
            if (hidden.contains(key)) {
                conflicts.add(key);
            }
        }
        return List.copyOf(conflicts);
    }

    /**
     * Checks the fingerprint/hex precedence rules of section 6.3 against what the patch actually
     * does, and reports which acknowledgements are missing.
     *
     * @return empty when the patch is unambiguous or already says the right things.
     */
    public List<Wire.ErrorDetail> ambiguities(SettingsSnapshot base, SettingsSnapshot candidate) {
        var missing = new ArrayList<Wire.ErrorDetail>();
        var globalHexBefore = base.settings().hexClientHello();
        var globalHexAfter = candidate.settings().hexClientHello();

        // Changing the fingerprint while a hex ClientHello is set changes nothing observable,
        // because hex wins. Refuse rather than accept a setting that will not be used.
        if (settings.containsKey("fingerprint") && !globalHexBefore.isEmpty() && !globalHexAfter.isEmpty()) {
            missing.add(Wire.ErrorDetail.of(Validation.settingsPath("fingerprint"),
                    "fingerprint_change_has_no_effect_while_hex_is_set"));
        }

        if (settings.containsKey("hexClientHello") && !globalHexAfter.isEmpty()
                && !acknowledgements.contains(Ack.GLOBAL_HEX_OVERRIDES_FINGERPRINT)) {
            missing.add(Wire.ErrorDetail.mismatch(Validation.settingsPath("hexClientHello"),
                    "missing_acknowledgement", Ack.GLOBAL_HEX_OVERRIDES_FINGERPRINT.name(), null));
        }

        for (var upsert : upserts) {
            var rule = candidate.ruleByKey(upsert.key());
            if (rule == null) {
                continue;
            }
            if (upsert.fields().containsKey("hexClientHello") && !rule.hexClientHello.isEmpty()
                    && !acknowledgements.contains(Ack.RULE_HEX_OVERRIDES_FINGERPRINT)) {
                missing.add(Wire.ErrorDetail.mismatch(Validation.rulePath(upsert.key(), "hexClientHello"),
                        "missing_acknowledgement", Ack.RULE_HEX_OVERRIDES_FINGERPRINT.name(), null));
            }
            // A rule fingerprint suppresses an inherited global hex for that host without clearing
            // it, so the global setting still reads as active while this host ignores it.
            if (upsert.fields().containsKey("fingerprint") && !rule.fingerprint.isEmpty()
                    && rule.hexClientHello.isEmpty() && !globalHexAfter.isEmpty()
                    && !acknowledgements.contains(Ack.RULE_FINGERPRINT_SUPPRESSES_INHERITED_HEX)) {
                missing.add(Wire.ErrorDetail.mismatch(Validation.rulePath(upsert.key(), "fingerprint"),
                        "missing_acknowledgement",
                        Ack.RULE_FINGERPRINT_SUPPRESSES_INHERITED_HEX.name(), null));
            }
        }
        return List.copyOf(missing);
    }

    /**
     * @return the acknowledgement names, sorted, for the proposal digest. Section 8.2 fixes this
     * order so that two identical patches hash identically regardless of how they were written.
     */
    public List<String> acknowledgementNames() {
        return acknowledgements.stream().map(Enum::name).sorted().toList();
    }

    /**
     * The patch in canonical form, for the proposal digest and the audit trail.
     */
    public JsonObject toCanonicalJson() {
        var root = new JsonObject();
        if (!settings.isEmpty()) {
            var object = new JsonObject();
            settings.forEach((field, value) -> object.add(field, Wire.scalar(value)));
            root.add("settings", object);
        }
        if (!upserts.isEmpty() || !removeKeys.isEmpty()) {
            var rules = new JsonObject();
            if (!upserts.isEmpty()) {
                var array = new com.google.gson.JsonArray();
                // Request order is preserved, because it decides the position of appended rules.
                for (var upsert : upserts) {
                    var entry = new JsonObject();
                    entry.addProperty("hostPattern", upsert.key());
                    upsert.fields().forEach((field, value) -> entry.add(field, Wire.scalar(value)));
                    array.add(entry);
                }
                rules.add("upsert", array);
            }
            if (!removeKeys.isEmpty()) {
                rules.add("remove", Wire.strings(removeKeys));
            }
            root.add("domainRules", rules);
        }
        return root;
    }
}
