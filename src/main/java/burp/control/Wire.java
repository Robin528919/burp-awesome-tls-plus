package burp.control;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.util.Comparator;
import java.util.List;

/**
 * The value types the two MCP tools return, and their JSON form.
 * <p>
 * ADR-0001 section 16.4 fixes these as closed records: every one serializes with
 * {@code additionalProperties: false}, and the array orders below are part of the contract because
 * a proposal's digest is taken over them. An unstable sort would change the digest of an unchanged
 * proposal and invalidate an approval the user is halfway through.
 * <p>
 * Kept free of MCP framing on purpose. These describe settings; the adapter wraps them.
 */
public final class Wire {
    private Wire() {
    }

    /** The business payload version, distinct from the wire protocol and journal versions. */
    public static final String SCHEMA_VERSION = "awesome_tls.settings.v1";

    /**
     * The v1 business error codes. Fixed: reusing one for a new condition, or moving a condition to
     * a different code, breaks clients that branch on them.
     */
    public enum Code {
        UNSUPPORTED_SCHEMA, VALIDATION_FAILED, REVISION_CONFLICT, DIRTY_UI, PROPOSAL_PENDING,
        EXPIRED, REQUEST_ID_CONFLICT, IDEMPOTENCY_CAPACITY, HIDDEN_RULE_CONFLICT,
        AMBIGUOUS_FINGERPRINT_HEX, CURSOR_INVALID, CURSOR_STALE, RULE_FILE_INVALID,
        EXTERNAL_DIVERGENCE, MERGE_CONFLICT, AUDIT_UNAVAILABLE, CONTROL_DISABLED,
        PERSISTENCE_FAILED, RECOVERY_REQUIRED;

        /**
         * @return whether retrying the same call could plausibly succeed later.
         */
        public boolean retryable() {
            return switch (this) {
                case REVISION_CONFLICT, DIRTY_UI, PROPOSAL_PENDING, EXPIRED, CURSOR_STALE,
                     EXTERNAL_DIVERGENCE, MERGE_CONFLICT, AUDIT_UNAVAILABLE, PERSISTENCE_FAILED,
                     RECOVERY_REQUIRED, HIDDEN_RULE_CONFLICT, RULE_FILE_INVALID -> true;
                // A malformed or unauthorized request will be just as malformed next time.
                case UNSUPPORTED_SCHEMA, VALIDATION_FAILED, REQUEST_ID_CONFLICT, IDEMPOTENCY_CAPACITY,
                     AMBIGUOUS_FINGERPRINT_HEX, CURSOR_INVALID, CONTROL_DISABLED -> false;
            };
        }
    }

    /**
     * Stands in for a string too large to inline. Only fields typed {@code StringValue} in the
     * schema may become one; a field typed plain {@code string} never does, so a client can rely on
     * its type not changing under load.
     */
    public record ChunkReference(String scopeDigest, String path, long totalUtf8Bytes,
                                 String sha256, String cursor) {
        JsonObject toJson() {
            var json = new JsonObject();
            json.addProperty("kind", "chunk_reference");
            json.addProperty("scopeDigest", scopeDigest);
            json.addProperty("path", path);
            json.addProperty("totalUtf8Bytes", totalUtf8Bytes);
            json.addProperty("sha256", sha256);
            json.addProperty("cursor", cursor);
            return json;
        }
    }

    /** One leaf-field change. Never a whole rule: a rename is a set of removes plus a set of adds. */
    public record FieldChange(String operation, String path, Object before, Object after) {
        public static FieldChange add(String path, Object after) {
            return new FieldChange("add", path, null, after);
        }

        public static FieldChange replace(String path, Object before, Object after) {
            return new FieldChange("replace", path, before, after);
        }

        public static FieldChange remove(String path, Object before) {
            return new FieldChange("remove", path, before, null);
        }

        JsonObject toJson() {
            var json = new JsonObject();
            json.addProperty("operation", operation);
            json.addProperty("path", path);
            if (!operation.equals("add")) {
                json.add("before", scalar(before));
            }
            if (!operation.equals("remove")) {
                json.add("after", scalar(after));
            }
            return json;
        }

        /** Output path, then operation. Stable, and independent of how the patch was written. */
        public static final Comparator<FieldChange> ORDER =
                Comparator.comparing(FieldChange::path).thenComparing(FieldChange::operation);
    }

    public record RiskFlag(String code, String severity, List<String> paths, String message) {
        public RiskFlag {
            paths = paths.stream().sorted().toList();
        }

        JsonObject toJson() {
            var json = new JsonObject();
            json.addProperty("code", code);
            json.addProperty("severity", severity);
            json.add("paths", strings(paths));
            json.addProperty("message", message);
            return json;
        }

        public boolean high() {
            return "HIGH".equals(severity);
        }

        public static final Comparator<RiskFlag> ORDER = Comparator.comparing(RiskFlag::code);
    }

    /**
     * When a change actually takes effect. {@code requiresUserAction} is the difference between
     * "this is live" and "this is saved but nothing is using it yet", which is exactly the
     * distinction a settings screen normally hides.
     */
    public record RuntimeImpact(String path, String effect, boolean requiresUserAction, String message) {
        JsonObject toJson() {
            var json = new JsonObject();
            json.addProperty("path", path);
            json.addProperty("effect", effect);
            json.addProperty("requiresUserAction", requiresUserAction);
            json.addProperty("message", message);
            return json;
        }

        public static final Comparator<RuntimeImpact> ORDER =
                Comparator.comparing(RuntimeImpact::path).thenComparing(RuntimeImpact::effect);
    }

    /** Configured versus active, for one setting. */
    public record RuntimeState(String path, Object configured, Object active, String effect) {
        JsonObject toJson() {
            var json = new JsonObject();
            json.addProperty("path", path);
            json.add("configured", scalar(configured));
            json.add("active", scalar(active));
            json.addProperty("effect", effect);
            return json;
        }
    }

    public record ErrorDetail(String path, String reason, Object expected, Object actual) {
        public static ErrorDetail of(String path, String reason) {
            return new ErrorDetail(path, reason, null, null);
        }

        public static ErrorDetail mismatch(String path, String reason, Object expected, Object actual) {
            return new ErrorDetail(path, reason, expected, actual);
        }

        JsonObject toJson() {
            var json = new JsonObject();
            if (path != null) {
                json.addProperty("path", path);
            }
            json.addProperty("reason", reason);
            // Absent and null are different: "expected: null" is a real expectation.
            if (expected != null) {
                json.add("expected", scalar(expected));
            }
            if (actual != null) {
                json.add("actual", scalar(actual));
            }
            return json;
        }
    }

    /**
     * The transport configuration a request to {@code host} would carry, resolved locally.
     * <p>
     * Locally is the operative word: no DNS, no connection, no proxied request. It is the view of
     * {@link burp.TransportConfig} before it is handed to the Go server, minus the request-only
     * fields, which are not settings and can never be proposed.
     */
    public record EffectiveConfig(
            String host,
            String matchedRuleHostPattern,
            BusinessSettings transport,
            java.util.Map<String, String> sources,
            String staticMode,
            String runtimeMode,
            String selectedPath,
            List<String> suppressedPaths) {

        JsonObject toJson() {
            var json = new JsonObject();
            json.addProperty("host", host);
            json.add("matchedRuleHostPattern", matchedRuleHostPattern == null
                    ? JsonNull.INSTANCE : new JsonPrimitive(matchedRuleHostPattern));

            var t = new JsonObject();
            t.addProperty("fingerprint", transport.fingerprint());
            t.addProperty("hexClientHello", transport.hexClientHello());
            t.addProperty("externalProxyUrl", transport.externalProxyUrl());
            t.addProperty("httpTimeout", transport.httpTimeout());
            t.addProperty("useInterceptedFingerprint", transport.useInterceptedFingerprint());
            t.addProperty("interceptProxyAddress", transport.interceptProxyAddress());
            t.addProperty("burpProxyAddress", transport.burpProxyAddress());
            json.add("transport", t);

            var s = new JsonObject();
            for (var entry : sources.entrySet()) {
                s.addProperty(entry.getKey(), entry.getValue());
            }
            json.add("sources", s);

            var resolution = new JsonObject();
            resolution.addProperty("staticMode", staticMode);
            resolution.addProperty("runtimeMode", runtimeMode);
            resolution.add("selectedPath", selectedPath == null
                    ? JsonNull.INSTANCE : new JsonPrimitive(selectedPath));
            resolution.add("suppressedPaths", strings(suppressedPaths));
            json.add("tlsResolution", resolution);
            return json;
        }
    }

    // ------------------------------------------------------------------ helpers

    /**
     * Serializes a {@code ScalarValue}: string, integer, boolean, null, or a chunk reference.
     */
    public static JsonElement scalar(Object value) {
        if (value == null) return JsonNull.INSTANCE;
        if (value instanceof ChunkReference chunk) return chunk.toJson();
        if (value instanceof String s) return new JsonPrimitive(s);
        if (value instanceof Boolean b) return new JsonPrimitive(b);
        if (value instanceof Integer i) return new JsonPrimitive(i);
        if (value instanceof Long l) return new JsonPrimitive(l);
        throw new IllegalArgumentException("not a scalar value: " + value.getClass());
    }

    public static JsonArray strings(List<String> values) {
        var array = new JsonArray();
        values.forEach(array::add);
        return array;
    }

    public static JsonArray changes(List<FieldChange> values) {
        var array = new JsonArray();
        values.stream().sorted(FieldChange.ORDER).forEach(c -> array.add(c.toJson()));
        return array;
    }

    public static JsonArray risks(List<RiskFlag> values) {
        var array = new JsonArray();
        values.stream().sorted(RiskFlag.ORDER).forEach(r -> array.add(r.toJson()));
        return array;
    }

    public static JsonArray impacts(List<RuntimeImpact> values) {
        var array = new JsonArray();
        values.stream().sorted(RuntimeImpact.ORDER).forEach(i -> array.add(i.toJson()));
        return array;
    }

    public static JsonArray details(List<ErrorDetail> values) {
        var array = new JsonArray();
        values.forEach(d -> array.add(d.toJson()));
        return array;
    }

    public static JsonArray runtimeStates(List<RuntimeState> values) {
        var array = new JsonArray();
        values.forEach(s -> array.add(s.toJson()));
        return array;
    }

    public static JsonArray effectiveConfigs(List<EffectiveConfig> values) {
        var array = new JsonArray();
        values.forEach(c -> array.add(c.toJson()));
        return array;
    }

    /**
     * The fixed error payload. Section 15 requires business failures to arrive as a successful
     * JSON-RPC result carrying this, not as a protocol-level error code: a rejected proposal is
     * the tool working correctly.
     */
    public static JsonObject error(Code code, String message, List<ErrorDetail> details, String currentRevision) {
        var json = new JsonObject();
        json.addProperty("kind", "error");
        json.addProperty("schemaVersion", SCHEMA_VERSION);
        json.addProperty("status", "ERROR");
        json.addProperty("code", code.name());
        json.addProperty("message", message);
        json.add("details", details(details == null ? List.of() : details));
        json.addProperty("retryable", code.retryable());
        if (currentRevision != null) {
            json.addProperty("currentRevision", currentRevision);
        }
        return json;
    }
}
