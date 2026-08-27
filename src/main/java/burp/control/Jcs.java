package burp.control;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;

/**
 * RFC 8785 JSON Canonicalization, plus the SHA-256 content digest built on top of it.
 * <p>
 * ADR-0001 identifies settings by the hash of their canonical bytes rather than by a counter, so
 * this is the definition of "the same settings": two documents that differ only in key order or
 * whitespace must produce identical bytes, and any change to an actual value must not.
 * <p>
 * Numbers are restricted to integers. The spec's canonical document has no fractional value, and
 * ECMAScript double formatting is the one part of RFC 8785 that is easy to get subtly wrong, so
 * a non-integral number is refused rather than serialized on a best guess.
 */
public final class Jcs {
    public static final String DIGEST_PREFIX = "sha256:";

    private Jcs() {
    }

    /**
     * @return {@code value} serialized as canonical UTF-8 bytes: sorted keys, minimal escapes,
     * no whitespace, no trailing newline.
     */
    public static byte[] bytes(JsonElement value) {
        var out = new StringBuilder();
        write(value, out);
        return out.toString().getBytes(StandardCharsets.UTF_8);
    }

    public static String string(JsonElement value) {
        var out = new StringBuilder();
        write(value, out);
        return out.toString();
    }

    /**
     * @return {@code sha256:<lowercase hex>} over the canonical bytes of {@code value}.
     */
    public static String digest(JsonElement value) {
        return DIGEST_PREFIX + sha256Hex(bytes(value));
    }

    public static String sha256Hex(byte[] data) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandated by the JLS; its absence is not a recoverable condition.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /**
     * @return {@code sha256:<hex>} over raw bytes, for files whose exact contents matter.
     */
    public static String digestOfBytes(byte[] data) {
        return DIGEST_PREFIX + sha256Hex(data);
    }

    public static boolean isDigest(String value) {
        if (value == null || value.length() != DIGEST_PREFIX.length() + 64) return false;
        if (!value.startsWith(DIGEST_PREFIX)) return false;
        for (var i = DIGEST_PREFIX.length(); i < value.length(); i++) {
            var c = value.charAt(i);
            if ((c < '0' || c > '9') && (c < 'a' || c > 'f')) return false;
        }
        return true;
    }

    private static void write(JsonElement value, StringBuilder out) {
        if (value == null || value.isJsonNull()) {
            out.append("null");
            return;
        }
        if (value.isJsonObject()) {
            writeObject(value.getAsJsonObject(), out);
            return;
        }
        if (value.isJsonArray()) {
            out.append('[');
            var first = true;
            for (var element : value.getAsJsonArray()) {
                if (!first) out.append(',');
                first = false;
                write(element, out);
            }
            out.append(']');
            return;
        }
        writePrimitive(value.getAsJsonPrimitive(), out);
    }

    private static void writeObject(JsonObject object, StringBuilder out) {
        // RFC 8785 sorts members on the UTF-16 code units of the key, which is exactly what
        // String.compareTo compares.
        var keys = new ArrayList<>(object.keySet());
        Collections.sort(keys);

        out.append('{');
        var first = true;
        for (var key : keys) {
            if (!first) out.append(',');
            first = false;
            writeString(key, out);
            out.append(':');
            write(object.get(key), out);
        }
        out.append('}');
    }

    private static void writePrimitive(JsonPrimitive primitive, StringBuilder out) {
        if (primitive.isBoolean()) {
            out.append(primitive.getAsBoolean() ? "true" : "false");
            return;
        }
        if (primitive.isNumber()) {
            var number = primitive.getAsNumber();
            var text = number.toString();
            long asLong;
            try {
                asLong = Long.parseLong(text);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(
                        "canonical documents carry integers only, got " + text);
            }
            out.append(asLong);
            return;
        }
        writeString(primitive.getAsString(), out);
    }

    /**
     * RFC 8785 section 3.2.2.2: escape only what JSON requires, using the two-character forms
     * where they exist. Everything else, including non-ASCII, stays literal.
     */
    private static void writeString(String value, StringBuilder out) {
        out.append('"');
        for (var i = 0; i < value.length(); i++) {
            var c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }

    /**
     * Self-check. Run with:
     * {@code java -ea -cp build/classes/java/main:<gson.jar> burp.control.Jcs}
     */
    public static void main(String[] args) {
        check(canon("{\"b\":1,\"a\":2}").equals("{\"a\":2,\"b\":1}"), "keys are sorted");
        check(canon("{ \"a\" : [ 1 , 2 ] }").equals("{\"a\":[1,2]}"), "whitespace is dropped");
        check(canon("[3,1,2]").equals("[3,1,2]"), "array order is preserved");
        check(canon("{\"a\":null,\"b\":true,\"c\":false}").equals("{\"a\":null,\"b\":true,\"c\":false}"),
                "literals round trip");

        // Sorting is on UTF-16 code units, not on a locale collation.
        check(canon("{\"B\":1,\"a\":2}").equals("{\"B\":1,\"a\":2}"), "uppercase sorts before lowercase");
        check(canon("{\"a\":1,\"A\":2,\"\":3}").equals("{\"\":3,\"A\":2,\"a\":1}"), "the empty key sorts first");

        check(canon("{\"a\":\"x\\\"y\"}").equals("{\"a\":\"x\\\"y\"}"), "quotes stay escaped");
        check(canon("{\"a\":\"x\\ny\"}").equals("{\"a\":\"x\\ny\"}"), "newlines use the short escape");
        check(canon("{\"a\":\"\\u0001\"}").equals("{\"a\":\"\\u0001\"}"), "other control chars use \\u");
        check(canon("{\"a\":\"/\"}").equals("{\"a\":\"/\"}"), "forward slashes are not escaped");
        check(canon("{\"a\":\"ü\"}").equals("{\"a\":\"ü\"}"), "non-ASCII stays literal");
        check(bytes("{\"a\":\"ü\"}").length == "{\"a\":\"ü\"}".getBytes(StandardCharsets.UTF_8).length,
                "output is UTF-8");

        // A fractional number would need ECMAScript double formatting to be reproducible; refuse
        // instead of guessing, since a wrong guess silently changes a revision.
        try {
            canon("{\"a\":1.5}");
            check(false, "a non-integral number is refused");
        } catch (IllegalArgumentException expected) {
            check(true, "a non-integral number is refused");
        }

        check(isDigest("sha256:" + "0".repeat(64)), "a well-formed digest is recognized");
        check(!isDigest("sha256:" + "0".repeat(63)), "a short digest is rejected");
        check(!isDigest("sha256:" + "A".repeat(64)), "uppercase hex is rejected");
        check(!isDigest(null) && !isDigest("nope"), "junk is rejected");

        // ADR-0001 section 8.1 golden vector: the empty-rules default document.
        var golden = "{\"advanced\":{\"burpProxyAddress\":\"127.0.0.1:8080\","
                + "\"interceptProxyAddress\":\"127.0.0.1:8886\",\"useInterceptedFingerprint\":false},"
                + "\"defaults\":{\"externalProxyUrl\":\"\",\"fingerprint\":\"default\",\"hexClientHello\":\"\","
                + "\"httpTimeout\":30,\"spoofProxyAddress\":\"127.0.0.1:8887\"},\"rules\":[],\"schemaVersion\":1}";
        check(canon(golden).equals(golden), "the golden document is already canonical");
        check(digest(JsonParser.parseString(golden))
                        .equals("sha256:3e3e681a6422f5cd90d4c3d6bb226e4ba6713a19efb43f5a9706b0eb8046f2b3"),
                "the golden revision vector matches");

        // Shuffling the same content must not move the digest.
        var shuffled = "{\"schemaVersion\":1,\"rules\":[],\"defaults\":{\"spoofProxyAddress\":\"127.0.0.1:8887\","
                + "\"httpTimeout\":30,\"hexClientHello\":\"\",\"fingerprint\":\"default\",\"externalProxyUrl\":\"\"},"
                + "\"advanced\":{\"useInterceptedFingerprint\":false,\"interceptProxyAddress\":\"127.0.0.1:8886\","
                + "\"burpProxyAddress\":\"127.0.0.1:8080\"}}";
        check(digest(JsonParser.parseString(shuffled)).equals(digest(JsonParser.parseString(golden))),
                "reordering the source does not change the revision");

        check(digestOfBytes(new byte[0])
                        .equals("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
                "the empty-input digest matches the published SHA-256");

        var nulls = new JsonObject();
        nulls.add("a", JsonNull.INSTANCE);
        check(string(nulls).equals("{\"a\":null}"), "an explicit null is written, not dropped");
        check(string(new JsonArray()).equals("[]"), "an empty array is written");

        System.out.println("Jcs self-check passed");
    }

    private static String canon(String json) {
        return string(JsonParser.parseString(json));
    }

    private static byte[] bytes(String json) {
        return bytes(JsonParser.parseString(json));
    }

    private static void check(boolean condition, String what) {
        if (!condition) throw new AssertionError("failed: " + what);
    }
}
