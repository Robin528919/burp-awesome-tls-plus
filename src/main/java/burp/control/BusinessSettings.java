package burp.control;

import com.google.gson.JsonObject;

import java.util.Locale;
import java.util.Objects;

/**
 * The global scalar settings, as an immutable value.
 * <p>
 * ADR-0001 separates these "business" settings from AI Control's own port, enable state and audit
 * toggle: only what is in here contributes to the settings revision, so turning the MCP listener
 * on does not invalidate a proposal that is waiting for review.
 *
 * @param spoofProxyAddress       where the Go server listens, {@code host:port}.
 * @param interceptProxyAddress   where the optional fingerprint-sniffing proxy listens.
 * @param burpProxyAddress        the Burp proxy the Go side forwards intercepted traffic to.
 * @param fingerprint             named TLS profile.
 * @param hexClientHello          raw ClientHello hex, which outranks {@code fingerprint} when set.
 * @param useInterceptedFingerprint whether to prefer a captured ClientHello. Global by design; the
 *                                Go server starts and stops one shared proxy from this flag.
 * @param httpTimeout             response timeout in seconds, 1..3600.
 * @param externalProxyUrl        upstream proxy URL, or empty for a direct connection.
 */
public record BusinessSettings(
        String spoofProxyAddress,
        String interceptProxyAddress,
        String burpProxyAddress,
        String fingerprint,
        String hexClientHello,
        boolean useInterceptedFingerprint,
        int httpTimeout,
        String externalProxyUrl) {

    public static final String DEFAULT_SPOOF_PROXY_ADDRESS = "127.0.0.1:8887";
    public static final String DEFAULT_INTERCEPT_PROXY_ADDRESS = "127.0.0.1:8886";
    public static final String DEFAULT_BURP_PROXY_ADDRESS = "127.0.0.1:8080";
    public static final String DEFAULT_FINGERPRINT = "default";
    public static final int DEFAULT_HTTP_TIMEOUT = 30;

    public static final int MIN_HTTP_TIMEOUT = 1;
    public static final int MAX_HTTP_TIMEOUT = 3600;

    public static BusinessSettings defaults() {
        return new BusinessSettings(
                DEFAULT_SPOOF_PROXY_ADDRESS,
                DEFAULT_INTERCEPT_PROXY_ADDRESS,
                DEFAULT_BURP_PROXY_ADDRESS,
                DEFAULT_FINGERPRINT,
                "",
                false,
                DEFAULT_HTTP_TIMEOUT,
                "");
    }

    /**
     * Field normalization, applied identically wherever settings are compared, hashed or stored.
     * <p>
     * Deliberately conservative: hex is lowercased because its case carries no meaning, but the
     * fingerprint name and proxy URL are only trimmed. Rewriting a URL on a guess would change a
     * value the user typed, and the Go dialer, not this code, decides what a URL means.
     */
    public BusinessSettings normalized() {
        return new BusinessSettings(
                trim(spoofProxyAddress),
                trim(interceptProxyAddress),
                trim(burpProxyAddress),
                trim(fingerprint),
                trim(hexClientHello).toLowerCase(Locale.ROOT),
                useInterceptedFingerprint,
                httpTimeout,
                trim(externalProxyUrl));
    }

    /**
     * @return the {@code defaults} and {@code advanced} halves of the canonical document,
     * merged into {@code root}. See ADR-0001 section 8.1.
     */
    void writeCanonical(JsonObject root) {
        var normalized = normalized();

        var defaults = new JsonObject();
        defaults.addProperty("externalProxyUrl", normalized.externalProxyUrl());
        defaults.addProperty("fingerprint", normalized.fingerprint());
        defaults.addProperty("hexClientHello", normalized.hexClientHello());
        defaults.addProperty("httpTimeout", normalized.httpTimeout());
        defaults.addProperty("spoofProxyAddress", normalized.spoofProxyAddress());

        var advanced = new JsonObject();
        advanced.addProperty("burpProxyAddress", normalized.burpProxyAddress());
        advanced.addProperty("interceptProxyAddress", normalized.interceptProxyAddress());
        advanced.addProperty("useInterceptedFingerprint", normalized.useInterceptedFingerprint());

        root.add("defaults", defaults);
        root.add("advanced", advanced);
    }

    /**
     * @return {@code sha256:<hex>} over just the scalar half of the canonical document.
     * <p>
     * Burp's {@link burp.api.montoya.persistence.Preferences} has no multi-key compare-and-swap
     * and its setters return {@code void}, so this digest is the only way to check afterwards that
     * a write landed as intended. See ADR-0001 section 10.
     */
    public String canonicalDigest() {
        var root = new JsonObject();
        writeCanonical(root);
        return Jcs.digest(root);
    }

    public BusinessSettings withSpoofProxyAddress(String value) {
        return new BusinessSettings(value, interceptProxyAddress, burpProxyAddress, fingerprint,
                hexClientHello, useInterceptedFingerprint, httpTimeout, externalProxyUrl);
    }

    public BusinessSettings withInterceptProxyAddress(String value) {
        return new BusinessSettings(spoofProxyAddress, value, burpProxyAddress, fingerprint,
                hexClientHello, useInterceptedFingerprint, httpTimeout, externalProxyUrl);
    }

    public BusinessSettings withBurpProxyAddress(String value) {
        return new BusinessSettings(spoofProxyAddress, interceptProxyAddress, value, fingerprint,
                hexClientHello, useInterceptedFingerprint, httpTimeout, externalProxyUrl);
    }

    public BusinessSettings withFingerprint(String value) {
        return new BusinessSettings(spoofProxyAddress, interceptProxyAddress, burpProxyAddress, value,
                hexClientHello, useInterceptedFingerprint, httpTimeout, externalProxyUrl);
    }

    public BusinessSettings withHexClientHello(String value) {
        return new BusinessSettings(spoofProxyAddress, interceptProxyAddress, burpProxyAddress, fingerprint,
                value, useInterceptedFingerprint, httpTimeout, externalProxyUrl);
    }

    public BusinessSettings withUseInterceptedFingerprint(boolean value) {
        return new BusinessSettings(spoofProxyAddress, interceptProxyAddress, burpProxyAddress, fingerprint,
                hexClientHello, value, httpTimeout, externalProxyUrl);
    }

    public BusinessSettings withHttpTimeout(int value) {
        return new BusinessSettings(spoofProxyAddress, interceptProxyAddress, burpProxyAddress, fingerprint,
                hexClientHello, useInterceptedFingerprint, value, externalProxyUrl);
    }

    public BusinessSettings withExternalProxyUrl(String value) {
        return new BusinessSettings(spoofProxyAddress, interceptProxyAddress, burpProxyAddress, fingerprint,
                hexClientHello, useInterceptedFingerprint, httpTimeout, value);
    }

    /**
     * @return the value at an output path such as {@code /settings/fingerprint}, or null.
     */
    public Object get(String field) {
        return switch (field) {
            case "spoofProxyAddress" -> spoofProxyAddress;
            case "interceptProxyAddress" -> interceptProxyAddress;
            case "burpProxyAddress" -> burpProxyAddress;
            case "fingerprint" -> fingerprint;
            case "hexClientHello" -> hexClientHello;
            case "useInterceptedFingerprint" -> useInterceptedFingerprint;
            case "httpTimeout" -> httpTimeout;
            case "externalProxyUrl" -> externalProxyUrl;
            default -> null;
        };
    }

    /**
     * Every settable field, in the order the UI and diffs present them.
     */
    public static final java.util.List<String> FIELDS = java.util.List.of(
            "spoofProxyAddress", "interceptProxyAddress", "burpProxyAddress", "fingerprint",
            "hexClientHello", "useInterceptedFingerprint", "httpTimeout", "externalProxyUrl");

    private static String trim(String value) {
        return value == null ? "" : value.trim();
    }

    /**
     * Records compare by component, but only after normalization is a comparison meaningful.
     */
    public boolean sameAs(BusinessSettings other) {
        return other != null && Objects.equals(normalized(), other.normalized());
    }
}
