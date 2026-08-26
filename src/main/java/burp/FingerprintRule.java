package burp;

/**
 * A per-domain override of the global transport settings.
 * <p>
 * Any field left null or empty inherits the corresponding global default, so a rule can
 * override just the fingerprint while still using the global proxy and timeout.
 * <p>
 * Unlike {@link TransportConfig}, this type never crosses the JNA boundary: it is only
 * serialized to JSON for Burp's preference store, so it uses normal Java naming.
 */
public class FingerprintRule {
    /**
     * Exact hostname ({@code example.com}) or wildcard suffix ({@code *.example.com}).
     * Matching is case-insensitive and ignores the port.
     */
    public String hostPattern = "";

    /**
     * Named TLS profile, or empty to inherit the global fingerprint.
     */
    public String fingerprint = "";

    /**
     * Raw ClientHello as a hex stream, or empty to inherit.
     * Takes precedence over {@link #fingerprint}, mirroring the Go side's ordering.
     */
    public String hexClientHello = "";

    /**
     * Upstream proxy URL, or empty to inherit.
     */
    public String externalProxyUrl = "";

    /**
     * Connection timeout in seconds, or null to inherit.
     */
    public Integer httpTimeout;

    /**
     * Disabled rules stay in the table but never match.
     */
    public boolean enabled = true;

    /**
     * Free-text note for whoever has to read this row later: where the capture came from, which
     * app version, why this host needs its own rule.
     * <p>
     * Never reaches the Go side and never affects matching. It is still part of the canonical
     * document and therefore of the settings revision, because it lives in the same file the
     * three-way merge works on — a note that did not change the revision would be silently
     * dropped by the next merge.
     */
    public String note = "";

    public FingerprintRule() {
    }

    public FingerprintRule(String hostPattern, String fingerprint, String hexClientHello, String externalProxyUrl, Integer httpTimeout, boolean enabled) {
        this(hostPattern, fingerprint, hexClientHello, externalProxyUrl, httpTimeout, enabled, "");
    }

    public FingerprintRule(String hostPattern, String fingerprint, String hexClientHello, String externalProxyUrl, Integer httpTimeout, boolean enabled, String note) {
        this.hostPattern = hostPattern;
        this.fingerprint = fingerprint;
        this.hexClientHello = hexClientHello;
        this.externalProxyUrl = externalProxyUrl;
        this.httpTimeout = httpTimeout;
        this.enabled = enabled;
        this.note = note;
    }

    /**
     * Applies this rule's non-empty fields on top of an already populated {@code config}.
     * <p>
     * Must be called on a {@link #normalized()} instance, which {@link RuleMatcher} guarantees
     * for anything it returns.
     */
    void applyTo(TransportConfig config) {
        // The Go side always prefers HexClientHello over Fingerprint, so the two have to be
        // overridden as a pair. Otherwise a rule that only sets Fingerprint would be silently
        // ignored whenever a global hex ClientHello is configured.
        if (!hexClientHello.isEmpty()) {
            config.HexClientHello = hexClientHello;
            config.Fingerprint = "";
        } else if (!fingerprint.isEmpty()) {
            config.Fingerprint = fingerprint;
            config.HexClientHello = "";
        }

        if (!externalProxyUrl.isEmpty()) {
            config.ExternalProxyUrl = externalProxyUrl;
        }

        if (httpTimeout != null && httpTimeout > 0) {
            config.HttpTimeout = httpTimeout;
        }
    }

    /**
     * Gson populates fields directly and bypasses the constructor, so string fields may be
     * null when loading JSON written by an older version. Normalize instead of null-checking
     * at every use site.
     */
    public FingerprintRule normalized() {
        return new FingerprintRule(
                orEmpty(hostPattern).trim(),
                orEmpty(fingerprint).trim(),
                orEmpty(hexClientHello).trim(),
                orEmpty(externalProxyUrl).trim(),
                httpTimeout,
                enabled,
                orEmpty(note).trim()
        );
    }

    /**
     * Like {@link #normalized()} but without the trim, so the stored spelling survives verbatim.
     * <p>
     * Rows the matcher rejects are kept on disk untouched and hashed as-is, so that editing one
     * still changes the settings revision. Trimming here would make {@code " a.com "} and
     * {@code "a.com"} hash alike, and a user who fixed the whitespace would be told nothing had
     * changed. Only the null-to-empty materialization Gson forces on us is applied.
     */
    public FingerprintRule materialized() {
        return new FingerprintRule(
                orEmpty(hostPattern),
                orEmpty(fingerprint),
                orEmpty(hexClientHello),
                orEmpty(externalProxyUrl),
                httpTimeout,
                enabled,
                orEmpty(note)
        );
    }

    /**
     * @return the value of one known field, for diffing and canonicalization.
     */
    public Object get(String field) {
        return switch (field) {
            case "hostPattern" -> hostPattern;
            case "fingerprint" -> fingerprint;
            case "hexClientHello" -> hexClientHello;
            case "externalProxyUrl" -> externalProxyUrl;
            case "httpTimeout" -> httpTimeout;
            case "enabled" -> enabled;
            case "note" -> note;
            default -> null;
        };
    }

    /**
     * Every known field, in the order the canonical document and the diff present them.
     */
    public static final java.util.List<String> FIELDS = java.util.List.of(
            "hostPattern", "enabled", "fingerprint", "hexClientHello", "externalProxyUrl", "httpTimeout",
            "note");

    private static String orEmpty(String s) {
        return s == null ? "" : s;
    }
}
