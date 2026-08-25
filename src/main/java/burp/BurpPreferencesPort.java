package burp;

import burp.api.montoya.persistence.Preferences;
import burp.control.BusinessSettings;
import burp.control.Ports;

/**
 * The scalar settings, on top of Burp's preference store.
 * <p>
 * The store offers String, Boolean and Integer and nothing else — no transaction, no flush, and
 * setters that return {@code void}. So {@link #write} can only report that no setter threw;
 * {@link burp.control.SettingsControl} re-reads and compares digests to get any confirmation at
 * all, and ADR-0001 section 10 is explicit that even that does not prove the values reached disk.
 */
final class BurpPreferencesPort implements Ports.PreferencesPort {
    private static final String SPOOF_PROXY_ADDRESS = "SpoofProxyAddress";
    private static final String INTERCEPT_PROXY_ADDRESS = "InterceptProxyAddress";
    private static final String BURP_PROXY_ADDRESS = "BurpProxyAddress";
    private static final String FINGERPRINT = "Fingerprint";
    private static final String HEX_CLIENT_HELLO = "HexClientHello";
    private static final String USE_INTERCEPTED_FINGERPRINT = "UseInterceptedFingerprint";
    private static final String HTTP_TIMEOUT = "HttpTimeout";
    private static final String EXTERNAL_PROXY_URL = "ExternalProxyUrl";

    private final Preferences storage;

    BurpPreferencesPort(Preferences storage) {
        this.storage = storage;
    }

    @Override
    public BusinessSettings read() {
        var defaults = BusinessSettings.defaults();
        return new BusinessSettings(
                string(SPOOF_PROXY_ADDRESS, defaults.spoofProxyAddress()),
                string(INTERCEPT_PROXY_ADDRESS, defaults.interceptProxyAddress()),
                string(BURP_PROXY_ADDRESS, defaults.burpProxyAddress()),
                string(FINGERPRINT, defaults.fingerprint()),
                string(HEX_CLIENT_HELLO, ""),
                bool(USE_INTERCEPTED_FINGERPRINT, defaults.useInterceptedFingerprint()),
                integer(HTTP_TIMEOUT, defaults.httpTimeout()),
                string(EXTERNAL_PROXY_URL, ""));
    }

    @Override
    public void write(BusinessSettings settings) {
        var value = settings.normalized();
        storage.setString(SPOOF_PROXY_ADDRESS, value.spoofProxyAddress());
        storage.setString(INTERCEPT_PROXY_ADDRESS, value.interceptProxyAddress());
        storage.setString(BURP_PROXY_ADDRESS, value.burpProxyAddress());
        storage.setString(FINGERPRINT, value.fingerprint());
        storage.setString(HEX_CLIENT_HELLO, value.hexClientHello());
        storage.setBoolean(USE_INTERCEPTED_FINGERPRINT, value.useInterceptedFingerprint());
        storage.setInteger(HTTP_TIMEOUT, value.httpTimeout());
        storage.setString(EXTERNAL_PROXY_URL, value.externalProxyUrl());
    }

    /**
     * Rules from before the rules file existed. Read once at startup and, per ADR-0001 section 11,
     * never deleted afterwards, so downgrading to an older build still finds them.
     */
    String legacyRulesJson() {
        return storage.getString("DomainRules");
    }

    private String string(String key, String fallback) {
        var value = storage.getString(key);
        // An empty stored string is indistinguishable from "never set" here, and every one of
        // these has a meaningful empty value only where the default is itself empty.
        return value == null || (value.isEmpty() && !fallback.isEmpty()) ? fallback : value;
    }

    private boolean bool(String key, boolean fallback) {
        var value = storage.getBoolean(key);
        return value == null ? fallback : value;
    }

    private int integer(String key, int fallback) {
        var value = storage.getInteger(key);
        return value == null ? fallback : value;
    }
}
