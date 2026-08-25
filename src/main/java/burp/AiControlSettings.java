package burp;

import burp.api.montoya.persistence.Preferences;

/**
 * AI Control's own settings, which are deliberately not part of the settings an AI can see.
 * <p>
 * ADR-0001 section 3 keeps this control plane separate: the port and the audit switch are stored,
 * the enabled state is not, and none of them contributes to the settings revision. That last part
 * matters — if switching the listener on changed the revision, every proposal waiting for review
 * would be invalidated by the act of turning on the thing that submitted it.
 * <p>
 * The enabled state is deliberately not persisted. An endpoint that returns full credentials to any
 * local process should not come back by itself after a restart; the user turns it on each session,
 * having seen the warning each time.
 */
final class AiControlSettings {
    private static final String PORT_KEY = "AiControlPort";
    private static final String AUDIT_KEY = "AiControlFullAudit";

    private final Preferences storage;

    private volatile int port;
    private volatile boolean fullAudit;

    /** Not stored anywhere: every Burp session starts with the endpoint closed. */
    private volatile boolean enabled;

    AiControlSettings(Preferences storage) {
        this.storage = storage;

        var storedPort = storage.getInteger(PORT_KEY);
        this.port = storedPort == null || storedPort < 1 || storedPort > 65535
                ? burp.control.McpServer.DEFAULT_PORT
                : storedPort;

        var storedAudit = storage.getBoolean(AUDIT_KEY);
        this.fullAudit = storedAudit != null && storedAudit;
    }

    int port() {
        return port;
    }

    /**
     * The port may only change while the listener is down; the caller enforces that, because the
     * UI has to disable the field rather than silently reject an edit.
     */
    void setPort(int value) {
        this.port = value;
        storage.setInteger(PORT_KEY, value);
    }

    boolean fullAudit() {
        return fullAudit;
    }

    void setFullAudit(boolean value) {
        this.fullAudit = value;
        storage.setBoolean(AUDIT_KEY, value);
    }

    boolean enabled() {
        return enabled;
    }

    void setEnabled(boolean value) {
        this.enabled = value;
    }
}
