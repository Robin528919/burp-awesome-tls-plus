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
    private static final String RISK_ACK_KEY = "AiControlRiskAcknowledged";
    private static final String AUTO_APPLY_KEY = "AiControlAutoApply";

    private final Preferences storage;

    private volatile int port;
    private volatile boolean fullAudit;

    /**
     * Whether the user has accepted that any local process can read these values.
     * <p>
     * Persisted, unlike {@link #enabled}. The risk is a property of the endpoint, not of today's
     * session, and it does not change between restarts — so re-collecting the same tick is friction
     * that buys nothing. The warning itself is still on screen every time the listener is down,
     * which is what ADR-0001 section 5 is actually protecting: the user seeing the fact, not the
     * clicking. Enabling stays a deliberate per-session action.
     */
    private volatile boolean riskAcknowledged;

    /**
     * Not stored anywhere: every Burp session starts with the endpoint closed.
     * <p>
     * This is the one that must not survive a restart. An unauthenticated endpoint returning full
     * credentials to any local process should never come back by itself; everything else here only
     * decides how it behaves once the user has deliberately opened it.
     */
    private volatile boolean enabled;

    /**
     * Whether a proposal is applied the moment it arrives, with no review.
     * <p>
     * Persisted (ADR-0001 section 24). It still cannot act on its own: the listener is closed on
     * every start and only the user can open it, so a stored arming decides what happens after
     * that deliberate act, not whether it happens. The confirmation is asked when the user arms
     * it, not when a stored arming is restored.
     */
    private volatile boolean autoApply;

    AiControlSettings(Preferences storage) {
        this.storage = storage;

        var storedPort = storage.getInteger(PORT_KEY);
        this.port = storedPort == null || storedPort < 1 || storedPort > 65535
                ? burp.control.McpServer.DEFAULT_PORT
                : storedPort;

        var storedAudit = storage.getBoolean(AUDIT_KEY);
        this.fullAudit = storedAudit != null && storedAudit;

        var storedAck = storage.getBoolean(RISK_ACK_KEY);
        this.riskAcknowledged = storedAck != null && storedAck;

        var storedAutoApply = storage.getBoolean(AUTO_APPLY_KEY);
        this.autoApply = storedAutoApply != null && storedAutoApply;
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

    boolean riskAcknowledged() {
        return riskAcknowledged;
    }

    void setRiskAcknowledged(boolean value) {
        this.riskAcknowledged = value;
        storage.setBoolean(RISK_ACK_KEY, value);
    }

    boolean enabled() {
        return enabled;
    }

    void setEnabled(boolean value) {
        this.enabled = value;
    }

    boolean autoApply() {
        return autoApply;
    }

    void setAutoApply(boolean value) {
        this.autoApply = value;
        storage.setBoolean(AUTO_APPLY_KEY, value);
    }
}
