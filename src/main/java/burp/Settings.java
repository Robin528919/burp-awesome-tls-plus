package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.control.AiSettingsService;
import burp.control.AuditTrail;
import burp.control.BusinessSettings;
import burp.control.McpServer;
import burp.control.Ports;
import burp.control.RuntimeStatus;
import burp.control.SettingsControl;
import burp.control.SettingsSnapshot;
import burp.control.TransactionJournal;
import com.google.gson.Gson;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Clock;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Composition root for the settings, and the face the Swing UI talks to.
 * <p>
 * Every read and write now goes through {@link SettingsControl}: ADR-0001 section 3 makes that the
 * single seam so that the UI, the MCP adapter and the request path cannot end up with three
 * slightly different ideas of what is valid, what the current values are, and when a change takes
 * effect. This class holds no state of its own beyond the wiring.
 * <p>
 * {@link #toTransportConfig(String)} runs on every proxied request, so it does exactly one volatile
 * read and no I/O.
 */
public class Settings {
    private final Logging logging;
    private final RuleStore ruleStore;
    private final BurpPreferencesPort preferences;
    private final AiControlSettings aiControl;
    private final SettingsControl control;
    private final AuditTrail audit;
    private final AiSettingsService aiService;
    private final McpServer mcpServer;

    /** Where the UI reports whether it is holding an edit that has not been committed. */
    private volatile Supplier<List<String>> dirtyReporter = List::of;

    public Settings(MontoyaApi api) {
        this.logging = api.logging();
        this.preferences = new BurpPreferencesPort(api.persistence().preferences());
        this.aiControl = new AiControlSettings(api.persistence().preferences());

        var configDir = RuleStore.configDir();
        this.ruleStore = new RuleStore(configDir.resolve(RuleStore.FILE_NAME), logging::logToError);
        this.audit = new AuditTrail(configDir.resolve("audit"));

        Ports.Log log = new Ports.Log() {
            @Override
            public void info(String message) {
                logging.logToOutput("Awesome TLS: " + message);
            }

            @Override
            public void error(String message) {
                logging.logToError("Awesome TLS: " + message);
            }
        };

        this.control = new SettingsControl(
                preferences,
                new RuleFileAdapter(ruleStore),
                new TransactionJournal(configDir.resolve(TransactionJournal.FILE_NAME)),
                audit,
                aiControl::fullAudit,
                this::runtimeStatus,
                this::fingerprintSet,
                () -> dirtyReporter.get(),
                log);

        this.aiService = new AiSettingsService(control, audit, aiControl::fullAudit,
                aiControl::enabled, Clock.systemUTC());
        control.addListener(aiService::onCommitted);

        this.mcpServer = new McpServer(aiService, audit, aiControl::fullAudit, log,
                api.extension().filename() == null ? "unknown" : "1");

        // Recovery first, then the pre-rename adoption, then the old preference key. The order is
        // fixed by ADR-0001 section 11: a migration that ran first could overwrite the very state
        // recovery is about to restore.
        var outcome = control.start(RuleStore.legacyConfigDir(), legacyRules());
        if (outcome instanceof SettingsControl.Outcome.RecoveryRequired recovery) {
            logging.logToError("Awesome TLS: settings are not usable until this is resolved — "
                    + recovery.message());
        }
    }

    /**
     * Rules from before the rules file existed. Deliberately left in the preference store after
     * migration so downgrading still finds them.
     */
    private List<FingerprintRule> legacyRules() {
        var json = preferences.legacyRulesJson();
        if (json == null || json.isBlank()) {
            return List.of();
        }
        try {
            List<FingerprintRule> parsed = new Gson().fromJson(json,
                    new com.google.gson.reflect.TypeToken<List<FingerprintRule>>() {
                    }.getType());
            if (parsed == null) {
                return List.of();
            }
            var rules = new java.util.ArrayList<FingerprintRule>();
            for (var rule : parsed) {
                if (rule != null) {
                    rules.add(rule.normalized());
                }
            }
            return List.copyOf(rules);
        } catch (Exception e) {
            logging.logToError("Awesome TLS: could not read the rules stored under the old "
                    + "preference key, ignoring them: " + e);
            return List.of();
        }
    }

    // ------------------------------------------------------------------ wiring

    public SettingsControl control() {
        return control;
    }

    public AiSettingsService aiService() {
        return aiService;
    }

    public McpServer mcpServer() {
        return mcpServer;
    }

    AiControlSettings aiControl() {
        return aiControl;
    }

    AuditTrail audit() {
        return audit;
    }

    /**
     * Lets the settings tab say whether it is holding an unsaved edit. A proposal cannot be created
     * or applied while it is, because either would fight with the editor for the same fields.
     */
    void setDirtyReporter(Supplier<List<String>> reporter) {
        this.dirtyReporter = reporter == null ? List::of : reporter;
    }

    public SettingsSnapshot snapshot() {
        return control.snapshot();
    }

    public RuntimeStatus runtimeStatus() {
        try {
            var json = ServerLibrary.INSTANCE.GetRuntimeStatus();
            if (json == null || json.isBlank()) {
                return RuntimeStatus.unknown();
            }
            var root = JsonParser.parseString(json).getAsJsonObject();
            return new RuntimeStatus(
                    listener(root, "spoof"),
                    listener(root, "intercept"),
                    emptyToNull(string(root, "burpUpstreamEndpoint")),
                    emptyToNull(string(root, "burpUpstreamError")));
        } catch (Throwable e) {
            // The native library may not be loaded at all. Reporting nothing is honest; guessing
            // that the configured address is live is what section 12 forbids.
            return RuntimeStatus.unknown();
        }
    }

    private static RuntimeStatus.Listener listener(com.google.gson.JsonObject root, String name) {
        if (!root.has(name) || !root.get(name).isJsonObject()) {
            return RuntimeStatus.Listener.stopped();
        }
        var object = root.getAsJsonObject(name);
        var state = string(object, "state");
        RuntimeStatus.State parsed;
        try {
            parsed = RuntimeStatus.State.valueOf(state);
        } catch (IllegalArgumentException e) {
            parsed = RuntimeStatus.State.STOPPED;
        }
        return new RuntimeStatus.Listener(parsed,
                emptyToNull(string(object, "actualAddress")),
                emptyToNull(string(object, "lastError")));
    }

    private static String string(com.google.gson.JsonObject object, String key) {
        return object.has(key) && object.get(key).isJsonPrimitive() ? object.get(key).getAsString() : "";
    }

    private static String emptyToNull(String value) {
        return value == null || value.isEmpty() ? null : value;
    }

    // ------------------------------------------------------------------ reading

    public String getSpoofProxyAddress() {
        return snapshot().settings().spoofProxyAddress();
    }

    /**
     * @return where the Go server is really listening, which is not the same thing as the
     * configured address once that has been changed. Requests must keep going to the live one until
     * the extension is reloaded, or they go to a port nothing is bound to.
     */
    public String activeSpoofProxyAddress() {
        var spoof = runtimeStatus().spoof();
        if (spoof != null && spoof.running() && spoof.actualAddress() != null) {
            return spoof.actualAddress();
        }
        return getSpoofProxyAddress();
    }

    public String getInterceptProxyAddress() {
        return snapshot().settings().interceptProxyAddress();
    }

    public String getBurpProxyAddress() {
        return snapshot().settings().burpProxyAddress();
    }

    public Boolean getUseInterceptedFingerprint() {
        return snapshot().settings().useInterceptedFingerprint();
    }

    public int getHttpTimeout() {
        return snapshot().settings().httpTimeout();
    }

    public String getFingerprint() {
        return snapshot().settings().fingerprint();
    }

    public String getHexClientHello() {
        return snapshot().settings().hexClientHello();
    }

    public String getExternalProxyUrl() {
        return snapshot().settings().externalProxyUrl();
    }

    /**
     * @return the configured per-domain rules, in storage order, including rows that are not usable
     * yet. The table shows all of them; the matcher uses only the usable ones.
     */
    public List<FingerprintRule> getRules() {
        return snapshot().storedRules();
    }

    public RuleStore getRuleStore() {
        return ruleStore;
    }

    public String[] getFingerprints() {
        try {
            return ServerLibrary.INSTANCE.GetFingerprints().split("\n");
        } catch (Throwable e) {
            logging.logToError("Awesome TLS: could not read the fingerprint list: " + e);
            return new String[0];
        }
    }

    public Set<String> fingerprintSet() {
        return Set.of(getFingerprints());
    }

    // ------------------------------------------------------------------ writing

    /**
     * Saves the global settings as one change. Every field goes together: an earlier version wrote
     * them one at a time, which meant a failure halfway left half the form applied.
     */
    public SettingsControl.Outcome saveGlobals(BusinessSettings settings) {
        return control.commit(snapshot().withSettings(settings), TransactionJournal.Source.UI_SAVE);
    }

    public SettingsControl.Outcome saveRules(List<FingerprintRule> rules,
                                             TransactionJournal.Source source) {
        return control.commit(snapshot().withRules(rules), source);
    }

    /**
     * Saves the global settings and the rules together, so one Save leaves nothing pending.
     */
    public SettingsControl.Outcome saveAll(BusinessSettings settings, List<FingerprintRule> rules) {
        return control.commit(SettingsSnapshot.of(settings, rules), TransactionJournal.Source.UI_SAVE);
    }

    // ------------------------------------------------------------------ request path

    /**
     * Builds the per-request configuration sent to the Go server, applying the most specific
     * domain rule for {@code host} on top of the global defaults.
     */
    public TransportConfig toTransportConfig(String host) {
        // One volatile read: the settings and the matcher were published together, so they cannot
        // disagree with each other however the change was made.
        var snapshot = control.snapshot();
        var settings = snapshot.settings();

        var transportConfig = new TransportConfig();
        transportConfig.Fingerprint = settings.fingerprint();
        transportConfig.HexClientHello = settings.hexClientHello();
        transportConfig.HttpTimeout = settings.httpTimeout();
        transportConfig.ExternalProxyUrl = settings.externalProxyUrl();

        // These stay global on purpose: the Go server starts and stops a single shared
        // intercept proxy based on these values, so varying them per request would make it
        // thrash (see server.go).
        transportConfig.UseInterceptedFingerprint = settings.useInterceptedFingerprint();
        transportConfig.BurpAddr = settings.burpProxyAddress();
        transportConfig.InterceptProxyAddr = settings.interceptProxyAddress();

        var rule = snapshot.matcher().match(host);
        if (rule != null) {
            rule.applyTo(transportConfig);
        }

        return transportConfig;
    }

    /**
     * The rules file, with the adoption step exposed so startup can order it after recovery.
     */
    private record RuleFileAdapter(RuleStore store) implements SettingsControl.RuleFileAdapter {
        @Override
        public RuleStore.Probe probe() {
            return store.probe();
        }

        @Override
        public void saveIfUnchanged(String expectedDigest, List<FingerprintRule> rules) throws IOException {
            store.saveIfUnchanged(expectedDigest, rules);
        }

        @Override
        public Path path() {
            return store.path();
        }

        @Override
        public boolean adoptFrom(Path legacyDir) {
            return store.adoptFrom(legacyDir);
        }
    }
}
