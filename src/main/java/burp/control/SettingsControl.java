package burp.control;

import burp.FingerprintRule;
import burp.RuleStore;
import com.google.gson.JsonObject;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * The one place settings are read from and written to.
 * <p>
 * Everything else — the Swing tab, the MCP adapter, the request path — goes through here, which is
 * what stops validation, revisioning and caching from forking into near-copies that disagree.
 * <p>
 * Two properties carry the design:
 * <ul>
 * <li><b>Publication is atomic.</b> The committed snapshot and its matcher live in a single
 * reference, replaced in one write, so a request thread sees a whole old configuration or a whole
 * new one and never a mixture.</li>
 * <li><b>There is exactly one commit decision.</b> Settings span two stores that cannot be written
 * together, so {@link #commit} stages both, verifies both, then makes a single durable decision.
 * Before it, any failure rolls back. After it, no failure rolls back — a change the user approved
 * is not undone because a phase marker or a UI refresh failed afterwards.</li>
 * </ul>
 * What is not claimed: that this is ACID. Burp's preference store offers no flush, no
 * acknowledgement and no multi-key compare-and-swap, and an ordinary filesystem offers no
 * compare-and-swap against an uncooperative editor. Writes are verified by reading back and
 * comparing digests, which detects an unwritten value but cannot prove one reached the platter.
 */
public final class SettingsControl {
    private final Ports.PreferencesPort preferences;
    private final Ports.RuleFilePort ruleFile;
    private final TransactionJournal journal;
    private final AuditTrail audit;
    private final BooleanSupplier auditEnabled;
    private final Ports.RuntimeStatePort runtime;
    private final Ports.FingerprintCatalog catalog;
    private final Ports.UiDirtyPort ui;
    private final Ports.Log log;

    /**
     * Snapshot and matcher, published together. Read on every proxied request.
     */
    private final AtomicReference<SettingsSnapshot> committed = new AtomicReference<>(SettingsSnapshot.empty());

    /**
     * Set when the stores are in a state this code will not write over. Everything that mutates
     * settings refuses while it is non-null, because the alternative is overwriting whatever the
     * user still needs in order to work out what happened.
     */
    private final AtomicReference<String> blocked = new AtomicReference<>();

    /**
     * The digest of {@code rules.json} as last observed. Used to guard the next write.
     */
    private final AtomicReference<String> rulesFileDigest = new AtomicReference<>();

    /** Serializes every mutation. Settings changes are rare; correctness is not. */
    private final Object writeLock = new Object();

    private final List<Consumer<SettingsSnapshot>> listeners = new CopyOnWriteArrayList<>();

    public SettingsControl(Ports.PreferencesPort preferences, Ports.RuleFilePort ruleFile,
                           TransactionJournal journal, AuditTrail audit, BooleanSupplier auditEnabled,
                           Ports.RuntimeStatePort runtime, Ports.FingerprintCatalog catalog,
                           Ports.UiDirtyPort ui, Ports.Log log) {
        this.preferences = preferences;
        this.ruleFile = ruleFile;
        this.journal = journal;
        this.audit = audit;
        this.auditEnabled = auditEnabled;
        this.runtime = runtime;
        this.catalog = catalog;
        this.ui = ui;
        this.log = log;
    }

    // ------------------------------------------------------------------ reading

    /**
     * @return the committed settings and their matcher. Safe to call from a request thread.
     */
    public SettingsSnapshot snapshot() {
        return committed.get();
    }

    public RuntimeStatus runtimeStatus() {
        try {
            return runtime.status();
        } catch (RuntimeException e) {
            // The Go library may not be loaded. Reporting nothing is honest; guessing is not.
            return RuntimeStatus.unknown();
        }
    }

    public java.util.Set<String> fingerprints() {
        try {
            return catalog.names();
        } catch (RuntimeException e) {
            return java.util.Set.of();
        }
    }

    public List<String> dirtyReasons() {
        try {
            return ui.dirtyReasons();
        } catch (RuntimeException e) {
            return List.of();
        }
    }

    /**
     * @return why settings cannot currently be changed, or null.
     */
    public String blockedReason() {
        return blocked.get();
    }

    public String rulesFileDigest() {
        return rulesFileDigest.get();
    }

    public java.nio.file.Path rulesFilePath() {
        return ruleFile.path();
    }

    /**
     * @return the rules file as it is on disk right now, without touching it. The only read that
     * inspect, propose and approval may use.
     */
    public RuleStore.Probe probeRuleFile() {
        try {
            return ruleFile.probe();
        } catch (RuntimeException e) {
            return new RuleStore.Probe.Invalid("could not be read: " + e, null);
        }
    }

    public void addListener(Consumer<SettingsSnapshot> listener) {
        listeners.add(listener);
    }

    // ------------------------------------------------------------------ outcomes

    public sealed interface Outcome {
        record Committed(SettingsSnapshot snapshot) implements Outcome {
        }

        /** Nothing changed; the stores hold what they held before. */
        record Failed(Wire.Code code, String message, List<Wire.ErrorDetail> details) implements Outcome {
        }

        /**
         * The stores are in a state that needs a person. Deliberately not a failure: the change may
         * or may not have been committed, and saying either would be a guess.
         */
        record RecoveryRequired(String message) implements Outcome {
        }
    }

    private static Outcome failed(Wire.Code code, String message, List<Wire.ErrorDetail> details) {
        return new Outcome.Failed(code, message, details == null ? List.of() : details);
    }

    // ------------------------------------------------------------------ startup

    /**
     * Establishes the first committed snapshot, after finishing any transaction that was in flight.
     * <p>
     * The order is fixed and load-bearing. Recovery runs before any migration, because a migration
     * that ran first could move the very file recovery is about to restore. Nothing is published,
     * and no listener is started, until this returns cleanly.
     *
     * @param legacyDir            the pre-rename config directory to adopt from, or null.
     * @param legacyPreferenceRules rules found under the old preference key, used only if there is
     *                             still no file afterwards.
     */
    public Outcome start(java.nio.file.Path legacyDir, List<FingerprintRule> legacyPreferenceRules) {
        synchronized (writeLock) {
            try {
                var recovered = recover();
                if (recovered != null) {
                    return recovered;
                }
            } catch (IOException e) {
                return block("Could not read the transaction journal at " + journal.path() + ": " + e);
            }

            // Only now that nothing is half-written may files move.
            var probe = ruleFile.probe();
            if (probe instanceof RuleStore.Probe.Missing && legacyDir != null) {
                try {
                    if (adopt(legacyDir)) {
                        probe = ruleFile.probe();
                    }
                } catch (IOException e) {
                    return block("Could not adopt rules from " + legacyDir + ": " + e);
                }
            }

            if (probe instanceof RuleStore.Probe.Invalid invalid) {
                return block("The rules file at " + ruleFile.path() + " " + invalid.reason()
                        + ". It has been left exactly as it is; repair or replace it in the AI Control tab.");
            }

            List<FingerprintRule> rules;
            if (probe instanceof RuleStore.Probe.Loaded loaded) {
                rules = loaded.rules();
                rulesFileDigest.set(loaded.rawDigest());
            } else {
                rules = List.of();
                rulesFileDigest.set(null);
            }

            var snapshot = SettingsSnapshot.of(preferences.read(), rules);

            // Rules that predate the file live under an old preference key. Migrate once, and
            // deliberately leave the old value in place so downgrading still finds them.
            if (rules.isEmpty() && legacyPreferenceRules != null && !legacyPreferenceRules.isEmpty()
                    && probe instanceof RuleStore.Probe.Missing) {
                var migrated = SettingsSnapshot.of(snapshot.settings(), legacyPreferenceRules);
                var outcome = commit(migrated, TransactionJournal.Source.MIGRATION);
                if (outcome instanceof Outcome.Committed committedOutcome) {
                    log.info("Migrated " + legacyPreferenceRules.size() + " domain rule(s) to "
                            + ruleFile.path());
                    return committedOutcome;
                }
                return outcome;
            }

            publish(snapshot);
            return new Outcome.Committed(snapshot);
        }
    }

    private boolean adopt(java.nio.file.Path legacyDir) throws IOException {
        if (ruleFile instanceof RuleFileAdapter adapter) {
            return adapter.adoptFrom(legacyDir);
        }
        return false;
    }

    /**
     * A {@link Ports.RuleFilePort} that can also perform the pre-rename adoption.
     */
    public interface RuleFileAdapter extends Ports.RuleFilePort {
        boolean adoptFrom(java.nio.file.Path legacyDir) throws IOException;
    }

    // ------------------------------------------------------------------ recovery

    /**
     * Finishes whatever the last run left in flight.
     *
     * @return null when there was nothing to do, otherwise the outcome.
     */
    private Outcome recover() throws IOException {
        var record = journal.read();
        if (record == null) {
            return null;
        }

        log.info("Finishing an interrupted settings change (" + record.transactionId()
                + ", phase " + record.phase() + ")");

        var decision = decisionEvidence(record);
        return switch (decision) {
            case FORWARD -> rollForward(record);
            case ROLLBACK -> rollBack(record);
            case BLOCK -> block("An interrupted settings change (" + record.transactionId()
                    + ", phase " + record.phase() + ") cannot be resolved automatically, because "
                    + "the audit trail cannot confirm whether it was committed. Nothing has been "
                    + "changed. Repair the audit trail or remove " + journal.path() + " by hand "
                    + "after checking which settings are correct.");
        };
    }

    private enum Decision {FORWARD, ROLLBACK, BLOCK}

    /**
     * Decides which way an interrupted transaction goes, using the transaction's own audit setting.
     * <p>
     * The asymmetry is deliberate: a durable committed audit event, or a durable
     * {@code COMMIT_DECIDED} for an unaudited transaction, is proof and rolls forward. Only being
     * able to prove the event is <em>absent</em> rolls back. Not being able to tell blocks, because
     * both other answers would be a guess about a change a user approved.
     */
    private Decision decisionEvidence(TransactionJournal.Record record) {
        if (record.phase() == TransactionJournal.Phase.COMMIT_DECIDED
                || record.phase() == TransactionJournal.Phase.RUNTIME_PUBLISHED
                || record.phase() == TransactionJournal.Phase.COMPLETE) {
            if (!record.auditEnabled()) {
                return Decision.FORWARD;
            }
            return switch (audit.probeCommitted(record.transactionId(), record.auditEventDigest())) {
                case FOUND -> Decision.FORWARD;
                // The journal says decided but the audit event it should have written is provably
                // not there. That combination cannot be produced by the commit path, so it is not
                // safe to roll either way on it.
                case ABSENT, INDETERMINATE -> Decision.BLOCK;
            };
        }

        if (record.phase() == TransactionJournal.Phase.COMMIT_READY) {
            if (!record.auditEnabled()) {
                // Without audit the decision is the journal, and it has not been written.
                return Decision.ROLLBACK;
            }
            return switch (audit.probeCommitted(record.transactionId(), record.auditEventDigest())) {
                case FOUND -> Decision.FORWARD;
                case ABSENT -> Decision.ROLLBACK;
                case INDETERMINATE -> Decision.BLOCK;
            };
        }

        // PREPARED, AUDIT_PREPARED, PREFERENCES_WRITTEN, RULES_WRITTEN: all before any decision.
        return Decision.ROLLBACK;
    }

    private Outcome rollForward(TransactionJournal.Record record) {
        var target = snapshotOf(record.newDocument());
        var outcome = reconcile(record, target, record.preferences().after(), record.rules().after());
        if (outcome != null) {
            return outcome;
        }
        publish(target);
        recordRecovery(record, "FORWARD", target.revision());
        finish(record);
        log.info("Recovered forward to revision " + target.revision());
        return new Outcome.Committed(target);
    }

    private Outcome rollBack(TransactionJournal.Record record) {
        var target = snapshotOf(record.oldDocument());
        var outcome = reconcile(record, target, record.preferences().before(), record.rules().before());
        if (outcome != null) {
            return outcome;
        }
        publish(target);
        recordRecovery(record, "ROLLBACK", target.revision());
        finish(record);
        log.info("Rolled back an interrupted settings change to revision " + target.revision());
        return new Outcome.Committed(target);
    }

    /**
     * Brings both stores to {@code target}, provided each currently holds a digest the journal
     * accounted for. Anything else means the stores were edited after the crash, and overwriting
     * that would destroy a change nobody recorded.
     *
     * @return null on success, otherwise the blocking outcome.
     */
    private Outcome reconcile(TransactionJournal.Record record, SettingsSnapshot target,
                              String targetPrefsDigest, String targetRulesDigest) {
        var knownPrefs = List.of(String.valueOf(record.preferences().before()),
                String.valueOf(record.preferences().after()));
        var actualPrefs = preferences.read().canonicalDigest();
        if (!knownPrefs.contains(actualPrefs)) {
            return block("The stored settings do not match either side of the interrupted change "
                    + record.transactionId() + ", so they were edited outside Burp after the "
                    + "interruption. Nothing has been changed.");
        }

        String actualRules;
        var probe = ruleFile.probe();
        if (probe instanceof RuleStore.Probe.Missing) {
            actualRules = null;
        } else if (probe instanceof RuleStore.Probe.Loaded loaded) {
            actualRules = loaded.rawDigest();
        } else {
            return block("The rules file at " + ruleFile.path() + " cannot be read while finishing "
                    + "the interrupted change " + record.transactionId()
                    + ". Nothing has been changed.");
        }
        if (!Objects.equals(actualRules, record.rules().before())
                && !Objects.equals(actualRules, record.rules().after())) {
            return block("The rules file does not match either side of the interrupted change "
                    + record.transactionId() + ", so it was edited after the interruption. "
                    + "Nothing has been changed.");
        }

        try {
            if (!Objects.equals(actualPrefs, targetPrefsDigest)) {
                preferences.write(target.settings());
                var readBack = preferences.read().canonicalDigest();
                if (!readBack.equals(targetPrefsDigest)) {
                    return block("Writing the stored settings while finishing change "
                            + record.transactionId() + " did not take effect.");
                }
            }
            if (!Objects.equals(actualRules, targetRulesDigest)) {
                ruleFile.saveIfUnchanged(actualRules, target.storedRules());
            }
            rulesFileDigest.set(targetRulesDigest);
        } catch (IOException e) {
            return block("Could not finish the interrupted change " + record.transactionId()
                    + ": " + e);
        }
        return null;
    }

    private void recordRecovery(TransactionJournal.Record record, String direction, String revision) {
        if (!record.auditEnabled()) {
            // A transaction that ran without audit does not start producing audit during recovery.
            return;
        }
        var body = new JsonObject();
        body.addProperty("transactionId", record.transactionId());
        body.addProperty("fromPhase", record.phase().name());
        body.addProperty("direction", direction);
        body.addProperty("resultingRevision", revision);
        try {
            audit.append("RECOVERY", body);
        } catch (IOException e) {
            log.error("Could not record recovery of " + record.transactionId() + ": " + e);
        }
    }

    private void finish(TransactionJournal.Record record) {
        try {
            journal.clear();
        } catch (IOException e) {
            // Harmless: a leftover journal is re-examined and cleaned up at the next start.
            log.error("Could not clear " + journal.path() + ": " + e);
        }
    }

    private static SettingsSnapshot snapshotOf(JsonObject canonicalDocument) {
        var settings = new BusinessSettings(
                canonicalDocument.getAsJsonObject("defaults").get("spoofProxyAddress").getAsString(),
                canonicalDocument.getAsJsonObject("advanced").get("interceptProxyAddress").getAsString(),
                canonicalDocument.getAsJsonObject("advanced").get("burpProxyAddress").getAsString(),
                canonicalDocument.getAsJsonObject("defaults").get("fingerprint").getAsString(),
                canonicalDocument.getAsJsonObject("defaults").get("hexClientHello").getAsString(),
                canonicalDocument.getAsJsonObject("advanced").get("useInterceptedFingerprint").getAsBoolean(),
                canonicalDocument.getAsJsonObject("defaults").get("httpTimeout").getAsInt(),
                canonicalDocument.getAsJsonObject("defaults").get("externalProxyUrl").getAsString());

        var rules = new ArrayList<FingerprintRule>();
        for (var element : canonicalDocument.getAsJsonArray("rules")) {
            var object = element.getAsJsonObject();
            var rule = new FingerprintRule();
            rule.hostPattern = object.get("hostPattern").getAsString();
            rule.enabled = object.get("enabled").getAsBoolean();
            rule.fingerprint = object.get("fingerprint").getAsString();
            rule.hexClientHello = object.get("hexClientHello").getAsString();
            rule.externalProxyUrl = object.get("externalProxyUrl").getAsString();
            rule.note = object.get("note").getAsString();
            rule.httpTimeout = object.get("httpTimeout").isJsonNull()
                    ? null : object.get("httpTimeout").getAsInt();
            rules.add(rule);
        }
        return SettingsSnapshot.of(settings, rules);
    }

    private Outcome block(String reason) {
        blocked.set(reason);
        log.error(reason);
        return new Outcome.RecoveryRequired(reason);
    }

    /**
     * Clears the blocking state after a user has repaired whatever caused it.
     */
    public void unblock() {
        blocked.set(null);
    }

    // ------------------------------------------------------------------ committing

    /**
     * Stages, verifies and commits {@code candidate}.
     */
    public Outcome commit(SettingsSnapshot candidate, TransactionJournal.Source source) {
        synchronized (writeLock) {
            var reason = blocked.get();
            if (reason != null) {
                return new Outcome.RecoveryRequired(reason);
            }

            var base = committed.get();
            if (candidate.revision().equals(base.revision())) {
                // Nothing to do, and nothing worth a journal entry.
                return new Outcome.Committed(base);
            }

            var problems = validate(candidate, base);
            if (!problems.isEmpty()) {
                return failed(Wire.Code.VALIDATION_FAILED,
                        "The settings are not valid: " + problems.get(0).message(),
                        problems.stream()
                                .map(p -> Wire.ErrorDetail.of(p.path(), p.reason()))
                                .toList());
            }

            // Re-read both stores. A write "succeeding" earlier is not evidence that nothing has
            // changed since, and Preferences gives no other way to notice.
            var observedPrefs = preferences.read().canonicalDigest();
            if (!observedPrefs.equals(base.settings().canonicalDigest())) {
                return failed(Wire.Code.EXTERNAL_DIVERGENCE,
                        "The stored settings changed outside this tab. Reload before saving.",
                        List.of(Wire.ErrorDetail.mismatch("/settings", "preferences_changed_externally",
                                base.settings().canonicalDigest(), observedPrefs)));
            }

            String observedRules;
            var probe = ruleFile.probe();
            if (probe instanceof RuleStore.Probe.Missing) {
                observedRules = null;
            } else if (probe instanceof RuleStore.Probe.Loaded loaded) {
                observedRules = loaded.rawDigest();
            } else {
                var invalid = (RuleStore.Probe.Invalid) probe;
                return failed(Wire.Code.RULE_FILE_INVALID,
                        "The rules file " + invalid.reason() + ". It has been left untouched.",
                        List.of(Wire.ErrorDetail.of("/domainRules", "rule_file_invalid")));
            }

            var candidateRulesBytes = RuleStore.serialize(candidate.storedRules())
                    .getBytes(StandardCharsets.UTF_8);
            var record = new TransactionJournal.Record(
                    TransactionJournal.FORMAT_VERSION,
                    TransactionJournal.newTransactionId(),
                    source,
                    auditEnabled.getAsBoolean(),
                    TransactionJournal.Phase.PREPARED,
                    base.revision(),
                    candidate.revision(),
                    new TransactionJournal.Participant(observedPrefs, candidate.settings().canonicalDigest()),
                    new TransactionJournal.Participant(observedRules, Jcs.digestOfBytes(candidateRulesBytes)),
                    null,
                    base.canonicalDocument(),
                    candidate.canonicalDocument());

            return run(record, base, candidate, observedRules);
        }
    }

    private List<Validation.Problem> validate(SettingsSnapshot candidate, SettingsSnapshot base) {
        var problems = new ArrayList<>(
                Validation.settings(candidate.settings(), fingerprints(), Validation.Policy.COMMIT));
        // Rule rows are checked structurally only. A pre-existing row naming a fingerprint this
        // build of the Go library does not offer must not deadlock every unrelated change.
        for (var i = 0; i < candidate.storedRules().size(); i++) {
            var rule = candidate.storedRules().get(i);
            if (candidate.hiddenIndexes().contains(i)) {
                continue; // already excluded from matching; kept as the user typed it
            }
            problems.addAll(Validation.structuralRule(rule, i));
        }
        return problems;
    }

    private Outcome run(TransactionJournal.Record record, SettingsSnapshot base,
                        SettingsSnapshot candidate, String observedRules) {
        var auditOn = record.auditEnabled();
        var commitBody = commitBody(record, base, candidate);
        var expectedDigest = AuditTrail.digestOf("MUTATION_COMMITTED", commitBody);
        record = new TransactionJournal.Record(record.formatVersion(), record.transactionId(),
                record.source(), auditOn, record.phase(), record.baseRevision(), record.candidateRevision(),
                record.preferences(), record.rules(), expectedDigest,
                record.oldDocument(), record.newDocument());

        try {
            journal.write(record);
        } catch (IOException e) {
            // Nothing has been touched, so this is a clean failure.
            return failed(Wire.Code.PERSISTENCE_FAILED,
                    "Could not record the change before making it: " + e, List.of());
        }

        if (auditOn) {
            try {
                audit.recordSnapshot(candidate);
                audit.append("MUTATION_PREPARED", commitBody);
                record = journal.advance(record, TransactionJournal.Phase.AUDIT_PREPARED);
            } catch (IOException e) {
                clearJournalQuietly();
                return failed(Wire.Code.AUDIT_UNAVAILABLE,
                        "Full audit is on and the change could not be recorded, so it was not made: " + e,
                        List.of());
            }
        }

        // ---- staging. Everything from here until the decision is reversible.
        try {
            preferences.write(candidate.settings());
            var readBack = preferences.read().canonicalDigest();
            if (!readBack.equals(record.preferences().after())) {
                compensate(record, base, observedRules);
                return failed(Wire.Code.PERSISTENCE_FAILED,
                        "The settings did not store correctly; nothing was changed.",
                        List.of(Wire.ErrorDetail.mismatch("/settings", "write_not_observed",
                                record.preferences().after(), readBack)));
            }
            record = journal.advance(record, TransactionJournal.Phase.PREFERENCES_WRITTEN);

            ruleFile.saveIfUnchanged(observedRules, candidate.storedRules());
            record = journal.advance(record, TransactionJournal.Phase.RULES_WRITTEN);
        } catch (RuleStore.ConflictException e) {
            compensate(record, base, observedRules);
            return failed(Wire.Code.EXTERNAL_DIVERGENCE,
                    "The rules file changed on disk while saving; nothing was changed.",
                    List.of(Wire.ErrorDetail.mismatch("/domainRules", "rules_file_changed_externally",
                            observedRules, e.actualDigest())));
        } catch (IOException e) {
            compensate(record, base, observedRules);
            return failed(Wire.Code.PERSISTENCE_FAILED, "Could not save: " + e, List.of());
        }

        try {
            if (auditOn) {
                audit.append("MUTATION_COMMIT_READY", commitBody);
            }
            record = journal.advance(record, TransactionJournal.Phase.COMMIT_READY);
        } catch (IOException e) {
            compensate(record, base, observedRules);
            return failed(auditOn ? Wire.Code.AUDIT_UNAVAILABLE : Wire.Code.PERSISTENCE_FAILED,
                    "Could not prepare the change for commit; nothing was changed: " + e, List.of());
        }

        // ---- the decision. Exactly one durable write, and it is not retried blindly.
        try {
            if (auditOn) {
                audit.append("MUTATION_COMMITTED", commitBody);
            }
            record = journal.advance(record, TransactionJournal.Phase.COMMIT_DECIDED);
        } catch (IOException e) {
            // The write reported failure, which is not the same as not having happened.
            var evidence = auditOn
                    ? audit.probeCommitted(record.transactionId(), expectedDigest)
                    : AuditTrail.Evidence.ABSENT;
            if (evidence == AuditTrail.Evidence.FOUND) {
                // It did happen. Carry on forward; this is now a committed change.
                record = record.withPhase(TransactionJournal.Phase.COMMIT_DECIDED);
            } else if (evidence == AuditTrail.Evidence.ABSENT && !journalReachedDecision()) {
                compensate(record, base, observedRules);
                return failed(auditOn ? Wire.Code.AUDIT_UNAVAILABLE : Wire.Code.PERSISTENCE_FAILED,
                        "Could not commit the change; nothing was changed: " + e, List.of());
            } else {
                return block("A settings change (" + record.transactionId() + ") could not be "
                        + "confirmed as committed or as not committed. The stored settings have been "
                        + "left as they are and no further changes will be made until this is "
                        + "resolved. Original error: " + e);
            }
        }

        // ---- past the decision. Nothing below may roll back.
        publish(candidate);
        rulesFileDigest.set(record.rules().after());

        try {
            record = journal.advance(record, TransactionJournal.Phase.RUNTIME_PUBLISHED);
            journal.advance(record, TransactionJournal.Phase.COMPLETE);
            journal.clear();
        } catch (IOException e) {
            // The change is committed and live. A leftover journal is tidied at the next start.
            log.error("Settings were committed, but the transaction journal could not be updated: " + e);
        }

        if (auditOn) {
            audit.enforceRetention();
        }
        return new Outcome.Committed(candidate);
    }

    private boolean journalReachedDecision() {
        try {
            var current = journal.read();
            return current != null && current.phase().afterDecision();
        } catch (IOException e) {
            return false;
        }
    }

    private static JsonObject commitBody(TransactionJournal.Record record, SettingsSnapshot base,
                                         SettingsSnapshot candidate) {
        var body = new JsonObject();
        body.addProperty("transactionId", record.transactionId());
        body.addProperty("source", record.source().name());
        body.addProperty("baseRevision", base.revision());
        body.addProperty("candidateRevision", candidate.revision());
        // The snapshot itself is stored once per revision and referenced, not repeated per event.
        body.addProperty("snapshotRef", candidate.revision());
        return body;
    }

    /**
     * Undoes this transaction's own staged writes. Only ever called before the commit decision.
     * <p>
     * Each store is reverted only if it currently holds what <em>this</em> transaction put there.
     * Anything else belongs to somebody else — most likely the external edit that caused the
     * failure in the first place — and rolling back over it would destroy a change nobody recorded,
     * which is worse than the failure being undone.
     */
    private void compensate(TransactionJournal.Record record, SettingsSnapshot base, String observedRules) {
        try {
            if (preferences.read().canonicalDigest().equals(record.preferences().after())) {
                preferences.write(base.settings());
                var readBack = preferences.read().canonicalDigest();
                if (!readBack.equals(record.preferences().before())) {
                    block("A settings change (" + record.transactionId() + ") failed and the stored "
                            + "settings could not be put back. No further changes will be made "
                            + "until this is resolved.");
                    return;
                }
            }

            var probe = ruleFile.probe();
            String actual = probe instanceof RuleStore.Probe.Loaded loaded ? loaded.rawDigest() : null;
            if (Objects.equals(actual, record.rules().after())
                    && !Objects.equals(actual, record.rules().before())) {
                ruleFile.saveIfUnchanged(actual, base.storedRules());
                rulesFileDigest.set(record.rules().before());
            } else {
                rulesFileDigest.set(actual);
            }
            clearJournalQuietly();
        } catch (IOException e) {
            block("A settings change (" + record.transactionId() + ") failed and could not be undone: "
                    + e + ". The transaction journal has been kept; no further changes will be made "
                    + "until this is resolved.");
        }
    }

    private void clearJournalQuietly() {
        try {
            journal.clear();
        } catch (IOException e) {
            log.error("Could not clear " + journal.path() + ": " + e);
        }
    }

    /**
     * The single publication point. One write, so readers never see a partially updated pair.
     */
    private void publish(SettingsSnapshot snapshot) {
        committed.set(snapshot);
        for (var listener : listeners) {
            try {
                listener.accept(snapshot);
            } catch (RuntimeException e) {
                // A listener failing must never look like the commit failing.
                log.error("A settings listener failed: " + e);
            }
        }
    }
}
