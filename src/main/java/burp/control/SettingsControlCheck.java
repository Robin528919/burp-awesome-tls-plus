package burp.control;

import burp.FingerprintRule;
import burp.RuleStore;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Fault-injection self-check for {@link SettingsControl}.
 * <p>
 * ADR-0001 section 17.1 asks for this specifically, and it lives outside the class it exercises
 * because it is bigger than the class's own happy path. Every scenario here is a failure that
 * cannot be produced on demand in a real installation — a crash between two stores, an audit
 * append that reports failure after succeeding, a rules file edited during approval — and each one
 * has exactly one acceptable outcome. Getting them wrong is silent: settings look fine, and one of
 * them is quietly the wrong half of a change.
 * <p>
 * Run with:
 * {@code java -ea -cp build/classes/java/main:<gson.jar> burp.control.SettingsControlCheck}
 */
public final class SettingsControlCheck {
    private SettingsControlCheck() {
    }

    public static void main(String[] args) throws Exception {
        happyPathPublishesAtomically();
        preferencesWriteNotObservedRollsBack();
        rulesWriteFailureRollsBack();
        externalRuleEditIsNotOverwritten();
        externalPreferenceEditIsRefused();
        auditFailureBeforeStagingChangesNothing();
        decisionFailureWithEvidenceRollsForward();
        decisionFailureWithoutEvidenceRollsBack();
        decisionFailureWithAmbiguousAuditBlocks();
        invalidCandidateIsRefused();
        blockedControlRefusesEverything();

        recoveryBeforeDecisionRollsBack();
        recoveryAtCommitReadyFollowsTheAudit();
        recoveryAfterDecisionRollsForward();
        recoveryFromCompleteCleansUp();
        recoveryRefusesUnknownDigests();
        startupAdoptsLegacyRulesAfterRecovery();

        System.out.println("SettingsControl fault-injection self-check passed");
    }

    // ------------------------------------------------------------------ commit path

    private static void happyPathPublishesAtomically() throws Exception {
        var fixture = Fixture.create();
        fixture.start();

        var published = new ArrayList<SettingsSnapshot>();
        fixture.control.addListener(published::add);

        var candidate = fixture.control.snapshot()
                .withSettings(BusinessSettings.defaults().withHttpTimeout(45))
                .withRules(List.of(new FingerprintRule("a.com", "chrome", "", "", null, true)));
        var outcome = fixture.control.commit(candidate, TransactionJournal.Source.UI_SAVE);

        check(outcome instanceof SettingsControl.Outcome.Committed, "a valid change commits");
        check(fixture.control.snapshot().revision().equals(candidate.revision()), "and is published");
        check(fixture.control.snapshot().matcher().match("a.com") != null,
                "the matcher published with it already knows the new rule");
        check(published.size() == 1, "listeners are told exactly once");
        check(fixture.preferences.read().canonicalDigest().equals(candidate.settings().canonicalDigest()),
                "the scalar settings are stored");
        check(fixture.loadedRules().size() == 1, "and so are the rules");
        check(!fixture.journal.exists(), "the journal is cleaned up");

        // Committing the same thing twice is not a change.
        var again = fixture.control.commit(candidate, TransactionJournal.Source.UI_SAVE);
        check(again instanceof SettingsControl.Outcome.Committed, "re-committing the same revision succeeds");
        check(published.size() == 1, "without republishing");
    }

    private static void preferencesWriteNotObservedRollsBack() throws Exception {
        var fixture = Fixture.create();
        fixture.start();
        var before = fixture.control.snapshot();
        fixture.seedRule("keep.com");

        // The setters do not throw, but the value is not there afterwards. This is the only failure
        // mode Burp's preference store actually exposes.
        fixture.preferences.swallowWrites = true;

        var candidate = fixture.control.snapshot()
                .withSettings(BusinessSettings.defaults().withHttpTimeout(45));
        var outcome = fixture.control.commit(candidate, TransactionJournal.Source.UI_SAVE);

        check(outcome instanceof SettingsControl.Outcome.Failed, "an unobserved write fails the commit");
        check(((SettingsControl.Outcome.Failed) outcome).code() == Wire.Code.PERSISTENCE_FAILED,
                "and reports why");
        check(fixture.control.snapshot().settings().httpTimeout() == before.settings().httpTimeout(),
                "nothing new is published");
        check(fixture.loadedRules().size() == 1, "and the rules file is untouched");
        check(!fixture.journal.exists(), "the journal is cleaned up after the rollback");
    }

    private static void rulesWriteFailureRollsBack() throws Exception {
        var fixture = Fixture.create();
        fixture.start();
        fixture.seedRule("keep.com");
        var before = fixture.control.snapshot();

        fixture.rules.failNextWrite = new IOException("disk full");

        var candidate = before.withSettings(BusinessSettings.defaults().withHttpTimeout(45))
                .withRules(List.of(new FingerprintRule("new.com", "chrome", "", "", null, true)));
        var outcome = fixture.control.commit(candidate, TransactionJournal.Source.UI_SAVE);

        check(outcome instanceof SettingsControl.Outcome.Failed, "a rules write failure fails the commit");
        check(fixture.control.snapshot().revision().equals(before.revision()), "nothing is published");
        // The half of the change that did land must be undone, or the two stores disagree.
        check(fixture.preferences.read().httpTimeout() == before.settings().httpTimeout(),
                "the scalar half that already landed is rolled back");
        check(fixture.loadedRules().get(0).hostPattern.equals("keep.com"), "and the rules are as they were");
    }

    private static void externalRuleEditIsNotOverwritten() throws Exception {
        var fixture = Fixture.create();
        fixture.start();
        fixture.seedRule("keep.com");
        var before = fixture.control.snapshot();

        // Someone edits the file between the snapshot being taken and the write.
        fixture.rules.beforeWrite = () -> Files.writeString(fixture.rulesPath,
                RuleStore.serialize(List.of(new FingerprintRule("theirs.com", "opera", "", "", null, true))));

        var candidate = before.withRules(List.of(new FingerprintRule("mine.com", "chrome", "", "", null, true)));
        var outcome = fixture.control.commit(candidate, TransactionJournal.Source.AI_APPLY);

        check(outcome instanceof SettingsControl.Outcome.Failed, "the write is refused");
        check(((SettingsControl.Outcome.Failed) outcome).code() == Wire.Code.EXTERNAL_DIVERGENCE,
                "as an external divergence");
        check(fixture.loadedRules().get(0).hostPattern.equals("theirs.com"),
                "and the external edit survives untouched");
        check(fixture.control.snapshot().revision().equals(before.revision()), "nothing is published");
    }

    private static void externalPreferenceEditIsRefused() throws Exception {
        var fixture = Fixture.create();
        fixture.start();
        var before = fixture.control.snapshot();

        // Something wrote the preference store without going through this seam.
        fixture.preferences.settings = fixture.preferences.settings.withFingerprint("firefox");

        var outcome = fixture.control.commit(
                before.withSettings(BusinessSettings.defaults().withHttpTimeout(45)),
                TransactionJournal.Source.UI_SAVE);

        check(outcome instanceof SettingsControl.Outcome.Failed, "the commit is refused");
        check(((SettingsControl.Outcome.Failed) outcome).code() == Wire.Code.EXTERNAL_DIVERGENCE,
                "rather than overwriting a change nobody recorded");
        check(fixture.preferences.read().fingerprint().equals("firefox"), "and the external value stands");
    }

    private static void auditFailureBeforeStagingChangesNothing() throws Exception {
        var fixture = Fixture.create();
        fixture.auditOn = true;
        fixture.start();
        var before = fixture.control.snapshot();

        // Make the audit directory unwritable by putting a file where the directory must go.
        Files.deleteIfExists(fixture.auditDir);
        Files.writeString(fixture.auditDir, "not a directory");

        var outcome = fixture.control.commit(
                before.withSettings(BusinessSettings.defaults().withHttpTimeout(45)),
                TransactionJournal.Source.AI_APPLY);

        check(outcome instanceof SettingsControl.Outcome.Failed, "an unrecordable change is not made");
        check(((SettingsControl.Outcome.Failed) outcome).code() == Wire.Code.AUDIT_UNAVAILABLE,
                "and says the audit trail is the reason");
        check(fixture.preferences.read().httpTimeout() == before.settings().httpTimeout(),
                "with nothing written to either store");
        check(fixture.control.snapshot().revision().equals(before.revision()), "and nothing published");
    }

    private static void decisionFailureWithEvidenceRollsForward() throws Exception {
        var fixture = Fixture.create();
        fixture.auditOn = true;
        fixture.start();
        var before = fixture.control.snapshot();

        // The committed event is written, and only then does the call report failure. This is the
        // case that must never roll back: the decision was made and is durable.
        fixture.journal.failAfterPhase = TransactionJournal.Phase.COMMIT_READY;

        var candidate = before.withSettings(BusinessSettings.defaults().withHttpTimeout(45));
        var outcome = fixture.control.commit(candidate, TransactionJournal.Source.AI_APPLY);

        check(outcome instanceof SettingsControl.Outcome.Committed,
                "a decision that is durably recorded is honoured despite the reported failure");
        check(fixture.control.snapshot().revision().equals(candidate.revision()), "and the change is published");
        check(fixture.preferences.read().httpTimeout() == 45, "with the stores holding the new value");
    }

    private static void decisionFailureWithoutEvidenceRollsBack() throws Exception {
        var fixture = Fixture.create();
        fixture.auditOn = false;
        fixture.start();
        var before = fixture.control.snapshot();

        // Without audit the journal is the decision, so failing to write it means no decision.
        fixture.journal.failAtPhase = TransactionJournal.Phase.COMMIT_DECIDED;

        var outcome = fixture.control.commit(
                before.withSettings(BusinessSettings.defaults().withHttpTimeout(45)),
                TransactionJournal.Source.AI_APPLY);

        check(outcome instanceof SettingsControl.Outcome.Failed, "an undecided change is rolled back");
        check(fixture.preferences.read().httpTimeout() == before.settings().httpTimeout(),
                "and the stores go back to what they held");
        check(fixture.control.snapshot().revision().equals(before.revision()), "with nothing published");
    }

    private static void decisionFailureWithAmbiguousAuditBlocks() throws Exception {
        var fixture = Fixture.create();
        fixture.auditOn = true;
        fixture.start();
        var before = fixture.control.snapshot();

        // The audit append fails and leaves the file damaged, so whether the decision was recorded
        // cannot be established either way.
        fixture.audit.failAppend = "MUTATION_COMMITTED";
        fixture.audit.corruptOnFailure = true;

        var outcome = fixture.control.commit(
                before.withSettings(BusinessSettings.defaults().withHttpTimeout(45)),
                TransactionJournal.Source.AI_APPLY);

        check(outcome instanceof SettingsControl.Outcome.RecoveryRequired,
                "an undecidable outcome blocks rather than guessing");
        check(fixture.control.snapshot().revision().equals(before.revision()),
                "nothing is published either way");
        check(fixture.control.blockedReason() != null, "and the control refuses further changes");

        var second = fixture.control.commit(
                before.withSettings(BusinessSettings.defaults().withHttpTimeout(99)),
                TransactionJournal.Source.UI_SAVE);
        check(second instanceof SettingsControl.Outcome.RecoveryRequired, "including from the UI");
    }

    private static void invalidCandidateIsRefused() throws Exception {
        var fixture = Fixture.create();
        fixture.start();
        var before = fixture.control.snapshot();

        var outcome = fixture.control.commit(
                before.withSettings(BusinessSettings.defaults().withSpoofProxyAddress("not-an-address")),
                TransactionJournal.Source.UI_SAVE);

        check(outcome instanceof SettingsControl.Outcome.Failed, "an invalid candidate is refused");
        check(((SettingsControl.Outcome.Failed) outcome).code() == Wire.Code.VALIDATION_FAILED, "as invalid");
        check(!fixture.journal.exists(), "before any journal is written");

        // A row the table is holding for the user must not block unrelated changes.
        var withDraft = before.withRules(List.of(
                new FingerprintRule("", "", "", "", null, true),
                new FingerprintRule("ok.com", "chrome", "", "", null, true)));
        check(fixture.control.commit(withDraft, TransactionJournal.Source.RULES_AUTOSAVE)
                instanceof SettingsControl.Outcome.Committed, "an incomplete row still saves");
        check(fixture.control.snapshot().hiddenInvalidRuleCount() == 1, "and stays hidden");
        check(fixture.control.snapshot().matcher().match("ok.com") != null, "while the rest still works");
    }

    private static void blockedControlRefusesEverything() throws Exception {
        var fixture = Fixture.create();
        fixture.start();
        var before = fixture.control.snapshot();

        Files.writeString(fixture.rulesPath, "{ not json");
        var restarted = Fixture.reopen(fixture);
        check(restarted.control.start(null, List.of()) instanceof SettingsControl.Outcome.RecoveryRequired,
                "a broken rules file blocks startup");
        check(restarted.control.blockedReason().contains("left exactly as it is"),
                "and says the file was not touched");
        check(Files.readString(fixture.rulesPath).equals("{ not json"), "which is true");

        check(restarted.control.commit(before, TransactionJournal.Source.UI_SAVE)
                instanceof SettingsControl.Outcome.RecoveryRequired, "and no change is accepted");
    }

    // ------------------------------------------------------------------ recovery

    private static void recoveryBeforeDecisionRollsBack() throws Exception {
        for (var phase : List.of(TransactionJournal.Phase.PREPARED, TransactionJournal.Phase.AUDIT_PREPARED,
                TransactionJournal.Phase.PREFERENCES_WRITTEN, TransactionJournal.Phase.RULES_WRITTEN)) {
            var fixture = Fixture.create();
            fixture.start();
            var old = fixture.control.snapshot();
            var candidate = old.withSettings(BusinessSettings.defaults().withHttpTimeout(45));

            // Simulate a crash: the stores hold the candidate, the journal says pre-decision.
            fixture.stageCandidate(candidate);
            fixture.writeJournal(phase, old, candidate, true);

            var restarted = Fixture.reopen(fixture);
            var outcome = restarted.control.start(null, List.of());

            check(outcome instanceof SettingsControl.Outcome.Committed, phase + " recovers");
            check(restarted.control.snapshot().revision().equals(old.revision()),
                    phase + " rolls back to the old revision");
            check(restarted.preferences.read().httpTimeout() == old.settings().httpTimeout(),
                    phase + " restores the stored settings");
            check(!restarted.journal.exists(), phase + " clears the journal");
        }
    }

    private static void recoveryAtCommitReadyFollowsTheAudit() throws Exception {
        // Audit off: the journal is the decision, and it never got written.
        var off = Fixture.create();
        off.auditOn = false;
        off.start();
        var oldOff = off.control.snapshot();
        var candidateOff = oldOff.withSettings(BusinessSettings.defaults().withHttpTimeout(45));
        off.stageCandidate(candidateOff);
        off.writeJournal(TransactionJournal.Phase.COMMIT_READY, oldOff, candidateOff, false);
        var restartedOff = Fixture.reopen(off);
        restartedOff.control.start(null, List.of());
        check(restartedOff.control.snapshot().revision().equals(oldOff.revision()),
                "COMMIT_READY without audit rolls back");

        // Audit on, matching event present: the decision was made.
        var found = Fixture.create();
        found.auditOn = true;
        found.start();
        var oldFound = found.control.snapshot();
        var candidateFound = oldFound.withSettings(BusinessSettings.defaults().withHttpTimeout(45));
        found.stageCandidate(candidateFound);
        var record = found.writeJournal(TransactionJournal.Phase.COMMIT_READY, oldFound, candidateFound, true);
        found.audit.append("MUTATION_COMMITTED", found.commitBody(record, oldFound, candidateFound));
        var restartedFound = Fixture.reopen(found);
        restartedFound.control.start(null, List.of());
        check(restartedFound.control.snapshot().revision().equals(candidateFound.revision()),
                "COMMIT_READY with a matching committed event rolls forward");

        // Audit on, event provably absent: no decision.
        var absent = Fixture.create();
        absent.auditOn = true;
        absent.start();
        var oldAbsent = absent.control.snapshot();
        var candidateAbsent = oldAbsent.withSettings(BusinessSettings.defaults().withHttpTimeout(45));
        absent.stageCandidate(candidateAbsent);
        absent.writeJournal(TransactionJournal.Phase.COMMIT_READY, oldAbsent, candidateAbsent, true);
        absent.audit.append("MCP_CALL", new com.google.gson.JsonObject());
        var restartedAbsent = Fixture.reopen(absent);
        restartedAbsent.control.start(null, List.of());
        check(restartedAbsent.control.snapshot().revision().equals(oldAbsent.revision()),
                "COMMIT_READY with the event provably absent rolls back");

        // Audit on, trail damaged: undecidable.
        var damaged = Fixture.create();
        damaged.auditOn = true;
        damaged.start();
        var oldDamaged = damaged.control.snapshot();
        var candidateDamaged = oldDamaged.withSettings(BusinessSettings.defaults().withHttpTimeout(45));
        damaged.stageCandidate(candidateDamaged);
        damaged.writeJournal(TransactionJournal.Phase.COMMIT_READY, oldDamaged, candidateDamaged, true);
        damaged.audit.append("MCP_CALL", new com.google.gson.JsonObject());
        Files.writeString(damaged.audit.eventsPath(), "{ torn",
                java.nio.file.StandardOpenOption.APPEND);
        var restartedDamaged = Fixture.reopen(damaged);
        var outcome = restartedDamaged.control.start(null, List.of());
        check(outcome instanceof SettingsControl.Outcome.RecoveryRequired,
                "COMMIT_READY with a damaged audit trail blocks");
        check(restartedDamaged.control.blockedReason().contains("cannot be resolved automatically"),
                "and says so plainly");
    }

    private static void recoveryAfterDecisionRollsForward() throws Exception {
        for (var phase : List.of(TransactionJournal.Phase.COMMIT_DECIDED,
                TransactionJournal.Phase.RUNTIME_PUBLISHED)) {
            var fixture = Fixture.create();
            fixture.auditOn = false;
            fixture.start();
            var old = fixture.control.snapshot();
            var candidate = old.withSettings(BusinessSettings.defaults().withHttpTimeout(45))
                    .withRules(List.of(new FingerprintRule("after.com", "chrome", "", "", null, true)));

            // Crash immediately after the decision, before either store finished.
            fixture.writeJournal(phase, old, candidate, false);

            var restarted = Fixture.reopen(fixture);
            restarted.control.start(null, List.of());

            check(restarted.control.snapshot().revision().equals(candidate.revision()),
                    phase + " rolls forward to the decided revision");
            check(restarted.preferences.read().httpTimeout() == 45, phase + " completes the settings write");
            check(restarted.loadedRules().size() == 1, phase + " completes the rules write");
            check(restarted.control.snapshot().matcher().match("after.com") != null,
                    phase + " publishes a matching matcher");
        }
    }

    private static void recoveryFromCompleteCleansUp() throws Exception {
        // Everything landed; only the cleanup was interrupted.
        var done = Fixture.create();
        done.auditOn = false;
        done.start();
        var old = done.control.snapshot();
        var candidate = old.withSettings(BusinessSettings.defaults().withHttpTimeout(45));
        done.stageCandidate(candidate);
        done.writeJournal(TransactionJournal.Phase.COMPLETE, old, candidate, false);

        var restarted = Fixture.reopen(done);
        restarted.control.start(null, List.of());
        check(restarted.control.snapshot().revision().equals(candidate.revision()),
                "COMPLETE publishes the candidate");
        check(!restarted.journal.exists(), "and clears the journal");

        // With audit on, COMPLETE alone is not evidence; the committed event has to be there.
        var missing = Fixture.create();
        missing.auditOn = true;
        missing.start();
        var oldMissing = missing.control.snapshot();
        var candidateMissing = oldMissing.withSettings(BusinessSettings.defaults().withHttpTimeout(45));
        missing.stageCandidate(candidateMissing);
        missing.writeJournal(TransactionJournal.Phase.COMPLETE, oldMissing, candidateMissing, true);

        var restartedMissing = Fixture.reopen(missing);
        var outcome = restartedMissing.control.start(null, List.of());
        check(outcome instanceof SettingsControl.Outcome.RecoveryRequired,
                "COMPLETE without the committed event blocks rather than trusting the phase");
    }

    private static void recoveryRefusesUnknownDigests() throws Exception {
        var fixture = Fixture.create();
        fixture.auditOn = false;
        fixture.start();
        var old = fixture.control.snapshot();
        var candidate = old.withSettings(BusinessSettings.defaults().withHttpTimeout(45));
        fixture.writeJournal(TransactionJournal.Phase.PREPARED, old, candidate, false);

        // Someone edited the settings after the crash, so neither side of the journal matches.
        fixture.preferences.settings = fixture.preferences.settings.withFingerprint("firefox");

        var restarted = Fixture.reopen(fixture);
        var outcome = restarted.control.start(null, List.of());
        check(outcome instanceof SettingsControl.Outcome.RecoveryRequired,
                "an unaccounted-for state blocks");
        check(restarted.preferences.read().fingerprint().equals("firefox"),
                "and the unrecorded edit is left alone");
        check(restarted.journal.exists(), "with the journal kept for inspection");
    }

    private static void startupAdoptsLegacyRulesAfterRecovery() throws Exception {
        var fixture = Fixture.create();

        // A pre-rename installation with rules, and nothing in the current location.
        var legacyDir = Files.createDirectories(fixture.dir.resolve("legacy"));
        new RuleStore(legacyDir.resolve(RuleStore.FILE_NAME), s -> {
        }).save(List.of(new FingerprintRule("old.com", "chrome", "", "", null, true)));

        fixture.control.start(legacyDir, List.of());
        check(fixture.control.snapshot().matcher().match("old.com") != null, "pre-rename rules are adopted");
        check(!Files.exists(legacyDir.resolve(RuleStore.FILE_NAME)),
                "and are not left behind to diverge");

        // Rules from before the file existed, held under the old preference key.
        var viaPreferences = Fixture.create();
        viaPreferences.control.start(null,
                List.of(new FingerprintRule("prefs.com", "firefox", "", "", null, true)));
        check(viaPreferences.control.snapshot().matcher().match("prefs.com") != null,
                "rules held in the preference store are migrated");
        check(viaPreferences.loadedRules().size() == 1, "into the file");

        // A migration must never run ahead of recovery.
        var pending = Fixture.create();
        pending.start();
        var old = pending.control.snapshot();
        var candidate = old.withRules(List.of(new FingerprintRule("recovered.com", "chrome", "", "", null, true)));
        pending.stageCandidate(candidate);
        pending.writeJournal(TransactionJournal.Phase.COMMIT_DECIDED, old, candidate, false);

        var legacyDir2 = Files.createDirectories(pending.dir.resolve("legacy2"));
        new RuleStore(legacyDir2.resolve(RuleStore.FILE_NAME), s -> {
        }).save(List.of(new FingerprintRule("shouldnotwin.com", "chrome", "", "", null, true)));

        var restarted = Fixture.reopen(pending);
        restarted.control.start(legacyDir2, List.of());
        check(restarted.control.snapshot().matcher().match("recovered.com") != null,
                "the interrupted change is recovered first");
        check(restarted.control.snapshot().matcher().match("shouldnotwin.com") == null,
                "and the pre-rename file does not overwrite it");
    }

    // ------------------------------------------------------------------ fixture

    /**
     * A complete {@link SettingsControl} over a temporary directory, with each port able to fail on
     * demand.
     */
    private static final class Fixture {
        final Path dir;
        final Path rulesPath;
        final Path auditDir;
        final FakePreferences preferences;
        final FakeRuleFile rules;
        final FakeJournal journal;
        final FakeAudit audit;
        final SettingsControl control;
        boolean auditOn;

        private Fixture(Path dir) {
            this.dir = dir;
            this.rulesPath = dir.resolve(RuleStore.FILE_NAME);
            this.auditDir = dir.resolve("audit");
            this.preferences = new FakePreferences();
            this.rules = new FakeRuleFile(rulesPath);
            this.journal = new FakeJournal(dir.resolve(TransactionJournal.FILE_NAME));
            this.audit = new FakeAudit(auditDir);
            this.control = new SettingsControl(preferences, rules, journal, audit, () -> auditOn,
                    RuntimeStatus::unknown, () -> Set.of("chrome", "firefox", "safari", "opera", "default"),
                    Ports.UiDirtyPort.SETTLED, Ports.Log.SILENT);
        }

        static Fixture create() throws IOException {
            return new Fixture(Files.createTempDirectory("awesome-tls-control"));
        }

        /**
         * A fresh control over the same directory and the same in-memory preference values, which
         * is what a Burp restart looks like.
         */
        static Fixture reopen(Fixture source) {
            var next = new Fixture(source.dir);
            next.preferences.settings = source.preferences.settings;
            next.auditOn = source.auditOn;
            return next;
        }

        void start() {
            var outcome = control.start(null, List.of());
            if (!(outcome instanceof SettingsControl.Outcome.Committed)) {
                throw new AssertionError("fixture failed to start: " + outcome);
            }
        }

        void seedRule(String host) {
            var candidate = control.snapshot()
                    .withRules(List.of(new FingerprintRule(host, "chrome", "", "", null, true)));
            var outcome = control.commit(candidate, TransactionJournal.Source.UI_SAVE);
            if (!(outcome instanceof SettingsControl.Outcome.Committed)) {
                throw new AssertionError("could not seed a rule: " + outcome);
            }
        }

        /** Puts both stores into the state a crash would have left them in. */
        void stageCandidate(SettingsSnapshot candidate) throws IOException {
            preferences.settings = candidate.settings();
            Files.writeString(rulesPath, RuleStore.serialize(candidate.storedRules()));
        }

        TransactionJournal.Record writeJournal(TransactionJournal.Phase phase, SettingsSnapshot old,
                                               SettingsSnapshot candidate, boolean withAudit) throws IOException {
            var record = new TransactionJournal.Record(
                    TransactionJournal.FORMAT_VERSION, "tx-" + phase.name().toLowerCase(java.util.Locale.ROOT),
                    TransactionJournal.Source.AI_APPLY, withAudit, phase,
                    old.revision(), candidate.revision(),
                    new TransactionJournal.Participant(old.settings().canonicalDigest(),
                            candidate.settings().canonicalDigest()),
                    new TransactionJournal.Participant(digestOfRules(old), digestOfRules(candidate)),
                    null, old.canonicalDocument(), candidate.canonicalDocument());
            record = new TransactionJournal.Record(record.formatVersion(), record.transactionId(),
                    record.source(), withAudit, phase, record.baseRevision(), record.candidateRevision(),
                    record.preferences(), record.rules(),
                    AuditTrail.digestOf("MUTATION_COMMITTED", commitBody(record, old, candidate)),
                    record.oldDocument(), record.newDocument());
            journal.write(record);
            return record;
        }

        com.google.gson.JsonObject commitBody(TransactionJournal.Record record, SettingsSnapshot base,
                                              SettingsSnapshot candidate) {
            var body = new com.google.gson.JsonObject();
            body.addProperty("transactionId", record.transactionId());
            body.addProperty("source", record.source().name());
            body.addProperty("baseRevision", base.revision());
            body.addProperty("candidateRevision", candidate.revision());
            body.addProperty("snapshotRef", candidate.revision());
            return body;
        }

        private String digestOfRules(SettingsSnapshot snapshot) {
            if (snapshot.storedRules().isEmpty() && !Files.exists(rulesPath)) {
                return null;
            }
            return Jcs.digestOfBytes(RuleStore.serialize(snapshot.storedRules())
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }

        List<FingerprintRule> loadedRules() {
            var probe = rules.probe();
            return probe instanceof RuleStore.Probe.Loaded loaded ? loaded.rules() : List.of();
        }
    }

    private static final class FakePreferences implements Ports.PreferencesPort {
        BusinessSettings settings = BusinessSettings.defaults();
        boolean swallowWrites;

        @Override
        public BusinessSettings read() {
            return settings;
        }

        @Override
        public void write(BusinessSettings value) {
            // Burp's setters return void, so a store that quietly drops a write looks like success.
            if (!swallowWrites) {
                settings = value.normalized();
            }
        }
    }

    private static final class FakeRuleFile implements SettingsControl.RuleFileAdapter {
        private final RuleStore store;
        private final Path path;
        IOException failNextWrite;
        ThrowingRunnable beforeWrite;

        FakeRuleFile(Path path) {
            this.path = path;
            this.store = new RuleStore(path, s -> {
            });
        }

        @Override
        public RuleStore.Probe probe() {
            return store.probe();
        }

        @Override
        public void saveIfUnchanged(String expectedDigest, List<FingerprintRule> rules) throws IOException {
            if (beforeWrite != null) {
                var hook = beforeWrite;
                beforeWrite = null;
                hook.run();
            }
            if (failNextWrite != null) {
                var failure = failNextWrite;
                failNextWrite = null;
                throw failure;
            }
            store.saveIfUnchanged(expectedDigest, rules);
        }

        @Override
        public Path path() {
            return path;
        }

        @Override
        public boolean adoptFrom(Path legacyDir) {
            return store.adoptFrom(legacyDir);
        }
    }

    private interface ThrowingRunnable {
        void run() throws IOException;
    }

    private static final class FakeJournal extends TransactionJournal {
        /** Fail while writing this phase, before it reaches disk. */
        Phase failAtPhase;
        /** Write this phase, then report failure anyway. */
        Phase failAfterPhase;

        FakeJournal(Path file) {
            super(file);
        }

        @Override
        public Record advance(Record record, Phase next) throws IOException {
            if (next == failAtPhase) {
                failAtPhase = null;
                throw new IOException("injected journal failure writing " + next);
            }
            var updated = super.advance(record, next);
            if (record.phase() == failAfterPhase) {
                failAfterPhase = null;
                throw new IOException("injected journal failure after " + next);
            }
            return updated;
        }
    }

    private static final class FakeAudit extends AuditTrail {
        /** Fail when appending this event type. */
        String failAppend;
        /** Leave a torn line behind, so the failure is undecidable rather than clean. */
        boolean corruptOnFailure;

        FakeAudit(Path directory) {
            super(directory);
        }

        @Override
        public String append(String type, com.google.gson.JsonObject body) throws IOException {
            if (type.equals(failAppend)) {
                failAppend = null;
                if (corruptOnFailure) {
                    Files.createDirectories(directory());
                    Files.writeString(eventsPath(), "{ torn append",
                            java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
                }
                throw new IOException("injected audit failure appending " + type);
            }
            return super.append(type, body);
        }
    }

    private static void check(boolean condition, String what) {
        if (!condition) throw new AssertionError("failed: " + what);
    }
}
