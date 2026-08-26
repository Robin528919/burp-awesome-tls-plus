package burp.control;

import burp.RuleStore;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The two things an AI client may do, and the three things only a person may do.
 * <p>
 * The asymmetry is the entire security model of this feature. {@link #inspect} and
 * {@link #propose} are reachable over MCP and neither of them changes a setting: propose validates,
 * computes a candidate, and parks it. {@link #approve}, {@link #reject} and {@link #revert} are
 * reachable only from the Burp UI. ADR-0001 section 2 lists an AI-callable apply as a non-goal, so
 * there is deliberately no code path from the adapter to a commit.
 * <p>
 * One pending proposal exists at a time, in memory, for fifteen minutes. Everything about that is a
 * limit rather than a feature: a queue of proposals would mean approving one while looking at
 * another, and persistence would mean a change outliving the session that asked for it.
 */
public final class AiSettingsService {
    /** Distinct idempotency keys remembered within one enabled session. */
    public static final int MAX_REQUEST_IDS = 1000;

    private final SettingsControl control;
    private final AuditTrail audit;
    private final java.util.function.BooleanSupplier auditEnabled;
    private final java.util.function.BooleanSupplier controlEnabled;

    /**
     * Whether a proposal is applied as soon as it is valid, with no review.
     * <p>
     * This removes the human gate and nothing else: the change still goes through the same
     * validation, the same journal, the same audit trail, the same three-way merge against the
     * rules file, and the same atomic publication. What it does mean is that an unauthenticated
     * local endpoint can change settings without being asked, which is why the switch is
     * session-scoped, off by default, and disarmed whenever the listener stops.
     */
    private final java.util.function.BooleanSupplier autoApply;

    private final Clock clock;

    private final AtomicReference<Proposal> pending = new AtomicReference<>();

    /**
     * The settings as they were immediately before the most recent AI apply, kept only so the user
     * can take it back. Section 13: memory only, this run only, and only while the AI's result is
     * still the committed revision — anything committed afterwards makes it meaningless.
     */
    private final AtomicReference<Revertible> revertible = new AtomicReference<>();

    private record Revertible(SettingsSnapshot before, String afterRevision) {
    }

    /**
     * Idempotency records. Bounded, and cleared when AI Control is switched off, because a replay
     * that outlives the session it belongs to is answering a question nobody is still asking.
     */
    private final Map<String, Replay> replays = new LinkedHashMap<>();

    private record Replay(String argumentsDigest, JsonObject result) {
    }

    private final Object lock = new Object();

    public AiSettingsService(SettingsControl control, AuditTrail audit,
                             java.util.function.BooleanSupplier auditEnabled,
                             java.util.function.BooleanSupplier controlEnabled,
                             java.util.function.BooleanSupplier autoApply, Clock clock) {
        this.control = control;
        this.audit = audit;
        this.auditEnabled = auditEnabled;
        this.controlEnabled = controlEnabled;
        this.autoApply = autoApply;
        this.clock = clock;
    }

    public SettingsControl control() {
        return control;
    }

    public Proposal pending() {
        var proposal = pending.get();
        if (proposal != null && proposal.status() == Proposal.Status.PENDING && proposal.expired(now())) {
            proposal.expire(now());
        }
        return proposal;
    }

    private Instant now() {
        return clock.instant();
    }

    /**
     * Clears everything that belongs to one enabled session. Called on disable and on unload.
     */
    public void clearSession() {
        synchronized (lock) {
            pending.set(null);
            revertible.set(null);
            replays.clear();
        }
    }

    // ------------------------------------------------------------------ inspect

    /**
     * @param sections which parts to return, or null for the default set.
     * @param hosts    hosts to resolve, or null.
     * @return an {@code InspectPage} or a {@code BusinessError}.
     */
    public JsonObject inspect(List<String> sections, List<String> hosts) {
        var disabled = refuseIfUnavailable();
        if (disabled != null) {
            return disabled;
        }

        if (hosts != null) {
            var problem = EffectiveConfigs.hostsProblem(hosts);
            if (problem != null) {
                return Wire.error(Wire.Code.VALIDATION_FAILED,
                        "The hosts to resolve are not acceptable.", List.of(problem), null);
            }
        }

        // A settings answer built from a rules file that cannot be read would be a lie about an
        // empty rule set, so refuse instead. The file is not touched.
        var probe = probeRules();
        if (probe instanceof RuleStore.Probe.Invalid invalid) {
            return Wire.error(Wire.Code.RULE_FILE_INVALID,
                    "The rules file " + invalid.reason() + ". It has been left untouched.",
                    List.of(Wire.ErrorDetail.of("/domainRules", "rule_file_invalid")), null);
        }

        var snapshot = control.snapshot();
        var wanted = sections == null || sections.isEmpty()
                ? defaultSections(hosts)
                : List.copyOf(sections);

        var page = new JsonObject();
        page.addProperty("kind", "inspect_page");
        page.addProperty("schemaVersion", Wire.SCHEMA_VERSION);
        page.addProperty("revision", snapshot.revision());

        var dirty = control.dirtyReasons();
        page.addProperty("dirty", !dirty.isEmpty());
        page.add("dirtyReasons", Wire.strings(dirty));
        page.addProperty("hiddenInvalidRuleCount", snapshot.hiddenInvalidRuleCount());

        var body = new JsonObject();
        if (wanted.contains("settings")) {
            body.add("settings", settingsJson(snapshot.settings()));
        }
        if (wanted.contains("rules")) {
            var rules = new JsonArray();
            // Only usable rules. A row the matcher refuses is one the user is still editing, and
            // showing it would invite a patch that overwrites it.
            for (var rule : snapshot.validRules()) {
                rules.add(ruleJson(rule));
            }
            body.add("rules", rules);
        }
        if (wanted.contains("fingerprints")) {
            body.add("fingerprints", Wire.strings(control.fingerprints().stream().sorted().toList()));
        }
        if (wanted.contains("runtime")) {
            body.add("runtime", Wire.runtimeStates(
                    Analysis.runtimeStates(snapshot, control.runtimeStatus())));
        }
        if (wanted.contains("proposal")) {
            body.add("proposal", proposalStateJson(snapshot.revision()));
        }
        if (wanted.contains("effectiveConfig") && hosts != null) {
            body.add("effectiveConfigs", Wire.effectiveConfigs(
                    EffectiveConfigs.resolveAll(snapshot, hosts)));
        }
        page.add("sections", body);

        // Fail closed: with full audit on, a result that could not be recorded is not returned.
        var recorded = record("MCP_INSPECT", page);
        return recorded == null ? page : recorded;
    }

    private static List<String> defaultSections(List<String> hosts) {
        var sections = new ArrayList<>(List.of("settings", "rules", "fingerprints", "runtime", "proposal"));
        if (hosts != null && !hosts.isEmpty()) {
            sections.add("effectiveConfig");
        }
        return sections;
    }

    private JsonObject proposalStateJson(String revision) {
        var proposal = pending();
        if (proposal == null) {
            var none = new JsonObject();
            none.addProperty("status", "NONE");
            return none;
        }
        return proposal.toStateJson(now(), revision);
    }

    private static JsonObject settingsJson(BusinessSettings settings) {
        var json = new JsonObject();
        // Unredacted, credentials and full ClientHello included. Section 4.2 makes this an
        // explicit, disclosed property rather than an oversight: anything that can reach the
        // loopback port can read it, and the enable warning says so.
        json.addProperty("spoofProxyAddress", settings.spoofProxyAddress());
        json.addProperty("interceptProxyAddress", settings.interceptProxyAddress());
        json.addProperty("burpProxyAddress", settings.burpProxyAddress());
        json.addProperty("fingerprint", settings.fingerprint());
        json.addProperty("hexClientHello", settings.hexClientHello());
        json.addProperty("useInterceptedFingerprint", settings.useInterceptedFingerprint());
        json.addProperty("httpTimeout", settings.httpTimeout());
        json.addProperty("externalProxyUrl", settings.externalProxyUrl());
        return json;
    }

    private static JsonObject ruleJson(burp.FingerprintRule rule) {
        var json = new JsonObject();
        json.addProperty("hostPattern", rule.hostPattern);
        json.addProperty("enabled", rule.enabled);
        json.addProperty("fingerprint", rule.fingerprint);
        json.addProperty("hexClientHello", rule.hexClientHello);
        json.addProperty("externalProxyUrl", rule.externalProxyUrl);
        json.addProperty("note", rule.note);
        if (rule.httpTimeout == null) {
            json.add("httpTimeout", com.google.gson.JsonNull.INSTANCE);
        } else {
            json.addProperty("httpTimeout", rule.httpTimeout);
        }
        return json;
    }

    // ------------------------------------------------------------------ propose

    /**
     * Validates a patch and parks the result for review. Changes nothing.
     *
     * @param arguments the full parsed tool arguments, used for the idempotency digest. The digest
     *                  is taken before any normalization, so the same request id cannot be reused
     *                  to collapse two different intents into one.
     */
    public JsonObject propose(String expectedRevision, String requestId, JsonObject patchJson,
                              List<String> acknowledgements, String summary, JsonObject arguments) {
        var disabled = refuseIfUnavailable();
        if (disabled != null) {
            return disabled;
        }

        var argumentsDigest = Jcs.digest(arguments);
        synchronized (lock) {
            var replay = replays.get(requestId);
            if (replay != null) {
                if (!replay.argumentsDigest().equals(argumentsDigest)) {
                    return Wire.error(Wire.Code.REQUEST_ID_CONFLICT,
                            "Request id \"" + requestId + "\" was already used for a different request.",
                            List.of(Wire.ErrorDetail.of("/requestId", "reused_with_different_arguments")),
                            control.snapshot().revision());
                }
                // A replay is still a call: record it, then return the original answer unchanged.
                var recorded = record("MCP_PROPOSE_REPLAY", replay.result());
                return recorded == null ? replay.result() : recorded;
            }
            if (replays.size() >= MAX_REQUEST_IDS) {
                // Nothing is evicted, because evicting inside a live session would make a replay
                // of an evicted id look like a brand new request.
                return Wire.error(Wire.Code.IDEMPOTENCY_CAPACITY,
                        "This session has already handled " + MAX_REQUEST_IDS
                                + " distinct request ids. Restart AI Control to continue.",
                        List.of(Wire.ErrorDetail.of("/requestId", "capacity_reached")),
                        control.snapshot().revision());
            }
        }

        var built = buildProposal(expectedRevision, patchJson, acknowledgements, summary);
        var isError = built.result().has("kind")
                && built.result().get("kind").getAsString().equals("error");

        // Record first, install second. With full audit on, a proposal must never be observable —
        // and therefore never approvable — before the event describing it is durable; building it
        // and then undoing the installation would leave a window where it was both.
        var recorded = record(isError ? "MCP_PROPOSE_REJECTED" : "MCP_PROPOSE", built.result());
        if (recorded != null) {
            return recorded;
        }

        var result = built.result();
        if (built.proposal() != null) {
            synchronized (lock) {
                if (autoApply.getAsBoolean()) {
                    // The gate is removed, not the pipeline: this is the same commit an Apply
                    // click performs, and it produces the same audit trail and the same undo.
                    result = applyImmediately(built.proposal());
                } else {
                    pending.set(built.proposal());
                }
            }
        }

        synchronized (lock) {
            replays.put(requestId, new Replay(argumentsDigest, result));
        }
        return result;
    }

    /**
     * Commits a freshly built proposal without review.
     *
     * @return the {@code APPLIED} result, or the business error explaining why it was not applied.
     */
    private JsonObject applyImmediately(Proposal proposal) {
        var outcome = applyNow(proposal);
        if (outcome instanceof ApprovalOutcome.Applied applied) {
            var before = proposal.base();
            var diff = Analysis.diff(before, applied.snapshot());
            var json = new JsonObject();
            json.addProperty("kind", "proposal_result");
            json.addProperty("schemaVersion", Wire.SCHEMA_VERSION);
            json.addProperty("status", "APPLIED");
            json.addProperty("proposalId", proposal.id());
            json.addProperty("baseRevision", proposal.baseRevision());
            json.addProperty("revision", applied.snapshot().revision());
            json.addProperty("appliedAt", now().toString());
            json.addProperty("summary", proposal.summary());
            // The diff that was actually committed, which is not always the one proposed: an
            // external edit to the rules file can merge cleanly and change the outcome.
            json.add("diff", Wire.changes(diff));
            json.add("riskFlags", Wire.risks(Analysis.risks(before, applied.snapshot(), diff)));
            json.add("runtimeImpact", Wire.impacts(
                    Analysis.impact(diff, control.runtimeStatus())));
            return json;
        }
        var refused = (ApprovalOutcome.Refused) outcome;
        return Wire.error(refused.code(), refused.message(), refused.details(),
                control.snapshot().revision());
    }

    /**
     * @param proposal the proposal to install once the result has been recorded, or null when the
     *                 call produced an error or changed nothing.
     */
    private record Built(JsonObject result, Proposal proposal) {
        static Built of(JsonObject result) {
            return new Built(result, null);
        }
    }

    private Built buildProposal(String expectedRevision, JsonObject patchJson,
                                List<String> acknowledgements, String summary) {
        var dirty = control.dirtyReasons();
        if (!dirty.isEmpty()) {
            return Built.of(Wire.error(Wire.Code.DIRTY_UI,
                    "The settings tab has unsaved edits; save or discard them first.",
                    dirty.stream().map(reason -> Wire.ErrorDetail.of("/ui", reason)).toList(),
                    control.snapshot().revision()));
        }

        var existing = pending();
        if (existing != null && (existing.status() == Proposal.Status.PENDING
                || existing.status() == Proposal.Status.CONFLICTED)) {
            return Built.of(Wire.error(Wire.Code.PROPOSAL_PENDING,
                    "A proposal is already waiting for review in Burp.",
                    List.of(Wire.ErrorDetail.of("/proposal", "another_proposal_is_pending")),
                    control.snapshot().revision()));
        }

        var base = control.snapshot();
        if (!base.revision().equals(expectedRevision)) {
            return Built.of(Wire.error(Wire.Code.REVISION_CONFLICT,
                    "The committed settings revision changed.",
                    List.of(Wire.ErrorDetail.mismatch("/expectedRevision",
                            "does_not_match_committed_revision", expectedRevision, base.revision())),
                    base.revision()));
        }

        var probe = probeRules();
        String observedRulesDigest = null;
        if (probe instanceof RuleStore.Probe.Invalid invalid) {
            return Built.of(Wire.error(Wire.Code.RULE_FILE_INVALID,
                    "The rules file " + invalid.reason() + ". It has been left untouched.",
                    List.of(Wire.ErrorDetail.of("/domainRules", "rule_file_invalid")), base.revision()));
        } else if (probe instanceof RuleStore.Probe.Loaded loaded) {
            observedRulesDigest = loaded.rawDigest();
            var onDisk = SettingsSnapshot.of(base.settings(), loaded.rules());
            if (!onDisk.revision().equals(base.revision())) {
                return Built.of(Wire.error(Wire.Code.EXTERNAL_DIVERGENCE,
                        "The rules file was changed outside Burp; reload the settings first.",
                        List.of(Wire.ErrorDetail.mismatch("/domainRules", "rules_file_changed_externally",
                                base.revision(), onDisk.revision())), base.revision()));
            }
        }

        var parsed = SettingsPatch.parse(patchJson, acknowledgements);
        if (parsed instanceof SettingsPatch.Parsed.Failed failure) {
            return Built.of(Wire.error(failure.code(), failure.message(), failure.details(),
                    base.revision()));
        }
        var patch = ((SettingsPatch.Parsed.Ok) parsed).patch();

        var hiddenConflicts = patch.hiddenRuleConflicts(base);
        if (!hiddenConflicts.isEmpty()) {
            return Built.of(Wire.error(Wire.Code.HIDDEN_RULE_CONFLICT,
                    "This proposal names " + hiddenConflicts.size() + " host(s) that match a rule the "
                            + "settings tab is holding but cannot use. Fix or remove those rows in Burp first.",
                    hiddenConflicts.stream()
                            .map(key -> Wire.ErrorDetail.of(Validation.rulePath(key, "hostPattern"),
                                    "conflicts_with_a_hidden_rule"))
                            .toList(), base.revision()));
        }

        var missing = patch.missingRemovals(base);
        if (!missing.isEmpty()) {
            return Built.of(Wire.error(Wire.Code.VALIDATION_FAILED,
                    "This proposal removes rules that do not exist.",
                    missing.stream()
                            .map(key -> Wire.ErrorDetail.of(Validation.rulePath(key, "hostPattern"),
                                    "no_such_rule"))
                            .toList(), base.revision()));
        }

        var candidate = patch.applyTo(base);

        var problems = new ArrayList<>(
                Validation.settings(candidate.settings(), control.fingerprints(),
                        Validation.Policy.AI_PROPOSAL));
        // Catalog checks apply only to rules the patch touched, so a pre-existing rule naming a
        // fingerprint this build does not offer cannot block an unrelated change.
        for (var upsert : patch.upserts()) {
            // Deliberately not ruleByKey: that only finds rows the candidate can use, so a rule the
            // patch has just made unusable would be validated by finding nothing, then committed as
            // a row that is hidden on arrival and reported with an empty diff.
            var rule = candidate.storedRuleWithKey(upsert.key());
            if (rule != null) {
                problems.addAll(Validation.rule(rule, 0, control.fingerprints(),
                        Validation.Policy.AI_PROPOSAL));
            }
        }
        // The backstop for anything the per-rule pass cannot name — a host pattern too broken to
        // look up by key, or a duplicate that disables both claimants. A proposal that adds a row
        // the settings cannot use is a proposal whose diff does not describe what it did.
        if (candidate.hiddenInvalidRuleCount() > base.hiddenInvalidRuleCount() && problems.isEmpty()) {
            return Built.of(Wire.error(Wire.Code.VALIDATION_FAILED,
                    "This proposal adds a rule the settings cannot use, so it would be stored but "
                            + "never match.", List.of(Wire.ErrorDetail.of("/patch/domainRules/upsert",
                            "would_be_hidden")), base.revision()));
        }
        if (!problems.isEmpty()) {
            return Built.of(Wire.error(Wire.Code.VALIDATION_FAILED,
                    "The proposed settings are not valid: " + problems.get(0).message(),
                    problems.stream().map(p -> Wire.ErrorDetail.of(p.path(), p.reason())).toList(),
                    base.revision()));
        }

        var ambiguities = patch.ambiguities(base, candidate);
        if (!ambiguities.isEmpty()) {
            return Built.of(Wire.error(Wire.Code.AMBIGUOUS_FINGERPRINT_HEX,
                    "The fingerprint and ClientHello settings interact; say explicitly which value "
                            + "you intend to take effect.", ambiguities, base.revision()));
        }

        if (candidate.revision().equals(base.revision())) {
            // A success, not an error: the patch was understood and normalized to nothing. It takes
            // no pending slot and produces no new revision.
            var unchanged = new JsonObject();
            unchanged.addProperty("kind", "proposal_result");
            unchanged.addProperty("schemaVersion", Wire.SCHEMA_VERSION);
            unchanged.addProperty("status", "NO_CHANGES");
            unchanged.addProperty("revision", base.revision());
            unchanged.add("diff", new JsonArray());
            unchanged.add("riskFlags", new JsonArray());
            unchanged.add("runtimeImpact", new JsonArray());
            return Built.of(unchanged);
        }

        var diff = Analysis.diff(base, candidate);
        var proposal = new Proposal(base, candidate, patch, summary, observedRulesDigest, diff,
                Analysis.risks(base, candidate, diff),
                Analysis.impact(diff, control.runtimeStatus()), now());

        // Deliberately not installed here; the caller installs it once it has been recorded.
        return new Built(proposal.toResultJson(), proposal);
    }

    // ------------------------------------------------------------------ approve, reject, revert

    /**
     * The outcome of a local approval.
     */
    public sealed interface ApprovalOutcome {
        record Applied(SettingsSnapshot snapshot) implements ApprovalOutcome {
        }

        /**
         * An external edit merged cleanly, but changed the result. The user has to look again.
         */
        record NeedsReview(Proposal proposal) implements ApprovalOutcome {
        }

        record Refused(Wire.Code code, String message, List<Wire.ErrorDetail> details)
                implements ApprovalOutcome {
        }
    }

    /**
     * Applies a proposal. Only ever called from the Burp UI.
     *
     * @param expectedDigest the digest the user was shown. Everything they looked at is in it, so a
     *                       mismatch means the change on screen is not the change about to happen.
     */
    public ApprovalOutcome approve(String proposalId, String expectedDigest) {
        synchronized (lock) {
            var proposal = pending();
            if (proposal == null || !proposal.id().equals(proposalId)) {
                return refuse(Wire.Code.EXPIRED, "That proposal is no longer available.", "/proposalId");
            }
            if (proposal.status() != Proposal.Status.PENDING) {
                return refuse(Wire.Code.EXPIRED, "That proposal is no longer pending.", "/proposalId");
            }
            if (proposal.expired(now())) {
                proposal.expire(now());
                return refuse(Wire.Code.EXPIRED, "That proposal expired before it was applied.", "/proposalId");
            }
            if (!proposal.digest().equals(expectedDigest)) {
                return refuse(Wire.Code.REVISION_CONFLICT,
                        "The proposal changed since it was displayed; review it again.", "/proposalDigest");
            }
            return commitProposal(proposal, true);
        }
    }

    /**
     * Applies a proposal that has just been built, with no review.
     * <p>
     * Reached only when auto-apply is armed. It is the same commit an Apply click performs — the
     * gate is what was removed, not any of the checking — so a dirty settings tab, a revision that
     * moved, an unreadable rules file or a genuine merge conflict all still stop it.
     */
    private ApprovalOutcome applyNow(Proposal proposal) {
        return commitProposal(proposal, false);
    }

    /**
     * @param reviewable whether a clean merge that changes the outcome should go back for another
     *                   look. It should when a person is watching, because what they confirmed is
     *                   no longer what would happen. With auto-apply there is nobody to ask, so the
     *                   merged result is committed and the caller is told what actually landed.
     */
    private ApprovalOutcome commitProposal(Proposal proposal, boolean reviewable) {
        var dirty = control.dirtyReasons();
        if (!dirty.isEmpty()) {
            return new ApprovalOutcome.Refused(Wire.Code.DIRTY_UI,
                    "The settings tab has unsaved edits; save or discard them first.",
                    dirty.stream().map(r -> Wire.ErrorDetail.of("/ui", r)).toList());
        }

        var current = control.snapshot();
        if (!current.revision().equals(proposal.baseRevision())) {
            proposal.conflict(Wire.Code.REVISION_CONFLICT,
                    List.of(Wire.ErrorDetail.mismatch("/baseRevision", "settings_changed_since_proposal",
                            proposal.baseRevision(), current.revision())), now());
            return refuse(Wire.Code.REVISION_CONFLICT,
                    "The settings changed after this proposal was created.", "/baseRevision");
        }

        var probe = probeRules();
        if (probe instanceof RuleStore.Probe.Invalid invalid) {
            proposal.conflict(Wire.Code.EXTERNAL_DIVERGENCE,
                    List.of(Wire.ErrorDetail.of("/domainRules", "rule_file_invalid")), now());
            return refuse(Wire.Code.RULE_FILE_INVALID,
                    "The rules file " + invalid.reason() + ". It has been left untouched.",
                    "/domainRules");
        }

        var onDisk = probe instanceof RuleStore.Probe.Loaded loaded
                ? SettingsSnapshot.of(current.settings(), loaded.rules())
                : SettingsSnapshot.of(current.settings(), List.of());
        var observedDigest = probe instanceof RuleStore.Probe.Loaded loaded ? loaded.rawDigest() : null;

        var candidate = proposal.candidate();
        if (!onDisk.revision().equals(current.revision())) {
            // Someone edited the file. Merge per field rather than choosing a side.
            var merge = ThreeWayMerge.merge(proposal.base(), onDisk, candidate);
            if (merge instanceof ThreeWayMerge.Result.Divergence divergence) {
                proposal.conflict(Wire.Code.EXTERNAL_DIVERGENCE, divergence.details(), now());
                return new ApprovalOutcome.Refused(Wire.Code.EXTERNAL_DIVERGENCE,
                        "The rules file was edited outside Burp in a way that cannot be merged.",
                        divergence.details());
            }
            if (merge instanceof ThreeWayMerge.Result.Conflict conflict) {
                proposal.conflict(Wire.Code.MERGE_CONFLICT, conflict.details(), now());
                return new ApprovalOutcome.Refused(Wire.Code.MERGE_CONFLICT,
                        "The proposal and the rules file changed the same field.", conflict.details());
            }

            var merged = (ThreeWayMerge.Result.Merged) merge;
            candidate = SettingsSnapshot.of(candidate.settings(), merged.rules());
            if (merged.changedFromProposed() && reviewable) {
                // What the user confirmed is not what would now be applied.
                var diff = Analysis.diff(current, candidate);
                var regenerated = proposal.reviewed(candidate, diff,
                        Analysis.risks(current, candidate, diff),
                        Analysis.impact(diff, control.runtimeStatus()), observedDigest);
                pending.set(regenerated);
                return new ApprovalOutcome.NeedsReview(regenerated);
            }
        }

        var outcome = control.commit(candidate, TransactionJournal.Source.AI_APPLY);
        if (outcome instanceof SettingsControl.Outcome.Committed committed) {
            pending.set(null);
            revertible.set(new Revertible(current, committed.snapshot().revision()));
            return new ApprovalOutcome.Applied(committed.snapshot());
        }
        if (outcome instanceof SettingsControl.Outcome.RecoveryRequired recovery) {
            return new ApprovalOutcome.Refused(Wire.Code.RECOVERY_REQUIRED, recovery.message(), List.of());
        }
        var failed = (SettingsControl.Outcome.Failed) outcome;
        return new ApprovalOutcome.Refused(failed.code(), failed.message(), failed.details());
    }

    private static ApprovalOutcome refuse(Wire.Code code, String message, String path) {
        return new ApprovalOutcome.Refused(code, message,
                List.of(Wire.ErrorDetail.of(path, code.name().toLowerCase(java.util.Locale.ROOT))));
    }

    public void reject(String proposalId, String reason) {
        synchronized (lock) {
            var proposal = pending();
            if (proposal != null && proposal.id().equals(proposalId)) {
                proposal.reject(reason, now());
                var body = new JsonObject();
                body.addProperty("proposalId", proposalId);
                body.addProperty("reason", proposal.statusReason());
                record("PROPOSAL_REJECTED", body);
            }
        }
    }

    /**
     * @return whether the most recent AI change can still be taken back.
     */
    public boolean canRevert() {
        var candidate = revertible.get();
        return candidate != null && control.snapshot().revision().equals(candidate.afterRevision());
    }

    public SettingsSnapshot revertTarget() {
        var candidate = revertible.get();
        return candidate == null ? null : candidate.before();
    }

    /**
     * Puts the settings back to what they were before the most recent AI change.
     * <p>
     * A normal committed change in its own right — validated, journalled, audited, and producing a
     * new revision — not a rewind. Reconstructing state from the audit trail was rejected in
     * section 13: the audit file is a record, and treating it as a source of truth for restoring
     * settings makes a damaged one into a settings problem.
     */
    public ApprovalOutcome revert() {
        synchronized (lock) {
            if (!canRevert()) {
                return refuse(Wire.Code.EXPIRED,
                        "There is nothing to revert; the settings have changed since the last AI change.",
                        "/revert");
            }
            var dirty = control.dirtyReasons();
            if (!dirty.isEmpty()) {
                return new ApprovalOutcome.Refused(Wire.Code.DIRTY_UI,
                        "The settings tab has unsaved edits; save or discard them first.",
                        dirty.stream().map(r -> Wire.ErrorDetail.of("/ui", r)).toList());
            }

            var target = revertible.get().before();
            var outcome = control.commit(target, TransactionJournal.Source.AI_REVERT);
            if (outcome instanceof SettingsControl.Outcome.Committed committed) {
                revertible.set(null);
                return new ApprovalOutcome.Applied(committed.snapshot());
            }
            if (outcome instanceof SettingsControl.Outcome.RecoveryRequired recovery) {
                return new ApprovalOutcome.Refused(Wire.Code.RECOVERY_REQUIRED, recovery.message(), List.of());
            }
            var failed = (SettingsControl.Outcome.Failed) outcome;
            return new ApprovalOutcome.Refused(failed.code(), failed.message(), failed.details());
        }
    }

    /**
     * Any committed change that is not the AI's own result invalidates the undo.
     */
    public void onCommitted(SettingsSnapshot snapshot) {
        var candidate = revertible.get();
        if (candidate != null && !snapshot.revision().equals(candidate.afterRevision())) {
            revertible.set(null);
        }
    }

    // ------------------------------------------------------------------ helpers

    private RuleStore.Probe probeRules() {
        return control.probeRuleFile();
    }

    private JsonObject refuseIfUnavailable() {
        if (!controlEnabled.getAsBoolean()) {
            return Wire.error(Wire.Code.CONTROL_DISABLED,
                    "AI Control is switched off in Burp.",
                    List.of(Wire.ErrorDetail.of("/aiControl", "disabled")), null);
        }
        var blocked = control.blockedReason();
        if (blocked != null) {
            return Wire.error(Wire.Code.RECOVERY_REQUIRED, blocked,
                    List.of(Wire.ErrorDetail.of("/settings", "recovery_required")), null);
        }
        return null;
    }

    /**
     * Records a result when full audit is on.
     *
     * @return null when there was nothing to do or the record was written, otherwise an
     * {@code AUDIT_UNAVAILABLE} error to return in place of the result.
     */
    private JsonObject record(String type, JsonObject payload) {
        if (!auditEnabled.getAsBoolean()) {
            return null;
        }
        try {
            var body = new JsonObject();
            body.add("result", payload);
            audit.append(type, body);
            return null;
        } catch (IOException e) {
            return Wire.error(Wire.Code.AUDIT_UNAVAILABLE,
                    "Full audit is switched on and this call could not be recorded, so no result "
                            + "was returned: " + e,
                    List.of(Wire.ErrorDetail.of("/audit", "append_failed")), null);
        }
    }
}
