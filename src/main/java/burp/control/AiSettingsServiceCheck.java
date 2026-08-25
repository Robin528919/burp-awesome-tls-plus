package burp.control;

import burp.FingerprintRule;
import burp.RuleStore;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Self-check for {@link AiSettingsService}: the boundary between what an AI may do and what only a
 * person may do.
 * <p>
 * The cases that matter most are the negative ones. A patch that names a field it should not, a
 * proposal approved after the settings moved underneath it, a replayed request id carrying
 * different arguments — each of those, allowed through, changes a setting nobody agreed to.
 * <p>
 * Run with:
 * {@code java -ea -cp build/classes/java/main:<gson.jar> burp.control.AiSettingsServiceCheck}
 */
public final class AiSettingsServiceCheck {
    private AiSettingsServiceCheck() {
    }

    public static void main(String[] args) throws Exception {
        inspectHasNoSideEffects();
        inspectReportsWhatItShould();
        inspectHidesUnusableRows();
        proposeChangesNothing();
        unauthorizedPatchesAreRefused();
        ambiguousFingerprintChangesAreRefused();
        hiddenRowConflictsAreRefused();
        revisionMustMatch();
        onlyOnePendingProposal();
        requestIdsAreIdempotent();
        dirtyUiBlocksEverything();
        approvalRequiresTheDigestTheUserSaw();
        expiredProposalsCannotBeApplied();
        externalEditsMergeOrStop();
        corruptRulesFileIsNeverTouched();
        revertIsLimitedToTheLastAiChange();
        auditFailureFailsClosed();
        controlDisabledRefusesEverything();

        System.out.println("AiSettingsService self-check passed");
    }

    // ------------------------------------------------------------------ inspect

    private static void inspectHasNoSideEffects() throws Exception {
        var f = Fixture.create();
        f.seedRule("a.com");
        var before = f.control.snapshot().revision();
        var rulesBefore = Files.readAllBytes(f.rulesPath);

        f.service.inspect(null, List.of("a.com", "other.com"));

        check(f.control.snapshot().revision().equals(before), "inspect does not change the revision");
        check(java.util.Arrays.equals(rulesBefore, Files.readAllBytes(f.rulesPath)),
                "inspect does not touch the rules file");
        check(!f.journal.exists(), "and writes no journal");
    }

    private static void inspectReportsWhatItShould() throws Exception {
        var f = Fixture.create();
        f.seedRule("a.com");

        var page = f.service.inspect(null, List.of("a.com"));
        check(page.get("kind").getAsString().equals("inspect_page"), "the result is an inspect page");
        check(page.get("revision").getAsString().equals(f.control.snapshot().revision()),
                "carrying the current revision");
        check(!page.get("dirty").getAsBoolean(), "and the UI state");

        var sections = page.getAsJsonObject("sections");
        check(sections.has("settings") && sections.has("rules") && sections.has("fingerprints")
                && sections.has("runtime") && sections.has("proposal"),
                "the default sections are all present");
        check(sections.has("effectiveConfigs"), "and effective config appears when hosts are given");
        check(sections.getAsJsonObject("proposal").get("status").getAsString().equals("NONE"),
                "with no proposal outstanding");

        // Values are returned in full, which is a disclosed property of this feature.
        f.commitSettings(BusinessSettings.defaults()
                .withExternalProxyUrl("http://user:hunter2@127.0.0.1:8080")
                .withHexClientHello("aabbccdd"));
        var full = f.service.inspect(List.of("settings"), null)
                .getAsJsonObject("sections").getAsJsonObject("settings");
        check(full.get("externalProxyUrl").getAsString().contains("hunter2"),
                "proxy credentials are returned unredacted, as documented");
        check(full.get("hexClientHello").getAsString().equals("aabbccdd"),
                "and so is the full ClientHello");

        var only = f.service.inspect(List.of("settings"), null).getAsJsonObject("sections");
        check(only.has("settings") && !only.has("rules"), "an explicit section list is honoured");
    }

    private static void inspectHidesUnusableRows() throws Exception {
        var f = Fixture.create();
        f.commitRules(List.of(
                new FingerprintRule("good.com", "chrome", "", "", null, true),
                new FingerprintRule("", "chrome", "", "", null, true)));

        var page = f.service.inspect(List.of("rules"), null);
        check(page.get("hiddenInvalidRuleCount").getAsInt() == 1, "the unusable row is counted");
        check(page.getAsJsonObject("sections").getAsJsonArray("rules").size() == 1,
                "but not listed, so a patch cannot overwrite what the user is still typing");
    }

    // ------------------------------------------------------------------ propose

    private static void proposeChangesNothing() throws Exception {
        var f = Fixture.create();
        var before = f.control.snapshot().revision();
        var rulesBefore = Files.exists(f.rulesPath) ? Files.readAllBytes(f.rulesPath) : new byte[0];

        var result = f.propose("r1", "{\"settings\":{\"httpTimeout\":45}}");
        check(result.get("status").getAsString().equals("PENDING"), "a valid patch produces a proposal");
        check(f.control.snapshot().revision().equals(before), "and changes nothing");
        check(f.preferences.read().httpTimeout() != 45, "the stored settings are untouched");
        check(java.util.Arrays.equals(rulesBefore,
                        Files.exists(f.rulesPath) ? Files.readAllBytes(f.rulesPath) : new byte[0]),
                "and so is the rules file");
        check(f.service.pending() != null, "the proposal is parked for review");

        check(result.has("diff") && result.getAsJsonArray("diff").size() == 1, "with a full diff");
        check(result.has("runtimeImpact"), "and its runtime impact");
        check(Jcs.isDigest(result.get("proposalDigest").getAsString()), "and a digest to approve against");

        // A patch that normalizes to nothing is a success, not an error, and takes no slot.
        var g = Fixture.create();
        var noop = g.propose("r1", "{\"settings\":{\"httpTimeout\":"
                + BusinessSettings.DEFAULT_HTTP_TIMEOUT + "}}");
        check(noop.get("status").getAsString().equals("NO_CHANGES"), "an empty change reports NO_CHANGES");
        check(g.service.pending() == null, "and does not occupy the pending slot");
    }

    private static void unauthorizedPatchesAreRefused() throws Exception {
        var f = Fixture.create();

        // Request-only transport fields are not settings and can never be proposed.
        rejects(f, "{\"settings\":{\"Host\":\"example.com\"}}", Wire.Code.VALIDATION_FAILED, "a request Host");
        rejects(f, "{\"settings\":{\"HeaderOrder\":\"a\"}}", Wire.Code.VALIDATION_FAILED, "a header order");
        rejects(f, "{\"settings\":{\"Scheme\":\"https\"}}", Wire.Code.VALIDATION_FAILED, "a scheme");

        rejects(f, "{\"settings\":{\"nope\":1}}", Wire.Code.VALIDATION_FAILED, "an unknown setting");
        rejects(f, "{\"nope\":{}}", Wire.Code.VALIDATION_FAILED, "an unknown patch section");
        rejects(f, "{}", Wire.Code.VALIDATION_FAILED, "an empty patch");

        // No wholesale rule replacement: it would delete rows the caller never saw.
        rejects(f, "{\"domainRules\":{\"replaceAll\":[]}}", Wire.Code.VALIDATION_FAILED,
                "wholesale rule replacement");

        // Global-only settings cannot vary per host.
        rejects(f, "{\"domainRules\":{\"upsert\":[{\"hostPattern\":\"a.com\","
                + "\"useInterceptedFingerprint\":true}]}}", Wire.Code.VALIDATION_FAILED,
                "the intercept toggle inside a rule");
        rejects(f, "{\"domainRules\":{\"upsert\":[{\"hostPattern\":\"a.com\","
                + "\"burpProxyAddress\":\"127.0.0.1:1\"}]}}", Wire.Code.VALIDATION_FAILED,
                "a proxy address inside a rule");

        rejects(f, "{\"settings\":{\"httpTimeout\":0}}", Wire.Code.VALIDATION_FAILED, "a timeout below range");
        rejects(f, "{\"settings\":{\"httpTimeout\":3601}}", Wire.Code.VALIDATION_FAILED, "a timeout above range");
        rejects(f, "{\"settings\":{\"spoofProxyAddress\":\"nope\"}}", Wire.Code.VALIDATION_FAILED,
                "an address that is not host:port");
        rejects(f, "{\"settings\":{\"externalProxyUrl\":\"ftp://h:1\"}}", Wire.Code.VALIDATION_FAILED,
                "a proxy scheme the Go dialer cannot use");
        rejects(f, "{\"settings\":{\"hexClientHello\":\"abc\"}}", Wire.Code.VALIDATION_FAILED,
                "odd-length hex");
        rejects(f, "{\"settings\":{\"fingerprint\":\"nosuchprofile\"}}", Wire.Code.VALIDATION_FAILED,
                "an unknown fingerprint");
        rejects(f, "{\"settings\":{\"fingerprint\":null}}", Wire.Code.VALIDATION_FAILED,
                "clearing a field that always has a value");

        rejects(f, "{\"domainRules\":{\"upsert\":[{\"hostPattern\":\"http://x.com\",\"enabled\":true}]}}",
                Wire.Code.VALIDATION_FAILED, "a host pattern that is a URL");
        rejects(f, "{\"domainRules\":{\"upsert\":[{\"hostPattern\":\"a.*.com\",\"enabled\":true}]}}",
                Wire.Code.VALIDATION_FAILED, "an unsupported wildcard");
        rejects(f, "{\"domainRules\":{\"upsert\":[{\"hostPattern\":\"a.com\"}]}}",
                Wire.Code.VALIDATION_FAILED, "an upsert that changes nothing");

        // The same host twice in one proposal has no defined order.
        rejects(f, "{\"domainRules\":{\"upsert\":[{\"hostPattern\":\"a.com\",\"enabled\":true},"
                + "{\"hostPattern\":\"A.COM\",\"enabled\":false}]}}", Wire.Code.VALIDATION_FAILED,
                "the same host upserted twice");
        rejects(f, "{\"domainRules\":{\"upsert\":[{\"hostPattern\":\"a.com\",\"enabled\":true}],"
                + "\"remove\":[\"a.com\"]}}", Wire.Code.VALIDATION_FAILED,
                "a host both upserted and removed");
        rejects(f, "{\"domainRules\":{\"remove\":[\"missing.com\"]}}", Wire.Code.VALIDATION_FAILED,
                "removing a rule that is not there");

        // The bulk ceiling.
        var many = new StringBuilder("{\"domainRules\":{\"upsert\":[");
        for (var i = 0; i <= SettingsPatch.MAX_RULE_CHANGES; i++) {
            if (i > 0) many.append(',');
            many.append("{\"hostPattern\":\"h").append(i).append(".com\",\"enabled\":true}");
        }
        rejects(f, many.append("]}}").toString(), Wire.Code.VALIDATION_FAILED,
                "more than " + SettingsPatch.MAX_RULE_CHANGES + " rule changes");

        check(f.service.pending() == null, "no rejected patch ever occupies the pending slot");
        check(f.control.snapshot().revision().equals(SettingsSnapshot.empty().revision()),
                "and none of them changed anything");
    }

    private static void ambiguousFingerprintChangesAreRefused() throws Exception {
        var f = Fixture.create();

        // Setting a hex ClientHello silently stops the fingerprint from being used; say so.
        var result = f.propose("r1", "{\"settings\":{\"hexClientHello\":\"aabb\"}}");
        check(codeOf(result) == Wire.Code.AMBIGUOUS_FINGERPRINT_HEX,
                "setting a global hex without acknowledging its precedence is refused");

        var acknowledged = f.propose("r2", "{\"settings\":{\"hexClientHello\":\"aabb\"}}",
                List.of("GLOBAL_HEX_OVERRIDES_FINGERPRINT"));
        check(acknowledged.get("status").getAsString().equals("PENDING"), "acknowledging it is enough");
        f.applyPending();

        // Now changing the fingerprint would have no observable effect at all.
        var pointless = f.propose("r3", "{\"settings\":{\"fingerprint\":\"firefox\"}}");
        check(codeOf(pointless) == Wire.Code.AMBIGUOUS_FINGERPRINT_HEX,
                "changing a fingerprint that hex overrides is refused rather than silently stored");

        // Clearing the hex in the same patch makes the intent unambiguous.
        var paired = f.propose("r4",
                "{\"settings\":{\"fingerprint\":\"firefox\",\"hexClientHello\":null}}");
        check(paired.get("status").getAsString().equals("PENDING"),
                "changing both together is accepted");

        // A rule fingerprint suppresses the inherited global hex for that host.
        var g = Fixture.create();
        g.commitSettings(BusinessSettings.defaults().withHexClientHello("ccdd"));
        var suppressing = g.propose("r1",
                "{\"domainRules\":{\"upsert\":[{\"hostPattern\":\"a.com\",\"fingerprint\":\"chrome\"}]}}");
        check(codeOf(suppressing) == Wire.Code.AMBIGUOUS_FINGERPRINT_HEX,
                "a rule fingerprint that suppresses the global hex must be acknowledged");
        var ok = g.propose("r2",
                "{\"domainRules\":{\"upsert\":[{\"hostPattern\":\"a.com\",\"fingerprint\":\"chrome\"}]}}",
                List.of("RULE_FINGERPRINT_SUPPRESSES_INHERITED_HEX"));
        check(ok.get("status").getAsString().equals("PENDING"), "and then it is accepted");
    }

    private static void hiddenRowConflictsAreRefused() throws Exception {
        var f = Fixture.create();
        // A row the user is midway through typing, which normalizes to a real host.
        f.commitRules(List.of(
                new FingerprintRule("draft.com", "chrome", "zz", "", null, true),
                new FingerprintRule("fine.com", "chrome", "", "", null, true)));
        check(f.control.snapshot().hiddenInvalidRuleCount() == 1, "the bad hex makes that row unusable");

        var result = f.propose("r1",
                "{\"domainRules\":{\"upsert\":[{\"hostPattern\":\"draft.com\",\"enabled\":false}]}}");
        check(codeOf(result) == Wire.Code.HIDDEN_RULE_CONFLICT,
                "a patch naming a hidden row is refused rather than overwriting it");

        var removing = f.propose("r2", "{\"domainRules\":{\"remove\":[\"draft.com\"]}}");
        check(codeOf(removing) == Wire.Code.HIDDEN_RULE_CONFLICT, "and so is removing it");

        // Unrelated changes still work while a hidden row exists.
        var unrelated = f.propose("r3",
                "{\"domainRules\":{\"upsert\":[{\"hostPattern\":\"fine.com\",\"enabled\":false}]}}");
        check(unrelated.get("status").getAsString().equals("PENDING"),
                "a hidden row does not block unrelated changes");
    }

    private static void revisionMustMatch() throws Exception {
        var f = Fixture.create();
        var stale = f.control.snapshot().revision();
        f.commitSettings(BusinessSettings.defaults().withHttpTimeout(99));

        var result = f.service.propose(stale, "r1", patch("{\"settings\":{\"httpTimeout\":45}}"),
                List.of(), "", arguments(stale, "r1", "{\"settings\":{\"httpTimeout\":45}}"));
        check(codeOf(result) == Wire.Code.REVISION_CONFLICT, "a stale revision is refused");
        check(result.get("currentRevision").getAsString().equals(f.control.snapshot().revision()),
                "and the caller is told the current one");
        check(result.get("retryable").getAsBoolean(), "so it can retry");
    }

    private static void onlyOnePendingProposal() throws Exception {
        var f = Fixture.create();
        f.propose("r1", "{\"settings\":{\"httpTimeout\":45}}");
        var second = f.propose("r2", "{\"settings\":{\"httpTimeout\":46}}");
        check(codeOf(second) == Wire.Code.PROPOSAL_PENDING, "a second proposal is refused while one waits");

        f.service.reject(f.service.pending().id(), "no thanks");
        var third = f.propose("r3", "{\"settings\":{\"httpTimeout\":47}}");
        check(third.get("status").getAsString().equals("PENDING"), "rejecting the first frees the slot");

        // A rejection stays visible to the caller until something replaces it.
        var g = Fixture.create();
        g.propose("r1", "{\"settings\":{\"httpTimeout\":45}}");
        var id = g.service.pending().id();
        g.service.reject(id, "not now");
        var state = g.service.inspect(List.of("proposal"), null)
                .getAsJsonObject("sections").getAsJsonObject("proposal");
        check(state.get("status").getAsString().equals("REJECTED"), "the rejection is reported");
        check(state.get("reason").getAsString().equals("not now"), "with the reason given in Burp");
    }

    private static void requestIdsAreIdempotent() throws Exception {
        var f = Fixture.create();
        var body = "{\"settings\":{\"httpTimeout\":45}}";

        var first = f.propose("same", body);
        var again = f.propose("same", body);
        check(again.get("proposalId").getAsString().equals(first.get("proposalId").getAsString()),
                "replaying a request id returns the original result");
        check(f.service.pending().id().equals(first.get("proposalId").getAsString()),
                "without creating a second proposal");

        // The same id with different arguments is a mistake, not a retry.
        var conflicting = f.propose("same", "{\"settings\":{\"httpTimeout\":46}}");
        check(codeOf(conflicting) == Wire.Code.REQUEST_ID_CONFLICT,
                "the same id with different arguments is refused");
        check(!conflicting.get("retryable").getAsBoolean(), "and retrying will not help");

        // Whitespace and key order do not make a different request.
        var g = Fixture.create();
        g.propose("k", "{\"settings\":{\"httpTimeout\":45,\"fingerprint\":\"chrome\"}}");
        var reordered = g.propose("k", "{ \"settings\" : { \"fingerprint\":\"chrome\" ,\"httpTimeout\" : 45 } }");
        check(reordered.has("proposalId"), "reformatting the same request is still the same request");

        // Switching AI Control off clears the session, ids included.
        g.service.clearSession();
        check(g.service.pending() == null, "clearing the session drops the pending proposal");
    }

    private static void dirtyUiBlocksEverything() throws Exception {
        var f = Fixture.create();
        f.propose("r1", "{\"settings\":{\"httpTimeout\":45}}");
        var proposal = f.service.pending();

        f.dirty.set(true);

        var page = f.service.inspect(null, null);
        check(page.get("dirty").getAsBoolean(), "inspect reports the unsaved edit");
        check(page.getAsJsonArray("dirtyReasons").size() > 0, "and why");

        var blocked = f.propose("r2", "{\"settings\":{\"httpTimeout\":46}}");
        check(codeOf(blocked) == Wire.Code.DIRTY_UI, "propose is refused");

        var approval = f.service.approve(proposal.id(), proposal.digest());
        check(approval instanceof AiSettingsService.ApprovalOutcome.Refused, "and so is approval");
        check(((AiSettingsService.ApprovalOutcome.Refused) approval).code() == Wire.Code.DIRTY_UI,
                "because the tab has a draft in it");
        check(f.control.snapshot().settings().httpTimeout() != 45, "nothing was applied");
    }

    private static void approvalRequiresTheDigestTheUserSaw() throws Exception {
        var f = Fixture.create();
        f.propose("r1", "{\"settings\":{\"httpTimeout\":45}}");
        var proposal = f.service.pending();

        var wrong = f.service.approve(proposal.id(), "sha256:" + "0".repeat(64));
        check(wrong instanceof AiSettingsService.ApprovalOutcome.Refused, "a mismatched digest is refused");
        check(f.control.snapshot().settings().httpTimeout() != 45, "and nothing is applied");

        var unknown = f.service.approve("not-a-proposal", proposal.digest());
        check(unknown instanceof AiSettingsService.ApprovalOutcome.Refused, "an unknown id is refused");

        var applied = f.service.approve(proposal.id(), proposal.digest());
        check(applied instanceof AiSettingsService.ApprovalOutcome.Applied, "the right digest applies it");
        check(f.control.snapshot().settings().httpTimeout() == 45, "and the change takes effect");
        check(f.preferences.read().httpTimeout() == 45, "and is stored");
        check(f.service.pending() == null, "the slot is freed");

        var twice = f.service.approve(proposal.id(), proposal.digest());
        check(twice instanceof AiSettingsService.ApprovalOutcome.Refused, "applying twice is refused");
    }

    private static void expiredProposalsCannotBeApplied() throws Exception {
        var f = Fixture.create();
        f.propose("r1", "{\"settings\":{\"httpTimeout\":45}}");
        var proposal = f.service.pending();

        f.clock.advance(Proposal.TTL.plusSeconds(1));

        var outcome = f.service.approve(proposal.id(), proposal.digest());
        check(outcome instanceof AiSettingsService.ApprovalOutcome.Refused, "an expired proposal is refused");
        check(((AiSettingsService.ApprovalOutcome.Refused) outcome).code() == Wire.Code.EXPIRED, "as expired");
        check(f.control.snapshot().settings().httpTimeout() != 45, "and nothing is applied");

        var state = f.service.inspect(List.of("proposal"), null)
                .getAsJsonObject("sections").getAsJsonObject("proposal");
        check(state.get("status").getAsString().equals("EXPIRED"), "the caller is told it expired");

        var next = f.propose("r2", "{\"settings\":{\"httpTimeout\":46}}");
        check(next.get("status").getAsString().equals("PENDING"), "and the slot is free again");
    }

    private static void externalEditsMergeOrStop() throws Exception {
        // Different fields: merge, then ask for another look.
        var f = Fixture.create();
        f.commitRules(List.of(new FingerprintRule("a.com", "chrome", "", "", 30, true)));
        f.propose("r1", "{\"domainRules\":{\"upsert\":[{\"hostPattern\":\"a.com\","
                + "\"fingerprint\":\"firefox\"}]}}");
        var proposal = f.service.pending();

        Files.writeString(f.rulesPath, RuleStore.serialize(
                List.of(new FingerprintRule("a.com", "chrome", "", "", 90, true))));

        var outcome = f.service.approve(proposal.id(), proposal.digest());
        check(outcome instanceof AiSettingsService.ApprovalOutcome.NeedsReview,
                "a clean merge that changes the result asks for another look");
        var regenerated = ((AiSettingsService.ApprovalOutcome.NeedsReview) outcome).proposal();
        check(regenerated.reviewGeneration() == 2, "at the next generation");
        check(!regenerated.digest().equals(proposal.digest()), "with a new digest, voiding the old click");

        var applied = f.service.approve(regenerated.id(), regenerated.digest());
        check(applied instanceof AiSettingsService.ApprovalOutcome.Applied, "which then applies");
        var merged = f.control.snapshot().ruleByKey("a.com");
        check(merged.fingerprint.equals("firefox"), "with the proposal's field");
        check(merged.httpTimeout == 90, "and the external edit both surviving");

        // Same field: no winner.
        var g = Fixture.create();
        g.commitRules(List.of(new FingerprintRule("a.com", "chrome", "", "", 30, true)));
        g.propose("r1", "{\"domainRules\":{\"upsert\":[{\"hostPattern\":\"a.com\","
                + "\"fingerprint\":\"firefox\"}]}}");
        var contested = g.service.pending();
        Files.writeString(g.rulesPath, RuleStore.serialize(
                List.of(new FingerprintRule("a.com", "safari", "", "", 30, true))));

        var refused = g.service.approve(contested.id(), contested.digest());
        check(refused instanceof AiSettingsService.ApprovalOutcome.Refused, "a contested field stops the apply");
        check(((AiSettingsService.ApprovalOutcome.Refused) refused).code() == Wire.Code.MERGE_CONFLICT,
                "as a merge conflict");
        check(RuleStore.parse(Files.readString(g.rulesPath)).get(0).fingerprint.equals("safari"),
                "and the file on disk is untouched");
    }

    private static void corruptRulesFileIsNeverTouched() throws Exception {
        var f = Fixture.create();
        f.seedRule("a.com");
        Files.writeString(f.rulesPath, "{ not json");
        var before = Files.readAllBytes(f.rulesPath);

        var page = f.service.inspect(null, null);
        check(codeOf(page) == Wire.Code.RULE_FILE_INVALID, "inspect refuses to answer from a broken file");
        check(java.util.Arrays.equals(before, Files.readAllBytes(f.rulesPath)),
                "and does not move, rewrite or quarantine it");

        var proposal = f.propose("r1", "{\"settings\":{\"httpTimeout\":45}}");
        check(codeOf(proposal) == Wire.Code.RULE_FILE_INVALID, "propose refuses too");
        check(java.util.Arrays.equals(before, Files.readAllBytes(f.rulesPath)), "still untouched");
        check(!Files.exists(f.rulesPath.resolveSibling(RuleStore.FILE_NAME + ".corrupt")),
                "nothing was quarantined behind the user's back");
    }

    private static void revertIsLimitedToTheLastAiChange() throws Exception {
        var f = Fixture.create();
        var original = f.control.snapshot().revision();

        check(!f.service.canRevert(), "there is nothing to revert before anything happens");

        f.propose("r1", "{\"settings\":{\"httpTimeout\":45}}");
        var proposal = f.service.pending();
        f.service.approve(proposal.id(), proposal.digest());

        check(f.service.canRevert(), "after an AI change there is");
        var reverted = f.service.revert();
        check(reverted instanceof AiSettingsService.ApprovalOutcome.Applied, "and it applies");
        check(f.control.snapshot().revision().equals(original), "returning to the previous settings");
        check(f.preferences.read().httpTimeout() != 45, "which is stored");
        check(!f.service.canRevert(), "and there is nothing left to revert");

        // Any later change makes the undo meaningless.
        var g = Fixture.create();
        g.propose("r1", "{\"settings\":{\"httpTimeout\":45}}");
        var second = g.service.pending();
        g.service.approve(second.id(), second.digest());
        check(g.service.canRevert(), "the undo is available");
        g.commitSettings(g.control.snapshot().settings().withFingerprint("firefox"));
        check(!g.service.canRevert(), "until something else is committed");

        // And it does not survive the session.
        var h = Fixture.create();
        h.propose("r1", "{\"settings\":{\"httpTimeout\":45}}");
        var third = h.service.pending();
        h.service.approve(third.id(), third.digest());
        h.service.clearSession();
        check(!h.service.canRevert(), "switching AI Control off drops the undo");
    }

    private static void auditFailureFailsClosed() throws Exception {
        var f = Fixture.create();
        f.auditOn.set(true);

        // Make the audit directory unusable.
        Files.deleteIfExists(f.auditDir);
        Files.writeString(f.auditDir, "not a directory");

        var page = f.service.inspect(null, null);
        check(codeOf(page) == Wire.Code.AUDIT_UNAVAILABLE, "an unrecordable inspect returns no settings");
        check(!page.has("sections"), "and no data leaks past the failure");

        var proposal = f.service.propose(f.control.snapshot().revision(), "r1",
                patch("{\"settings\":{\"httpTimeout\":45}}"), List.of(), "",
                arguments(f.control.snapshot().revision(), "r1", "{\"settings\":{\"httpTimeout\":45}}"));
        check(codeOf(proposal) == Wire.Code.AUDIT_UNAVAILABLE, "an unrecordable propose returns nothing");
        check(f.service.pending() == null,
                "and leaves no pending proposal behind for someone to approve unlogged");

        // A rejection that could not be recorded must not discard an unrelated pending proposal.
        var g = Fixture.create();
        g.propose("r1", "{\"settings\":{\"httpTimeout\":45}}");
        var waiting = g.service.pending();
        check(waiting != null, "a proposal is waiting");
        g.auditOn.set(true);
        Files.deleteIfExists(g.auditDir);
        Files.writeString(g.auditDir, "not a directory");
        var second = g.propose("r2", "{\"settings\":{\"httpTimeout\":46}}");
        check(codeOf(second) == Wire.Code.AUDIT_UNAVAILABLE, "the second call cannot be recorded");
        check(g.service.pending() == waiting,
                "and the proposal that was already waiting is still there");
    }

    private static void controlDisabledRefusesEverything() throws Exception {
        var f = Fixture.create();
        f.enabled.set(false);

        check(codeOf(f.service.inspect(null, null)) == Wire.Code.CONTROL_DISABLED, "inspect is refused");
        check(codeOf(f.service.propose("sha256:" + "0".repeat(64), "r1",
                        patch("{\"settings\":{\"httpTimeout\":45}}"), List.of(), "", new JsonObject()))
                        == Wire.Code.CONTROL_DISABLED, "and so is propose");
    }

    // ------------------------------------------------------------------ fixture

    private static final class Fixture {
        final Path dir;
        final Path rulesPath;
        final Path auditDir;
        final MutableClock clock = new MutableClock(Instant.parse("2026-08-25T12:00:00Z"));
        final AtomicBoolean auditOn = new AtomicBoolean(false);
        final AtomicBoolean enabled = new AtomicBoolean(true);
        final AtomicBoolean dirty = new AtomicBoolean(false);
        final Prefs preferences = new Prefs();
        final TransactionJournal journal;
        final SettingsControl control;
        final AiSettingsService service;

        private Fixture(Path dir) {
            this.dir = dir;
            this.rulesPath = dir.resolve(RuleStore.FILE_NAME);
            this.auditDir = dir.resolve("audit");
            this.journal = new TransactionJournal(dir.resolve(TransactionJournal.FILE_NAME));
            var audit = new AuditTrail(auditDir);
            var store = new RuleStore(rulesPath, s -> {
            });
            Ports.RuleFilePort rules = new Ports.RuleFilePort() {
                @Override
                public RuleStore.Probe probe() {
                    return store.probe();
                }

                @Override
                public void saveIfUnchanged(String expectedDigest, List<FingerprintRule> value)
                        throws IOException {
                    store.saveIfUnchanged(expectedDigest, value);
                }

                @Override
                public Path path() {
                    return rulesPath;
                }
            };
            this.control = new SettingsControl(preferences, rules, journal, audit, auditOn::get,
                    RuntimeStatus::unknown,
                    () -> Set.of("chrome", "firefox", "safari", "opera", "default"),
                    () -> dirty.get() ? List.of("UNSAVED_UI_DRAFT") : List.of(),
                    Ports.Log.SILENT);
            this.service = new AiSettingsService(control, audit, auditOn::get, enabled::get, clock);
            control.addListener(service::onCommitted);
        }

        static Fixture create() throws IOException {
            var fixture = new Fixture(Files.createTempDirectory("awesome-tls-ai"));
            var started = fixture.control.start(null, List.of());
            if (!(started instanceof SettingsControl.Outcome.Committed)) {
                throw new AssertionError("fixture failed to start: " + started);
            }
            return fixture;
        }

        JsonObject propose(String requestId, String patchJson) {
            return propose(requestId, patchJson, List.of());
        }

        JsonObject propose(String requestId, String patchJson, List<String> acks) {
            var revision = control.snapshot().revision();
            return service.propose(revision, requestId, patch(patchJson), acks, "",
                    arguments(revision, requestId, patchJson, acks));
        }

        void applyPending() {
            var proposal = service.pending();
            var outcome = service.approve(proposal.id(), proposal.digest());
            if (!(outcome instanceof AiSettingsService.ApprovalOutcome.Applied)) {
                throw new AssertionError("could not apply: " + outcome);
            }
        }

        void seedRule(String host) {
            commitRules(List.of(new FingerprintRule(host, "chrome", "", "", null, true)));
        }

        void commitRules(List<FingerprintRule> rules) {
            expectCommitted(control.commit(control.snapshot().withRules(rules),
                    TransactionJournal.Source.UI_SAVE));
        }

        void commitSettings(BusinessSettings settings) {
            expectCommitted(control.commit(control.snapshot().withSettings(settings),
                    TransactionJournal.Source.UI_SAVE));
        }

        private static void expectCommitted(SettingsControl.Outcome outcome) {
            if (!(outcome instanceof SettingsControl.Outcome.Committed)) {
                throw new AssertionError("expected a commit, got " + outcome);
            }
        }
    }

    private static final class Prefs implements Ports.PreferencesPort {
        private BusinessSettings settings = BusinessSettings.defaults();

        @Override
        public BusinessSettings read() {
            return settings;
        }

        @Override
        public void write(BusinessSettings value) {
            settings = value.normalized();
        }
    }

    /**
     * A clock that only moves when a test says so, because a fifteen-minute TTL is not otherwise
     * testable.
     */
    private static final class MutableClock extends Clock {
        private final AtomicReference<Instant> now;

        MutableClock(Instant start) {
            this.now = new AtomicReference<>(start);
        }

        void advance(Duration by) {
            now.updateAndGet(current -> current.plus(by));
        }

        @Override
        public Instant instant() {
            return now.get();
        }

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }
    }

    // ------------------------------------------------------------------ helpers

    private static JsonObject patch(String json) {
        return JsonParser.parseString(json).getAsJsonObject();
    }

    private static JsonObject arguments(String revision, String requestId, String patchJson) {
        return arguments(revision, requestId, patchJson, List.of());
    }

    private static JsonObject arguments(String revision, String requestId, String patchJson,
                                        List<String> acks) {
        var json = new JsonObject();
        json.addProperty("schemaVersion", Wire.SCHEMA_VERSION);
        json.addProperty("expectedRevision", revision);
        json.addProperty("requestId", requestId);
        json.add("patch", patch(patchJson));
        if (!acks.isEmpty()) {
            json.add("acknowledgements", Wire.strings(acks));
        }
        return json;
    }

    private static Wire.Code codeOf(JsonObject result) {
        if (!result.has("code")) {
            return null;
        }
        return Wire.Code.valueOf(result.get("code").getAsString());
    }

    private static void rejects(Fixture fixture, String patchJson, Wire.Code expected, String what) {
        var result = fixture.propose("id-" + Math.abs(patchJson.hashCode()), patchJson);
        var actual = codeOf(result);
        if (actual != expected) {
            throw new AssertionError("failed: " + what + " must be refused with " + expected
                    + ", got " + (actual == null ? result : actual));
        }
    }

    private static void check(boolean condition, String what) {
        if (!condition) throw new AssertionError("failed: " + what);
    }
}
