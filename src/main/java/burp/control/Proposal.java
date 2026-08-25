package burp.control;

import com.google.gson.JsonObject;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

/**
 * A change waiting for a person to approve it in Burp.
 * <p>
 * Only ever in memory, and only one at a time. ADR-0001 section 8.2 keeps it that way so that
 * closing AI Control, unloading the extension or simply waiting fifteen minutes leaves nothing
 * approvable behind — a proposal that outlived the session that created it is a change nobody is
 * still expecting to be asked about.
 * <p>
 * {@link #digest} is what an approval is checked against. It covers the patch, the candidate, the
 * whole rendered diff, the risks, the runtime impact and the review generation, so a click on
 * Apply can only ever commit the exact change that was on screen. It deliberately excludes the
 * summary and the reported client name: those are display text, and letting them into the digest
 * would let a caller change the digest without changing the change.
 */
public final class Proposal {
    /** How long an unreviewed proposal stays approvable. */
    public static final Duration TTL = Duration.ofMinutes(15);

    /** Section 8.2 asks for at least 128 bits from a CSPRNG. */
    private static final int ID_BYTES = 16;
    private static final SecureRandom RANDOM = new SecureRandom();

    public enum Status {PENDING, REJECTED, EXPIRED, CONFLICTED}

    private final String id;
    private final String baseRevision;
    private final SettingsSnapshot base;
    private final SettingsSnapshot candidate;
    private final SettingsPatch patch;
    private final String summary;
    private final Instant createdAt;
    private final Instant expiresAt;

    private volatile int reviewGeneration;
    private volatile List<Wire.FieldChange> diff;
    private volatile List<Wire.RiskFlag> risks;
    private volatile List<Wire.RuntimeImpact> impact;
    private volatile String digest;

    private volatile Status status = Status.PENDING;
    private volatile String statusReason;
    private volatile Instant statusAt;
    private volatile Wire.Code conflictCode;
    private volatile List<Wire.ErrorDetail> conflictDetails = List.of();

    /**
     * The rules file digest observed when this proposal was built. The merge at approval time
     * compares against it to see whether anyone has edited the file since.
     */
    private final String baseRulesFileDigest;

    public Proposal(SettingsSnapshot base, SettingsSnapshot candidate, SettingsPatch patch,
                    String summary, String baseRulesFileDigest, List<Wire.FieldChange> diff,
                    List<Wire.RiskFlag> risks, List<Wire.RuntimeImpact> impact, Instant now) {
        this(newId(), base, candidate, patch, summary, baseRulesFileDigest, diff, risks, impact,
                now, now.plus(TTL), 1);
    }

    private Proposal(String id, SettingsSnapshot base, SettingsSnapshot candidate, SettingsPatch patch,
                     String summary, String baseRulesFileDigest, List<Wire.FieldChange> diff,
                     List<Wire.RiskFlag> risks, List<Wire.RuntimeImpact> impact,
                     Instant createdAt, Instant expiresAt, int reviewGeneration) {
        this.id = id;
        this.base = base;
        this.candidate = candidate;
        this.baseRevision = base.revision();
        this.patch = patch;
        this.summary = summary == null ? "" : summary;
        this.baseRulesFileDigest = baseRulesFileDigest;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
        this.reviewGeneration = reviewGeneration;
        this.diff = diff;
        this.risks = risks;
        this.impact = impact;
        this.digest = computeDigest();
    }

    private static String newId() {
        var bytes = new byte[ID_BYTES];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    // ------------------------------------------------------------------ accessors

    public String id() {
        return id;
    }

    public String digest() {
        return digest;
    }

    public String baseRevision() {
        return baseRevision;
    }

    public String candidateRevision() {
        return candidate.revision();
    }

    public SettingsSnapshot base() {
        return base;
    }

    public SettingsSnapshot candidate() {
        return candidate;
    }

    public SettingsPatch patch() {
        return patch;
    }

    public String summary() {
        return summary;
    }

    public String baseRulesFileDigest() {
        return baseRulesFileDigest;
    }

    public Instant createdAt() {
        return createdAt;
    }

    public Instant expiresAt() {
        return expiresAt;
    }

    public int reviewGeneration() {
        return reviewGeneration;
    }

    public List<Wire.FieldChange> diff() {
        return diff;
    }

    public List<Wire.RiskFlag> risks() {
        return risks;
    }

    public List<Wire.RuntimeImpact> impact() {
        return impact;
    }

    public Status status() {
        return status;
    }

    public String statusReason() {
        return statusReason;
    }

    public Instant statusAt() {
        return statusAt;
    }

    public Wire.Code conflictCode() {
        return conflictCode;
    }

    public List<Wire.ErrorDetail> conflictDetails() {
        return conflictDetails;
    }

    public boolean highRisk() {
        return Analysis.highRisk(risks);
    }

    public boolean expired(Instant now) {
        return !now.isBefore(expiresAt);
    }

    public boolean pending(Instant now) {
        return status == Status.PENDING && !expired(now);
    }

    // ------------------------------------------------------------------ transitions

    public void reject(String reason, Instant now) {
        this.status = Status.REJECTED;
        this.statusReason = reason == null || reason.isBlank() ? "Rejected in Burp." : reason;
        this.statusAt = now;
    }

    public void expire(Instant now) {
        this.status = Status.EXPIRED;
        this.statusReason = "TTL_EXPIRED";
        this.statusAt = now;
    }

    /**
     * Records that the proposal can no longer be applied as it stands. It keeps the pending slot,
     * so a caller cannot paper over the problem by immediately submitting another proposal; the
     * user has to reject it or let it expire.
     */
    public void conflict(Wire.Code code, List<Wire.ErrorDetail> details, Instant now) {
        this.status = Status.CONFLICTED;
        this.conflictCode = code;
        this.conflictDetails = List.copyOf(details);
        this.statusAt = now;
    }

    /**
     * Replaces the candidate after an automatic merge with an external edit.
     * <p>
     * Same identity, new digest, next generation: whatever the user confirmed applied to the old
     * generation only, and they have to look again. Section 16.4 is explicit that a merge which
     * changes the outcome invalidates the earlier confirmation.
     *
     * @return the regenerated proposal, which is a new object because the candidate is immutable.
     */
    public Proposal reviewed(SettingsSnapshot mergedCandidate, List<Wire.FieldChange> newDiff,
                             List<Wire.RiskFlag> newRisks, List<Wire.RuntimeImpact> newImpact,
                             String observedRulesFileDigest) {
        // The identity a client already holds must not change under it, so the id and the original
        // expiry carry over; everything a reviewer looks at is replaced.
        return new Proposal(id, base, mergedCandidate, patch, summary, observedRulesFileDigest,
                newDiff, newRisks, newImpact, createdAt, expiresAt, reviewGeneration + 1);
    }

    // ------------------------------------------------------------------ digest

    /**
     * The closed document an approval is checked against. Every array here is already in its
     * contract order, so the same proposal always hashes the same way.
     */
    private String computeDigest() {
        return Jcs.digest(digestDocument());
    }

    /**
     * @return exactly what is hashed. Exposed so the self-check can assert the field set rather
     * than infer it, since "the summary is not in the digest" is otherwise untestable.
     */
    JsonObject digestDocument() {
        var document = new JsonObject();
        document.addProperty("schemaVersion", Wire.SCHEMA_VERSION);
        document.addProperty("proposalId", id);
        document.addProperty("baseRevision", baseRevision);
        document.addProperty("candidateRevision", candidate.revision());
        document.add("patch", patch.toCanonicalJson());
        document.add("acknowledgements", Wire.strings(patch.acknowledgementNames()));
        document.add("diff", Wire.changes(diff));
        document.add("riskFlags", Wire.risks(risks));
        document.add("runtimeImpact", Wire.impacts(impact));
        document.addProperty("reviewGeneration", reviewGeneration);
        document.addProperty("expiresAt", expiresAt.toString());
        return document;
    }

    /**
     * @return the {@code ProposalState} an inspect call reports.
     */
    public JsonObject toStateJson(Instant now, String currentRevision) {
        var json = new JsonObject();
        if (status == Status.PENDING && expired(now)) {
            json.addProperty("status", "EXPIRED");
            json.addProperty("proposalId", id);
            json.addProperty("reason", "TTL_EXPIRED");
            json.addProperty("expiredAt", expiresAt.toString());
            return json;
        }
        switch (status) {
            case REJECTED -> {
                json.addProperty("status", "REJECTED");
                json.addProperty("proposalId", id);
                json.addProperty("reason", statusReason);
                json.addProperty("rejectedAt", statusAt.toString());
            }
            case EXPIRED -> {
                json.addProperty("status", "EXPIRED");
                json.addProperty("proposalId", id);
                json.addProperty("reason", "TTL_EXPIRED");
                json.addProperty("expiredAt", statusAt.toString());
            }
            case CONFLICTED -> {
                json.addProperty("status", "CONFLICTED");
                json.addProperty("proposalId", id);
                json.addProperty("code", conflictCode.name());
                json.addProperty("message", conflictMessage());
                json.add("details", Wire.details(conflictDetails));
                json.addProperty("detectedAt", statusAt.toString());
                json.addProperty("currentRevision", currentRevision);
            }
            default -> writePending(json);
        }
        return json;
    }

    private String conflictMessage() {
        return switch (conflictCode) {
            case REVISION_CONFLICT -> "The committed settings changed after this proposal was created.";
            case EXTERNAL_DIVERGENCE -> "The rules file was edited outside Burp in a way that cannot be merged.";
            case MERGE_CONFLICT -> "The proposal and the rules file changed the same field.";
            case DIRTY_UI -> "The settings tab has unsaved edits.";
            default -> "This proposal can no longer be applied.";
        };
    }

    private void writePending(JsonObject json) {
        json.addProperty("status", "PENDING");
        json.addProperty("proposalId", id);
        json.addProperty("proposalDigest", digest);
        json.addProperty("baseRevision", baseRevision);
        json.addProperty("candidateRevision", candidate.revision());
        json.addProperty("createdAt", createdAt.toString());
        json.addProperty("expiresAt", expiresAt.toString());
        json.addProperty("reviewGeneration", reviewGeneration);
        json.addProperty("summary", summary);
        json.add("diff", Wire.changes(diff));
        json.add("riskFlags", Wire.risks(risks));
        json.add("runtimeImpact", Wire.impacts(impact));
    }

    /**
     * @return the {@code ProposalPendingResult} a propose call returns.
     */
    public JsonObject toResultJson() {
        var json = new JsonObject();
        json.addProperty("kind", "proposal_result");
        json.addProperty("schemaVersion", Wire.SCHEMA_VERSION);
        writePending(json);
        return json;
    }

    /**
     * Self-check.
     * Run with: {@code java -ea -cp build/classes/java/main:<gson.jar> burp.control.Proposal}
     */
    public static void main(String[] args) {
        var now = Instant.parse("2026-08-25T12:00:00Z");
        var base = SettingsSnapshot.empty();
        var candidate = SettingsSnapshot.of(BusinessSettings.defaults().withHttpTimeout(45), List.of());
        var patch = patchOf("{\"settings\":{\"httpTimeout\":45}}");
        var diff = Analysis.diff(base, candidate);
        var risks = Analysis.risks(base, candidate, diff);
        var impact = Analysis.impact(diff, RuntimeStatus.unknown());

        var proposal = new Proposal(base, candidate, patch, "raise the timeout", null, diff, risks, impact, now);

        check(proposal.status() == Status.PENDING && proposal.pending(now), "a new proposal is pending");
        check(Jcs.isDigest(proposal.digest()), "it has a well-formed digest");
        check(proposal.id().length() >= 22, "and an identifier with real entropy");
        check(!proposal.id().contains("/") && !proposal.id().contains("+"), "which is URL-safe");
        check(proposal.reviewGeneration() == 1, "at generation one");
        check(proposal.expiresAt().equals(now.plus(TTL)), "expiring after the fixed TTL");

        // Identifiers must not be guessable from each other.
        var second = new Proposal(base, candidate, patch, "", null, diff, risks, impact, now);
        check(!second.id().equals(proposal.id()), "two proposals get different identifiers");

        // Section 8.2 fixes exactly what an approval is checked against. Assert the field set
        // directly: "the summary is not in there" cannot be shown by comparing two digests,
        // because the identifier differs too.
        var hashed = proposal.digestDocument().keySet();
        check(hashed.equals(java.util.Set.of("schemaVersion", "proposalId", "baseRevision",
                        "candidateRevision", "patch", "acknowledgements", "diff", "riskFlags",
                        "runtimeImpact", "reviewGeneration", "expiresAt")),
                "the digest covers exactly the locked field set");
        check(!hashed.contains("summary"), "the summary is display text and stays out of it");
        check(!hashed.contains("clientInfo"), "and so is the self-reported client name");

        // Two proposals are never interchangeable, even for the same change.
        check(!second.digest().equals(proposal.digest()), "each proposal has its own digest");

        check(!proposal.expired(now.plus(TTL).minusSeconds(1)), "not expired a second early");
        check(proposal.expired(now.plus(TTL)), "expired exactly on the TTL");
        check(!proposal.pending(now.plus(TTL)), "and no longer pending");

        var expiredState = proposal.toStateJson(now.plus(TTL), base.revision());
        check(expiredState.get("status").getAsString().equals("EXPIRED"),
                "an unreviewed proposal reports itself expired without being touched");

        // A merge that changes the outcome invalidates the earlier confirmation.
        var mergedCandidate = SettingsSnapshot.of(BusinessSettings.defaults().withHttpTimeout(45),
                List.of(new burp.FingerprintRule("external.com", "chrome", "", "", null, true)));
        var mergedDiff = Analysis.diff(base, mergedCandidate);
        var regenerated = proposal.reviewed(mergedCandidate, mergedDiff,
                Analysis.risks(base, mergedCandidate, mergedDiff),
                Analysis.impact(mergedDiff, RuntimeStatus.unknown()), null);
        check(regenerated.id().equals(proposal.id()), "the identity survives a re-review");
        check(regenerated.reviewGeneration() == 2, "the generation advances");
        check(!regenerated.digest().equals(proposal.digest()), "and the digest changes, so the old click is void");

        var rejected = new Proposal(base, candidate, patch, "", null, diff, risks, impact, now);
        rejected.reject("not now", now);
        var state = rejected.toStateJson(now, base.revision());
        check(state.get("status").getAsString().equals("REJECTED"), "a rejection is reported");
        check(state.get("reason").getAsString().equals("not now"), "with its reason");

        var conflicted = new Proposal(base, candidate, patch, "", null, diff, risks, impact, now);
        conflicted.conflict(Wire.Code.MERGE_CONFLICT,
                List.of(Wire.ErrorDetail.of("/domainRules/byHost/a.com/fingerprint", "changed_both")), now);
        var conflictState = conflicted.toStateJson(now, base.revision());
        check(conflictState.get("status").getAsString().equals("CONFLICTED"), "a conflict is reported");
        check(conflictState.get("code").getAsString().equals("MERGE_CONFLICT"), "with its code");
        check(conflictState.getAsJsonArray("details").size() == 1, "and its details");

        var result = proposal.toResultJson();
        check(result.get("kind").getAsString().equals("proposal_result"), "the propose result is tagged");
        check(result.get("status").getAsString().equals("PENDING"), "as pending");
        check(result.get("summary").getAsString().equals("raise the timeout"), "and carries the summary");

        System.out.println("Proposal self-check passed");
    }

    private static SettingsPatch patchOf(String json) {
        var parsed = SettingsPatch.parse(
                com.google.gson.JsonParser.parseString(json).getAsJsonObject(), List.of());
        return ((SettingsPatch.Parsed.Ok) parsed).patch();
    }

    private static void check(boolean condition, String what) {
        if (!condition) throw new AssertionError("failed: " + what);
    }
}
