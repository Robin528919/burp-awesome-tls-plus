package burp.control;

import burp.FingerprintRule;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;

/**
 * Reconciles an AI proposal with edits someone made to {@code rules.json} while the proposal was
 * waiting for review.
 * <p>
 * There is no file watcher, by design: ADR-0001 section 10 checks the file at approval time
 * instead, which is the only moment the answer has to be right. The merge is per field within a
 * rule, so an AI changing a timeout and a person changing that rule's proxy both survive; anything
 * genuinely contradictory stops the whole proposal rather than picking a winner.
 * <p>
 * Rows the matcher refuses are treated as opaque and immovable. An AI cannot see them, so if the
 * file's hidden rows have been added to, removed, reordered or edited, there is no stable identity
 * to merge along and approval is blocked instead of guessed at.
 */
public final class ThreeWayMerge {
    private ThreeWayMerge() {
    }

    public sealed interface Result {
        /**
         * @param changedFromProposed whether the merge produced something other than what the user
         *                            was shown. When true the proposal must be re-rendered and
         *                            re-approved: the earlier click was for a different change.
         */
        record Merged(List<FingerprintRule> rules, boolean changedFromProposed) implements Result {
        }

        /** The proposal and the file disagree about the same field. */
        record Conflict(List<Wire.ErrorDetail> details) implements Result {
        }

        /** The file's unusable rows moved, so rules can no longer be matched up reliably. */
        record Divergence(List<Wire.ErrorDetail> details) implements Result {
        }
    }

    /**
     * @param base     the rules as they were when the proposal was built.
     * @param current  the rules on disk right now.
     * @param proposed the rules the proposal would produce, ignoring the external edit.
     */
    public static Result merge(SettingsSnapshot base, SettingsSnapshot current, SettingsSnapshot proposed) {
        var divergence = hiddenRowDivergence(base, current);
        if (divergence != null) {
            return new Result.Divergence(List.of(divergence));
        }

        var keys = new LinkedHashSet<String>();
        keys.addAll(base.indexByKey().keySet());
        keys.addAll(current.indexByKey().keySet());
        keys.addAll(proposed.indexByKey().keySet());

        var conflicts = new ArrayList<Wire.ErrorDetail>();
        var resolved = new java.util.LinkedHashMap<String, FingerprintRule>();
        var deleted = new LinkedHashSet<String>();

        for (var key : keys) {
            var b = base.ruleByKey(key);
            var c = current.ruleByKey(key);
            var p = proposed.ruleByKey(key);

            if (same(p, b)) {
                // The proposal does not touch this rule, so whatever is on disk stands.
                if (c == null) {
                    deleted.add(key);
                } else {
                    resolved.put(key, c);
                }
                continue;
            }
            if (same(c, b)) {
                // Nobody else touched it; the proposal applies as written.
                if (p == null) {
                    deleted.add(key);
                } else {
                    resolved.put(key, p);
                }
                continue;
            }

            // Both sides changed it.
            if (p == null && c == null) {
                deleted.add(key);
                continue;
            }
            if (p == null || c == null) {
                conflicts.add(Wire.ErrorDetail.of(Validation.rulePath(key, "hostPattern"),
                        p == null ? "proposal_deletes_a_rule_that_was_edited_on_disk"
                                : "disk_deletes_a_rule_that_the_proposal_edits"));
                continue;
            }

            var merged = mergeFields(key, b, c, p, conflicts);
            if (merged != null) {
                resolved.put(key, merged);
            }
        }

        if (!conflicts.isEmpty()) {
            return new Result.Conflict(List.copyOf(conflicts));
        }

        var rules = rebuild(current, resolved, deleted, proposed);
        var mergedSnapshot = SettingsSnapshot.of(proposed.settings(), rules);
        return new Result.Merged(rules, !mergedSnapshot.revision().equals(proposed.revision()));
    }

    /**
     * @return the merged rule, or null after recording a conflict.
     */
    private static FingerprintRule mergeFields(String key, FingerprintRule base, FingerprintRule current,
                                               FingerprintRule proposed, List<Wire.ErrorDetail> conflicts) {
        var merged = current.materialized();
        var clean = true;

        for (var field : FingerprintRule.FIELDS) {
            if (field.equals("hostPattern")) {
                continue;
            }
            var b = base == null ? null : base.get(field);
            var c = current.get(field);
            var p = proposed.get(field);

            if (Objects.equals(p, b)) {
                continue; // the proposal leaves this field alone
            }
            if (Objects.equals(c, b)) {
                set(merged, field, p);
                continue;
            }
            if (Objects.equals(c, p)) {
                continue; // both arrived at the same value
            }
            conflicts.add(Wire.ErrorDetail.mismatch(Validation.rulePath(key, field),
                    "changed_both_in_the_proposal_and_on_disk", p, c));
            clean = false;
        }
        return clean ? merged : null;
    }

    private static void set(FingerprintRule rule, String field, Object value) {
        switch (field) {
            case "enabled" -> rule.enabled = (Boolean) value;
            case "fingerprint" -> rule.fingerprint = value == null ? "" : (String) value;
            case "hexClientHello" -> rule.hexClientHello = value == null ? "" : (String) value;
            case "externalProxyUrl" -> rule.externalProxyUrl = value == null ? "" : (String) value;
            case "note" -> rule.note = value == null ? "" : (String) value;
            case "httpTimeout" -> rule.httpTimeout = (Integer) value;
            default -> throw new IllegalStateException("unreachable: unknown rule field " + field);
        }
    }

    /**
     * Reassembles the file: the disk's order is authoritative, updated rows stay where they are,
     * unusable rows keep their positions untouched, and anything the proposal adds goes at the end.
     */
    private static List<FingerprintRule> rebuild(SettingsSnapshot current,
                                                 java.util.Map<String, FingerprintRule> resolved,
                                                 java.util.Set<String> deleted,
                                                 SettingsSnapshot proposed) {
        var keyByIndex = new java.util.HashMap<Integer, String>();
        current.indexByKey().forEach((key, index) -> keyByIndex.put(index, key));

        var out = new ArrayList<FingerprintRule>();
        var placed = new LinkedHashSet<String>();

        for (var i = 0; i < current.storedRules().size(); i++) {
            var key = keyByIndex.get(i);
            if (key == null) {
                // An unusable row: preserved verbatim, in place.
                out.add(current.storedRules().get(i).materialized());
                continue;
            }
            if (deleted.contains(key)) {
                continue;
            }
            var merged = resolved.get(key);
            if (merged == null) {
                out.add(current.storedRules().get(i).materialized());
                continue;
            }
            // Keep the spelling that is on disk; only the fields that changed change.
            var row = current.storedRules().get(i).materialized();
            for (var field : FingerprintRule.FIELDS) {
                if (!field.equals("hostPattern")) {
                    set(row, field, merged.get(field));
                }
            }
            out.add(row);
            placed.add(key);
        }

        // New rules the proposal introduces, in the order the proposal listed them.
        for (var key : proposed.indexByKey().keySet()) {
            if (placed.contains(key) || deleted.contains(key) || current.indexByKey().containsKey(key)) {
                continue;
            }
            var added = resolved.get(key);
            if (added != null) {
                out.add(added.materialized());
            }
        }
        return List.copyOf(out);
    }

    /**
     * @return why the file's unusable rows can no longer be matched up, or null if they are
     * byte-for-byte what they were.
     */
    private static Wire.ErrorDetail hiddenRowDivergence(SettingsSnapshot base, SettingsSnapshot current) {
        var before = hiddenRows(base);
        var after = hiddenRows(current);
        if (before.equals(after)) {
            return null;
        }
        return Wire.ErrorDetail.mismatch("/domainRules", "hidden_rows_changed_on_disk",
                before.size(), after.size());
    }

    private static List<String> hiddenRows(SettingsSnapshot snapshot) {
        var rows = new ArrayList<String>();
        for (var index : snapshot.hiddenIndexes()) {
            var rule = snapshot.storedRules().get(index);
            var json = new com.google.gson.JsonObject();
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
            rows.add(Jcs.string(json));
        }
        return rows;
    }

    private static boolean same(FingerprintRule a, FingerprintRule b) {
        if (a == null || b == null) {
            return a == b;
        }
        for (var field : FingerprintRule.FIELDS) {
            if (!Objects.equals(a.get(field), b.get(field))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Self-check.
     * Run with: {@code java -ea -cp build/classes/java/main:<gson.jar> burp.control.ThreeWayMerge}
     */
    public static void main(String[] args) {
        var defaults = BusinessSettings.defaults();

        // Untouched on disk: the proposal applies exactly as reviewed.
        var base = snapshot(rule("a.com", "chrome", "", 30));
        var proposed = snapshot(rule("a.com", "firefox", "", 30));
        var clean = (Result.Merged) merge(base, base, proposed);
        check(!clean.changedFromProposed(), "with no external edit the proposal is unchanged");
        check(clean.rules().get(0).fingerprint.equals("firefox"), "and is what gets written");

        // Different fields: both survive.
        var edited = snapshot(rule("a.com", "chrome", "", 90));
        var merged = (Result.Merged) merge(base, edited, proposed);
        check(merged.rules().get(0).fingerprint.equals("firefox"), "the proposal's field is applied");
        check(merged.rules().get(0).httpTimeout == 90, "and the external edit survives");
        check(merged.changedFromProposed(), "the result differs from what was reviewed, so re-review");

        // Same field, different values: no winner.
        var contested = snapshot(rule("a.com", "safari", "", 30));
        check(merge(base, contested, proposed) instanceof Result.Conflict, "the same field twice is a conflict");
        var conflict = (Result.Conflict) merge(base, contested, proposed);
        check(conflict.details().get(0).path().equals("/domainRules/byHost/a.com/fingerprint"),
                "and the conflict names the field");

        // Identical intent is not a conflict.
        check(merge(base, proposed, proposed) instanceof Result.Merged,
                "both sides making the same change is not a conflict");

        // Delete versus modify, in both directions.
        check(merge(base, snapshot(), proposed) instanceof Result.Conflict,
                "deleting on disk what the proposal edits is a conflict");
        check(merge(base, edited, snapshot()) instanceof Result.Conflict,
                "deleting in the proposal what was edited on disk is a conflict");
        check(merge(base, snapshot(), snapshot()) instanceof Result.Merged,
                "both deleting it is agreement");

        // A rule added on disk must not be swept away by an unrelated proposal.
        var addedOnDisk = snapshot(rule("a.com", "chrome", "", 30), rule("new.com", "opera", "", 30));
        var keeps = (Result.Merged) merge(base, addedOnDisk, proposed);
        check(keeps.rules().size() == 2, "a rule added on disk survives");
        check(keeps.rules().stream().anyMatch(r -> r.hostPattern.equals("new.com")), "with its own contents");

        // The disk's order and spelling win.
        var spelled = SettingsSnapshot.of(defaults, List.of(rule("  A.COM  ", "chrome", "", 30)));
        var respelled = (Result.Merged) merge(base, spelled, proposed);
        check(respelled.rules().get(0).hostPattern.equals("  A.COM  "), "the stored spelling is preserved");
        check(respelled.rules().get(0).fingerprint.equals("firefox"), "while the field still changes");

        checkHiddenRows();
        checkAppendOrder();

        System.out.println("ThreeWayMerge self-check passed");
    }

    private static void checkHiddenRows() {
        var hidden = rule("", "chrome", "", 30);
        var base = SettingsSnapshot.of(BusinessSettings.defaults(), List.of(rule("a.com", "chrome", "", 30), hidden));
        var proposed = SettingsSnapshot.of(BusinessSettings.defaults(),
                List.of(rule("a.com", "firefox", "", 30), hidden));

        check(merge(base, base, proposed) instanceof Result.Merged, "an unchanged hidden row merges fine");
        var kept = (Result.Merged) merge(base, base, proposed);
        check(kept.rules().size() == 2 && kept.rules().get(1).hostPattern.isEmpty(),
                "and the hidden row is preserved in place");

        // Any movement of a hidden row makes identity unreliable.
        var removed = SettingsSnapshot.of(BusinessSettings.defaults(), List.of(rule("a.com", "chrome", "", 30)));
        check(merge(base, removed, proposed) instanceof Result.Divergence, "removing a hidden row diverges");

        var extra = SettingsSnapshot.of(BusinessSettings.defaults(),
                List.of(rule("a.com", "chrome", "", 30), hidden, rule("  ", "", "", 30)));
        check(merge(base, extra, proposed) instanceof Result.Divergence, "adding one diverges");

        var altered = SettingsSnapshot.of(BusinessSettings.defaults(),
                List.of(rule("a.com", "chrome", "", 30), rule("", "firefox", "", 30)));
        check(merge(base, altered, proposed) instanceof Result.Divergence, "editing one diverges");
    }

    private static void checkAppendOrder() {
        var base = snapshot(rule("a.com", "chrome", "", 30));
        var proposed = snapshot(rule("a.com", "chrome", "", 30),
                rule("new1.com", "firefox", "", 30), rule("new2.com", "safari", "", 30));
        var onDisk = snapshot(rule("a.com", "chrome", "", 30), rule("theirs.com", "opera", "", 30));

        var merged = (Result.Merged) merge(base, onDisk, proposed);
        var hosts = merged.rules().stream().map(r -> r.hostPattern).toList();
        check(hosts.equals(List.of("a.com", "theirs.com", "new1.com", "new2.com")),
                "the disk order is kept and new rules append after it, in proposal order");
    }

    private static SettingsSnapshot snapshot(FingerprintRule... rules) {
        return SettingsSnapshot.of(BusinessSettings.defaults(), List.of(rules));
    }

    private static FingerprintRule rule(String host, String fingerprint, String hex, Integer timeout) {
        return new FingerprintRule(host, fingerprint, hex, "", timeout, true);
    }

    private static void check(boolean condition, String what) {
        if (!condition) throw new AssertionError("failed: " + what);
    }
}
