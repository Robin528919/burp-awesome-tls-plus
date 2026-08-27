package probe;

import burp.FingerprintRule;
import burp.RuleStore;
import burp.control.*;

import java.nio.file.Files;
import java.time.Clock;
import java.util.List;
import java.util.Set;

/**
 * ADR-0001 sections 2 and 17.3: inspect and propose must produce no DNS and no target-side traffic.
 * Every hostname below is one that would have to be resolved if anything tried.
 */
public class NoNetworkProbe {
    public static void main(String[] args) throws Exception {
        var dir = Files.createTempDirectory("nonet");
        var audit = new AuditTrail(dir.resolve("audit"));
        var store = new RuleStore(dir.resolve(RuleStore.FILE_NAME), s -> {});
        var prefs = new Ports.PreferencesPort() {
            BusinessSettings s = BusinessSettings.defaults();
            public BusinessSettings read() { return s; }
            public void write(BusinessSettings v) { s = v.normalized(); }
        };
        var rules = new Ports.RuleFilePort() {
            public RuleStore.Probe probe() { return store.probe(); }
            public void saveIfUnchanged(String d, List<FingerprintRule> r) throws java.io.IOException {
                store.saveIfUnchanged(d, r);
            }
            public java.nio.file.Path path() { return dir.resolve(RuleStore.FILE_NAME); }
        };
        var control = new SettingsControl(prefs, rules,
                new TransactionJournal(dir.resolve(TransactionJournal.FILE_NAME)), audit,
                () -> false, RuntimeStatus::unknown, () -> Set.of("chrome", "default"),
                Ports.UiDirtyPort.SETTLED, Ports.Log.SILENT);
        control.start(null, List.of());
        control.commit(control.snapshot().withRules(List.of(
                new FingerprintRule("api.example.com", "chrome", "", "http://proxy.example.net:8080", 60, true),
                new FingerprintRule("*.cdn.example.org", "chrome", "", "", null, true))),
                TransactionJournal.Source.UI_SAVE);
        var service = new AiSettingsService(control, audit, () -> false, () -> true, () -> false,
                Clock.systemUTC());

        // Baseline after setup, so only the calls under test are counted.
        var forwardBefore = CountingResolverProvider.FORWARD.get();
        var reverseBefore = CountingResolverProvider.REVERSE.get();

        var page = service.inspect(null, List.of(
                "api.example.com", "v2.api.example.com", "images.cdn.example.org",
                "unmatched.example.net", "xn--bcher-kva.de"));
        if (!page.getAsJsonObject("sections").has("effectiveConfigs")) {
            throw new AssertionError("inspect did not resolve the hosts at all");
        }
        var resolved = page.getAsJsonObject("sections").getAsJsonArray("effectiveConfigs");
        if (resolved.size() != 5) {
            throw new AssertionError("expected five effective configs, got " + resolved.size());
        }
        // Sanity: the answers are real, not empty stubs.
        var first = resolved.get(0).getAsJsonObject();
        if (!"api.example.com".equals(first.get("matchedRuleHostPattern").getAsString())) {
            throw new AssertionError("the exact rule did not match");
        }
        if (!"*.cdn.example.org".equals(resolved.get(2).getAsJsonObject()
                .get("matchedRuleHostPattern").getAsString())) {
            throw new AssertionError("the wildcard rule did not match");
        }

        var revision = control.snapshot().revision();
        var patch = com.google.gson.JsonParser.parseString(
                "{\"domainRules\":{\"upsert\":[{\"hostPattern\":\"new.example.com\","
                        + "\"externalProxyUrl\":\"socks5://another.example.net:1080\"}]}}").getAsJsonObject();
        var arguments = com.google.gson.JsonParser.parseString(
                "{\"schemaVersion\":\"" + Wire.SCHEMA_VERSION + "\",\"expectedRevision\":\"" + revision
                        + "\",\"requestId\":\"nonet\",\"patch\":" + patch + "}").getAsJsonObject();
        var proposal = service.propose(revision, "nonet", patch, List.of(), "", arguments);
        if (!"PENDING".equals(proposal.get("status").getAsString())) {
            throw new AssertionError("propose did not produce a proposal: " + proposal);
        }

        var forward = CountingResolverProvider.FORWARD.get() - forwardBefore;
        var reverse = CountingResolverProvider.REVERSE.get() - reverseBefore;
        if (forward != 0 || reverse != 0) {
            throw new AssertionError("inspect/propose resolved " + forward + " name(s) and "
                    + reverse + " address(es); both must be zero");
        }

        // The counter itself has to work, or the result above means nothing.
        try {
            java.net.InetAddress.getByName("localhost");
        } catch (Exception ignored) {
        }
        if (CountingResolverProvider.FORWARD.get() <= forwardBefore) {
            throw new AssertionError("the resolver counter is not installed; the result is meaningless");
        }

        System.out.println("No-network probe passed: inspect and propose resolved 0 names, 0 addresses");
    }
}
