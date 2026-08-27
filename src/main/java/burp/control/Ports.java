package burp.control;

import burp.FingerprintRule;
import burp.RuleStore;

import java.io.IOException;
import java.util.List;
import java.util.Set;

/**
 * The seams {@link SettingsControl} works through.
 * <p>
 * Grouped rather than scattered because the point of them is collective: they are what makes the
 * coordinator testable without Burp, a Go library, or a Swing event thread — which is the only way
 * the failure paths ADR-0001 section 17.1 asks for can be exercised at all, since none of them can
 * be provoked on demand in a real installation.
 */
public final class Ports {
    private Ports() {
    }

    /**
     * The scalar half of the settings, backed by Burp's preference store.
     * <p>
     * Note what is missing: there is no flush, commit or durability acknowledgement, because
     * Montoya's {@code Preferences} offers none. {@link #write} returning normally means the
     * setters did not throw, nothing more; the coordinator re-reads and compares digests to get
     * even that much confirmation.
     */
    public interface PreferencesPort {
        BusinessSettings read();

        void write(BusinessSettings settings) throws IOException;
    }

    /**
     * The rules file. Reads must be side-effect free; writes must be digest-guarded.
     */
    public interface RuleFilePort {
        RuleStore.Probe probe();

        void saveIfUnchanged(String expectedDigest, List<FingerprintRule> rules) throws IOException;

        java.nio.file.Path path();
    }

    /**
     * What the Go side reports about its own listeners. Never inferred on the Java side.
     */
    public interface RuntimeStatePort {
        RuntimeStatus status();
    }

    /**
     * Whether the Swing UI is holding an edit that has not been committed.
     * <p>
     * A settings change while a cell editor is open would either be overwritten by the editor or
     * overwrite it, so ADR-0001 section 8.3 refuses instead — the user resolves their own draft.
     */
    public interface UiDirtyPort {
        /**
         * @return {@code ACTIVE_CELL_EDITOR}, {@code PENDING_AUTOSAVE} and/or
         * {@code UNSAVED_UI_DRAFT}; empty when the UI is settled.
         */
        List<String> dirtyReasons();

        UiDirtyPort SETTLED = List::of;
    }

    /**
     * The fingerprint names the loaded Go library offers.
     */
    public interface FingerprintCatalog {
        Set<String> names();

        /** Used before the native library has answered, and by tests. */
        FingerprintCatalog EMPTY = Set::of;
    }

    /**
     * Somewhere to report a problem a user needs to see. Kept as a port so the coordinator does
     * not depend on Burp's logging.
     */
    public interface Log {
        void info(String message);

        void error(String message);

        Log SILENT = new Log() {
            @Override
            public void info(String message) {
            }

            @Override
            public void error(String message) {
            }
        };
    }
}
