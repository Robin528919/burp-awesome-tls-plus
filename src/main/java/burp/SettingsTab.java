package burp;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.JTableHeader;
import java.awt.*;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;

/**
 * The "Awesome TLS" suite tab.
 * <p>
 * Built by hand rather than with the IntelliJ GUI designer: the form file was never part of
 * the Gradle build, so its generated code could only be regenerated inside the IDE.
 * <p>
 * Two constraints shape everything here:
 * <ul>
 *   <li><b>No HTML.</b> Burp disables Swing's HTML rendering, so markup in a label shows up as
 *       literal text. Multi-line copy uses {@link #descriptionText} instead.</li>
 *   <li><b>Colors come from {@link UIManager}.</b> Burp ships light and dark themes; hardcoded
 *       colors render black-on-black under the dark one.</li>
 * </ul>
 */
public class SettingsTab {
    private static final int TAB_DEFAULTS = 0;
    private static final int TAB_RULES = 1;
    private static final int TAB_ADVANCED = 2;
    private static final int TAB_AI_CONTROL = 3;

    private static final String AI_CONTROL_TITLE = "AI Control";

    /**
     * Keeps text fields to a readable width instead of stretching across Burp's full window.
     */
    private static final int FIELD_COLUMNS = 34;

    private static final int FEEDBACK_TIMEOUT_MS = 6000;

    /**
     * Editing a cell fires a change per keystroke; coalesce them so a burst of typing results in
     * one write and one matcher rebuild.
     */
    private static final int AUTO_SAVE_DELAY_MS = 500;

    /**
     * Stands in for the empty option in the rule table's fingerprint drop-down.
     */
    private static final String INHERIT_LABEL = "(inherit from Defaults)";

    private final Settings settings;

    private final JPanel panelMain = new JPanel(new BorderLayout());
    private final JTabbedPane tabs = new JTabbedPane();
    private final JLabel labelServerStatus = new JLabel("Starting…");
    private final JLabel labelFeedback = new JLabel(" ");

    private final JTextField textFieldSpoofProxyAddress = new JTextField(FIELD_COLUMNS);
    private final SearchableComboBox comboBoxFingerprint;
    private final JTextField textFieldHexClientHello = new JTextField(FIELD_COLUMNS);
    private final JTextField textFieldExternalProxyUrl = new JTextField(FIELD_COLUMNS);
    private final JSpinner spinnerHttpTimeout = new JSpinner(new SpinnerNumberModel(30, 1, 3600, 1));

    private final JCheckBox checkBoxUseInterceptedFingerprint = new JCheckBox("Use intercepted TLS fingerprint");
    private final JTextField textFieldInterceptProxyAddress = new JTextField(FIELD_COLUMNS);
    private final JTextField textFieldBurpProxyAddress = new JTextField(FIELD_COLUMNS);

    private final RuleTableModel ruleTableModel = new RuleTableModel();
    private final JTable ruleTable;

    private final List<String> fingerprints;

    private final AiControlPanel aiControlPanel;

    /**
     * The revision this tab last committed. A commit made from here has already left the form and
     * the table in the right state; reloading in response to it would reset the user's selection
     * and scroll position for no reason.
     */
    private volatile String selfCommittedRevision;

    private final Timer autoSaveTimer;

    /**
     * Suppresses auto-save while the table is being populated programmatically, so loading or
     * importing does not immediately write back what was just read.
     */
    private boolean populating;

    /**
     * A validation failure, together with where the user has to go to fix it.
     */
    private record ValidationError(String message, int tabIndex, int ruleRow) {
        static ValidationError on(int tabIndex, String message) {
            return new ValidationError(message, tabIndex, -1);
        }

        static ValidationError onRule(int row, String message) {
            return new ValidationError("Rule " + (row + 1) + ": " + message, TAB_RULES, row);
        }
    }

    public SettingsTab(Settings settings) {
        this.settings = settings;
        this.fingerprints = loadFingerprints(settings);
        this.comboBoxFingerprint = new SearchableComboBox(fingerprints);
        this.ruleTable = createRuleTable();

        tabs.addTab("Defaults", buildDefaultsPanel());
        tabs.addTab("Domain rules", buildRulesPanel());
        tabs.addTab("Advanced", buildAdvancedPanel());
        this.aiControlPanel = new AiControlPanel(settings, this::refreshPendingBadge);
        tabs.addTab(AI_CONTROL_TITLE, aiControlPanel.getUI());

        panelMain.setBorder(new EmptyBorder(8, 8, 8, 8));
        panelMain.add(buildStatusBar(), BorderLayout.NORTH);
        panelMain.add(tabs, BorderLayout.CENTER);
        panelMain.add(buildActionBar(), BorderLayout.SOUTH);

        autoSaveTimer = new Timer(AUTO_SAVE_DELAY_MS, e -> persistRules());
        autoSaveTimer.setRepeats(false);
        ruleTableModel.addTableModelListener(e -> {
            if (!populating) {
                autoSaveTimer.restart();
            }
        });

        // The tab has to be able to say whether it is holding an edit, because a proposal is
        // reviewed against committed settings and nothing else.
        settings.setDirtyReporter(this::dirtyReasons);
        settings.control().addListener(snapshot -> onSettingsCommitted());

        load();
        refreshPendingBadge();
    }

    /**
     * Marks the tab when a proposal is waiting. Deliberately just a label: ADR-0001 section 9
     * forbids stealing focus or opening a dialog, because a proposal can arrive at any moment and
     * an unexpected modal over someone's work is how a review gets clicked through.
     */
    private void refreshPendingBadge() {
        SwingUtilities.invokeLater(() -> {
            var proposal = settings.aiService().pending();
            var waiting = proposal != null
                    && proposal.status() == burp.control.Proposal.Status.PENDING;
            tabs.setTitleAt(TAB_AI_CONTROL, waiting ? AI_CONTROL_TITLE + " \u2022" : AI_CONTROL_TITLE);
        });
    }

    public JPanel getUI() {
        return this.panelMain;
    }

    /**
     * Updates the status line. Safe to call from any thread.
     */
    public void setServerStatus(String message, boolean isError) {
        SwingUtilities.invokeLater(() -> {
            labelServerStatus.setText(message);
            labelServerStatus.setForeground(isError ? errorColor() : normalColor());
        });
    }

    /**
     * The fingerprint list comes from the Go library over JNA. If that library failed to load,
     * the tab should still render with a usable minimum instead of taking the extension down.
     */
    private static List<String> loadFingerprints(Settings settings) {
        try {
            return List.of(settings.getFingerprints());
        } catch (Throwable t) {
            return List.of(burp.control.BusinessSettings.DEFAULT_FINGERPRINT);
        }
    }

    // ---------------------------------------------------------------- layout

    private JComponent buildStatusBar() {
        var title = new JLabel("Server status:");
        title.setFont(title.getFont().deriveFont(Font.BOLD));

        var line = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        line.add(title);
        line.add(labelServerStatus);

        var bar = new JPanel(new BorderLayout());
        bar.setBorder(new EmptyBorder(0, 4, 8, 4));
        bar.add(line, BorderLayout.WEST);
        return bar;
    }

    private JComponent buildActionBar() {
        var buttonSave = new JButton("Save settings");
        buttonSave.addActionListener(e -> save());
        buttonSave.setToolTipText("Saves the Defaults and Advanced tabs, and any pending rule edit.");

        var bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        bar.setBorder(new EmptyBorder(8, 4, 0, 4));
        bar.add(buttonSave);
        bar.add(labelFeedback);

        // AI Control has nothing this button saves: the port is stored when the listener starts and
        // the audit switch when it is clicked. Leaving it visible there invites a click that
        // silently commits whatever is sitting in a tab the user is not looking at.
        tabs.addChangeListener(e -> bar.setVisible(tabs.getSelectedIndex() != TAB_AI_CONTROL));
        return bar;
    }

    private JComponent buildDefaultsPanel() {
        var form = new FormPanel();
        form.addNote("Applied to every request that no domain rule matches, and used as the fallback for any "
                + "field a matching rule leaves empty.");
        form.addField("Listen address:", textFieldSpoofProxyAddress,
                "Local address the spoof proxy listens on. Requires an extension reload.");
        form.addField("Fingerprint:", comboBoxFingerprint,
                "Browser TLS profile to spoof. Type to filter the list.");
        form.addField("Hex ClientHello:", textFieldHexClientHello,
                "Raw ClientHello hex stream, pasted from Wireshark. Overrides the fingerprint above when set.");
        form.addField("External proxy URL:", textFieldExternalProxyUrl,
                "Upstream proxy, e.g. http://user:pass@127.0.0.1:8080 or socks5://127.0.0.1:1080. Empty = direct.");
        form.addField("HTTP timeout (seconds):", spinnerHttpTimeout,
                "How long to wait for a connection to complete, between 1 and 3600.");
        form.addFiller();
        return wrapScrollable(form);
    }

    private JComponent buildAdvancedPanel() {
        var form = new FormPanel();
        form.addNote("Reuses the real TLS fingerprint of a client instead of a preconfigured profile. Point your "
                + "browser or app at the intercept proxy below; its ClientHello is captured and replayed for "
                + "outgoing requests.");
        form.addNote("These settings stay global and cannot be set per domain: the local server runs a single "
                + "shared intercept proxy, so varying them per request would restart it repeatedly.");
        form.addFullWidth(checkBoxUseInterceptedFingerprint);
        form.addField("Intercept proxy address:", textFieldInterceptProxyAddress,
                "Local address the intercept proxy listens on. Point your client at it. Requires an extension reload.");
        form.addField("Burp proxy address:", textFieldBurpProxyAddress,
                "Burp's own proxy listener, where intercepted traffic is forwarded to.");
        form.addFiller();
        return wrapScrollable(form);
    }

    private JComponent buildRulesPanel() {
        var panel = new JPanel(new BorderLayout(0, 8));
        panel.setBorder(new EmptyBorder(12, 12, 12, 12));

        panel.add(buildRulesHelp(), BorderLayout.NORTH);
        panel.add(new JScrollPane(ruleTable), BorderLayout.CENTER);

        var buttonAdd = new JButton("Add rule");
        buttonAdd.addActionListener(e -> {
            stopEditing();
            ruleTableModel.addRule();
            var last = ruleTableModel.getRowCount() - 1;
            ruleTable.setRowSelectionInterval(last, last);
            ruleTable.scrollRectToVisible(ruleTable.getCellRect(last, 0, true));
            ruleTable.editCellAt(last, RuleTableModel.COL_HOST);
        });

        var buttonRemove = new JButton("Remove selected");
        buttonRemove.addActionListener(e -> removeSelectedRules());

        var buttonImport = new JButton("Import…");
        buttonImport.setToolTipText("Load rules from a JSON file exported earlier.");
        buttonImport.addActionListener(e -> importRules());

        var buttonExport = new JButton("Export…");
        buttonExport.setToolTipText("Save the current rules to a JSON file.");
        buttonExport.addActionListener(e -> exportRules());

        var buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        buttons.add(buttonAdd);
        buttons.add(buttonRemove);
        buttons.add(Box.createHorizontalStrut(16));
        buttons.add(buttonImport);
        buttons.add(buttonExport);

        var footer = new JPanel(new BorderLayout(0, 4));
        footer.add(buttons, BorderLayout.NORTH);
        footer.add(descriptionText("Saved automatically to " + settings.getRuleStore().path()
                + " — edit that file directly if you prefer, then reload the extension."), BorderLayout.CENTER);
        panel.add(footer, BorderLayout.SOUTH);

        return panel;
    }

    private void removeSelectedRules() {
        stopEditing();

        var selected = ruleTable.getSelectedRows();
        if (selected.length == 0) {
            showFeedback("Select the rules to remove first.", true);
            return;
        }

        // Saving is automatic, so a deletion hits disk straight away and there is no undo.
        var confirmed = JOptionPane.showConfirmDialog(panelMain,
                "Remove " + selected.length + " rule" + (selected.length == 1 ? "" : "s") + "?\n\n"
                        + "Rules are saved automatically, so this takes effect immediately.\n"
                        + "The previous version is kept as " + settings.getRuleStore().backupPath().getFileName() + ".",
                "Remove rules", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (confirmed != JOptionPane.OK_OPTION) {
            return;
        }

        ruleTableModel.removeRules(selected);
    }

    /**
     * Explains what belongs in each column. Discoverability matters more than compactness here:
     * the table alone gives no hint about the wildcard syntax or that empty means "inherit".
     */
    private JComponent buildRulesHelp() {
        var help = new JPanel(new GridBagLayout());

        var intro = descriptionText("Give individual targets their own fingerprint. When several rules could match, "
                + "the most specific one wins — an exact host beats a wildcard, and a longer wildcard beats a "
                + "shorter one — so row order does not matter.");
        var introConstraints = new GridBagConstraints();
        introConstraints.gridx = 0;
        introConstraints.gridy = 0;
        introConstraints.gridwidth = 2;
        introConstraints.weightx = 1;
        introConstraints.fill = GridBagConstraints.HORIZONTAL;
        introConstraints.insets = new Insets(0, 0, 8, 0);
        help.add(intro, introConstraints);

        for (var i = 0; i < RuleTableModel.COLUMNS.length; i++) {
            addHelpRow(help, i + 1, RuleTableModel.COLUMNS[i], RuleTableModel.COLUMN_HELP[i]);
        }

        return help;
    }

    private static void addHelpRow(JPanel parent, int row, String column, String explanation) {
        var name = new JLabel(column);
        name.setFont(name.getFont().deriveFont(Font.BOLD));

        var nameConstraints = new GridBagConstraints();
        nameConstraints.gridx = 0;
        nameConstraints.gridy = row;
        nameConstraints.anchor = GridBagConstraints.NORTHWEST;
        nameConstraints.insets = new Insets(1, 0, 1, 12);
        parent.add(name, nameConstraints);

        var text = descriptionText(explanation);
        var textConstraints = new GridBagConstraints();
        textConstraints.gridx = 1;
        textConstraints.gridy = row;
        textConstraints.weightx = 1;
        textConstraints.fill = GridBagConstraints.HORIZONTAL;
        textConstraints.insets = new Insets(1, 0, 1, 0);
        parent.add(text, textConstraints);
    }

    private JTable createRuleTable() {
        // Anonymous subclass purely to give each column header its own tooltip.
        var table = new JTable(ruleTableModel) {
            @Override
            protected JTableHeader createDefaultTableHeader() {
                return new JTableHeader(columnModel) {
                    @Override
                    public String getToolTipText(MouseEvent event) {
                        var view = columnModel.getColumnIndexAtX(event.getPoint().x);
                        if (view < 0) return null;
                        return RuleTableModel.COLUMN_HELP[columnModel.getColumn(view).getModelIndex()];
                    }
                };
            }
        };

        table.setRowHeight(24);
        table.setFillsViewportHeight(true);
        // Share the extra width proportionally. AUTO_RESIZE_LAST_COLUMN would hand all of Burp's
        // very wide window to Timeout while squeezing the columns that actually hold long values.
        table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        table.putClientProperty("terminateEditOnFocusLost", Boolean.TRUE);
        table.getSelectionModel().setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

        // Inherit-or-pick; not the searchable variant, because an editable combo inside a table
        // can lose uncommitted text when focus moves to another cell.
        var choices = new ArrayList<String>();
        choices.add("");
        choices.addAll(fingerprints);
        var editor = new JComboBox<>(choices.toArray(new String[0]));
        editor.setMaximumRowCount(15);

        // Spell out the empty entry. Otherwise it is a blank line sitting right above "default",
        // and the two are easy to confuse even though they mean different things: blank inherits
        // the Defaults tab, while "default" pins this host to the library's built-in profile.
        editor.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                          boolean selected, boolean focused) {
                var label = value == null || value.toString().isEmpty() ? INHERIT_LABEL : value.toString();
                return super.getListCellRendererComponent(list, label, index, selected, focused);
            }
        });
        table.getColumnModel().getColumn(RuleTableModel.COL_FINGERPRINT).setCellEditor(new DefaultCellEditor(editor));

        // Blank cells are the common case and say nothing about what will actually be used, so
        // each one spells out what it resolves to.
        var inheritance = new InheritanceRenderer();
        table.getColumnModel().getColumn(RuleTableModel.COL_FINGERPRINT).setCellRenderer(inheritance);
        table.getColumnModel().getColumn(RuleTableModel.COL_HEX).setCellRenderer(inheritance);
        table.getColumnModel().getColumn(RuleTableModel.COL_PROXY).setCellRenderer(inheritance);
        table.getColumnModel().getColumn(RuleTableModel.COL_TIMEOUT).setCellRenderer(inheritance);

        // Auto-save accepts half-finished rows, so flag the ones that will not match anything
        // rather than blocking the save.
        table.getColumnModel().getColumn(RuleTableModel.COL_HOST).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable owner, Object value, boolean selected,
                                                           boolean focused, int row, int column) {
                var component = super.getTableCellRendererComponent(owner, value, selected, focused, row, column);

                var problem = hostPatternProblem(value == null ? "" : value.toString());
                if (problem != null) {
                    component.setForeground(errorColor());
                    setToolTipText(problem);
                } else {
                    setToolTipText(RuleTableModel.COLUMN_HELP[RuleTableModel.COL_HOST]);
                }
                return component;
            }
        });

        // A checkbox and a number never benefit from extra width, so pin them and let the columns
        // holding hostnames, hex streams and proxy URLs split what is left.
        fixColumnWidth(table, RuleTableModel.COL_ENABLED, 44);
        setColumnWidth(table, RuleTableModel.COL_HOST, 220, 140);
        setColumnWidth(table, RuleTableModel.COL_FINGERPRINT, 180, 120);
        setColumnWidth(table, RuleTableModel.COL_HEX, 260, 140);
        setColumnWidth(table, RuleTableModel.COL_PROXY, 240, 140);
        capColumnWidth(table, RuleTableModel.COL_TIMEOUT, 90, 70, 120);

        return table;
    }

    /**
     * Sets the share of the table this column gets, plus the width below which its content
     * becomes unreadable.
     */
    /**
     * What a cell resolves to at request time.
     *
     * @param text     what to show.
     * @param explicit true when the value was typed into this row; false when it is inherited or
     *                 not used, which is rendered in the muted color.
     * @param tooltip  the reason, or null to keep the column's own help text.
     */
    private record ResolvedCell(String text, boolean explicit, String tooltip) {
        static ResolvedCell own(String text) {
            return new ResolvedCell(text, true, null);
        }

        static ResolvedCell muted(String text, String tooltip) {
            return new ResolvedCell(text, false, tooltip);
        }
    }

    /**
     * Works out what a rule cell actually resolves to, mirroring
     * {@link FingerprintRule#applyTo(TransportConfig)}.
     * <p>
     * The fingerprint and hex columns are the subtle pair: setting either one silences the other
     * for that row rather than falling back to the Defaults tab, so a row with a hex stream never
     * uses its own fingerprint column. Saying so in the cell is the only way that is discoverable.
     */
    private ResolvedCell resolveCell(int row, int column, String own) {
        // Ask the real code what this row resolves to instead of restating its precedence rules,
        // which would silently start lying the moment applyTo changes.
        var effective = new TransportConfig();
        effective.Fingerprint = settings.getFingerprint();
        effective.HexClientHello = settings.getHexClientHello();
        effective.ExternalProxyUrl = settings.getExternalProxyUrl();
        effective.HttpTimeout = settings.getHttpTimeout();
        ruleTableModel.ruleAt(row).applyTo(effective);

        var value = switch (column) {
            case RuleTableModel.COL_FINGERPRINT -> effective.Fingerprint;
            case RuleTableModel.COL_HEX -> effective.HexClientHello;
            case RuleTableModel.COL_PROXY -> effective.ExternalProxyUrl;
            case RuleTableModel.COL_TIMEOUT -> String.valueOf(effective.HttpTimeout);
            default -> own;
        };
        value = value == null ? "" : value.trim();

        if (!own.isEmpty()) {
            if (own.equals(value)) {
                return ResolvedCell.own(own);
            }
            // Typed in, but another column of the same row overrode it.
            return ResolvedCell.muted(own + "   (not used)", overriddenReason(column));
        }

        if (!value.isEmpty()) {
            return ResolvedCell.muted(value, "Inherited from the Defaults tab.");
        }

        return ResolvedCell.muted(emptyLabel(column, row), emptyReason(column, row));
    }

    private static String overriddenReason(int column) {
        if (column == RuleTableModel.COL_FINGERPRINT) {
            return "Not used: this row's Hex ClientHello takes precedence over the fingerprint.";
        }
        return "Not used: another column of this row takes precedence.";
    }

    /**
     * A blank fingerprint or hex cell means two very different things depending on its sibling,
     * so say which one applies rather than showing "(none)" for both.
     */
    private String emptyLabel(int column, int row) {
        if (column == RuleTableModel.COL_FINGERPRINT && hasOwnHex(row)) {
            return "(not used — hex wins)";
        }
        if (column == RuleTableModel.COL_HEX && hasOwnFingerprint(row)) {
            return "(not used — fingerprint set for this row)";
        }
        return "(none)";
    }

    private String emptyReason(int column, int row) {
        if (column == RuleTableModel.COL_FINGERPRINT && hasOwnHex(row)) {
            return "Not used: this row's Hex ClientHello takes precedence over the fingerprint.";
        }
        if (column == RuleTableModel.COL_HEX && hasOwnFingerprint(row)) {
            return "Setting a fingerprint on a row clears the hex ClientHello it would otherwise inherit.";
        }
        return "Empty here, and the Defaults tab does not set one either.";
    }

    private boolean hasOwnHex(int row) {
        return !ruleTableModel.ruleAt(row).hexClientHello.isEmpty();
    }

    private boolean hasOwnFingerprint(int row) {
        return !ruleTableModel.ruleAt(row).fingerprint.isEmpty();
    }

    private final class InheritanceRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable owner, Object value, boolean selected,
                                                       boolean focused, int row, int column) {
            var component = super.getTableCellRendererComponent(owner, value, selected, focused, row, column);

            var modelColumn = owner.convertColumnIndexToModel(column);
            var resolved = resolveCell(owner.convertRowIndexToModel(row), modelColumn,
                    value == null ? "" : value.toString().trim());

            setText(resolved.text());
            setToolTipText(resolved.tooltip() != null
                    ? resolved.tooltip()
                    : RuleTableModel.COLUMN_HELP[modelColumn]);

            if (!resolved.explicit()) {
                component.setForeground(hintColor());
            }
            return component;
        }
    }

    private static void setColumnWidth(JTable table, int column, int preferred, int minimum) {
        var col = table.getColumnModel().getColumn(column);
        col.setPreferredWidth(preferred);
        col.setMinWidth(minimum);
    }

    private static void capColumnWidth(JTable table, int column, int preferred, int minimum, int maximum) {
        setColumnWidth(table, column, preferred, minimum);
        table.getColumnModel().getColumn(column).setMaxWidth(maximum);
    }

    private static void fixColumnWidth(JTable table, int column, int width) {
        var col = table.getColumnModel().getColumn(column);
        col.setPreferredWidth(width);
        col.setMinWidth(width);
        col.setMaxWidth(width);
    }

    private static JComponent wrapScrollable(JComponent content) {
        var scroll = new JScrollPane(content);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        return scroll;
    }

    /**
     * Wrapping, non-editable body text. A plain JLabel would clip instead of wrapping, and HTML
     * is not an option because Burp renders it literally.
     */
    /**
     * Like {@link #descriptionText}, but in the normal text colour.
     * <p>
     * The muted hint colour is right for a field's explanation and wrong for a security
     * disclosure: Burp renders non-editable text areas dimmed, so the AI Control warning ends up
     * looking like disabled text — exactly the thing a reader's eye skips.
     */
    static JTextArea warningText(String text) {
        var area = descriptionText(text);
        var foreground = UIManager.getColor("Label.foreground");
        if (foreground != null) {
            area.setForeground(foreground);
        }
        return area;
    }

    static JTextArea descriptionText(String text) {
        var area = new JTextArea(text);
        area.setEditable(false);
        area.setOpaque(false);
        area.setFocusable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setBorder(null);
        area.setForeground(hintColor());

        // JTextArea defaults to a monospaced font, which looks foreign next to Burp's labels.
        var labelFont = UIManager.getFont("Label.font");
        if (labelFont != null) {
            area.setFont(labelFont);
        }
        return area;
    }

    // ---------------------------------------------------------------- load & save

    /**
     * Writes the rule table to disk. Invalid rows are stored as-is rather than blocking the save:
     * a half-typed rule is a normal intermediate state when saving is automatic, and
     * {@link RuleMatcher} already ignores rows with no host pattern.
     */
    private void persistRules() {
        var error = writeRules();
        if (error != null) {
            showFeedback(error, true);
            return;
        }

        var invalid = ruleTableModel.invalidRowCount();
        if (invalid > 0) {
            showFeedback("Domain rules saved. " + invalid + " incomplete row"
                    + (invalid == 1 ? " is" : "s are") + " highlighted and will be ignored.", false);
        } else {
            showFeedback("Domain rules saved.", false);
        }
    }

    /**
     * @return an error message if the rules could not be committed, else null.
     * <p>
     * Note what changed with ADR-0001: rules are no longer applied to the live configuration first
     * and written afterwards. A change that cannot be stored is a change that does not happen, so
     * that what is running and what is on disk cannot drift apart.
     */
    private String writeRules() {
        var outcome = settings.saveRules(ruleTableModel.snapshot(),
                burp.control.TransactionJournal.Source.RULES_AUTOSAVE);
        rememberSelfCommit(outcome);
        return outcomeError(outcome, "Domain rules were NOT saved");
    }

    private void rememberSelfCommit(burp.control.SettingsControl.Outcome outcome) {
        if (outcome instanceof burp.control.SettingsControl.Outcome.Committed committed) {
            selfCommittedRevision = committed.snapshot().revision();
        }
    }

    /**
     * @return a message for a failed commit, or null when it succeeded.
     */
    private static String outcomeError(burp.control.SettingsControl.Outcome outcome, String prefix) {
        if (outcome instanceof burp.control.SettingsControl.Outcome.Committed) {
            return null;
        }
        if (outcome instanceof burp.control.SettingsControl.Outcome.RecoveryRequired recovery) {
            return prefix + ". " + recovery.message();
        }
        return prefix + ": " + ((burp.control.SettingsControl.Outcome.Failed) outcome).message();
    }

    private void exportRules() {
        stopEditing();

        var chooser = new JFileChooser();
        chooser.setDialogTitle("Export domain rules");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON files", "json"));
        chooser.setSelectedFile(new File("awesome-tls-rules.json"));

        if (chooser.showSaveDialog(panelMain) != JFileChooser.APPROVE_OPTION) {
            return;
        }

        var target = chooser.getSelectedFile().toPath();
        var rules = ruleTableModel.snapshot();

        try {
            Files.writeString(target, RuleStore.serialize(rules), StandardCharsets.UTF_8);
            showFeedback("Exported " + rules.size() + " rule" + (rules.size() == 1 ? "" : "s") + " to " + target, false);
        } catch (IOException e) {
            showFeedback("Could not write " + target + ": " + e.getMessage(), true);
        }
    }

    private void importRules() {
        stopEditing();

        var chooser = new JFileChooser();
        chooser.setDialogTitle("Import domain rules");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON files", "json"));

        if (chooser.showOpenDialog(panelMain) != JFileChooser.APPROVE_OPTION) {
            return;
        }

        var source = chooser.getSelectedFile().toPath();

        List<FingerprintRule> imported;
        try {
            imported = RuleStore.parse(Files.readString(source, StandardCharsets.UTF_8));
        } catch (Exception e) {
            showFeedback("Could not read " + source + ": " + e.getMessage(), true);
            return;
        }

        if (imported.isEmpty()) {
            showFeedback("No rules found in " + source, true);
            return;
        }

        // An imported file is untrusted input, so it goes through the same checks as manual edits.
        var error = validateRules(imported);
        if (error != null) {
            showFeedback("Import rejected — " + error.message(), true);
            return;
        }

        var current = ruleTableModel.snapshot();
        var choice = JOptionPane.showOptionDialog(panelMain,
                "The file contains " + imported.size() + " rule" + (imported.size() == 1 ? "" : "s") + ".\n"
                        + "You currently have " + current.size() + ".\n\n"
                        + "Replace discards your current rules.\n"
                        + "Merge keeps them, with imported rules winning where the host pattern matches.",
                "Import domain rules", JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null,
                new String[]{"Merge", "Replace all", "Cancel"}, "Merge");

        List<FingerprintRule> result;
        if (choice == 0) {
            result = merge(current, imported);
        } else if (choice == 1) {
            result = imported;
        } else {
            return;
        }

        setTableRules(result);
        persistRules();
        showFeedback("Imported " + imported.size() + " rule" + (imported.size() == 1 ? "" : "s")
                + "; " + result.size() + " active.", false);
    }

    /**
     * Later rules win, so imported entries replace existing ones with the same host pattern while
     * everything else is kept. Insertion order is preserved for a stable table.
     */
    private static List<FingerprintRule> merge(List<FingerprintRule> current, List<FingerprintRule> imported) {
        var byPattern = new LinkedHashMap<String, FingerprintRule>();
        for (var rule : current) {
            byPattern.put(rule.hostPattern.toLowerCase(Locale.ROOT), rule);
        }
        for (var rule : imported) {
            byPattern.put(rule.hostPattern.toLowerCase(Locale.ROOT), rule);
        }
        return List.copyOf(byPattern.values());
    }

    /**
     * Fills the table without tripping auto-save.
     */
    private void setTableRules(List<FingerprintRule> rules) {
        populating = true;
        try {
            ruleTableModel.setRules(rules);
        } finally {
            populating = false;
        }
    }

    private void load() {
        textFieldSpoofProxyAddress.setText(settings.getSpoofProxyAddress());
        comboBoxFingerprint.setValue(settings.getFingerprint());
        textFieldHexClientHello.setText(settings.getHexClientHello());
        textFieldExternalProxyUrl.setText(settings.getExternalProxyUrl());
        spinnerHttpTimeout.setValue(clampTimeout(settings.getHttpTimeout()));

        checkBoxUseInterceptedFingerprint.setSelected(settings.getUseInterceptedFingerprint());
        textFieldInterceptProxyAddress.setText(settings.getInterceptProxyAddress());
        textFieldBurpProxyAddress.setText(settings.getBurpProxyAddress());

        setTableRules(settings.getRules());
    }

    /**
     * Saves the Defaults and Advanced tabs. Domain rules are not handled here: they save
     * themselves as they are edited.
     * <p>
     * Both tabs are always written together. An earlier version had one button per tab, each
     * persisting only its own fields, so editing two tabs and saving from one silently discarded
     * the other.
     */
    private void save() {
        // A cell still being edited has not written back to the model yet.
        stopEditing();

        var error = validateGlobals();
        if (error != null) {
            reportError(error);
            return;
        }

        var addressChanged = !textFieldSpoofProxyAddress.getText().trim().equals(settings.getSpoofProxyAddress())
                || !textFieldInterceptProxyAddress.getText().trim().equals(settings.getInterceptProxyAddress());

        // One commit for the whole form, rules included. Writing the fields one at a time meant a
        // failure halfway through left half the form applied and half not, with nothing saying so.
        // Flushing the rule debounce here is also what makes Save leave nothing pending, which the
        // AI Control tab depends on: a proposal cannot be reviewed against a draft.
        autoSaveTimer.stop();
        var outcome = settings.saveAll(formSettings(), ruleTableModel.snapshot());
        rememberSelfCommit(outcome);
        var failure = outcomeError(outcome, "Not saved");
        if (failure != null) {
            showFeedback(failure, true);
            return;
        }

        // Rule cells show the values they inherit from this tab, so they are now stale.
        ruleTable.repaint();

        var message = "Saved.";
        if (addressChanged) {
            message += " Reload the extension for the new listen address to take effect.";
        }
        showFeedback(message, false);
    }

    /**
     * @return the global settings exactly as the form currently reads them.
     */
    private burp.control.BusinessSettings formSettings() {
        return new burp.control.BusinessSettings(
                textFieldSpoofProxyAddress.getText().trim(),
                textFieldInterceptProxyAddress.getText().trim(),
                textFieldBurpProxyAddress.getText().trim(),
                comboBoxFingerprint.getValue(),
                textFieldHexClientHello.getText().trim(),
                checkBoxUseInterceptedFingerprint.isSelected(),
                (Integer) spinnerHttpTimeout.getValue(),
                textFieldExternalProxyUrl.getText().trim());
    }

    /**
     * Why a proposal cannot be created or applied right now.
     * <p>
     * ADR-0001 section 8.3: a settings change while the user has an edit in progress would either
     * overwrite their draft or be overwritten by it. Reporting the draft and refusing is the only
     * option that does not lose someone's work.
     */
    List<String> dirtyReasons() {
        var reasons = new java.util.ArrayList<String>();
        if (ruleTable.getCellEditor() != null) {
            reasons.add("ACTIVE_CELL_EDITOR");
        }
        if (autoSaveTimer.isRunning()) {
            reasons.add("PENDING_AUTOSAVE");
        }
        if (!formSettings().sameAs(settings.snapshot().settings())) {
            reasons.add("UNSAVED_UI_DRAFT");
        }
        return List.copyOf(reasons);
    }

    /**
     * Refreshes the form after a change committed somewhere else — an approved proposal, a revert,
     * or startup recovery. Always on the EDT, and never while the user is mid-edit.
     */
    void onSettingsCommitted() {
        var snapshot = settings.snapshot();
        if (snapshot.revision().equals(selfCommittedRevision)) {
            SwingUtilities.invokeLater(() -> {
                ruleTable.repaint();
                if (aiControlPanel != null) {
                    aiControlPanel.refresh();
                }
            });
            return;
        }

        SwingUtilities.invokeLater(() -> {
            if (ruleTable.getCellEditor() != null || autoSaveTimer.isRunning()) {
                // A refusal to overwrite a draft; the change is committed either way, and the tab
                // catches up once the draft is resolved.
                return;
            }
            load();
            ruleTable.repaint();
            if (aiControlPanel != null) {
                aiControlPanel.refresh();
            }
        });
    }

    /**
     * Sends the user to the field that needs fixing. Reporting "Rule 1: ..." while the Defaults
     * tab is open leaves no way to tell where the problem is.
     */
    private void reportError(ValidationError error) {
        tabs.setSelectedIndex(error.tabIndex());

        if (error.ruleRow() >= 0 && error.ruleRow() < ruleTableModel.getRowCount()) {
            ruleTable.setRowSelectionInterval(error.ruleRow(), error.ruleRow());
            ruleTable.scrollRectToVisible(ruleTable.getCellRect(error.ruleRow(), 0, true));
        }

        showFeedback(error.message(), true);
    }

    /**
     * Checks the Defaults and Advanced tabs, which are saved explicitly and can therefore refuse
     * to save.
     */
    private ValidationError validateGlobals() {
        var addressError = validateAddress(textFieldSpoofProxyAddress.getText(), "Listen address");
        if (addressError != null) return ValidationError.on(TAB_DEFAULTS, addressError);

        if (!isHex(textFieldHexClientHello.getText())) {
            return ValidationError.on(TAB_DEFAULTS, "Hex ClientHello must be an even-length hexadecimal string.");
        }

        addressError = validateAddress(textFieldInterceptProxyAddress.getText(), "Intercept proxy address");
        if (addressError != null) return ValidationError.on(TAB_ADVANCED, addressError);

        addressError = validateAddress(textFieldBurpProxyAddress.getText(), "Burp proxy address");
        if (addressError != null) return ValidationError.on(TAB_ADVANCED, addressError);

        return null;
    }

    /**
     * Checks a whole rule set. Used to vet imported files; the table itself tolerates incomplete
     * rows and flags them instead, because auto-save cannot reject what the user is still typing.
     */
    private ValidationError validateRules(List<FingerprintRule> rules) {
        var seen = new HashSet<String>();
        for (var i = 0; i < rules.size(); i++) {
            var rule = rules.get(i);

            var problem = hostPatternProblem(rule.hostPattern);
            if (problem != null) {
                return ValidationError.onRule(i, problem);
            }
            if (!seen.add(rule.hostPattern.toLowerCase(Locale.ROOT))) {
                return ValidationError.onRule(i, "duplicate host pattern '" + rule.hostPattern + "'.");
            }
            if (!rule.hexClientHello.isEmpty() && !isHex(rule.hexClientHello)) {
                return ValidationError.onRule(i, "Hex ClientHello must be an even-length hexadecimal string.");
            }
            if (!rule.fingerprint.isEmpty() && !comboBoxFingerprint.isKnown(rule.fingerprint)) {
                return ValidationError.onRule(i, "unknown fingerprint '" + rule.fingerprint + "'.");
            }
            if (rule.httpTimeout != null && (rule.httpTimeout < 1 || rule.httpTimeout > 3600)) {
                return ValidationError.onRule(i, "timeout must be between 1 and 3600 seconds, or empty to inherit.");
            }
        }

        return null;
    }

    /**
     * Shared by import validation and the table's highlighting of incomplete rows.
     *
     * @return what is wrong with the host pattern, or null if it is usable.
     */
    static String hostPatternProblem(String hostPattern) {
        var pattern = hostPattern == null ? "" : hostPattern.trim();

        if (pattern.isEmpty()) {
            return "host pattern is required, e.g. example.com or *.example.com";
        }
        if (pattern.contains("/") || pattern.contains(":") || pattern.contains(" ")) {
            return "host pattern must be a bare hostname, without scheme, port or spaces.";
        }
        if (pattern.contains("*") && !pattern.startsWith("*.")) {
            return "the only supported wildcard form is *.example.com";
        }
        return null;
    }

    private static String validateAddress(String value, String label) {
        var address = value == null ? "" : value.trim();
        var separator = address.lastIndexOf(':');
        if (separator <= 0 || separator == address.length() - 1) {
            return label + " must be in host:port form, e.g. 127.0.0.1:8887.";
        }

        try {
            var port = Integer.parseInt(address.substring(separator + 1));
            if (port < 1 || port > 65535) {
                return label + " port must be between 1 and 65535.";
            }
        } catch (NumberFormatException e) {
            return label + " port must be a number.";
        }

        return null;
    }

    private static boolean isHex(String value) {
        var hex = value == null ? "" : value.trim();
        if (hex.isEmpty()) return true;
        if (hex.length() % 2 != 0) return false;

        for (var c = 0; c < hex.length(); c++) {
            if (Character.digit(hex.charAt(c), 16) < 0) return false;
        }
        return true;
    }

    private static int clampTimeout(int seconds) {
        // Older versions stored the timeout without bounds; the spinner model would throw on those.
        return Math.min(3600, Math.max(1, seconds));
    }

    private void stopEditing() {
        var editor = ruleTable.getCellEditor();
        if (editor != null) {
            editor.stopCellEditing();
        }
    }

    /**
     * Success messages clear themselves; errors stay until the next save, so they cannot be
     * missed while the user is busy fixing the field they point at.
     */
    private void showFeedback(String message, boolean isError) {
        labelFeedback.setText(message);
        labelFeedback.setForeground(isError ? errorColor() : normalColor());

        if (!isError) {
            var timer = new Timer(FEEDBACK_TIMEOUT_MS, e -> labelFeedback.setText(" "));
            timer.setRepeats(false);
            timer.start();
        }
    }

    // ---------------------------------------------------------------- theming

    private static Color normalColor() {
        var color = UIManager.getColor("Label.foreground");
        return color != null ? color : new JLabel().getForeground();
    }

    private static Color errorColor() {
        var color = UIManager.getColor("Label.errorForeground");
        if (color == null) color = UIManager.getColor("Actions.Red");
        // Fallback chosen to stay legible against both light and dark backgrounds.
        return color != null ? color : new Color(0xC0392B);
    }

    private static Color hintColor() {
        var color = UIManager.getColor("Label.disabledForeground");
        return color != null ? color : normalColor();
    }

    // ---------------------------------------------------------------- helpers

    /**
     * Label/field form with a trailing filler column, so fields keep their natural width instead
     * of stretching across the whole Burp window.
     */
    private static final class FormPanel extends JPanel {
        private static final int COL_LABEL = 0;
        private static final int COL_FIELD = 1;

        private int row;

        FormPanel() {
            super(new GridBagLayout());
            setBorder(new EmptyBorder(12, 12, 12, 12));
        }

        void addField(String label, JComponent field, String hint) {
            var labelConstraints = new GridBagConstraints();
            labelConstraints.gridx = COL_LABEL;
            labelConstraints.gridy = row;
            labelConstraints.anchor = GridBagConstraints.WEST;
            labelConstraints.insets = new Insets(4, 0, 2, 12);
            add(new JLabel(label), labelConstraints);

            var fieldConstraints = new GridBagConstraints();
            fieldConstraints.gridx = COL_FIELD;
            fieldConstraints.gridy = row;
            fieldConstraints.anchor = GridBagConstraints.WEST;
            fieldConstraints.fill = GridBagConstraints.HORIZONTAL;
            fieldConstraints.insets = new Insets(4, 0, 2, 0);
            field.setToolTipText(hint);
            add(field, fieldConstraints);

            row++;

            var hintConstraints = new GridBagConstraints();
            hintConstraints.gridx = COL_FIELD;
            hintConstraints.gridy = row;
            hintConstraints.anchor = GridBagConstraints.WEST;
            hintConstraints.fill = GridBagConstraints.HORIZONTAL;
            hintConstraints.insets = new Insets(0, 0, 12, 0);
            var hintText = descriptionText(hint);
            hintText.setFont(hintText.getFont().deriveFont(hintText.getFont().getSize2D() - 1f));
            add(hintText, hintConstraints);

            row++;
        }

        void addFullWidth(JComponent component) {
            var constraints = new GridBagConstraints();
            constraints.gridx = COL_LABEL;
            constraints.gridy = row++;
            constraints.gridwidth = 2;
            constraints.anchor = GridBagConstraints.WEST;
            constraints.insets = new Insets(4, 0, 12, 0);
            add(component, constraints);
        }

        /**
         * No {@code weightx} on purpose: the note spans the label and field columns, so any weight
         * here is taken from the filler column and stretches the fields with it. Worse, a wrapping
         * {@link JTextArea} reports its current width back as its preferred width, so once stretched
         * the form can only grow — a window that was maximised once keeps a horizontal scrollbar.
         */
        void addNote(String text) {
            var constraints = new GridBagConstraints();
            constraints.gridx = COL_LABEL;
            constraints.gridy = row++;
            constraints.gridwidth = 2;
            constraints.fill = GridBagConstraints.HORIZONTAL;
            constraints.insets = new Insets(0, 0, 12, 0);
            add(descriptionText(text), constraints);
        }

        /**
         * Absorbs the leftover space, keeping the fields packed at the top left.
         */
        void addFiller() {
            var constraints = new GridBagConstraints();
            constraints.gridx = 2;
            constraints.gridy = row++;
            constraints.weightx = 1;
            constraints.weighty = 1;
            constraints.fill = GridBagConstraints.BOTH;
            add(Box.createGlue(), constraints);
        }
    }

    /**
     * Backs the domain rule table.
     * <p>
     * The timeout column is kept as text so a half-typed or empty value survives editing; it is
     * parsed on save and reported through {@link #firstInvalidTimeoutRow()}.
     */
    private static final class RuleTableModel extends AbstractTableModel {
        static final int COL_ENABLED = 0;
        static final int COL_HOST = 1;
        static final int COL_FINGERPRINT = 2;
        static final int COL_HEX = 3;
        static final int COL_PROXY = 4;
        static final int COL_TIMEOUT = 5;

        static final String[] COLUMNS = {"On", "Host pattern", "Fingerprint", "Hex ClientHello", "External proxy", "Timeout"};

        /**
         * Shown both as a header tooltip and in the legend above the table.
         */
        static final String[] COLUMN_HELP = {
                "Uncheck to switch a rule off without deleting it.",
                "Required. \"example.com\" matches that host only; \"*.example.com\" matches its subdomains but not "
                        + "example.com itself. No scheme, port or path.",
                "Browser TLS profile to spoof for this host. Empty inherits the Defaults tab; note that "
                        + "\"default\" is a profile in its own right, not the same as leaving this empty.",
                "Raw ClientHello hex stream from Wireshark. Overrides the Fingerprint column when set. "
                        + "Empty inherits the Defaults tab.",
                "Upstream proxy for this host, e.g. socks5://127.0.0.1:1080. Empty inherits the Defaults tab.",
                "Connection timeout in seconds, 1 to 3600. Empty inherits the Defaults tab.",
        };

        private final List<FingerprintRule> rules = new ArrayList<>();

        /**
         * Raw text of the timeout column, parallel to {@link #rules}.
         */
        private final List<String> timeouts = new ArrayList<>();

        void setRules(List<FingerprintRule> source) {
            rules.clear();
            timeouts.clear();
            for (var rule : source) {
                var normalized = rule.normalized();
                rules.add(normalized);
                timeouts.add(normalized.httpTimeout == null ? "" : String.valueOf(normalized.httpTimeout));
            }
            fireTableDataChanged();
        }

        void addRule() {
            rules.add(new FingerprintRule());
            timeouts.add("");
            fireTableRowsInserted(rules.size() - 1, rules.size() - 1);
        }

        void removeRules(int[] rows) {
            // Descending, so earlier removals do not shift the indices still to be removed.
            var sorted = rows.clone();
            java.util.Arrays.sort(sorted);
            for (var i = sorted.length - 1; i >= 0; i--) {
                rules.remove(sorted[i]);
                timeouts.remove(sorted[i]);
            }
            if (sorted.length > 0) {
                fireTableDataChanged();
            }
        }

        /**
         * @return the rules with the timeout column parsed, ready to be persisted.
         */
        List<FingerprintRule> snapshot() {
            var out = new ArrayList<FingerprintRule>(rules.size());
            for (var i = 0; i < rules.size(); i++) {
                var rule = rules.get(i).normalized();
                rule.httpTimeout = parseTimeout(timeouts.get(i));
                out.add(rule);
            }
            return out;
        }

        /**
         * @return the row's rule, with its timeout column parsed. Never null for a valid row index.
         */
        FingerprintRule ruleAt(int row) {
            var rule = rules.get(row).normalized();
            rule.httpTimeout = parseTimeout(timeouts.get(row));
            return rule;
        }

        /**
         * @return how many rows will be ignored at request time because their host pattern is
         * missing or malformed.
         */
        int invalidRowCount() {
            var count = 0;
            for (var rule : rules) {
                if (hostPatternProblem(rule.hostPattern) != null) {
                    count++;
                }
            }
            return count;
        }

        /**
         * @return the index of the first row whose timeout text cannot be parsed, or -1.
         */
        int firstInvalidTimeoutRow() {
            for (var i = 0; i < timeouts.size(); i++) {
                var text = timeouts.get(i).trim();
                if (text.isEmpty()) continue;
                try {
                    Integer.parseInt(text);
                } catch (NumberFormatException e) {
                    return i;
                }
            }
            return -1;
        }

        private static Integer parseTimeout(String text) {
            var trimmed = text == null ? "" : text.trim();
            if (trimmed.isEmpty()) return null;
            try {
                return Integer.parseInt(trimmed);
            } catch (NumberFormatException e) {
                return null;
            }
        }

        @Override
        public int getRowCount() {
            return rules.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMNS.length;
        }

        @Override
        public String getColumnName(int column) {
            return COLUMNS[column];
        }

        @Override
        public Class<?> getColumnClass(int column) {
            return column == COL_ENABLED ? Boolean.class : String.class;
        }

        @Override
        public boolean isCellEditable(int row, int column) {
            return true;
        }

        @Override
        public Object getValueAt(int row, int column) {
            var rule = rules.get(row);
            return switch (column) {
                case COL_ENABLED -> rule.enabled;
                case COL_HOST -> rule.hostPattern;
                case COL_FINGERPRINT -> rule.fingerprint;
                case COL_HEX -> rule.hexClientHello;
                case COL_PROXY -> rule.externalProxyUrl;
                case COL_TIMEOUT -> timeouts.get(row);
                default -> "";
            };
        }

        @Override
        public void setValueAt(Object value, int row, int column) {
            var rule = rules.get(row);
            switch (column) {
                case COL_ENABLED -> rule.enabled = Boolean.TRUE.equals(value);
                case COL_HOST -> rule.hostPattern = text(value);
                case COL_FINGERPRINT -> rule.fingerprint = text(value);
                case COL_HEX -> rule.hexClientHello = text(value);
                case COL_PROXY -> rule.externalProxyUrl = text(value);
                case COL_TIMEOUT -> timeouts.set(row, text(value));
                default -> {
                }
            }
            fireTableCellUpdated(row, column);
        }

        private static String text(Object value) {
            return value == null ? "" : value.toString().trim();
        }
    }
}
