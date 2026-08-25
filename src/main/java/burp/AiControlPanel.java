package burp;

import burp.control.AiSettingsService;
import burp.control.McpServer;
import burp.control.Proposal;
import burp.control.Wire;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.Desktop;
import java.awt.FlowLayout;
import java.awt.datatransfer.StringSelection;
import java.awt.Toolkit;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * The AI Control tab: the only place a proposal can be applied, rejected or taken back.
 * <p>
 * ADR-0001 makes this the whole authorization boundary. The MCP endpoint can describe a change and
 * park it; a person here is the only thing that can make it real. Everything on this panel exists
 * to make that decision an informed one — the full unredacted diff, what each change will actually
 * affect and when, and a second confirmation for the changes that can take an installation offline.
 * <p>
 * Swing by hand, and without hardcoded colours: Burp ships light and dark themes and applies its own
 * styling pass over this panel. It also disables Swing's HTML rendering, so anything longer than a
 * line uses a wrapping text area rather than {@code <html>} markup, which would show as literal tags.
 */
final class AiControlPanel {
    private static final int MAX_AUDIT_EVENTS = 50;

    /** Longer than this and a value is shown truncated, with the whole thing one click away. */
    private static final int INLINE_VALUE_LIMIT = 120;

    private final Settings settings;
    private final Runnable onProposalChanged;

    private final JPanel root = new JPanel(new BorderLayout(0, 8));

    private final JSpinner spinnerPort =
            new JSpinner(new SpinnerNumberModel(McpServer.DEFAULT_PORT, 1, 65535, 1));
    private final JButton buttonToggle = new JButton("Enable");
    private final JLabel labelStatus = new JLabel();
    private final JLabel labelEndpoint = new JLabel();
    private final JCheckBox checkBoxUnderstood =
            new JCheckBox("I understand and accept that any process on this machine can read these values");
    private final JCheckBox checkBoxFullAudit = new JCheckBox("Record everything to the audit trail");

    private final DiffTableModel diffModel = new DiffTableModel();
    private final JTable tableDiff = new JTable(diffModel);
    private final JTextArea textProposalSummary = SettingsTab.descriptionText("");
    private final JTextArea textRisk = SettingsTab.descriptionText("");
    private final JTextArea textValueDetail = SettingsTab.descriptionText("");
    private final JButton buttonCopyValue = new JButton("Copy value");
    private final JButton buttonApply = new JButton("Apply");
    private final JButton buttonReject = new JButton("Reject");
    private final JButton buttonRevert = new JButton("Revert last AI apply");

    private final DefaultListModel<String> auditModel = new DefaultListModel<>();
    private final JList<String> listAudit = new JList<>(auditModel);
    private final JTextArea textAuditDetail = SettingsTab.descriptionText("");
    private final List<String> auditDetails = new ArrayList<>();

    AiControlPanel(Settings settings, Runnable onProposalChanged) {
        this.settings = settings;
        this.onProposalChanged = onProposalChanged;

        // Without an explicit editor a JSpinner applies the locale's grouping separator, so the
        // port renders as "8,885". A port is an identifier, not a quantity.
        spinnerPort.setEditor(new JSpinner.NumberEditor(spinnerPort, "#"));
        spinnerPort.setValue(settings.aiControl().port());
        checkBoxFullAudit.setSelected(settings.aiControl().fullAudit());

        root.setBorder(new EmptyBorder(8, 8, 8, 8));
        root.add(buildHeader(), BorderLayout.NORTH);
        root.add(buildBody(), BorderLayout.CENTER);

        buttonToggle.addActionListener(e -> toggle());
        checkBoxUnderstood.addActionListener(e -> syncControls());
        checkBoxFullAudit.addActionListener(e -> {
            settings.aiControl().setFullAudit(checkBoxFullAudit.isSelected());
            syncControls();
        });
        buttonApply.addActionListener(e -> apply());
        buttonReject.addActionListener(e -> reject());
        buttonRevert.addActionListener(e -> revert());
        tableDiff.getSelectionModel().addListSelectionListener(e -> showSelectedValue());
        buttonCopyValue.addActionListener(e -> copySelectedValue());
        listAudit.addListSelectionListener(e -> showSelectedAuditEvent());

        refresh();
    }

    JComponent getUI() {
        return root;
    }

    // ------------------------------------------------------------------ layout

    private JComponent buildHeader() {
        var panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setAlignmentX(JComponent.LEFT_ALIGNMENT);

        var controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        controls.setAlignmentX(JComponent.LEFT_ALIGNMENT);
        controls.add(new JLabel("Port"));
        controls.add(spinnerPort);
        controls.add(buttonToggle);
        controls.add(labelStatus);
        panel.add(controls);

        labelEndpoint.setBorder(new EmptyBorder(0, 8, 4, 0));
        panel.add(leftAligned(labelEndpoint));

        // The disclosure, in full, every time. Section 4.2 requires it to be unavoidable rather
        // than something that scrolls past once during setup.
        var warning = new JPanel();
        warning.setLayout(new BoxLayout(warning, BoxLayout.Y_AXIS));
        warning.setAlignmentX(JComponent.LEFT_ALIGNMENT);
        warning.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("Before you enable this"),
                new EmptyBorder(4, 8, 8, 8)));
        warning.add(leftAligned(SettingsTab.warningText(
                "The endpoint listens on 127.0.0.1 only, and has no authentication of any kind.\n\n"
                        + "• Any process running as you on this machine can read your complete "
                        + "settings through it, including external proxy credentials and the full "
                        + "hex ClientHello.\n"
                        + "• Any such process can submit a settings proposal.\n"
                        + "• Nothing it submits is applied until you approve it here. Applying, "
                        + "rejecting and reverting are only ever done in this tab.\n"
                        + "• Binding to loopback is not authentication, and this warning is shown "
                        + "every time for that reason.")));
        warning.add(Box.createVerticalStrut(6));
        warning.add(leftAligned(checkBoxUnderstood));
        panel.add(warning);

        var auditPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        auditPanel.setAlignmentX(JComponent.LEFT_ALIGNMENT);
        auditPanel.add(checkBoxFullAudit);
        var openFolder = new JButton("Open audit folder");
        openFolder.addActionListener(e -> openAuditFolder());
        auditPanel.add(openFolder);
        panel.add(auditPanel);
        panel.add(leftAligned(SettingsTab.descriptionText(
                "The audit trail is plain text and is not encrypted. It records complete request "
                        + "and result values, credentials included, and can be read by anything with "
                        + "access to the folder — other local users, backup software, and sync "
                        + "clients. There is no delete button here; manage the files yourself.")));

        return panel;
    }

    /**
     * BoxLayout positions each child by its own alignmentX, and the defaults differ by component —
     * a check box centres itself while a text area does not — so anything stacked vertically has to
     * say which edge it wants or the column comes out ragged.
     */
    private static <T extends JComponent> T leftAligned(T component) {
        component.setAlignmentX(JComponent.LEFT_ALIGNMENT);
        return component;
    }

    private JComponent buildBody() {
        var proposal = new JPanel(new BorderLayout(0, 6));
        proposal.setBorder(BorderFactory.createTitledBorder("Proposal"));
        proposal.add(textProposalSummary, BorderLayout.NORTH);

        var centre = new JPanel(new BorderLayout(0, 6));
        var scroll = new JScrollPane(tableDiff);
        scroll.setPreferredSize(new java.awt.Dimension(600, 180));
        centre.add(scroll, BorderLayout.CENTER);

        var detail = new JPanel(new BorderLayout(0, 4));
        detail.setBorder(BorderFactory.createTitledBorder("Selected value"));
        detail.add(textValueDetail, BorderLayout.CENTER);
        var detailButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        detailButtons.add(buttonCopyValue);
        detail.add(detailButtons, BorderLayout.SOUTH);
        centre.add(detail, BorderLayout.SOUTH);
        proposal.add(centre, BorderLayout.CENTER);

        var footer = new JPanel(new BorderLayout(0, 4));
        footer.add(textRisk, BorderLayout.CENTER);
        var buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        buttons.add(buttonApply);
        buttons.add(buttonReject);
        buttons.add(buttonRevert);
        footer.add(buttons, BorderLayout.SOUTH);
        proposal.add(footer, BorderLayout.SOUTH);

        var auditPanel = new JPanel(new BorderLayout(0, 4));
        auditPanel.setBorder(BorderFactory.createTitledBorder("Recent audit events"));
        auditPanel.add(new JScrollPane(listAudit), BorderLayout.CENTER);
        auditPanel.add(new JScrollPane(textAuditDetail), BorderLayout.SOUTH);

        var split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, proposal, auditPanel);
        split.setResizeWeight(0.65);
        return split;
    }

    // ------------------------------------------------------------------ lifecycle

    private void toggle() {
        var control = settings.aiControl();
        if (control.enabled()) {
            settings.mcpServer().stop();
            control.setEnabled(false);
            // Ticking the box again is part of enabling again, on purpose.
            checkBoxUnderstood.setSelected(false);
            refresh();
            return;
        }

        var blocked = settings.control().blockedReason();
        if (blocked != null) {
            JOptionPane.showMessageDialog(root,
                    "Settings need attention before AI Control can be enabled.\n\n" + blocked,
                    "Cannot enable", JOptionPane.ERROR_MESSAGE);
            return;
        }

        var port = (Integer) spinnerPort.getValue();
        try {
            settings.aiControl().setPort(port);
            settings.mcpServer().start(port);
            control.setEnabled(true);
        } catch (IOException e) {
            // A taken port fails and stays failed. Section 4.1 forbids moving to another one: the
            // client is configured with a fixed endpoint and would end up talking to whatever else
            // is on the original port.
            control.setEnabled(false);
            JOptionPane.showMessageDialog(root,
                    "Could not listen on 127.0.0.1:" + port + ".\n\n" + e.getMessage()
                            + "\n\nAI Control is off. Choose a different port, or stop whatever is "
                            + "using this one, and try again.",
                    "Could not enable AI Control", JOptionPane.ERROR_MESSAGE);
        }
        refresh();
    }

    private void openAuditFolder() {
        var directory = settings.audit().directory();
        try {
            java.nio.file.Files.createDirectories(directory);
            if (Desktop.isDesktopSupported()) {
                Desktop.getDesktop().open(directory.toFile());
            } else {
                JOptionPane.showMessageDialog(root, directory.toString(), "Audit folder",
                        JOptionPane.INFORMATION_MESSAGE);
            }
        } catch (IOException | UnsupportedOperationException e) {
            JOptionPane.showMessageDialog(root, directory + "\n\n" + e.getMessage(), "Audit folder",
                    JOptionPane.INFORMATION_MESSAGE);
        }
    }

    // ------------------------------------------------------------------ approval

    private void apply() {
        var proposal = settings.aiService().pending();
        if (proposal == null) {
            refresh();
            return;
        }

        // The second look, for changes that can take an installation offline or move traffic
        // somewhere else. It is an extra confirmation, never a way to apply part of a proposal:
        // section 9 keeps the whole thing atomic.
        if (proposal.highRisk() && !confirmHighRisk(proposal)) {
            return;
        }

        var outcome = settings.aiService().approve(proposal.id(), proposal.digest());
        if (outcome instanceof AiSettingsService.ApprovalOutcome.Applied applied) {
            JOptionPane.showMessageDialog(root,
                    "Applied. The settings are now at revision\n" + applied.snapshot().revision(),
                    "Applied", JOptionPane.INFORMATION_MESSAGE);
        } else if (outcome instanceof AiSettingsService.ApprovalOutcome.NeedsReview review) {
            JOptionPane.showMessageDialog(root,
                    "The rules file was edited outside Burp since this proposal was created.\n\n"
                            + "The changes merged cleanly, but the result is not what you were "
                            + "shown, so nothing has been applied. Review the updated diff and "
                            + "press Apply again.\n\nReview " + review.proposal().reviewGeneration(),
                    "Review again", JOptionPane.WARNING_MESSAGE);
        } else {
            var refused = (AiSettingsService.ApprovalOutcome.Refused) outcome;
            JOptionPane.showMessageDialog(root,
                    refused.message() + "\n\nNothing has been changed.",
                    "Not applied (" + refused.code() + ")", JOptionPane.ERROR_MESSAGE);
        }
        refresh();
    }

    private boolean confirmHighRisk(Proposal proposal) {
        var summary = new StringBuilder("This proposal includes changes that need a second look:\n\n");
        for (var risk : proposal.risks()) {
            if (risk.high()) {
                summary.append("• ").append(risk.message()).append('\n');
            }
        }
        summary.append("\nApply the whole proposal?");
        return JOptionPane.showConfirmDialog(root, summary.toString(), "Confirm a high-risk change",
                JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE) == JOptionPane.YES_OPTION;
    }

    private void reject() {
        var proposal = settings.aiService().pending();
        if (proposal == null) {
            refresh();
            return;
        }
        var reason = JOptionPane.showInputDialog(root, "Why are you rejecting it? (optional)",
                "Reject proposal", JOptionPane.QUESTION_MESSAGE);
        if (reason == null) {
            return;
        }
        settings.aiService().reject(proposal.id(), reason);
        refresh();
    }

    private void revert() {
        var target = settings.aiService().revertTarget();
        if (target == null) {
            refresh();
            return;
        }
        var confirmed = JOptionPane.showConfirmDialog(root,
                "Put the settings back to how they were before the last AI change?\n\n"
                        + "This is itself a change: it is validated, recorded, and produces a new "
                        + "revision. There is nothing to undo it with afterwards.",
                "Revert last AI apply", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
        if (confirmed != JOptionPane.YES_OPTION) {
            return;
        }

        var outcome = settings.aiService().revert();
        if (outcome instanceof AiSettingsService.ApprovalOutcome.Refused refused) {
            JOptionPane.showMessageDialog(root, refused.message(), "Not reverted",
                    JOptionPane.ERROR_MESSAGE);
        }
        refresh();
    }

    // ------------------------------------------------------------------ display

    void refresh() {
        SwingUtilities.invokeLater(() -> {
            syncControls();
            showProposal();
            showAudit();
            onProposalChanged.run();
        });
    }

    private void syncControls() {
        var enabled = settings.aiControl().enabled();
        var running = settings.mcpServer().running();

        buttonToggle.setText(enabled ? "Disable" : "Enable");
        // Enabling is gated on the acknowledgement; disabling never is.
        buttonToggle.setEnabled(enabled || checkBoxUnderstood.isSelected());
        // The port is part of a fixed endpoint a client is configured with, so it can only change
        // while nothing is listening.
        spinnerPort.setEnabled(!enabled);
        checkBoxUnderstood.setEnabled(!enabled);

        var blocked = settings.control().blockedReason();
        if (blocked != null) {
            labelStatus.setText("Settings need attention — AI Control cannot be enabled");
            labelEndpoint.setText(blocked);
            return;
        }

        labelStatus.setText(running ? "Listening" : "Off");
        labelEndpoint.setText(running
                ? "Endpoint: " + settings.mcpServer().endpoint()
                        + "   —   full audit is " + (settings.aiControl().fullAudit() ? "ON" : "OFF")
                : "Not listening. Enabling is per Burp session; it is never restored automatically.");
    }

    private void showProposal() {
        var proposal = settings.aiService().pending();
        var pending = proposal != null && proposal.status() == Proposal.Status.PENDING;

        buttonApply.setEnabled(pending);
        buttonReject.setEnabled(proposal != null && proposal.status() != Proposal.Status.REJECTED);
        buttonRevert.setEnabled(settings.aiService().canRevert());

        if (proposal == null) {
            textProposalSummary.setText("No proposal is waiting.\n\nCurrent revision: "
                    + settings.snapshot().revision());
            diffModel.set(List.of());
            textRisk.setText(" ");
            textValueDetail.setText(" ");
            buttonCopyValue.setEnabled(false);
            return;
        }

        var header = new StringBuilder();
        header.append("Status: ").append(proposal.status());
        if (proposal.reviewGeneration() > 1) {
            header.append("   (review ").append(proposal.reviewGeneration()).append(')');
        }
        header.append('\n');
        if (!proposal.summary().isEmpty()) {
            // Text supplied by the caller, and untrusted: shown as a label, and it is deliberately
            // not part of what an approval is checked against.
            header.append("Client summary: ").append(proposal.summary()).append('\n');
        }
        header.append("From revision: ").append(proposal.baseRevision()).append('\n');
        header.append("To revision:   ").append(proposal.candidateRevision()).append('\n');
        header.append("Expires:       ").append(proposal.expiresAt());
        if (proposal.status() == Proposal.Status.CONFLICTED) {
            header.append("\n\nThis proposal can no longer be applied (")
                    .append(proposal.conflictCode())
                    .append("). Reject it and ask for a new one.");
        }
        textProposalSummary.setText(header.toString());

        diffModel.set(proposal.diff());
        textRisk.setText(riskText(proposal));
        textValueDetail.setText(" ");
        buttonCopyValue.setEnabled(false);
    }

    private static String riskText(Proposal proposal) {
        var text = new StringBuilder();
        if (proposal.risks().isEmpty()) {
            text.append("No risks flagged.");
        } else {
            for (var risk : proposal.risks()) {
                text.append('[').append(risk.severity()).append("] ").append(risk.message()).append('\n');
            }
        }
        if (!proposal.impact().isEmpty()) {
            text.append('\n');
            for (var impact : proposal.impact()) {
                text.append(impact.path()).append(" — ").append(impact.effect());
                if (impact.requiresUserAction()) {
                    text.append(" (needs a reload)");
                }
                text.append(": ").append(impact.message()).append('\n');
            }
        }
        return text.toString();
    }

    private void showSelectedValue() {
        var row = tableDiff.getSelectedRow();
        // A control that does nothing when pressed is worse than one that is visibly unavailable,
        // and every other button on this panel already disables itself.
        buttonCopyValue.setEnabled(row >= 0);
        if (row < 0) {
            textValueDetail.setText(" ");
            return;
        }
        var change = diffModel.at(row);
        var text = new StringBuilder(change.path()).append('\n');
        if (change.before() != null) {
            text.append("\nBefore:\n").append(render(change.before()));
        }
        if (change.after() != null) {
            text.append("\nAfter:\n").append(render(change.after()));
        }
        textValueDetail.setText(text.toString());
    }

    private void copySelectedValue() {
        var row = tableDiff.getSelectedRow();
        if (row < 0) {
            return;
        }
        var change = diffModel.at(row);
        var value = change.after() != null ? change.after() : change.before();
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(render(value)), null);
    }

    private static String render(Object value) {
        return value == null ? "(none)" : String.valueOf(value);
    }

    private void showAudit() {
        auditModel.clear();
        auditDetails.clear();
        for (var event : settings.audit().recent(MAX_AUDIT_EVENTS)) {
            var type = event.has("event") && event.get("event").isJsonObject()
                    && event.getAsJsonObject("event").has("type")
                    ? event.getAsJsonObject("event").get("type").getAsString()
                    : "?";
            var at = event.has("at") ? event.get("at").getAsString() : "";
            auditModel.addElement(at + "  " + type);
            auditDetails.add(burp.control.Jcs.string(event));
        }
        textAuditDetail.setText(auditModel.isEmpty()
                ? (settings.aiControl().fullAudit()
                ? "Nothing recorded yet." : "Full audit is off, so nothing is being recorded.")
                : " ");
    }

    private void showSelectedAuditEvent() {
        var index = listAudit.getSelectedIndex();
        if (index >= 0 && index < auditDetails.size()) {
            textAuditDetail.setText(auditDetails.get(index));
            textAuditDetail.setCaretPosition(0);
        }
    }

    /**
     * The field-level diff. One row per changed leaf field, never a whole rule, so nothing can hide
     * inside a collapsed object.
     */
    private static final class DiffTableModel extends AbstractTableModel {
        private static final String[] COLUMNS = {"Setting", "Change", "Before", "After"};

        private List<Wire.FieldChange> changes = List.of();

        void set(List<Wire.FieldChange> value) {
            this.changes = value;
            fireTableDataChanged();
        }

        Wire.FieldChange at(int row) {
            return changes.get(row);
        }

        @Override
        public int getRowCount() {
            return changes.size();
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
        public Object getValueAt(int row, int column) {
            var change = changes.get(row);
            return switch (column) {
                case 0 -> change.path();
                case 1 -> change.operation();
                case 2 -> summarize(change.before());
                default -> summarize(change.after());
            };
        }

        /**
         * A full hex ClientHello is thousands of characters; showing it inline would push every
         * other row off the screen. It is truncated here and available in full below.
         */
        private static String summarize(Object value) {
            if (value == null) {
                return "";
            }
            var text = String.valueOf(value);
            return text.length() <= INLINE_VALUE_LIMIT
                    ? text
                    : text.substring(0, INLINE_VALUE_LIMIT) + "… (" + text.length() + " chars)";
        }
    }
}
