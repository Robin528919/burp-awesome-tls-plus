package burp;

import burp.control.AiSettingsService;
import burp.control.ClientSnippets;
import burp.control.ClientSnippets.Kind;
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
import java.awt.Component;
import java.awt.Desktop;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
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

    /** What the server is called in a client's configuration. */
    private static final String SERVER_NAME = "awesome-tls";

    /**
     * The companion skill, served from the repository rather than the jar.
     * <p>
     * Registering the endpoint leaves a client knowing two tool names and their schemas, and
     * nothing about fingerprint precedence, the acknowledgements a proposal must carry, or how a
     * ClientHello is captured in the first place. Fetching it keeps one copy authoritative instead
     * of shipping a snapshot that ages with the installed jar.
     */
    private static final String SKILL_URL = "https://raw.githubusercontent.com/Robin528919/"
            + "burp-awesome-tls-plus/main/skills/awesome-tls-mcp/SKILL.md";

    private final Settings settings;
    private final Runnable onProposalChanged;

    private final JPanel root = new JPanel(new BorderLayout(0, 8));

    private final JSpinner spinnerPort =
            new JSpinner(new SpinnerNumberModel(McpServer.DEFAULT_PORT, 1, 65535, 1));
    private final JButton buttonToggle = new JButton("Enable");
    private final JLabel labelStatus = new JLabel();
    private final JLabel labelEndpoint = new JLabel();
    private final JLabel labelAuditState = new JLabel();
    private final JLabel labelAutoApplyState = new JLabel();
    private final JTextArea textGoServer = SettingsTab.descriptionText(" ");
    /** ADR-0001 section 4.2's disclosure, in full. Shown until acknowledged, and again on unticking. */
    private static final String RISK_TEXT =
            "The endpoint listens on 127.0.0.1 only, and has no authentication of any kind.\n\n"
                    + "\u2022 Any process running as you on this machine can read your complete "
                    + "settings through it, including external proxy credentials and the full hex "
                    + "ClientHello.\n"
                    + "\u2022 Any such process can submit a settings change.\n"
                    + "\u2022 With \"Apply changes automatically\" off, nothing it submits takes "
                    + "effect until you approve it here.\n"
                    + "\u2022 Binding to loopback is not authentication. \"Risk acknowledged\" is "
                    + "remembered across restarts; enabling the endpoint is not.\n\n"
                    + "The audit trail is plain text and is not encrypted. It records complete "
                    + "request and result values, credentials included, and can be read by anything "
                    + "with access to the folder \u2014 other local users, backup software, and "
                    + "sync clients. There is no delete button here; manage the files yourself.";

    /**
     * Lives in the toolbar rather than inside the warning, because the warning collapses once this
     * is ticked and a control that hides itself cannot be unticked. The short label is only ever
     * read after the full sentence has been on screen — it cannot be ticked before that.
     */
    private final JCheckBox checkBoxUnderstood = new JCheckBox("Risk acknowledged");

    {
        checkBoxUnderstood.setToolTipText(
                "I understand and accept that any process on this machine can read these values. "
                        + "Untick to read the full warning again.");
    }
    private final JCheckBox checkBoxFullAudit = new JCheckBox("Record everything to the audit trail");

    /**
     * The long-form disclosure. Collapsed once acknowledged rather than once enabled: the point at
     * which the user has read it is the tick, not the button, and leaving five paragraphs on screen
     * after that is just something to scroll past.
     */
    private final Stack panelRiskDetail = new Stack();
    private final JCheckBox checkBoxAutoApply =
            new JCheckBox("Apply changes automatically, without review");

    /**
     * Everything that only matters while deciding whether to switch this on. It is hidden once the
     * listener is running, because it is 200 pixels of text competing with the diff a user is
     * trying to review — and the panel's two jobs never happen at the same time. Nothing is lost:
     * the listener can only be enabled while this is visible, which is exactly what section 4.2
     * requires of the warning.
     */
    private final JPanel panelSetup = new JPanel();

    private final JPanel panelSelectedValue = new JPanel(new BorderLayout(0, 4));

    private final JTextArea textConnect = SettingsTab.descriptionText(" ");
    private final JLabel labelCopied = new JLabel(" ");

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
        checkBoxUnderstood.setSelected(settings.aiControl().riskAcknowledged());

        root.setBorder(new EmptyBorder(8, 8, 8, 8));
        var content = new Stack();
        content.row(buildHeader());
        content.row(buildProposalSection(), 1);
        content.row(buildAuditSection());
        var scroll = new JScrollPane(content,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.setBorder(null);
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        root.add(scroll, BorderLayout.CENTER);

        // Outside the scroll area on purpose. These are the only actions on the panel that change
        // anything, and one of them was landing below the fold on a short window — a decision the
        // user cannot take without first discovering they need to scroll for it.
        var actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        actions.setBorder(new EmptyBorder(4, 0, 0, 0));
        actions.add(buttonApply);
        actions.add(buttonReject);
        actions.add(buttonRevert);
        root.add(actions, BorderLayout.SOUTH);

        buttonToggle.addActionListener(e -> toggle());
        checkBoxUnderstood.addActionListener(e -> {
            settings.aiControl().setRiskAcknowledged(checkBoxUnderstood.isSelected());
            syncControls();
        });
        checkBoxFullAudit.addActionListener(e -> {
            settings.aiControl().setFullAudit(checkBoxFullAudit.isSelected());
            syncControls();
        });
        checkBoxAutoApply.addActionListener(e -> armAutoApply());
        buttonApply.addActionListener(e -> apply());
        buttonReject.addActionListener(e -> reject());
        buttonRevert.addActionListener(e -> revert());
        // The commands quote the port that is actually in the field, so editing it before
        // enabling still produces a command that will work.
        spinnerPort.addChangeListener(e -> showConnectSnippet(lastCopied));
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
        var panel = new Stack();

        var controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        controls.add(new JLabel("Port"));
        controls.add(spinnerPort);
        controls.add(buttonToggle);
        controls.add(labelStatus);
        controls.add(Box.createHorizontalStrut(16));
        controls.add(checkBoxUnderstood);
        controls.add(checkBoxAutoApply);
        controls.add(checkBoxFullAudit);
        var openFolder = new JButton("Open audit folder");
        openFolder.addActionListener(e -> openAuditFolder());
        controls.add(openFolder);
        panel.row(controls);

        labelEndpoint.setBorder(new EmptyBorder(0, 8, 4, 0));
        panel.row(labelEndpoint);
        panel.row(textGoServer);

        // The disclosure is unavoidable rather than something that scrolls past once during setup:
        // it is in full, and Enable stays dead, until it has been acknowledged. Then the whole box
        // goes — its only remaining job would be to occupy the screen. Unticking in the toolbar
        // brings it back, which is the same action that blocks Enable again.
        var warning = new Stack();
        warning.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("Before you enable this"),
                new EmptyBorder(4, 8, 8, 8)));
        warning.row(SettingsTab.warningText(RISK_TEXT));
        warning.row(Box.createVerticalStrut(6));
        // Section 4.2 also requires the enable-time warning to state whether full audit is on. It
        // used to appear only in the endpoint line, which reads "not listening" at exactly the
        // moment this is being decided.
        warning.row(labelAuditState);
        warning.row(Box.createVerticalStrut(4));
        warning.row(labelAutoApplyState);

        panelSetup.setLayout(new BorderLayout(0, 4));
        var setupRows = new Stack();
        setupRows.row(warning);
        panelSetup.add(setupRows, BorderLayout.CENTER);
        panel.row(panelSetup);

        panel.row(buildConnectSection());
        return panel;
    }

    /**
     * A one-column layout whose rows each get the container's full width.
     * <p>
     * BoxLayout cannot be used for this. It sizes a child to that child's preferred width, and a
     * wrapping JTextArea has no meaningful preferred width — it needs to be told how wide it is
     * before it can work out how tall it is. The result is description text clipped at the right
     * edge, which is exactly what happened to the audit and client-setup paragraphs here.
     */
    private static final class Stack extends JPanel implements javax.swing.Scrollable {
        private int row;

        Stack() {
            super(new GridBagLayout());
        }

        Stack row(Component component) {
            return row(component, 0);
        }

        /**
         * @param weighty how much of any leftover height this row should absorb.
         */
        Stack row(Component component, double weighty) {
            var constraints = new GridBagConstraints();
            constraints.gridx = 0;
            constraints.gridy = row++;
            constraints.weightx = 1;
            constraints.weighty = weighty;
            constraints.fill = weighty > 0 ? GridBagConstraints.BOTH : GridBagConstraints.HORIZONTAL;
            constraints.anchor = GridBagConstraints.NORTHWEST;
            super.add(component, constraints);
            return this;
        }

        @Override
        public java.awt.Dimension getPreferredScrollableViewportSize() {
            return getPreferredSize();
        }

        @Override
        public int getScrollableUnitIncrement(java.awt.Rectangle visible, int orientation, int direction) {
            return 16;
        }

        @Override
        public int getScrollableBlockIncrement(java.awt.Rectangle visible, int orientation, int direction) {
            return visible.height;
        }

        /** Never scrolls sideways; the point of this layout is that rows take the full width. */
        @Override
        public boolean getScrollableTracksViewportWidth() {
            return true;
        }

        /**
         * Fills a tall window, scrolls a short one. Without this the panel either cannot grow or
         * cannot shrink, and in a short window a BorderLayout section smaller than its own minimum
         * draws its parts on top of each other.
         */
        @Override
        public boolean getScrollableTracksViewportHeight() {
            return getParent() instanceof javax.swing.JViewport viewport
                    && viewport.getHeight() > getPreferredSize().height;
        }
    }

    /**
     * Ready-made commands for pointing a client at this endpoint.
     * <p>
     * The endpoint is fixed and the port is configurable, so the thing a user needs is not the URL
     * on its own but the exact command their client takes — which is easy to get subtly wrong, and
     * whose failure mode is a client that silently never connects.
     */
    private JComponent buildConnectSection() {
        var panel = new Stack();
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("Connect a client"),
                new EmptyBorder(4, 8, 8, 8)));

        var buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        buttons.add(copyButton("Copy endpoint URL", Kind.ENDPOINT));
        buttons.add(copyButton("Claude Code", Kind.CLAUDE_CODE));
        buttons.add(copyButton("Codex", Kind.CODEX));
        buttons.add(copyButton("JSON config", Kind.JSON));
        buttons.add(copyButton("JSON config: OpenCode", Kind.JSON_OPENCODE));
        buttons.add(labelCopied);
        panel.row(buttons);

        panel.row(textConnect);
        panel.row(SettingsTab.descriptionText(
                "The Claude Code and Codex commands register the server globally, for every "
                        + "project. Drop \"--scope user\" to keep it to the current project instead. "
                        + "A globally registered client can reach this endpoint from any session, "
                        + "whenever it is enabled here."));
        panel.row(SettingsTab.descriptionText(
                "Registering is not the same as connecting. This endpoint speaks MCP "
                        + McpServer.PROTOCOL_VERSION + " and nothing else: Codex Desktop and Codex "
                        + "CLI are what it is built against, any other client on that revision "
                        + "is best-effort, and a client still on 2025-11-25 or earlier is answered "
                        + "with HTTP 400 and \"unsupported protocol version\" \u2014 the endpoint "
                        + "refusing the handshake, not a mistake in the command above. Those "
                        + "clients are not stuck: the skill below carries the plain HTTP requests, "
                        + "which need no MCP support at all and can do everything the tools can."));

        var skillButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        skillButtons.add(copyButton("Install skill (all agents)", Kind.SKILL));
        skillButtons.add(copyButton("Install skill: Codex", Kind.CODEX_SKILL));
        panel.row(skillButtons);
        panel.row(SettingsTab.descriptionText(
                "Registering the endpoint only tells a client that two tools exist. These install "
                        + "the usage guide alongside it \u2014 which of a fingerprint and a hex "
                        + "ClientHello wins, the acknowledgements a proposal has to carry, how to "
                        + "capture a ClientHello, and the raw HTTP requests for clients that "
                        + "cannot speak this MCP revision. Optional, and it changes nothing in "
                        + "Burp. The first line writes the two paths every agent scans "
                        + "(~/.claude/skills and ~/.agents/skills), which is what Claude Code, "
                        + "OpenCode, Cursor, Copilot and Gemini CLI all read; Codex has its own "
                        + "~/.codex/skills. Both lines are safe to run twice."));
        return panel;
    }

    /** The snippets themselves live in {@link ClientSnippets}, which has a self-check. */
    private Kind lastCopied = Kind.ENDPOINT;

    private JButton copyButton(String label, Kind snippet) {
        var button = new JButton(label);
        button.addActionListener(e -> {
            var text = snippetFor(snippet);
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(text), null);
            lastCopied = snippet;
            showConnectSnippet(snippet);
            labelCopied.setText("Copied");
            var timer = new javax.swing.Timer(3000, event -> labelCopied.setText(" "));
            timer.setRepeats(false);
            timer.start();
        });
        return button;
    }

    private void showConnectSnippet(Kind snippet) {
        textConnect.setText(snippetFor(snippet));
    }

    /**
     * @return the endpoint the client should be pointed at: the one actually bound when the
     * listener is up, and otherwise the one the port field would produce.
     */
    private String currentEndpoint() {
        var running = settings.mcpServer().endpoint();
        if (running != null) {
            return running;
        }
        return "http://" + McpServer.BIND_HOST + ":" + spinnerPort.getValue() + McpServer.PATH;
    }

    private String snippetFor(Kind snippet) {
        return ClientSnippets.of(snippet, SERVER_NAME, currentEndpoint(), SKILL_URL);
    }

    private JComponent buildProposalSection() {
        var proposal = new JPanel(new BorderLayout(0, 6));
        proposal.setBorder(BorderFactory.createTitledBorder("Proposal"));
        proposal.add(textProposalSummary, BorderLayout.NORTH);

        // The diff is the reason this panel exists, so it takes whatever height is left over.
        tableDiff.setPreferredScrollableViewportSize(new java.awt.Dimension(600, 200));
        tableDiff.setFillsViewportHeight(true);
        // Only the trailing value column absorbs a window resize; the rest keep their widths.
        tableDiff.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        // Scope and field have to stay readable — truncating them loses the only part of a row
        // that says what changed — while "add"/"replace"/"remove" never needs more than its own
        // width. Both the current and the preferred width are set: in this resize mode the columns
        // that are not last keep whatever width they already have, which is the 75px default.
        columnWidth(0, 210, 120);
        columnWidth(1, 130, 90);
        columnWidth(2, 75, 60);
        columnWidth(3, 200, 60);
        columnWidth(4, 200, 60);

        var centre = new JPanel(new BorderLayout(0, 6));
        centre.add(new JScrollPane(tableDiff), BorderLayout.CENTER);

        panelSelectedValue.setBorder(BorderFactory.createTitledBorder("Selected value"));
        var valueScroll = new JScrollPane(textValueDetail);
        valueScroll.setPreferredSize(new java.awt.Dimension(600, 90));
        panelSelectedValue.add(valueScroll, BorderLayout.CENTER);
        var detailButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        detailButtons.add(buttonCopyValue);
        panelSelectedValue.add(detailButtons, BorderLayout.SOUTH);
        // Only takes space once there is something in it; an empty titled box in the middle of the
        // panel is a hundred pixels that never say anything.
        panelSelectedValue.setVisible(false);
        centre.add(panelSelectedValue, BorderLayout.SOUTH);
        proposal.add(centre, BorderLayout.CENTER);

        proposal.add(textRisk, BorderLayout.SOUTH);
        return proposal;
    }

    private void columnWidth(int index, int width, int minimum) {
        var column = tableDiff.getColumnModel().getColumn(index);
        column.setMinWidth(minimum);
        column.setPreferredWidth(width);
        column.setWidth(width);
    }

    private JComponent buildAuditSection() {
        var auditPanel = new JPanel(new BorderLayout(0, 4));
        auditPanel.setBorder(BorderFactory.createTitledBorder("Recent audit events"));
        var listScroll = new JScrollPane(listAudit);
        listScroll.setPreferredSize(new java.awt.Dimension(600, 90));
        auditPanel.add(listScroll, BorderLayout.CENTER);
        var auditDetailScroll = new JScrollPane(textAuditDetail);
        auditDetailScroll.setPreferredSize(new java.awt.Dimension(600, 70));
        auditPanel.add(auditDetailScroll, BorderLayout.SOUTH);
        return auditPanel;
    }

    // ------------------------------------------------------------------ lifecycle

    private void toggle() {
        var control = settings.aiControl();
        if (control.enabled()) {
            settings.mcpServer().stop();
            control.setEnabled(false);
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

    /**
     * Arms or disarms applying without review.
     * <p>
     * Confirmed each time it is armed, and never persisted. It removes the only thing standing
     * between an unauthenticated local endpoint and a silent settings change, so it should be a
     * thing the user decided today, not a thing they decided once and forgot.
     */
    private void armAutoApply() {
        if (!checkBoxAutoApply.isSelected()) {
            settings.aiControl().setAutoApply(false);
            refresh();
            return;
        }

        var confirmed = JOptionPane.showConfirmDialog(root,
                "Apply settings changes as soon as they arrive, without reviewing them?\n\n"
                        + "This endpoint has no authentication. While this is armed, any process "
                        + "running as you on this machine can change your settings — including the "
                        + "upstream proxy your traffic goes through, and the address the listener "
                        + "binds to — with no prompt.\n\n"
                        + "Everything else still applies: changes are validated, recorded, and "
                        + "\"Revert last AI apply\" still undoes the most recent one. It is only "
                        + "the review step that is skipped.\n\n"
                        + "This is remembered across restarts. The listener itself is not — it "
                        + "stays closed until you open it, so nothing can arrive before you do.",
                "Arm automatic apply", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);

        var armed = confirmed == JOptionPane.YES_OPTION;
        settings.aiControl().setAutoApply(armed);
        checkBoxAutoApply.setSelected(armed);
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
            showConnectSnippet(lastCopied);
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
                        + (settings.aiControl().autoApply() ? "   —   AUTO-APPLY ARMED" : "")
                : "Not listening. Enabling is per Burp session; it is never restored automatically.");
        checkBoxAutoApply.setSelected(settings.aiControl().autoApply());
        labelAutoApplyState.setText(settings.aiControl().autoApply()
                ? "Automatic apply is ARMED. A valid change takes effect the moment it arrives, "
                        + "with no review."
                : "Automatic apply is off. A change waits here until you approve it.");

        labelAuditState.setText("Full audit is currently "
                + (settings.aiControl().fullAudit() ? "ON" : "OFF")
                + ". Everything above would " + (settings.aiControl().fullAudit() ? "" : "not ")
                + "be written to the audit trail in full.");

        describeGoServer();

        // Setting up and reviewing never happen at the same moment, so they do not have to share
        // the window. While the listener is down the panel is a decision; while it is up it is a
        // review surface, and the diff needs the room. Acknowledging ends the decision early, so
        // it collapses on the tick too rather than waiting for the button.
        panelSetup.setVisible(!running && !checkBoxUnderstood.isSelected());
    }

    /**
     * Says what the Go server is doing, and why when it is not doing it.
     * <p>
     * Everything else on this panel reports the local listener; this reports the one that actually
     * carries traffic. It is worth its own line because the two can disagree — most usefully when
     * a reload leaves a previous instance holding the port and this one never bound, which
     * otherwise shows up only as an inspect result quietly claiming there is no listener.
     */
    private void describeGoServer() {
        var status = settings.runtimeStatus();
        var spoof = status.spoof();
        if (spoof != null && spoof.running() && spoof.actualAddress() != null) {
            textGoServer.setText("The Go server is listening on " + spoof.actualAddress() + ".");
            return;
        }

        var reason = spoof == null ? null : spoof.lastError();
        if (reason != null && !reason.isBlank()) {
            textGoServer.setText("The Go server this extension controls is not listening: " + reason
                    + "\n\nIf the port is already in use, it is most likely held by a previous load "
                    + "of this extension. A native library cannot be unloaded, so reloading the "
                    + "extension leaves the old one running and the new one never binds — meaning "
                    + "traffic is still being handled by the previous build. Restart Burp to clear it.");
            return;
        }
        textGoServer.setText("The Go server this extension controls reports that it is not listening. "
                + "If traffic is still working, it is being handled by a previous load of this "
                + "extension; restart Burp to make this instance the one serving.");
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
            panelSelectedValue.setVisible(false);
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
        panelSelectedValue.setVisible(false);
    }

    /**
     * Risks first, then what actually happens and when.
     * <p>
     * The runtime impact is grouped rather than listed per field. A proposal that adds two rules
     * produces a dozen entries all saying the same thing, and the one entry that matters — the
     * change that will not take effect until something is reloaded — ends up indistinguishable from
     * the rest of the wall. So the ordinary case is counted, and anything else is spelled out.
     */
    private static String riskText(Proposal proposal) {
        var text = new StringBuilder();
        if (proposal.risks().isEmpty()) {
            text.append("No risks flagged.");
        } else {
            for (var risk : proposal.risks()) {
                text.append('[').append(risk.severity()).append("] ").append(risk.message()).append('\n');
            }
        }

        var immediate = proposal.impact().stream()
                .filter(impact -> "NEXT_REQUEST".equals(impact.effect()))
                .count();
        var deferred = proposal.impact().stream()
                .filter(impact -> !"NEXT_REQUEST".equals(impact.effect()))
                .toList();

        if (immediate > 0 || !deferred.isEmpty()) {
            text.append('\n');
        }
        if (immediate > 0) {
            text.append(immediate).append(immediate == 1 ? " change takes" : " changes take")
                    .append(" effect on the next request.\n");
        }
        for (var impact : deferred) {
            text.append(impact.path()).append(" — ").append(impact.effect());
            if (impact.requiresUserAction()) {
                text.append(" (needs a reload)");
            }
            text.append(": ").append(impact.message()).append('\n');
        }
        return text.toString();
    }

    private void showSelectedValue() {
        var row = tableDiff.getSelectedRow();
        // A control that does nothing when pressed is worse than one that is visibly unavailable,
        // and every other button on this panel already disables itself.
        buttonCopyValue.setEnabled(row >= 0);
        panelSelectedValue.setVisible(row >= 0);
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
    /**
     * The field-level diff. One row per changed leaf field, never a whole rule, so nothing can hide
     * inside a collapsed object.
     * <p>
     * Scope and field are separate columns rather than one output path. A path renders as
     * {@code /domainRules/byHost/*.cdn.example.org/fingerprint}, and the first thing a column of
     * that width truncates is the tail — which is the only part that says which field changed.
     */
    private static final class DiffTableModel extends AbstractTableModel {
        private static final String[] COLUMNS = {"Scope", "Field", "Change", "Before", "After"};
        private static final String RULE_PREFIX = "/domainRules/byHost/";
        private static final String SETTINGS_PREFIX = "/settings/";

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
                case 0 -> scopeOf(change.path());
                case 1 -> fieldOf(change.path());
                case 2 -> change.operation();
                case 3 -> summarize(change.before());
                default -> summarize(change.after());
            };
        }

        private static String scopeOf(String path) {
            if (path.startsWith(SETTINGS_PREFIX)) {
                return "Global";
            }
            if (!path.startsWith(RULE_PREFIX)) {
                return path;
            }
            var rest = path.substring(RULE_PREFIX.length());
            var slash = rest.lastIndexOf('/');
            return unescape(slash < 0 ? rest : rest.substring(0, slash));
        }

        private static String fieldOf(String path) {
            var slash = path.lastIndexOf('/');
            return slash < 0 ? path : unescape(path.substring(slash + 1));
        }

        /** RFC 6901 tokens are escaped in the wire path; the table shows what the user typed. */
        private static String unescape(String token) {
            return token.replace("~1", "/").replace("~0", "~");
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
