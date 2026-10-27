package vaultlite.gui;

import java.awt.AWTEvent;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Font;
import java.awt.GraphicsEnvironment;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.Window;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;
import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.Timer;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import vaultlite.Audit;
import vaultlite.Clip;
import vaultlite.Crypto;
import vaultlite.Entry;
import vaultlite.Hibp;
import vaultlite.Strength;
import vaultlite.Vault;
import vaultlite.VaultException;

public final class VaultPanel extends JPanel {
    private static final int CLIP_SECONDS = 20;

    private final Path file;
    private final int autolockSeconds;
    private Vault vault;
    private long lastActivity = System.currentTimeMillis();
    private boolean loading, dirty;
    private Set<String> flagged = new HashSet<>();

    private final DefaultListModel<Entry> model = new DefaultListModel<>();
    private final JList<Entry> list = new JList<>(model);
    private final JTextField search = new JTextField();
    private final JTextField title = new JTextField(24);
    private final JTextField user = new JTextField(24);
    private final JPasswordField pass = new JPasswordField(24);
    private final JCheckBox show = new JCheckBox("Show");
    private final JLabel meter = new JLabel(" ");
    private final JTextField url = new JTextField(24);
    private final JTextField tags = new JTextField(24);
    private final JTextArea notes = new JTextArea(6, 24);
    private final JLabel status = new JLabel(" ");
    private final char defaultEcho = pass.getEchoChar();

    public VaultPanel(Path file, int autolockSeconds) {
        super(new BorderLayout());
        this.file = file;
        this.autolockSeconds = autolockSeconds;

        search.getAccessibleContext().setAccessibleName("Search entries");
        title.getAccessibleContext().setAccessibleName("Title");
        user.getAccessibleContext().setAccessibleName("Username");
        pass.getAccessibleContext().setAccessibleName("Password");
        url.getAccessibleContext().setAccessibleName("URL");
        tags.getAccessibleContext().setAccessibleName("Tags, comma separated");
        notes.getAccessibleContext().setAccessibleName("Notes");
        list.getAccessibleContext().setAccessibleName("Entries");
        notes.setLineWrap(true);
        notes.setWrapStyleWord(true);
        list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        list.setCellRenderer(new javax.swing.DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> l, Object v, int i, boolean sel, boolean focus) {
                Entry e = (Entry) v;
                String text = e.username.isEmpty() ? e.title : e.title + " (" + e.username + ")";
                if (flagged.contains(e.id)) text += "  [weak or reused]";
                return super.getListCellRendererComponent(l, text, i, sel, focus);
            }
        });
        list.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) load(list.getSelectedValue());
        });
        search.getDocument().addDocumentListener(new Changed(this::refresh));
        DocumentListener mark = new Changed(() -> {
            if (!loading) dirty = true;
        });
        for (javax.swing.text.JTextComponent c : new javax.swing.text.JTextComponent[] {title, user, pass, url, tags, notes}) {
            c.getDocument().addDocumentListener(mark);
        }
        pass.getDocument().addDocumentListener(new Changed(this::rate));
        show.addActionListener(e -> pass.setEchoChar(show.isSelected() ? 0 : defaultEcho));
        pass.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));

        JPanel left = new JPanel(new BorderLayout(0, 4));
        left.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 3));
        left.add(search, BorderLayout.NORTH);
        left.add(new JScrollPane(list), BorderLayout.CENTER);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, details());
        split.setDividerLocation(280);
        split.setBorder(null);

        status.setBorder(BorderFactory.createEmptyBorder(3, 8, 3, 8));
        add(menuBar(), BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);
        add(status, BorderLayout.SOUTH);
        setPreferredSize(new java.awt.Dimension(860, 520));
        setUnlocked(false);
        rate();

        if (autolockSeconds > 0) {
            Toolkit.getDefaultToolkit().addAWTEventListener(ev -> lastActivity = System.currentTimeMillis(),
                    AWTEvent.MOUSE_EVENT_MASK | AWTEvent.KEY_EVENT_MASK | AWTEvent.MOUSE_MOTION_EVENT_MASK
                            | AWTEvent.MOUSE_WHEEL_EVENT_MASK);
            new Timer(1000, e -> {
                if (vault != null && System.currentTimeMillis() - lastActivity > autolockSeconds * 1000L) {
                    lock("Locked after " + autolockSeconds + "s of inactivity.");
                }
            }).start();
        }
    }

    public static VaultPanel demo() {
        VaultPanel p = new VaultPanel(Path.of("demo.vlt"), 0);
        p.vault = Vault.demo();
        p.setUnlocked(true);
        p.refresh();
        p.list.setSelectedIndex(1);
        p.status.setText("Unlocked.");
        p.setSize(860, 520);
        Layouts.settle(p);
        return p;
    }

    private JPanel details() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(BorderFactory.createEmptyBorder(6, 3, 6, 6));
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(3, 3, 3, 3);
        g.anchor = GridBagConstraints.NORTHWEST;
        JPanel passRow = new JPanel(new BorderLayout(4, 0));
        passRow.add(pass, BorderLayout.CENTER);
        passRow.add(show, BorderLayout.EAST);
        Object[][] rows = {{"Title", title}, {"Username", user}, {"Password", passRow}, {"", meter}, {"URL", url},
                {"Notes", new JScrollPane(notes)}, {"Tags", tags}};
        for (int i = 0; i < rows.length; i++) {
            g.gridy = i; g.gridx = 0; g.weightx = 0; g.weighty = 0; g.fill = GridBagConstraints.NONE;
            p.add(new JLabel((String) rows[i][0]), g);
            g.gridx = 1; g.weightx = 1; g.fill = GridBagConstraints.HORIZONTAL;
            if (i == 5) { g.weighty = 1; g.fill = GridBagConstraints.BOTH; }
            p.add((Component) rows[i][1], g);
        }
        JButton[] buttons = {button("New", this::newEntry), button("Save", this::saveEntry),
                button("Delete", this::deleteEntry), button("Generate", this::generate),
                button("Copy password", this::copyPassword)};
        JPanel row = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT, 4, 0));
        for (JButton b : buttons) row.add(b);
        g.gridy = rows.length; g.gridx = 0; g.gridwidth = 2; g.weighty = 0; g.fill = GridBagConstraints.HORIZONTAL;
        p.add(row, g);
        return p;
    }

    private static JButton button(String label, Runnable run) {
        JButton b = new JButton(label);
        b.addActionListener(e -> run.run());
        return b;
    }

    private JMenuBar menuBar() {
        int mask = GraphicsEnvironment.isHeadless() ? InputEvent.CTRL_DOWN_MASK : Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        JMenu f = new JMenu("File");
        f.add(item("Unlock...", this::unlock, 0, 0));
        f.add(item("Lock", () -> lock("Locked."), KeyEvent.VK_L, mask));
        f.addSeparator();
        f.add(item("Export...", this::exportVault, 0, 0));
        f.add(item("Import...", this::importVault, 0, 0));
        f.addSeparator();
        f.add(item("Exit", () -> {
            if (vault != null) vault.close();
            System.exit(0);
        }, 0, 0));
        JMenu e = new JMenu("Entry");
        e.add(item("New", this::newEntry, KeyEvent.VK_N, mask));
        e.add(item("Save", this::saveEntry, KeyEvent.VK_S, mask));
        e.add(item("Delete", this::deleteEntry, 0, 0));
        e.addSeparator();
        e.add(item("Copy password", this::copyPassword, KeyEvent.VK_C, mask | InputEvent.SHIFT_DOWN_MASK));
        e.add(item("Check breach...", this::breach, 0, 0));
        JMenu t = new JMenu("Tools");
        t.add(item("Find", () -> search.requestFocusInWindow(), KeyEvent.VK_F, mask));
        t.add(item("Audit", this::audit, 0, 0));
        t.add(item("Generate password...", () -> Dialogs.generator(this), 0, 0));
        JMenuBar bar = new JMenuBar();
        bar.add(f);
        bar.add(e);
        bar.add(t);
        return bar;
    }

    private static JMenuItem item(String label, Runnable run, int key, int mods) {
        JMenuItem m = new JMenuItem(label);
        if (key != 0) m.setAccelerator(KeyStroke.getKeyStroke(key, mods));
        m.addActionListener(ev -> run.run());
        return m;
    }

    private static final class Changed implements DocumentListener {
        private final Runnable r;

        Changed(Runnable r) { this.r = r; }

        public void insertUpdate(DocumentEvent e) { r.run(); }
        public void removeUpdate(DocumentEvent e) { r.run(); }
        public void changedUpdate(DocumentEvent e) { r.run(); }
    }

    public void start() {
        SwingUtilities.invokeLater(this::unlock);
    }

    private void unlock() {
        if (vault != null) return;
        Vault v = UnlockPanel.ask(this, file);
        if (v == null) {
            say("Locked. Use File > Unlock to try again.");
            return;
        }
        vault = v;
        lastActivity = System.currentTimeMillis();
        setUnlocked(true);
        refresh();
        say(v.needsUpgrade() ? "Unlocked. This vault uses only " + v.iterations() + " PBKDF2 iterations; run 'vaultlite rekey'." : "Unlocked.");
    }

    private void setUnlocked(boolean on) {
        for (Component c : new Component[] {search, list, title, user, pass, show, url, tags, notes}) c.setEnabled(on);
    }

    public void lock(String why) {
        if (vault == null) return;
        for (Window w : Window.getWindows()) {
            if (w.isShowing() && w != SwingUtilities.getWindowAncestor(this)) w.dispose();
        }
        vault.close();
        vault = null;
        flagged = new HashSet<>();
        model.clear();
        search.setText("");
        clearForm();
        setUnlocked(false);
        say(why);
        SwingUtilities.invokeLater(this::unlock);
    }

    private void say(String s) {
        status.setText(s);
    }

    private void clearForm() {
        loading = true;
        for (javax.swing.text.JTextComponent c : new javax.swing.text.JTextComponent[] {title, user, pass, url, tags, notes}) {
            c.setText("");
        }
        show.setSelected(false);
        pass.setEchoChar(defaultEcho);
        loading = false;
        dirty = false;
        rate();
    }

    private void load(Entry e) {
        if (e == null) return;
        loading = true;
        title.setText(e.title);
        user.setText(e.username);
        pass.setText(e.password);
        url.setText(e.url);
        tags.setText(String.join(", ", e.tags));
        notes.setText(e.notes);
        notes.setCaretPosition(0);
        loading = false;
        dirty = false;
        show.setSelected(false);
        pass.setEchoChar(defaultEcho);
        rate();
    }

    private void rate() {
        String p = new String(pass.getPassword());
        if (p.isEmpty()) {
            meter.setText(" ");
            return;
        }
        Strength.Result r = Strength.estimate(p);
        meter.setText(r.label() + String.format(" (about %.0f bits)", r.bits()));
    }

    private void refresh() {
        if (vault == null) return;
        String keep = list.getSelectedValue() == null ? null : list.getSelectedValue().id;
        flagged = new HashSet<>();
        for (List<Entry> g : Audit.reused(vault.entries())) for (Entry e : g) flagged.add(e.id);
        for (Entry e : Audit.weak(vault.entries())) flagged.add(e.id);
        model.clear();
        int sel = -1;
        for (Entry e : vault.entries()) {
            if (!e.matches(search.getText())) continue;
            model.addElement(e);
            if (e.id.equals(keep)) sel = model.size() - 1;
        }
        if (sel >= 0) list.setSelectedIndex(sel);
        list.repaint();
    }

    private Entry current() {
        return list.getSelectedValue();
    }

    private boolean discardOk() {
        return !dirty || JOptionPane.showConfirmDialog(this, "Discard unsaved changes?", "Unsaved changes",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE) == JOptionPane.OK_OPTION;
    }

    private void newEntry() {
        if (vault == null || !discardOk()) return;
        list.clearSelection();
        clearForm();
        title.requestFocusInWindow();
        say("New entry. Fill it in and press Save.");
    }

    private void saveEntry() {
        if (vault == null) return;
        if (title.getText().isBlank()) {
            say("An entry needs a title.");
            return;
        }
        Entry old = current();
        Entry e = old == null ? new Entry() : old.copy();
        e.title = title.getText().trim();
        e.username = user.getText();
        e.password = new String(pass.getPassword());
        e.url = url.getText().trim();
        e.notes = notes.getText();
        e.tags = new ArrayList<>();
        for (String t : tags.getText().split(",")) if (!t.isBlank()) e.tags.add(t.trim());
        e.updated = System.currentTimeMillis() / 1000;
        if (old == null) vault.entries().add(e);
        else vault.entries().set(vault.entries().indexOf(old), e);
        try {
            vault.save();
        } catch (VaultException ex) {
            say(ex.getMessage());
            return;
        }
        dirty = false;
        search.setText("");
        refresh();
        select(e.id);
        say("Saved " + e.title + ".");
    }

    private void select(String id) {
        for (int i = 0; i < model.size(); i++) {
            if (model.get(i).id.equals(id)) {
                list.setSelectedIndex(i);
                return;
            }
        }
    }

    private void deleteEntry() {
        Entry e = current();
        if (vault == null || e == null) return;
        if (JOptionPane.showConfirmDialog(this, "Delete \"" + e.title + "\"? This cannot be undone.", "Delete",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE) != JOptionPane.OK_OPTION) return;
        vault.entries().remove(e);
        try {
            vault.save();
            say("Deleted " + e.title + ".");
        } catch (VaultException ex) {
            say(ex.getMessage());
        }
        list.clearSelection();
        clearForm();
        refresh();
    }

    private void generate() {
        if (vault == null) return;
        Dialogs.GenPanel gp = new Dialogs.GenPanel();
        if (JOptionPane.showConfirmDialog(this, gp, "Use this password?", JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE) == JOptionPane.OK_OPTION && !gp.value().isEmpty()) {
            pass.setText(gp.value());
        }
    }

    private void copyPassword() {
        String p = new String(pass.getPassword());
        if (p.isEmpty()) {
            say("Nothing to copy.");
            return;
        }
        try {
            Clip.copy(p, CLIP_SECONDS);
            say("Password copied; the clipboard clears in " + CLIP_SECONDS + "s.");
        } catch (RuntimeException ex) {
            say("No clipboard available.");
        }
    }

    private <T> void background(Callable<T> work, Consumer<T> ok, Consumer<String> fail) {
        new SwingWorker<T, Void>() {
            @Override protected T doInBackground() throws Exception { return work.call(); }
            @Override protected void done() {
                try {
                    ok.accept(get());
                } catch (ExecutionException e) {
                    Throwable c = e.getCause();
                    fail.accept(c instanceof VaultException ? c.getMessage() : String.valueOf(c));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }.execute();
    }

    private void breach() {
        String pw = new String(pass.getPassword());
        if (vault == null || pw.isEmpty()) return;
        String msg = "Check this password against Have I Been Pwned?\n\nOnly the first 5 characters of its SHA-1 hash ("
                + Hibp.prefix(pw) + ") are sent to api.pwnedpasswords.com. The password itself never leaves this machine.";
        if (JOptionPane.showConfirmDialog(this, msg, "Breach check", JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.QUESTION_MESSAGE) != JOptionPane.OK_OPTION) return;
        say("Asking the range API...");
        background(() -> Hibp.check(pw, Hibp.DEFAULT_BASE),
                n -> say(n == 0 ? "Not found in known breaches." : "Seen " + n + " times in breaches. Change it."),
                m -> say(m));
    }

    private void audit() {
        if (vault != null) Dialogs.report(this, "Audit", Audit.report(vault.entries()));
    }

    private void exportVault() {
        if (vault == null) return;
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new File("vaultlite-export.vlt"));
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        Path target = fc.getSelectedFile().toPath();
        if (Files.exists(target)) {
            say("Not overwriting " + target.getFileName() + ".");
            return;
        }
        char[][] box = new char[1][];
        if (!Dialogs.newPasswordPair(this, "Export password", box)) return;
        char[] p = box[0];
        if (p.length < 8) {
            Crypto.zero(p);
            say("Export password needs at least 8 characters.");
            return;
        }
        say("Encrypting export...");
        background(() -> {
            try {
                vault.exportTo(target, p, Crypto.DEFAULT_ITERATIONS);
            } finally {
                Crypto.zero(p);
            }
            return target;
        }, t -> say("Exported to " + t.getFileName() + "."), m -> say(m));
    }

    private void importVault() {
        if (vault == null) return;
        JFileChooser fc = new JFileChooser();
        if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
        Path src = fc.getSelectedFile().toPath();
        char[] p = Dialogs.askPassword(this, "Export password");
        if (p == null) return;
        say("Decrypting export...");
        background(() -> {
            try {
                return Vault.readExport(src, p);
            } finally {
                Crypto.zero(p);
            }
        }, imported -> {
            if (vault == null) return;
            int added = vault.merge(imported);
            try {
                vault.save();
                say("Imported " + added + " of " + imported.size() + " entries.");
            } catch (VaultException ex) {
                say(ex.getMessage());
            }
            refresh();
        }, m -> say(m));
    }
}
