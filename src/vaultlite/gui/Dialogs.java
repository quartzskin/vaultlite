package vaultlite.gui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.Arrays;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import vaultlite.Clip;
import vaultlite.Generator;
import vaultlite.Strength;
import vaultlite.VaultException;

final class Dialogs {
    private Dialogs() {}

    static final class GenPanel extends JPanel {
        private final JSpinner length = new JSpinner(new SpinnerNumberModel(20, 4, 128, 1));
        private final JSpinner words = new JSpinner(new SpinnerNumberModel(5, 3, 12, 1));
        private final JCheckBox upper = new JCheckBox("A-Z", true);
        private final JCheckBox lower = new JCheckBox("a-z", true);
        private final JCheckBox digits = new JCheckBox("0-9", true);
        private final JCheckBox symbols = new JCheckBox("symbols", true);
        private final JCheckBox ambiguous = new JCheckBox("skip look-alikes (O/0, l/1)");
        private final JCheckBox phrase = new JCheckBox("passphrase from word list");
        private final JTextField out = new JTextField(28);
        private final JLabel meter = new JLabel(" ");

        GenPanel() {
            super(new GridBagLayout());
            out.setEditable(false);
            out.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 14));
            out.getAccessibleContext().setAccessibleName("Generated password");
            JButton again = new JButton("Generate again");
            JButton copy = new JButton("Copy (clears in 20s)");
            again.addActionListener(e -> roll());
            copy.addActionListener(e -> {
                try {
                    Clip.copy(out.getText(), 20);
                } catch (RuntimeException ex) {
                    meter.setText("no clipboard available");
                }
            });
            for (JCheckBox c : new JCheckBox[] {upper, lower, digits, symbols, ambiguous, phrase}) {
                c.addActionListener(e -> roll());
            }
            GridBagConstraints g = new GridBagConstraints();
            g.insets = new Insets(3, 3, 3, 3);
            g.anchor = GridBagConstraints.WEST;
            g.gridy = 0; g.gridx = 0; add(new JLabel("Length"), g);
            g.gridx = 1; add(length, g);
            g.gridx = 2; add(new JLabel("Words"), g);
            g.gridx = 3; add(words, g);
            JPanel sets = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
            sets.add(upper); sets.add(lower); sets.add(digits); sets.add(symbols);
            g.gridy = 1; g.gridx = 0; g.gridwidth = 4; add(sets, g);
            g.gridy = 2; add(ambiguous, g);
            g.gridy = 3; add(phrase, g);
            g.gridy = 4; g.fill = GridBagConstraints.HORIZONTAL; add(out, g);
            g.gridy = 5; add(meter, g);
            JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
            btns.add(again); btns.add(copy);
            g.gridy = 6; add(btns, g);
            length.addChangeListener(e -> roll());
            words.addChangeListener(e -> roll());
            roll();
        }

        void roll() {
            try {
                String p;
                double bits;
                if (phrase.isSelected()) {
                    int n = (Integer) words.getValue();
                    p = Generator.passphrase(n, "-", true, true);
                    bits = Generator.passphraseBits(n, true);
                } else {
                    Generator.Options o = new Generator.Options();
                    o.length = (Integer) length.getValue();
                    o.upper = upper.isSelected();
                    o.lower = lower.isSelected();
                    o.digits = digits.isSelected();
                    o.symbols = symbols.isSelected();
                    o.noAmbiguous = ambiguous.isSelected();
                    p = Generator.password(o);
                    bits = Strength.estimate(p).bits();
                }
                out.setText(p);
                meter.setText(String.format("about %.0f bits", bits));
            } catch (VaultException e) {
                out.setText("");
                meter.setText(e.getMessage());
            }
        }

        String value() {
            return out.getText();
        }
    }

    static void generator(Component parent) {
        JOptionPane.showMessageDialog(parent, new GenPanel(), "Password generator", JOptionPane.PLAIN_MESSAGE);
    }

    static void report(Component parent, String heading, String text) {
        JTextArea a = new JTextArea(text, 14, 44);
        a.setEditable(false);
        a.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        a.getAccessibleContext().setAccessibleName(heading);
        JOptionPane.showMessageDialog(parent, new JScrollPane(a), heading, JOptionPane.PLAIN_MESSAGE);
    }

    static char[] askPassword(Component parent, String label) {
        JPasswordField f = new JPasswordField(24);
        f.getAccessibleContext().setAccessibleName(label);
        JPanel p = new JPanel(new BorderLayout(4, 4));
        p.add(new JLabel(label), BorderLayout.NORTH);
        p.add(f, BorderLayout.CENTER);
        p.setPreferredSize(new Dimension(300, p.getPreferredSize().height));
        f.addAncestorListener(new FocusOnShow(f));
        char[] out = JOptionPane.showConfirmDialog(parent, p, label, JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE) == JOptionPane.OK_OPTION ? f.getPassword() : null;
        f.setText("");
        return out;
    }

    static boolean newPasswordPair(Component parent, String label, char[][] result) {
        char[] a = askPassword(parent, label);
        if (a == null) return false;
        char[] b = askPassword(parent, "Repeat " + label.toLowerCase());
        if (b == null || !Arrays.equals(a, b)) {
            if (b != null) JOptionPane.showMessageDialog(parent, "The two passwords differ.");
            vaultlite.Crypto.zero(a);
            vaultlite.Crypto.zero(b);
            return false;
        }
        vaultlite.Crypto.zero(b);
        result[0] = a;
        return true;
    }

    private static final class FocusOnShow implements javax.swing.event.AncestorListener {
        private final Component c;

        FocusOnShow(Component c) { this.c = c; }

        public void ancestorAdded(javax.swing.event.AncestorEvent e) { c.requestFocusInWindow(); }
        public void ancestorRemoved(javax.swing.event.AncestorEvent e) {}
        public void ancestorMoved(javax.swing.event.AncestorEvent e) {}
    }
}
