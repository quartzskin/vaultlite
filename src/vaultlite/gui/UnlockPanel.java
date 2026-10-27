package vaultlite.gui;

import java.awt.Component;
import java.awt.Dialog;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.ExecutionException;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import vaultlite.Crypto;
import vaultlite.Vault;
import vaultlite.VaultException;

final class UnlockPanel extends JPanel {
    private final Path file;
    private final boolean creating;
    private final JPasswordField pw = new JPasswordField(24);
    private final JPasswordField again = new JPasswordField(24);
    private final JButton unlock = new JButton();
    private final JButton cancel = new JButton("Cancel");
    private final JLabel status = new JLabel(" ");
    private JDialog dialog;
    private Vault result;

    UnlockPanel(Path file, boolean creating) {
        super(new GridBagLayout());
        this.file = file;
        this.creating = creating;
        setBorder(javax.swing.BorderFactory.createEmptyBorder(10, 10, 10, 10));
        unlock.setText(creating ? "Create" : "Unlock");
        pw.getAccessibleContext().setAccessibleName("Master password");
        again.getAccessibleContext().setAccessibleName("Repeat master password");
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(4, 6, 4, 6);
        g.anchor = GridBagConstraints.WEST;
        int y = 0;
        if (creating) {
            g.gridy = y++; g.gridx = 0; g.gridwidth = 2;
            add(new JLabel("No vault at this location yet. Choose a master password (8+ characters)."), g);
            g.gridwidth = 1;
        }
        g.gridy = y++; g.gridx = 0; g.fill = GridBagConstraints.NONE; add(new JLabel("Master password"), g);
        g.gridx = 1; g.fill = GridBagConstraints.HORIZONTAL; add(pw, g);
        if (creating) {
            g.gridy = y++; g.gridx = 0; g.fill = GridBagConstraints.NONE; add(new JLabel("Repeat"), g);
            g.gridx = 1; g.fill = GridBagConstraints.HORIZONTAL; add(again, g);
        }
        g.gridy = y++; g.gridx = 0; g.gridwidth = 2; add(status, g);
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        buttons.add(unlock);
        buttons.add(cancel);
        g.gridy = y; add(buttons, g);
        unlock.addActionListener(e -> attempt());
        cancel.addActionListener(e -> {
            if (dialog != null) dialog.dispose();
        });
    }

    static UnlockPanel demo() {
        UnlockPanel p = new UnlockPanel(Path.of("demo.vlt"), false);
        p.pw.setText("correct horse");
        return p;
    }

    static Vault ask(Component parent, Path file) {
        UnlockPanel p = new UnlockPanel(file, !Files.exists(file));
        JDialog d = new JDialog(SwingUtilities.getWindowAncestor(parent), "Unlock vault", Dialog.ModalityType.APPLICATION_MODAL);
        p.dialog = d;
        d.setContentPane(p);
        d.getRootPane().setDefaultButton(p.unlock);
        d.setResizable(false);
        d.pack();
        d.setLocationRelativeTo(parent);
        d.setVisible(true);
        return p.result;
    }

    private void say(String s) {
        status.setText(s);
    }

    private void attempt() {
        char[] p = pw.getPassword();
        if (p.length == 0) {
            say("Type the master password first.");
            return;
        }
        if (creating) {
            char[] b = again.getPassword();
            boolean same = Arrays.equals(p, b);
            Crypto.zero(b);
            if (p.length < 8) {
                Crypto.zero(p);
                say("A new master password needs at least 8 characters.");
                return;
            }
            if (!same) {
                Crypto.zero(p);
                say("The two passwords differ.");
                return;
            }
        }
        unlock.setEnabled(false);
        say(creating ? "Creating vault..." : "Unlocking (key derivation)...");
        new SwingWorker<Vault, Void>() {
            @Override protected Vault doInBackground() {
                try {
                    if (creating) {
                        try (Vault v = Vault.create(file, p, Crypto.DEFAULT_ITERATIONS)) {
                            v.save();
                        }
                    }
                    return Vault.open(file, p);
                } finally {
                    Crypto.zero(p);
                }
            }

            @Override protected void done() {
                try {
                    Vault v = get();
                    if (dialog == null || !dialog.isDisplayable()) {
                        v.close();
                        return;
                    }
                    result = v;
                    dialog.dispose();
                } catch (ExecutionException e) {
                    Throwable c = e.getCause();
                    say(c instanceof VaultException ? c.getMessage() : String.valueOf(c));
                    pw.setText("");
                    unlock.setEnabled(true);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }.execute();
    }
}
