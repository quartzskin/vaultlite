package vaultlite.gui;

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import javax.imageio.ImageIO;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import vaultlite.VaultException;

public final class VaultApp {
    private VaultApp() {}

    public static void main(String[] args) {
        String vault = System.getenv("VAULTLITE_FILE");
        String snapshot = null;
        boolean locked = false;
        int autolock = 120;
        try {
            for (int i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case "--vault" -> vault = args[++i];
                    case "--snapshot" -> snapshot = args[++i];
                    case "--locked" -> locked = true;
                    case "--autolock" -> autolock = Integer.parseInt(args[++i]);
                    default -> throw new VaultException("unknown gui option " + args[i]);
                }
            }
        } catch (ArrayIndexOutOfBoundsException | NumberFormatException e) {
            throw new VaultException("bad gui arguments");
        }
        if (snapshot != null) System.setProperty("java.awt.headless", "true");
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {
            // keep the default look and feel
        }
        if (snapshot != null) {
            snapshot(snapshot, locked);
            return;
        }
        Path path = Path.of(vault != null ? vault : System.getProperty("user.home") + "/.vaultlite/vault.vlt");
        int secs = autolock;
        SwingUtilities.invokeLater(() -> {
            JFrame f = new JFrame("vaultlite");
            VaultPanel p = new VaultPanel(path, secs);
            f.setContentPane(p);
            f.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            f.pack();
            f.setLocationRelativeTo(null);
            f.setVisible(true);
            p.start();
        });
    }

    private static void snapshot(String out, boolean locked) {
        JComponent p;
        if (locked) {
            UnlockPanel u = UnlockPanel.demo();
            u.setSize(u.getPreferredSize());
            Layouts.settle(u);
            p = u;
        } else {
            p = VaultPanel.demo();
        }
        BufferedImage img = new BufferedImage(p.getWidth(), p.getHeight(), BufferedImage.TYPE_INT_RGB);
        java.awt.Graphics2D g = img.createGraphics();
        p.printAll(g);
        g.dispose();
        try {
            ImageIO.write(img, "png", new File(out));
        } catch (IOException e) {
            throw new VaultException("cannot write " + out + ": " + e.getMessage());
        }
        System.out.println("wrote " + out);
        System.exit(0);
    }
}
