package vaultlite.gui;

import java.awt.Component;
import java.awt.Container;
import javax.swing.JSplitPane;

final class Layouts {
    private Layouts() {}

    // A component that was never shown has no peer, so lay it out by hand before printing it.
    static void settle(Component c) {
        if (c instanceof JSplitPane s) s.setDividerLocation(280);
        if (c instanceof Container k) {
            k.doLayout();
            for (Component x : k.getComponents()) settle(x);
        }
    }
}
