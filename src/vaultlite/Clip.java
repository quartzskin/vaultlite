package vaultlite;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.util.Timer;
import java.util.TimerTask;

public final class Clip {
    private static final Timer TIMER = new Timer("clip-clear", true);

    private Clip() {}

    /** Copies text and clears the clipboard after the delay, but only if it still holds that text. */
    public static void copy(String text, int seconds) {
        Clipboard cb = Toolkit.getDefaultToolkit().getSystemClipboard();
        cb.setContents(new StringSelection(text), null);
        if (seconds <= 0) return;
        TIMER.schedule(new TimerTask() {
            @Override
            public void run() {
                clearIfHolds(cb, text);
            }
        }, seconds * 1000L);
    }

    /** CLI variant: stays alive until the clear has happened. */
    public static void copyAndWait(String text, int seconds) throws InterruptedException {
        copy(text, 0);
        Clipboard cb = Toolkit.getDefaultToolkit().getSystemClipboard();
        Thread.sleep(seconds * 1000L);
        clearIfHolds(cb, text);
    }

    private static void clearIfHolds(Clipboard cb, String text) {
        try {
            if (cb.isDataFlavorAvailable(DataFlavor.stringFlavor)
                    && text.equals(cb.getData(DataFlavor.stringFlavor))) {
                cb.setContents(new StringSelection(""), null);
            }
        } catch (Exception ignored) {
            // clipboard owned by another app right now; nothing sensible to do
        }
    }
}
