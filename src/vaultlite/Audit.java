package vaultlite;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class Audit {
    private Audit() {}

    public static List<List<Entry>> reused(List<Entry> entries) {
        Map<String, List<Entry>> by = new LinkedHashMap<>();
        for (Entry e : entries) {
            if (!e.password.isEmpty()) by.computeIfAbsent(e.password, k -> new ArrayList<>()).add(e);
        }
        List<List<Entry>> out = new ArrayList<>();
        for (List<Entry> g : by.values()) if (g.size() > 1) out.add(g);
        return out;
    }

    public static List<Entry> weak(List<Entry> entries) {
        List<Entry> out = new ArrayList<>();
        for (Entry e : entries) {
            if (!e.password.isEmpty() && Strength.estimate(e.password).score() <= 1) out.add(e);
        }
        return out;
    }

    public static String report(List<Entry> entries) {
        StringBuilder sb = new StringBuilder();
        List<List<Entry>> groups = reused(entries);
        sb.append("Reused passwords: ").append(groups.size()).append(" group(s)\n");
        for (List<Entry> g : groups) {
            sb.append("  - ");
            for (int i = 0; i < g.size(); i++) sb.append(i > 0 ? ", " : "").append(g.get(i).title);
            sb.append('\n');
        }
        List<Entry> w = weak(entries);
        sb.append("Weak passwords: ").append(w.size()).append('\n');
        for (Entry e : w) {
            sb.append("  - ").append(e.title).append(" (").append(Strength.estimate(e.password).label()).append(")\n");
        }
        return sb.toString();
    }
}
