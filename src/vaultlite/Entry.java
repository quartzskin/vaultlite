package vaultlite;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class Entry {
    private static final SecureRandom RNG = new SecureRandom();

    public String id;
    public String title = "";
    public String username = "";
    public String password = "";
    public String url = "";
    public String notes = "";
    public List<String> tags = new ArrayList<>();
    public long created;
    public long updated;

    public Entry() {
        byte[] b = new byte[6];
        RNG.nextBytes(b);
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        id = sb.toString();
        created = updated = System.currentTimeMillis() / 1000;
    }

    public Entry(String title, String username, String password, String url, String notes, String... tags) {
        this();
        this.title = title;
        this.username = username;
        this.password = password;
        this.url = url;
        this.notes = notes;
        this.tags = new ArrayList<>(List.of(tags));
    }

    public Entry copy() {
        Entry e = new Entry();
        e.id = id;
        e.title = title;
        e.username = username;
        e.password = password;
        e.url = url;
        e.notes = notes;
        e.tags = new ArrayList<>(tags);
        e.created = created;
        e.updated = updated;
        return e;
    }

    public boolean sameContent(Entry o) {
        return title.equals(o.title) && username.equals(o.username) && password.equals(o.password)
                && url.equals(o.url) && notes.equals(o.notes);
    }

    public boolean matches(String query) {
        String q = query.toLowerCase();
        if (q.isEmpty()) return true;
        for (String f : new String[] {title, username, url, notes, String.join(" ", tags)}) {
            if (f.toLowerCase().contains(q)) return true;
        }
        return false;
    }

    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("title", title);
        m.put("username", username);
        m.put("password", password);
        m.put("url", url);
        m.put("notes", notes);
        m.put("tags", new ArrayList<Object>(tags));
        m.put("created", created);
        m.put("updated", updated);
        return m;
    }

    public static Entry fromMap(Object o, int index) {
        if (!(o instanceof Map<?, ?> m)) throw new VaultException("entry " + index + ": not an object");
        Entry e = new Entry();
        String title = str(m, "title", index, true);
        if (title.isBlank()) throw new VaultException("entry " + index + ": empty title");
        e.title = title;
        e.username = str(m, "username", index, false);
        e.password = str(m, "password", index, false);
        e.url = str(m, "url", index, false);
        e.notes = str(m, "notes", index, false);
        String id = str(m, "id", index, false);
        if (!id.isEmpty()) e.id = id;
        Object t = m.get("tags");
        if (t != null) {
            if (!(t instanceof List<?> l)) throw new VaultException("entry " + index + ": tags must be a list");
            for (Object x : l) {
                if (!(x instanceof String s)) throw new VaultException("entry " + index + ": tags must be strings");
                e.tags.add(s);
            }
        }
        e.created = num(m.get("created"), e.created);
        e.updated = num(m.get("updated"), e.updated);
        return e;
    }

    private static long num(Object o, long dflt) {
        return o instanceof Long l ? l : dflt;
    }

    private static String str(Map<?, ?> m, String key, int index, boolean required) {
        Object v = m.get(key);
        if (v == null) {
            if (required) throw new VaultException("entry " + index + ": missing " + key);
            return "";
        }
        if (!(v instanceof String s)) throw new VaultException("entry " + index + ": " + key + " must be a string");
        return s;
    }
}
