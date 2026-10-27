package vaultlite;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class Vault implements AutoCloseable {
    private final List<Entry> entries = new ArrayList<>();
    private final Path path;
    private byte[] key;
    private byte[] salt;
    private int iterations;

    private Vault(Path path, byte[] key, byte[] salt, int iterations) {
        this.path = path;
        this.key = key;
        this.salt = salt;
        this.iterations = iterations;
    }

    public static Vault create(Path path, char[] password, int iterations) {
        byte[] salt = Crypto.randomBytes(Crypto.SALT_LEN);
        return new Vault(path, Crypto.deriveKey(password, salt, iterations), salt, iterations);
    }

    public static Vault open(Path path, char[] password) {
        byte[] file = read(path);
        Crypto.Header h = Crypto.parseHeader(file);
        byte[] key = Crypto.deriveKey(password, h.salt(), h.iterations());
        byte[] plain = null;
        try {
            plain = Crypto.unseal(key, file, h);
            Vault v = new Vault(path, key, h.salt(), h.iterations());
            v.entries.addAll(decode(plain));
            return v;
        } catch (RuntimeException e) {
            Crypto.zero(key);
            throw e;
        } finally {
            Crypto.zero(plain);
        }
    }

    /** Decrypts an export file (same container, its own password) without needing a vault. */
    public static List<Entry> readExport(Path file, char[] password) {
        try (Vault v = open(file, password)) {
            return new ArrayList<>(v.entries);
        }
    }

    public static Vault demo() {
        Vault v = new Vault(null, new byte[32], new byte[Crypto.SALT_LEN], 1);
        v.entries.add(new Entry("Mail", "ada@example.test", "violet-Anchor-4419", "https://mail.example.test", "Recovery code in the red folder", "personal"));
        v.entries.add(new Entry("Bank", "ada.l", "Tr0ub4dor&3xq!", "https://bank.example.test", "", "finance"));
        v.entries.add(new Entry("Router", "admin", "admin1234", "http://192.0.2.1", "Change this one", "home"));
        v.entries.add(new Entry("Forum", "ada", "admin1234", "https://forum.example.test", "", "social"));
        v.entries.add(new Entry("Git host", "ada-l", "maple.river.cobalt.tent.62", "https://git.example.test", "Deploy token lives elsewhere", "work", "dev"));
        v.entries.add(new Entry("Wi-Fi", "", "Kj9#mP2$vL8@nQ4x", "", "Guest network, rotate yearly", "home"));
        v.entries.add(new Entry("Storage box", "ada", "pebble-orbit-lantern-9", "https://files.example.test", "", "work"));
        v.entries.add(new Entry("Streaming", "ada@example.test", "password1", "https://watch.example.test", "", "social"));
        v.entries.add(new Entry("Library card", "0042 1187", "7731", "", "PIN only", "personal"));
        return v;
    }

    public List<Entry> entries() {
        return entries;
    }

    public int iterations() {
        return iterations;
    }

    public Path path() {
        return path;
    }

    public boolean needsUpgrade() {
        return iterations < Crypto.DEFAULT_ITERATIONS;
    }

    public void save() {
        if (path == null) throw new VaultException("this vault has no file");
        writeAtomic(path, Crypto.seal(key, salt, iterations, encode(entries)), true);
    }

    /** Fresh salt and key for the new cost; takes effect on the next save. */
    public void rekey(char[] newPassword, int newIterations) {
        byte[] newSalt = Crypto.randomBytes(Crypto.SALT_LEN);
        byte[] newKey = Crypto.deriveKey(newPassword, newSalt, newIterations);
        Crypto.zero(key);
        key = newKey;
        salt = newSalt;
        iterations = newIterations;
    }

    public void exportTo(Path file, char[] exportPassword, int exportIterations) {
        byte[] s = Crypto.randomBytes(Crypto.SALT_LEN);
        byte[] k = Crypto.deriveKey(exportPassword, s, exportIterations);
        try {
            writeAtomic(file, Crypto.seal(k, s, exportIterations, encode(entries)), false);
        } finally {
            Crypto.zero(k);
        }
    }

    public int merge(List<Entry> incoming) {
        int added = 0;
        for (Entry in : incoming) {
            boolean dup = false;
            for (Entry e : entries) {
                if (e.sameContent(in)) { dup = true; break; }
            }
            if (!dup) {
                Entry c = in.copy();
                for (Entry e : entries) {
                    if (e.id.equals(c.id)) { c.id = new Entry().id; break; }
                }
                entries.add(c);
                added++;
            }
        }
        return added;
    }

    public Entry find(String titleOrId) {
        for (Entry e : entries) if (e.id.equals(titleOrId)) return e;
        for (Entry e : entries) if (e.title.equalsIgnoreCase(titleOrId)) return e;
        return null;
    }

    @Override
    public void close() {
        Crypto.zero(key);
        Crypto.zero(salt);
        entries.clear();
    }

    private static byte[] read(Path path) {
        try {
            return Files.readAllBytes(path);
        } catch (IOException e) {
            throw new VaultException("cannot read " + path + ": " + e.getMessage(), e);
        }
    }

    private static byte[] encode(List<Entry> entries) {
        List<Object> list = new ArrayList<>();
        for (Entry e : entries) list.add(e.toMap());
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("v", 1L);
        root.put("entries", list);
        return Json.write(root).getBytes(StandardCharsets.UTF_8);
    }

    static List<Entry> decode(byte[] plain) {
        Object root = Json.parse(new String(plain, StandardCharsets.UTF_8));
        if (!(root instanceof Map<?, ?> m) || !(m.get("entries") instanceof List<?> l)) {
            throw new VaultException("payload has no entries list");
        }
        List<Entry> out = new ArrayList<>();
        for (int i = 0; i < l.size(); i++) out.add(Entry.fromMap(l.get(i), i + 1));
        return out;
    }

    private static void writeAtomic(Path target, byte[] data, boolean keepBackup) {
        try {
            Path dir = target.toAbsolutePath().getParent();
            if (dir != null) Files.createDirectories(dir);
            Path tmp = target.resolveSibling(target.getFileName() + ".tmp");
            try (FileChannel ch = FileChannel.open(tmp, StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                ch.write(java.nio.ByteBuffer.wrap(data));
                ch.force(true);
            }
            if (keepBackup && Files.exists(target)) {
                Files.copy(target, target.resolveSibling(target.getFileName() + ".bak"), StandardCopyOption.REPLACE_EXISTING);
            }
            Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new VaultException("cannot write " + target + ": " + e.getMessage(), e);
        }
    }
}
