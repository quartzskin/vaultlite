package vaultlite;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class Cli {
    static final String USAGE = """
            usage: vaultlite [--vault FILE] <command> [options]

              init [--iterations N]            create a new vault
              add <title> [--user U] [--url U] [--notes N] [--tag T]... [--gen]
              edit <title> [--title T] [--user U] [--url U] [--notes N] [--tag T]... [--gen]
              list [--tag T]                   titles only
              search <text>
              show <title> [--reveal]          password is hidden unless --reveal
              copy <title> [--field username|password] [--clear SECONDS]   (default 20)
              rm <title> --yes
              gen [--length N] [--no-upper] [--no-lower] [--no-digits] [--no-symbols] [--no-ambiguous]
              gen --passphrase [--words N] [--sep S] [--capitalise] [--digit]
              strength                         estimate for a password read from the prompt
              audit                            reused and weak passwords
              breach <title> --online          HIBP range lookup, sends 5 hash chars
              export <file>                    encrypted JSON, asks for an export password
              import <file>                    merges, skips entries already present
              rekey [--iterations N]           re-derive the key at a higher cost
              gui [--vault FILE] [--autolock SECONDS] [--snapshot out.png [--locked]]

            The vault defaults to %VAULTLITE_FILE% or ~/.vaultlite/vault.vlt.
            """;

    private static final Set<String> FLAGS = Set.of("reveal", "yes", "gen", "online", "no-upper", "no-lower",
            "no-digits", "no-symbols", "no-ambiguous", "passphrase", "capitalise", "digit", "locked", "help");

    private final InputStream in;
    private final PrintStream out;
    private final PrintStream err;
    private BufferedReader stdin;

    public Cli(InputStream in, PrintStream out, PrintStream err) {
        this.in = in;
        this.out = out;
        this.err = err;
    }

    private static final class Args {
        final List<String> pos = new ArrayList<>();
        final Map<String, List<String>> opts = new HashMap<>();

        Args(String[] a, int from) {
            for (int i = from; i < a.length; i++) {
                if (a[i].startsWith("--")) {
                    String k = a[i].substring(2);
                    String v = "";
                    if (!FLAGS.contains(k)) {
                        if (i + 1 >= a.length) throw new VaultException("--" + k + " needs a value");
                        v = a[++i];
                    }
                    opts.computeIfAbsent(k, x -> new ArrayList<>()).add(v);
                } else {
                    pos.add(a[i]);
                }
            }
        }

        boolean has(String k) { return opts.containsKey(k); }
        String get(String k) { return has(k) ? opts.get(k).get(opts.get(k).size() - 1) : null; }
        int num(String k, int dflt) {
            String v = get(k);
            if (v == null) return dflt;
            try {
                return Integer.parseInt(v);
            } catch (NumberFormatException e) {
                throw new VaultException("--" + k + " must be a number");
            }
        }
    }

    public int run(String[] argv) {
        try {
            int i = 0;
            String file = System.getenv("VAULTLITE_FILE");
            if (argv.length >= 2 && argv[0].equals("--vault")) {
                file = argv[1];
                i = 2;
            }
            if (i >= argv.length || argv[i].equals("--help") || argv[i].equals("help")) {
                out.print(USAGE);
                return i >= argv.length ? 2 : 0;
            }
            Path path = Path.of(file != null ? file : System.getProperty("user.home") + "/.vaultlite/vault.vlt");
            String cmd = argv[i];
            Args a = new Args(argv, i + 1);
            switch (cmd) {
                case "init" -> init(path, a);
                case "gen" -> gen(a);
                case "strength" -> strength();
                case "gui" -> { return gui(path, argv, i + 1); }
                case "add", "edit", "list", "search", "show", "copy", "rm", "audit", "breach", "export", "import", "rekey" ->
                    withVault(path, cmd, a);
                default -> throw new VaultException("unknown command '" + cmd + "' (try: vaultlite help)");
            }
            return 0;
        } catch (VaultException e) {
            err.println("vaultlite: " + e.getMessage());
            return 1;
        }
    }

    private int gui(Path path, String[] argv, int from) {
        List<String> a = new ArrayList<>(Arrays.asList(argv).subList(from, argv.length));
        if (!a.contains("--vault")) {
            a.add(0, path.toString());
            a.add(0, "--vault");
        }
        try {
            Class.forName("vaultlite.gui.VaultApp").getMethod("main", String[].class).invoke(null, (Object) a.toArray(new String[0]));
            return 0;
        } catch (ReflectiveOperationException e) {
            throw new VaultException("cannot start the GUI: " + e);
        }
    }

    private void init(Path path, Args a) {
        if (Files.exists(path)) throw new VaultException(path + " already exists");
        int iters = a.num("iterations", Crypto.DEFAULT_ITERATIONS);
        if (iters < Crypto.DEFAULT_ITERATIONS) {
            throw new VaultException("iterations must be at least " + Crypto.DEFAULT_ITERATIONS);
        }
        char[] pw = secret("New master password: ");
        char[] again = secret("Repeat: ");
        try {
            if (pw.length < 8) throw new VaultException("master password must be at least 8 characters");
            if (!Arrays.equals(pw, again)) throw new VaultException("passwords do not match");
            try (Vault v = Vault.create(path, pw, iters)) {
                v.save();
            }
            out.println("created " + path + " (PBKDF2-HMAC-SHA256, " + iters + " iterations)");
        } finally {
            Crypto.zero(pw);
            Crypto.zero(again);
        }
    }

    private void gen(Args a) {
        if (a.has("passphrase")) {
            int n = a.num("words", 5);
            String p = Generator.passphrase(n, a.has("sep") ? a.get("sep") : "-", a.has("capitalise"), a.has("digit"));
            out.println(p);
            out.printf("about %.0f bits%n", Generator.passphraseBits(n, a.has("digit")));
            return;
        }
        Generator.Options o = new Generator.Options();
        o.length = a.num("length", 20);
        o.upper = !a.has("no-upper");
        o.lower = !a.has("no-lower");
        o.digits = !a.has("no-digits");
        o.symbols = !a.has("no-symbols");
        o.noAmbiguous = a.has("no-ambiguous");
        String p = Generator.password(o);
        out.println(p);
        Strength.Result r = Strength.estimate(p);
        out.printf("%s (about %.0f bits)%n", r.label(), r.bits());
    }

    private void strength() {
        char[] pw = secret("Password to rate: ");
        try {
            Strength.Result r = Strength.estimate(new String(pw));
            out.printf("%s (about %.0f bits)%n", r.label(), r.bits());
        } finally {
            Crypto.zero(pw);
        }
    }

    private void withVault(Path path, String cmd, Args a) {
        if (!Files.exists(path)) throw new VaultException("no vault at " + path + " (run: vaultlite init)");
        char[] pw = secret("Master password: ");
        try (Vault v = Vault.open(path, pw)) {
            if (v.needsUpgrade() && !cmd.equals("rekey")) {
                err.println("note: this vault uses " + v.iterations() + " PBKDF2 iterations; run 'vaultlite rekey' to raise it");
            }
            switch (cmd) {
                case "add" -> add(v, a);
                case "edit" -> edit(v, a);
                case "list" -> list(v, a);
                case "search" -> search(v, a);
                case "show" -> show(v, a);
                case "copy" -> copy(v, a);
                case "rm" -> remove(v, a);
                case "audit" -> out.print(Audit.report(v.entries()));
                case "breach" -> breach(v, a);
                case "export" -> export(v, a);
                case "import" -> importFile(v, a);
                case "rekey" -> rekey(v, pw, a);
                default -> throw new IllegalStateException(cmd);
            }
        } finally {
            Crypto.zero(pw);
        }
    }

    private static String title(Args a) {
        if (a.pos.isEmpty()) throw new VaultException("missing title");
        return a.pos.get(0);
    }

    private Entry need(Vault v, Args a) {
        Entry e = v.find(title(a));
        if (e == null) throw new VaultException("no entry '" + title(a) + "'");
        return e;
    }

    private void add(Vault v, Args a) {
        String t = title(a);
        if (v.find(t) != null) throw new VaultException("an entry called '" + t + "' exists (use edit)");
        Entry e = new Entry();
        e.title = t;
        fill(e, a, true);
        v.entries().add(e);
        v.save();
        out.println("added " + t);
    }

    private void edit(Vault v, Args a) {
        Entry e = need(v, a);
        fill(e, a, false);
        e.updated = System.currentTimeMillis() / 1000;
        v.save();
        out.println("updated " + e.title);
    }

    private void fill(Entry e, Args a, boolean askPassword) {
        if (a.has("title")) e.title = a.get("title");
        if (a.has("user")) e.username = a.get("user");
        if (a.has("url")) e.url = a.get("url");
        if (a.has("notes")) e.notes = a.get("notes");
        if (a.has("tag")) e.tags = new ArrayList<>(a.opts.get("tag"));
        if (a.has("gen")) {
            e.password = Generator.password(new Generator.Options());
            out.println("generated password: " + e.password);
        } else if (askPassword) {
            char[] p = secret("Entry password: ");
            e.password = new String(p);
            Crypto.zero(p);
        }
    }

    private void list(Vault v, Args a) {
        for (Entry e : v.entries()) {
            if (a.has("tag") && !e.tags.contains(a.get("tag"))) continue;
            out.println(e.title + (e.username.isEmpty() ? "" : "  <" + e.username + ">"));
        }
    }

    private void search(Vault v, Args a) {
        String q = String.join(" ", a.pos);
        for (Entry e : v.entries()) if (e.matches(q)) out.println(e.title + (e.url.isEmpty() ? "" : "  " + e.url));
    }

    private void show(Vault v, Args a) {
        Entry e = need(v, a);
        out.println("title:    " + e.title);
        out.println("username: " + e.username);
        out.println("password: " + (a.has("reveal") ? e.password : "********  (--reveal to print)"));
        out.println("url:      " + e.url);
        out.println("tags:     " + String.join(", ", e.tags));
        if (!e.notes.isEmpty()) out.println("notes:    " + e.notes);
        if (!e.password.isEmpty()) {
            Strength.Result r = Strength.estimate(e.password);
            out.printf("strength: %s (about %.0f bits)%n", r.label(), r.bits());
        }
    }

    private void copy(Vault v, Args a) {
        Entry e = need(v, a);
        String field = a.has("field") ? a.get("field") : "password";
        String text = switch (field) {
            case "password" -> e.password;
            case "username" -> e.username;
            default -> throw new VaultException("--field must be username or password");
        };
        int secs = a.num("clear", 20);
        if (secs < 1) throw new VaultException("--clear must be at least 1 second");
        try {
            out.println("copied " + field + " of " + e.title + "; clearing in " + secs + "s (keep this window open)");
            Clip.copyAndWait(text, secs);
            out.println("clipboard cleared");
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        } catch (java.awt.HeadlessException ex) {
            throw new VaultException("no clipboard available in this session");
        }
    }

    private void remove(Vault v, Args a) {
        Entry e = need(v, a);
        if (!a.has("yes")) throw new VaultException("add --yes to delete '" + e.title + "'");
        v.entries().remove(e);
        v.save();
        out.println("removed " + e.title);
    }

    private void breach(Vault v, Args a) {
        Entry e = need(v, a);
        if (!a.has("online")) {
            throw new VaultException("this contacts api.pwnedpasswords.com and sends the first 5 characters of the "
                    + "password's SHA-1 (" + Hibp.prefix(e.password) + "); add --online to go ahead");
        }
        String base = System.getenv("VAULTLITE_HIBP_URL");
        long n = Hibp.check(e.password, base != null ? base : Hibp.DEFAULT_BASE);
        out.println(n == 0 ? e.title + ": not found in the breach corpus"
                : e.title + ": seen " + n + " times in breaches, change it");
    }

    private void export(Vault v, Args a) {
        if (a.pos.isEmpty()) throw new VaultException("missing output file");
        Path f = Path.of(a.pos.get(0));
        if (Files.exists(f)) throw new VaultException(f + " already exists");
        char[] p = secret("Export password: ");
        try {
            if (p.length < 8) throw new VaultException("export password must be at least 8 characters");
            v.exportTo(f, p, Crypto.DEFAULT_ITERATIONS);
            out.println("wrote " + v.entries().size() + " entries to " + f + " (encrypted)");
        } finally {
            Crypto.zero(p);
        }
    }

    private void importFile(Vault v, Args a) {
        if (a.pos.isEmpty()) throw new VaultException("missing input file");
        char[] p = secret("Export password: ");
        try {
            List<Entry> in = Vault.readExport(Path.of(a.pos.get(0)), p);
            int added = v.merge(in);
            v.save();
            out.println("imported " + added + " of " + in.size() + " entries");
        } finally {
            Crypto.zero(p);
        }
    }

    private void rekey(Vault v, char[] pw, Args a) {
        int iters = a.num("iterations", Crypto.DEFAULT_ITERATIONS);
        if (iters < v.iterations()) throw new VaultException("refusing to lower the iteration count");
        if (iters < Crypto.DEFAULT_ITERATIONS) throw new VaultException("iterations must be at least " + Crypto.DEFAULT_ITERATIONS);
        v.rekey(pw, iters);
        v.save();
        out.println("re-encrypted with a new salt, " + iters + " iterations");
    }

    private char[] secret(String prompt) {
        if (in == System.in && System.console() != null) {
            char[] c = System.console().readPassword("%s", prompt);
            if (c == null) throw new VaultException("no input");
            return c;
        }
        try {
            if (stdin == null) stdin = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            err.print(prompt);
            err.flush();
            String line = stdin.readLine();
            if (line == null) throw new VaultException("no input");
            return line.toCharArray();
        } catch (IOException e) {
            throw new VaultException("cannot read input: " + e.getMessage());
        }
    }
}
