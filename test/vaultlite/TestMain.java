package vaultlite;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Minimal runner: each check is a named lambda; exit code is the failure count. */
public final class TestMain {
    interface Body { void run() throws Exception; }

    private static int failed, passed;
    private static Path tmp;
    private static final int FAST = 1000; // test-only cost; the CLI refuses this

    static void test(String name, Body b) {
        try {
            b.run();
            passed++;
            System.out.println("ok    " + name);
        } catch (Throwable t) {
            failed++;
            System.out.println("FAIL  " + name + ": " + t);
        }
    }

    static void check(boolean c, String msg) {
        if (!c) throw new AssertionError(msg);
    }

    static void rejects(Body b, String what) throws Exception {
        try {
            b.run();
        } catch (VaultException e) {
            return;
        }
        throw new AssertionError("expected VaultException: " + what);
    }

    static Vault sample(Path p, String pw) {
        Vault v = Vault.create(p, pw.toCharArray(), FAST);
        v.entries().add(new Entry("Mail", "ada", "s3cret-\u00e9\"\\", "https://x.test", "line1\nline2", "a", "b"));
        v.entries().add(new Entry("Bank", "ada", "other", "", ""));
        v.save();
        return v;
    }

    static void flip(Path p, int offset) throws Exception {
        byte[] b = Files.readAllBytes(p);
        b[offset] ^= 1;
        Files.write(p, b);
    }

    public static void main(String[] args) throws Exception {
        tmp = Files.createTempDirectory("vaultlite-test");

        test("round trip keeps every field", () -> {
            Path p = tmp.resolve("rt.vlt");
            sample(p, "hunter2hunter2").close();
            try (Vault v = Vault.open(p, "hunter2hunter2".toCharArray())) {
                check(v.entries().size() == 2, "count");
                Entry e = v.find("mail");
                check(e.password.equals("s3cret-\u00e9\"\\"), "password");
                check(e.notes.equals("line1\nline2"), "notes");
                check(e.tags.equals(List.of("a", "b")), "tags");
            }
        });

        test("file does not contain plaintext", () -> {
            Path p = tmp.resolve("pt.vlt");
            sample(p, "pw-pw-pw-pw").close();
            String raw = new String(Files.readAllBytes(p), StandardCharsets.ISO_8859_1);
            check(!raw.contains("Mail") && !raw.contains("https://x.test") && !raw.contains("other"), "plaintext leaked");
        });

        test("wrong password fails", () -> {
            Path p = tmp.resolve("wp.vlt");
            sample(p, "right-password").close();
            rejects(() -> Vault.open(p, "wrong-password".toCharArray()), "wrong pw");
        });

        test("tampered ciphertext fails", () -> {
            Path p = tmp.resolve("tc.vlt");
            sample(p, "pw-pw-pw-pw").close();
            flip(p, (int) Files.size(p) - 20);
            rejects(() -> Vault.open(p, "pw-pw-pw-pw".toCharArray()), "ciphertext");
        });

        test("tampered tag fails", () -> {
            Path p = tmp.resolve("tt.vlt");
            sample(p, "pw-pw-pw-pw").close();
            flip(p, (int) Files.size(p) - 1);
            rejects(() -> Vault.open(p, "pw-pw-pw-pw".toCharArray()), "tag");
        });

        test("every header byte is authenticated", () -> {
            Path p = tmp.resolve("th.vlt");
            sample(p, "pw-pw-pw-pw").close();
            byte[] orig = Files.readAllBytes(p);
            int headerLen = 4 + 1 + 1 + 4 + 1 + Crypto.SALT_LEN + Crypto.NONCE_LEN;
            for (int i = 0; i < headerLen; i++) {
                byte[] b = orig.clone();
                b[i] ^= 1;
                // iteration byte flips are kept small so a bad guess cannot make the test slow
                if (i >= 6 && i <= 8) b[i] = orig[i];
                Path q = tmp.resolve("th2.vlt");
                Files.write(q, b);
                if (java.util.Arrays.equals(b, orig)) continue;
                final int at = i;
                rejects(() -> Vault.open(q, "pw-pw-pw-pw".toCharArray()), "header byte " + at);
            }
            // iteration field low byte: header says a different cost, so key and AAD both differ
            byte[] b = orig.clone();
            b[9] ^= 1;
            Files.write(tmp.resolve("th3.vlt"), b);
            rejects(() -> Vault.open(tmp.resolve("th3.vlt"), "pw-pw-pw-pw".toCharArray()), "iteration field");
        });

        test("truncated files are rejected", () -> {
            Path p = tmp.resolve("tr.vlt");
            sample(p, "pw-pw-pw-pw").close();
            byte[] orig = Files.readAllBytes(p);
            int[] cuts = {0, 3, 10, 30, 50, orig.length - 1, orig.length / 2};
            for (int cut : cuts) {
                Path q = tmp.resolve("tr2.vlt");
                Files.write(q, java.util.Arrays.copyOf(orig, cut));
                rejects(() -> Vault.open(q, "pw-pw-pw-pw".toCharArray()), "cut at " + cut);
            }
        });

        test("garbage and wrong magic are rejected", () -> {
            Path p = tmp.resolve("g.vlt");
            Files.write(p, "this is certainly not a vault file, just text padding padding padding".getBytes());
            rejects(() -> Vault.open(p, "x".toCharArray()), "garbage");
            rejects(() -> Vault.open(tmp.resolve("missing.vlt"), "x".toCharArray()), "missing");
        });

        test("absurd iteration count in header is refused before deriving", () -> {
            Path p = tmp.resolve("it.vlt");
            sample(p, "pw-pw-pw-pw").close();
            byte[] b = Files.readAllBytes(p);
            b[6] = (byte) 0x7f;
            Files.write(p, b);
            long t0 = System.currentTimeMillis();
            rejects(() -> Vault.open(p, "pw-pw-pw-pw".toCharArray()), "huge iterations");
            check(System.currentTimeMillis() - t0 < 2000, "should fail fast");
        });

        test("header iteration count just above the cap is refused with a clear error", () -> {
            Path p = tmp.resolve("cap.vlt");
            sample(p, "pw-pw-pw-pw").close();
            byte[] b = Files.readAllBytes(p);
            int over = Crypto.MAX_ITERATIONS + 1;
            b[6] = (byte) (over >>> 24); b[7] = (byte) (over >>> 16); b[8] = (byte) (over >>> 8); b[9] = (byte) over;
            Files.write(p, b);
            try {
                Vault.open(p, "pw-pw-pw-pw".toCharArray());
                check(false, "should have been refused");
            } catch (VaultException e) {
                check(e.getMessage().contains("above the limit"), "message: " + e.getMessage());
            }
        });

        test("nonces are unique across saves", () -> {
            Path p = tmp.resolve("n.vlt");
            Set<String> seen = new HashSet<>();
            try (Vault v = sample(p, "pw-pw-pw-pw")) {
                for (int i = 0; i < 200; i++) {
                    v.save();
                    byte[] f = Files.readAllBytes(p);
                    check(seen.add(java.util.HexFormat.of().formatHex(Crypto.parseHeader(f).nonce())), "nonce reused at " + i);
                }
            }
            check(seen.size() == 200, "count");
        });

        test("same plaintext encrypts differently each time", () -> {
            byte[] k = new byte[32], s = new byte[16];
            byte[] a = Crypto.seal(k, s, FAST, "x".getBytes());
            byte[] b = Crypto.seal(k, s, FAST, "x".getBytes());
            check(!java.util.Arrays.equals(a, b), "identical output");
        });

        test("salts differ between vaults", () -> {
            Path a = tmp.resolve("s1.vlt"), b = tmp.resolve("s2.vlt");
            sample(a, "pw-pw-pw-pw").close();
            sample(b, "pw-pw-pw-pw").close();
            check(!java.util.Arrays.equals(Crypto.parseHeader(Files.readAllBytes(a)).salt(),
                    Crypto.parseHeader(Files.readAllBytes(b)).salt()), "same salt");
        });

        test("KDF params upgrade via rekey keeps data and changes salt", () -> {
            Path p = tmp.resolve("rk.vlt");
            byte[] oldSalt;
            try (Vault v = sample(p, "old-password")) {
                check(v.needsUpgrade(), "test vault should be below default");
                oldSalt = Crypto.parseHeader(Files.readAllBytes(p)).salt();
                v.rekey("new-password".toCharArray(), FAST * 3);
                v.save();
            }
            Crypto.Header h = Crypto.parseHeader(Files.readAllBytes(p));
            check(h.iterations() == FAST * 3, "iterations stored");
            check(!java.util.Arrays.equals(h.salt(), oldSalt), "salt rotated");
            rejects(() -> Vault.open(p, "old-password".toCharArray()), "old pw after rekey");
            try (Vault v = Vault.open(p, "new-password".toCharArray())) {
                check(v.entries().size() == 2 && v.iterations() == FAST * 3, "data kept");
            }
        });

        test("vault opens with the iteration count stored in its own header", () -> {
            Path p = tmp.resolve("own.vlt");
            sample(p, "pw-pw-pw-pw").close();
            try (Vault v = Vault.open(p, "pw-pw-pw-pw".toCharArray())) {
                check(v.iterations() == FAST, "read from header");
            }
            check(Crypto.DEFAULT_ITERATIONS >= 600_000, "default cost");
        });

        test("save keeps a backup of the previous file, no temp left", () -> {
            Path p = tmp.resolve("bk.vlt");
            try (Vault v = sample(p, "pw-pw-pw-pw")) {
                byte[] before = Files.readAllBytes(p);
                v.entries().add(new Entry("Third", "", "p", "", ""));
                v.save();
                Path bak = tmp.resolve("bk.vlt.bak");
                check(Files.exists(bak) && java.util.Arrays.equals(Files.readAllBytes(bak), before), "backup is previous file");
                check(!Files.exists(tmp.resolve("bk.vlt.tmp")), "temp removed");
                try (Vault old = Vault.open(bak, "pw-pw-pw-pw".toCharArray())) {
                    check(old.entries().size() == 2, "backup opens");
                }
            }
        });

        test("export and import round trip, merge skips duplicates", () -> {
            Path src = tmp.resolve("e1.vlt"), ex = tmp.resolve("exp.vlt"), dst = tmp.resolve("e2.vlt");
            try (Vault a = sample(src, "pw-pw-pw-pw")) {
                a.exportTo(ex, "export-pass".toCharArray(), FAST);
            }
            rejects(() -> Vault.readExport(ex, "nope-nope".toCharArray()), "wrong export pw");
            List<Entry> in = Vault.readExport(ex, "export-pass".toCharArray());
            check(in.size() == 2, "read back");
            try (Vault b = Vault.create(dst, "other-password".toCharArray(), FAST)) {
                check(b.merge(in) == 2, "first merge");
                check(b.merge(in) == 0, "second merge adds nothing");
            }
        });

        test("import of malformed payloads fails cleanly", () -> {
            String[] bad = {"", "{", "[]", "{\"entries\":5}", "{\"entries\":[1]}", "{\"entries\":[{}]}",
                "{\"entries\":[{\"title\":\"\"}]}", "{\"entries\":[{\"title\":5}]}",
                "{\"entries\":[{\"title\":\"a\",\"tags\":\"x\"}]}", "{\"entries\":[{\"title\":\"a\",\"tags\":[1]}]}",
                "{\"entries\":[]} trailing", "{\"entries\":[\"\\u12\"]}", "nul\u0000l"};
            for (String s : bad) {
                Path p = tmp.resolve("bad.vlt");
                byte[] k = Crypto.deriveKey("pw-pw-pw-pw".toCharArray(), new byte[16], FAST);
                Files.write(p, Crypto.seal(k, new byte[16], FAST, s.getBytes(StandardCharsets.UTF_8)));
                // sealed with salt zero, so opening with the matching password reaches the parser
                rejects(() -> Vault.open(p, "pw-pw-pw-pw".toCharArray()), "payload " + s);
            }
        });

        test("deeply nested JSON is refused, not a stack overflow", () -> {
            rejects(() -> Json.parse("[".repeat(5000)), "nesting");
        });

        test("json round trip with escapes", () -> {
            String s = "q\"\\/\n\t\u0001\u00e9\ud83d\ude00";
            check(Json.parse(Json.write(List.of(s))).equals(List.of(s)), "escapes");
        });

        test("generator honours length and every chosen set", () -> {
            for (int len = 4; len < 60; len++) {
                for (int mask = 1; mask < 16; mask++) {
                    Generator.Options o = new Generator.Options();
                    o.lower = (mask & 1) != 0;
                    o.upper = (mask & 2) != 0;
                    o.digits = (mask & 4) != 0;
                    o.symbols = (mask & 8) != 0;
                    o.length = len;
                    String p = Generator.password(o);
                    check(p.length() == len, "length");
                    check(!o.lower || p.chars().anyMatch(c -> Generator.LOWER.indexOf(c) >= 0), "lower " + p);
                    check(!o.upper || p.chars().anyMatch(c -> Generator.UPPER.indexOf(c) >= 0), "upper " + p);
                    check(!o.digits || p.chars().anyMatch(c -> Generator.DIGITS.indexOf(c) >= 0), "digit " + p);
                    check(!o.symbols || p.chars().anyMatch(c -> Generator.SYMBOLS.indexOf(c) >= 0), "symbol " + p);
                    check(o.lower || p.chars().noneMatch(c -> Generator.LOWER.indexOf(c) >= 0), "unwanted lower");
                    check(o.symbols || p.chars().noneMatch(c -> Generator.SYMBOLS.indexOf(c) >= 0), "unwanted symbol");
                }
            }
        });

        test("generator skips ambiguous characters and rejects bad options", () -> {
            Generator.Options o = new Generator.Options();
            o.noAmbiguous = true;
            o.length = 500;
            check(Generator.password(o).chars().noneMatch(c -> "O0oIl1|".indexOf(c) >= 0), "ambiguous present");
            o.lower = o.upper = o.digits = o.symbols = false;
            rejects(() -> Generator.password(o), "no sets");
            Generator.Options t = new Generator.Options();
            t.length = 3;
            rejects(() -> Generator.password(t), "too short for 4 sets");
        });

        test("generated passwords are not constant", () -> {
            Set<String> s = new HashSet<>();
            for (int i = 0; i < 50; i++) s.add(Generator.password(new Generator.Options()));
            check(s.size() == 50, "collision");
        });

        test("passphrase word count, separator and wordlist", () -> {
            check(Generator.words().size() == 256, "wordlist size " + Generator.words().size());
            check(new HashSet<>(Generator.words()).size() == 256, "duplicate words");
            String p = Generator.passphrase(6, ".", false, false);
            check(p.split("\\.").length == 6, "six words: " + p);
            for (String w : p.split("\\.")) check(Generator.words().contains(w), "unknown word " + w);
            rejects(() -> Generator.passphrase(2, "-", false, false), "too few words");
            check(Math.abs(Generator.passphraseBits(6, false) - 48) < 0.01, "6 words of 256 = 48 bits");
        });

        test("strength ordering", () -> {
            check(Strength.estimate("password1").score() == 0, "common");
            check(Strength.estimate("").score() == 0, "empty");
            check(Strength.estimate("aaaaaaaaaaaa").score() < Strength.estimate("kJ9#mP2$vL8@nQ4x").score(), "repeat vs random");
            check(Strength.estimate("kJ9#mP2$vL8@nQ4x").score() >= 3, "random is good");
            check(Strength.estimate("abcd1234").score() <= 1, "runs are weak");
        });

        test("audit finds reused and weak passwords", () -> {
            List<Entry> l = new ArrayList<>();
            l.add(new Entry("a", "", "same-pass-1!", "", ""));
            l.add(new Entry("b", "", "same-pass-1!", "", ""));
            l.add(new Entry("c", "", "unique-kJ9#mP2$", "", ""));
            l.add(new Entry("d", "", "", "", ""));
            l.add(new Entry("e", "", "", "", ""));
            check(Audit.reused(l).size() == 1 && Audit.reused(l).get(0).size() == 2, "one group of two; empty passwords ignored");
            l.add(new Entry("f", "", "123456", "", ""));
            check(Audit.weak(l).size() == 1, "weak");
        });

        test("hibp sends only a 5 char prefix and parses ranges", () -> {
            check(Hibp.sha1Hex("password").equals("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"), "sha1 vector");
            check(Hibp.prefix("password").equals("5BAA6"), "prefix");
            String body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\n0000000000000000000000000000000000A:0\r\n";
            check(Hibp.countIn(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8") == 3861493, "hit");
            check(Hibp.countIn(body, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF") == 0, "miss");
            rejects(() -> Hibp.countIn("ABC:xyz", "ABC"), "malformed count");
        });

        test("hibp request path contains only the prefix (local stub server)", () -> {
            var srv = com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1", 0), 0);
            List<String> paths = new ArrayList<>();
            srv.createContext("/range/", ex -> {
                paths.add(ex.getRequestURI().toString());
                byte[] r = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\r\n".getBytes();
                ex.sendResponseHeaders(200, r.length);
                ex.getResponseBody().write(r);
                ex.close();
            });
            srv.start();
            try {
                long n = Hibp.check("password", "http://127.0.0.1:" + srv.getAddress().getPort() + "/range/");
                check(n == 42, "count " + n);
                check(paths.equals(List.of("/range/5BAA6")), "path " + paths);
            } finally {
                srv.stop(0);
            }
        });

        test("cli: init, add, show hides password, wrong password, breach needs opt-in", () -> {
            Path p = tmp.resolve("cli.vlt");
            String pw = "cli-master-pw";
            String[] r1 = cli(p, pw + "\n" + pw + "\n", "init");
            check(r1[0].equals("0"), "init: " + r1[2]);
            String[] r2 = cli(p, pw + "\nentry-pass\n", "add", "Site", "--user", "me", "--tag", "x");
            check(r2[0].equals("0"), "add: " + r2[2]);
            String[] r3 = cli(p, pw + "\n", "show", "Site");
            check(r3[0].equals("0") && !r3[1].contains("entry-pass"), "hidden");
            check(cli(p, pw + "\n", "show", "Site", "--reveal")[1].contains("entry-pass"), "reveal");
            check(cli(p, "bad-password\n", "show", "Site")[0].equals("1"), "wrong pw exit code");
            String[] b = cli(p, pw + "\n", "breach", "Site");
            check(b[0].equals("1") && b[2].contains("--online"), "breach refused without --online");
            check(cli(p, pw + "\n", "list")[1].contains("Site"), "list");
            check(cli(p, pw + "\n", "search", "ME")[1].contains("Site"), "search is case-insensitive");
            check(cli(p, pw + "\n", "rm", "Site")[0].equals("1"), "rm needs --yes");
            check(cli(p, "x\nx\n", "init")[0].equals("1"), "init refuses to overwrite");
            check(cli(p, "short\nshort\n", "init", "--iterations", "10")[0].equals("1"), "low iterations refused");
        });

        test("demo vault is synthetic and has one reuse group", () -> {
            check(Vault.demo().entries().size() >= 8, "demo size");
            check(Audit.reused(Vault.demo().entries()).size() == 1, "demo has one reuse group");
        });

        test("gui snapshot writes a png, bad gui options are rejected", () -> {
            for (boolean locked : new boolean[] {false, true}) {
                Path img = tmp.resolve("snap" + locked + ".png");
                List<String> cmd = new ArrayList<>(List.of(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                        "-Djava.awt.headless=true", "-cp", System.getProperty("java.class.path"), "vaultlite.Main",
                        "gui", "--snapshot", img.toString()));
                if (locked) cmd.add("--locked");
                Process pr = new ProcessBuilder(cmd).redirectErrorStream(true).start();
                String out = new String(pr.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                check(pr.waitFor() == 0, "snapshot exit: " + out);
                byte[] png = Files.readAllBytes(img);
                check(png.length > 500 && png[1] == 'P' && png[2] == 'N' && png[3] == 'G', "not a png");
            }
            check(cli(tmp.resolve("g.vlt"), "", "gui", "--bogus")[0].equals("1"), "unknown gui option");
            check(cli(tmp.resolve("g.vlt"), "", "gui", "--autolock", "soon")[0].equals("1"), "bad autolock");
        });

        System.out.println(passed + " passed, " + failed + " failed");
        System.exit(failed == 0 ? 0 : 1);
    }

    private static String[] cli(Path vault, String stdin, String... args) {
        ByteArrayOutputStream o = new ByteArrayOutputStream(), e = new ByteArrayOutputStream();
        String[] full = new String[args.length + 2];
        full[0] = "--vault";
        full[1] = vault.toString();
        System.arraycopy(args, 0, full, 2, args.length);
        int code = new Cli(new ByteArrayInputStream(stdin.getBytes(StandardCharsets.UTF_8)),
                new PrintStream(o), new PrintStream(e)).run(full);
        return new String[] {String.valueOf(code), o.toString(), e.toString()};
    }
}
