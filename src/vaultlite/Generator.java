package vaultlite;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public final class Generator {
    public static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
    public static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    public static final String DIGITS = "0123456789";
    public static final String SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/";
    private static final String AMBIGUOUS = "O0oIl1|";
    private static final SecureRandom RNG = new SecureRandom();
    private static List<String> words;

    private Generator() {}

    public static final class Options {
        public int length = 20;
        public boolean lower = true, upper = true, digits = true, symbols = true;
        public boolean noAmbiguous = false;
    }

    public static String password(Options o) {
        List<String> sets = new ArrayList<>();
        if (o.lower) sets.add(clean(LOWER, o));
        if (o.upper) sets.add(clean(UPPER, o));
        if (o.digits) sets.add(clean(DIGITS, o));
        if (o.symbols) sets.add(clean(SYMBOLS, o));
        if (sets.isEmpty()) throw new VaultException("pick at least one character set");
        if (o.length < sets.size()) throw new VaultException("length too short for the chosen sets");
        if (o.length > 1024) throw new VaultException("length above 1024 not supported");
        StringBuilder pool = new StringBuilder();
        for (String s : sets) pool.append(s);
        char[] out = new char[o.length];
        for (int i = 0; i < out.length; i++) out[i] = pool.charAt(RNG.nextInt(pool.length()));
        // overwrite distinct random positions so every chosen set appears at least once
        List<Integer> pos = new ArrayList<>();
        for (int i = 0; i < out.length; i++) pos.add(i);
        for (String s : sets) {
            int p = pos.remove(RNG.nextInt(pos.size()));
            out[p] = s.charAt(RNG.nextInt(s.length()));
        }
        return new String(out);
    }

    public static String passphrase(int count, String separator, boolean capitalise, boolean addDigit) {
        if (count < 3 || count > 20) throw new VaultException("word count must be 3 to 20");
        List<String> list = words();
        List<String> parts = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            String w = list.get(RNG.nextInt(list.size()));
            if (capitalise) w = Character.toUpperCase(w.charAt(0)) + w.substring(1);
            parts.add(w);
        }
        if (addDigit) {
            int at = RNG.nextInt(parts.size());
            parts.set(at, parts.get(at) + RNG.nextInt(10));
        }
        return String.join(separator, parts);
    }

    public static double passphraseBits(int count, boolean addDigit) {
        double b = count * log2(words().size());
        return addDigit ? b + log2(count) + log2(10) : b;
    }

    public static synchronized List<String> words() {
        if (words == null) {
            List<String> l = new ArrayList<>();
            try (InputStream in = Generator.class.getResourceAsStream("wordlist.txt")) {
                if (in == null) throw new VaultException("wordlist.txt missing from the jar");
                BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
                String line;
                while ((line = r.readLine()) != null) if (!line.isBlank()) l.add(line.trim());
            } catch (IOException e) {
                throw new VaultException("cannot read wordlist", e);
            }
            words = l;
        }
        return words;
    }

    private static String clean(String set, Options o) {
        if (!o.noAmbiguous) return set;
        StringBuilder sb = new StringBuilder();
        for (char c : set.toCharArray()) if (AMBIGUOUS.indexOf(c) < 0) sb.append(c);
        return sb.toString();
    }

    private static double log2(double x) {
        return Math.log(x) / Math.log(2);
    }
}
