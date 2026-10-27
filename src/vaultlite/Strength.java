package vaultlite;

import java.util.Set;

/** Rough guess from character pool and length with penalties; not a real guessing model. */
public final class Strength {
    private static final Set<String> COMMON = Set.of("password", "123456", "12345678", "qwerty", "abc123", "letmein",
            "admin", "welcome", "monkey", "dragon", "iloveyou", "football", "login", "passw0rd", "master", "hello",
            "sunshine", "princess", "trustno1", "111111", "000000");

    public record Result(double bits, int score, String label) {}

    private Strength() {}

    public static Result estimate(String pw) {
        if (pw.isEmpty()) return new Result(0, 0, "empty");
        String lower = pw.toLowerCase();
        for (String c : COMMON) {
            if (lower.equals(c) || lower.replaceAll("[0-9!@#$%^&*]+$", "").equals(c)) {
                return new Result(Math.min(12, pw.length() * 2), 0, "very weak");
            }
        }
        int pool = 0;
        if (pw.chars().anyMatch(Character::isLowerCase)) pool += 26;
        if (pw.chars().anyMatch(Character::isUpperCase)) pool += 26;
        if (pw.chars().anyMatch(Character::isDigit)) pool += 10;
        if (pw.chars().anyMatch(c -> !Character.isLetterOrDigit(c))) pool += 32;
        double bits = pw.length() * Math.log(Math.max(pool, 2)) / Math.log(2);
        // repeated characters and straight runs (abc, 123) add little
        int dull = 0;
        for (int i = 1; i < pw.length(); i++) {
            int d = pw.charAt(i) - pw.charAt(i - 1);
            if (d == 0 || d == 1 || d == -1) dull++;
        }
        bits -= dull * Math.log(Math.max(pool, 2)) / Math.log(2) * 0.8;
        long distinct = pw.chars().distinct().count();
        if (distinct * 2 < pw.length()) bits *= 0.7;
        bits = Math.max(bits, 0);
        int score = bits < 28 ? 0 : bits < 40 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
        String[] labels = {"very weak", "weak", "fair", "good", "strong"};
        return new Result(bits, score, labels[score]);
    }
}
