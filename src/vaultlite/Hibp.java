package vaultlite;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Locale;

/** Have I Been Pwned range lookup: only the first 5 hex chars of the SHA-1 leave the machine. */
public final class Hibp {
    public static final String DEFAULT_BASE = "https://api.pwnedpasswords.com/range/";

    private Hibp() {}

    public static String sha1Hex(String s) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-1").digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02X", b));
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new VaultException("SHA-1 unavailable", e);
        }
    }

    public static String prefix(String password) {
        return sha1Hex(password).substring(0, 5);
    }

    public static long countIn(String body, String suffix) {
        String want = suffix.toUpperCase(Locale.ROOT);
        for (String line : body.split("\\r?\\n")) {
            int c = line.indexOf(':');
            if (c <= 0) continue;
            if (line.substring(0, c).trim().equals(want)) {
                try {
                    return Long.parseLong(line.substring(c + 1).trim());
                } catch (NumberFormatException e) {
                    throw new VaultException("malformed range response");
                }
            }
        }
        return 0;
    }

    public static long check(String password, String baseUrl) {
        String hash = sha1Hex(password);
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + hash.substring(0, 5)))
                .timeout(Duration.ofSeconds(15))
                .header("Add-Padding", "true")
                .header("User-Agent", "vaultlite")
                .GET().build();
        try {
            HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
            HttpResponse<String> r = client.send(req, HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() != 200) throw new VaultException("breach service answered HTTP " + r.statusCode());
            return countIn(r.body(), hash.substring(5));
        } catch (IOException e) {
            throw new VaultException("breach check failed: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new VaultException("breach check interrupted", e);
        }
    }
}
