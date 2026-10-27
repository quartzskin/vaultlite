package vaultlite;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * File layout: "VLT1" | version(1) | kdf id(1) | iterations(4, BE) | salt len(1) | salt | nonce(12) | ciphertext+tag.
 * Everything before the ciphertext is passed to GCM as associated data.
 */
public final class Crypto {
    public static final int DEFAULT_ITERATIONS = 600_000;
    public static final int MAX_ITERATIONS = 10_000_000;
    public static final int SALT_LEN = 16;
    public static final int NONCE_LEN = 12;
    public static final int TAG_BITS = 128;

    private static final byte[] MAGIC = {'V', 'L', 'T', '1'};
    private static final int VERSION = 1;
    private static final int KDF_PBKDF2_SHA256 = 1;
    private static final int HEADER_LEN = 4 + 1 + 1 + 4 + 1 + SALT_LEN + NONCE_LEN;
    private static final SecureRandom RNG = new SecureRandom();

    private Crypto() {}

    public record Header(int iterations, byte[] salt, byte[] nonce, byte[] raw) {}

    public static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }

    public static byte[] deriveKey(char[] password, byte[] salt, int iterations) {
        if (iterations < 1 || iterations > MAX_ITERATIONS) throw new VaultException("bad iteration count");
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, 256);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new VaultException("PBKDF2 unavailable", e);
        } finally {
            spec.clearPassword();
        }
    }

    public static byte[] seal(byte[] key, byte[] salt, int iterations, byte[] plaintext) {
        byte[] nonce = randomBytes(NONCE_LEN);
        ByteBuffer hb = ByteBuffer.allocate(HEADER_LEN);
        hb.put(MAGIC).put((byte) VERSION).put((byte) KDF_PBKDF2_SHA256).putInt(iterations);
        hb.put((byte) salt.length).put(salt).put(nonce);
        byte[] header = hb.array();
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, nonce));
            c.updateAAD(header);
            byte[] ct = c.doFinal(plaintext);
            byte[] out = new byte[header.length + ct.length];
            System.arraycopy(header, 0, out, 0, header.length);
            System.arraycopy(ct, 0, out, header.length, ct.length);
            return out;
        } catch (GeneralSecurityException e) {
            throw new VaultException("encryption failed", e);
        }
    }

    public static Header parseHeader(byte[] file) {
        if (file.length < HEADER_LEN + TAG_BITS / 8) throw new VaultException("file too short to be a vault");
        if (!Arrays.equals(Arrays.copyOf(file, 4), MAGIC)) throw new VaultException("not a vaultlite file");
        ByteBuffer b = ByteBuffer.wrap(file);
        b.position(4);
        int version = b.get() & 0xff;
        int kdf = b.get() & 0xff;
        if (version != VERSION || kdf != KDF_PBKDF2_SHA256) throw new VaultException("unsupported vault version");
        int iterations = b.getInt();
        if (iterations < 1) throw new VaultException("bad iteration count in header");
        if (iterations > MAX_ITERATIONS) {
            throw new VaultException("iteration count in header (" + Integer.toUnsignedString(iterations) + ") is above the limit of " + MAX_ITERATIONS + "; file is corrupt or hostile");
        }
        if ((b.get() & 0xff) != SALT_LEN) throw new VaultException("bad salt length in header");
        byte[] salt = new byte[SALT_LEN];
        b.get(salt);
        byte[] nonce = new byte[NONCE_LEN];
        b.get(nonce);
        return new Header(iterations, salt, nonce, Arrays.copyOf(file, HEADER_LEN));
    }

    public static byte[] unseal(byte[] key, byte[] file, Header h) {
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, h.nonce()));
            c.updateAAD(h.raw());
            return c.doFinal(file, HEADER_LEN, file.length - HEADER_LEN);
        } catch (GeneralSecurityException e) {
            throw new VaultException("wrong password, or the file is corrupted or has been tampered with");
        }
    }

    public static void zero(byte[] b) {
        if (b != null) Arrays.fill(b, (byte) 0);
    }

    public static void zero(char[] c) {
        if (c != null) Arrays.fill(c, '\0');
    }
}
