package com.nxshield.runtime;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Mirrors the offline engine/crypto.py scheme:
 * MAGIC(4) || salt(8) || hmac-sha256/16 || rolling-xor(plain).
 */
public final class NXCrypto {

    private static final byte[] MAGIC = {'N', 'X', 'S', '1'};
    private static final int ROUNDS = 4096;

    private NXCrypto() {
    }

    public static byte[] decrypt(byte[] blob, byte[] password) {
        if (blob == null || blob.length < 28) {
            return new byte[0];
        }
        if (blob[0] != MAGIC[0] || blob[1] != MAGIC[1]
                || blob[2] != MAGIC[2] || blob[3] != MAGIC[3]) {
            throw new IllegalArgumentException("invalid nxshield blob");
        }
        byte[] salt = Arrays.copyOfRange(blob, 4, 12);
        byte[] digest = Arrays.copyOfRange(blob, 12, 28);
        byte[] xored = Arrays.copyOfRange(blob, 28, blob.length);
        byte[] dk = deriveKey(password, salt);
        byte[] check = hmac(dk, xored);
        if (!constantTimeEquals(Arrays.copyOfRange(check, 0, 16), digest)) {
            throw new SecurityException("blob mac mismatch");
        }
        return rollingXor(xored, dk);
    }

    public static byte[] deriveKey(byte[] password, byte[] salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] seed = new byte[password.length + salt.length];
            System.arraycopy(password, 0, seed, 0, password.length);
            System.arraycopy(salt, 0, seed, password.length, salt.length);
            byte[] dk = seed;
            for (int i = 0; i < ROUNDS; i++) {
                dk = md.digest(dk);
            }
            return dk;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] rollingXor(byte[] data, byte[] key) {
        if (key == null || key.length == 0) {
            return data.clone();
        }
        byte[] out = new byte[data.length];
        int acc = 0xA5;
        for (int i = 0; i < data.length; i++) {
            int k = key[i % key.length] & 0xFF;
            acc = (acc + k + (i & 0xFF) + 1) & 0xFF;
            out[i] = (byte) (data[i] ^ k ^ (acc & 0xFF));
        }
        return out;
    }

    public static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int r = 0;
        for (int i = 0; i < a.length; i++) {
            r |= a[i] ^ b[i];
        }
        return r == 0;
    }

    public static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            bos.write(p, 0, p.length);
        }
        return bos.toByteArray();
    }
}
