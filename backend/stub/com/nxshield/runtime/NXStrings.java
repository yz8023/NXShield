package com.nxshield.runtime;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.HashMap;
import java.util.Map;

/**
 * Decodes the encrypted string tables produced by the offline packer and
 * resolves them by original string-id index. The packer replaced sensitive
 * literals (CJK text, vip/premium and similar keywords) with a length-preserving
 * placeholder, so {@link #get(int)} restores the real value at runtime.
 */
public final class NXStrings {

    private static final String TAG = "NXStrings";
    private static final Map<Integer, byte[]> TABLE = new HashMap<Integer, byte[]>();

    private NXStrings() {
    }

    public static synchronized void registerTable(byte[] raw) {
        if (raw == null || raw.length < 5) {
            return;
        }
        if (!(raw[0] == 'N' && raw[1] == 'X' && raw[2] == 'S'
                && raw[3] == 'T' && raw[4] == 'R')) {
            return;
        }
        ByteBuffer buf = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);
        buf.position(5);
        while (buf.remaining() >= 8) {
            int idx = buf.getInt();
            int len = buf.getInt();
            if (len < 0 || len > buf.remaining()) {
                break;
            }
            byte[] enc = new byte[len];
            buf.get(enc);
            TABLE.put(idx, enc);
        }
        NXLog.i(TAG, "string table entries: " + TABLE.size());
    }

    public static String get(int index) {
        byte[] enc = TABLE.get(index);
        if (enc == null) {
            return null;
        }
        byte[] plain = NXCrypto.rollingXor(enc, keystream(index));
        return new String(plain, java.nio.charset.Charset.forName("UTF-8"));
    }

    private static byte[] keystream(int index) {
        byte[] seed = NXStringsKey.SEED;
        byte[] mix = new byte[seed.length + 4];
        System.arraycopy(seed, 0, mix, 0, seed.length);
        mix[seed.length] = (byte) (index & 0xFF);
        mix[seed.length + 1] = (byte) ((index >> 8) & 0xFF);
        mix[seed.length + 2] = (byte) ((index >> 16) & 0xFF);
        mix[seed.length + 3] = (byte) ((index >> 24) & 0xFF);
        byte[] out = new byte[32];
        int acc = 0x5A;
        for (int i = 0; i < out.length; i++) {
            int b = mix[i % mix.length] & 0xFF;
            acc = (acc + b + i * 13) & 0xFF;
            out[i] = (byte) acc;
        }
        return out;
    }
}
