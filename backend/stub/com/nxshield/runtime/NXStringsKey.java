package com.nxshield.runtime;

/**
 * Seed material for string-table decoding. The offline packer can override this
 * byte array during a build; keeping it in its own class makes the substitution
 * a single, well-defined patch point.
 */
public final class NXStringsKey {
    public static final byte[] SEED = new byte[]{
            (byte) 0x4E, (byte) 0x58, (byte) 0x53, (byte) 0x68,
            (byte) 0x69, (byte) 0x65, (byte) 0x6C, (byte) 0x64,
            (byte) 0x2D, (byte) 0x53, (byte) 0x65, (byte) 0x65,
            (byte) 0x64, (byte) 0x2D, (byte) 0x30, (byte) 0x31
    };

    private NXStringsKey() {
    }
}
