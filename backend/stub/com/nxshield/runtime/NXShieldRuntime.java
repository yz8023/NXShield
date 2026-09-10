package com.nxshield.runtime;

import android.content.Context;
import android.content.res.AssetManager;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * NXShield runtime stub (self-developed).
 *
 * Loads encrypted assets (.nxs), the NX-VM image and the string tables that the
 * offline packer produced, then decrypts them in memory. This class is the only
 * bootstrap that must be added to the host application (usually from
 * {@code Application.attachBaseContext}).
 */
public final class NXShieldRuntime {

    private static final String TAG = "NXShield";
    private static final String MAGIC = "NXS1";
    private static final String PAYLOAD_DIR = "nxshield";

    private static byte[] sKey;
    private static boolean sReady;

    private NXShieldRuntime() {
    }

    public static void install(Context context, byte[] key) {
        if (sReady) {
            return;
        }
        sKey = key.clone();
        try {
            unpackAssets(context);
            loadVmImage(context);
            loadStringTables(context);
            sReady = true;
            NXLog.i(TAG, "runtime installed");
        } catch (Throwable t) {
            NXLog.e(TAG, "runtime install failed: " + t.getMessage());
        }
    }

    public static boolean isReady() {
        return sReady;
    }

    private static void unpackAssets(Context context) throws IOException {
        AssetManager am = context.getAssets();
        String[] names = am.list(PAYLOAD_DIR);
        if (names == null) {
            return;
        }
        File outDir = new File(context.getFilesDir(), PAYLOAD_DIR);
        if (!outDir.exists() && !outDir.mkdirs()) {
            throw new IOException("cannot create payload dir");
        }
        for (String name : names) {
            if (!name.endsWith(".nxs")) {
                continue;
            }
            String logical = name.substring(0, name.length() - 4);
            byte[] plain = NXCrypto.decrypt(readAsset(am, PAYLOAD_DIR + "/" + name), sKey);
            writeFile(new File(outDir, logical), plain);
            NXLog.i(TAG, "unpacked asset " + logical + " (" + plain.length + " bytes)");
        }
    }

    private static void loadVmImage(Context context) throws IOException {
        byte[] blob = readAsset(context.getAssets(), PAYLOAD_DIR + "/vm.bin");
        if (blob == null || blob.length == 0) {
            return;
        }
        byte[] image = NXCrypto.decrypt(blob, sKey);
        NXVM.registerImage(image);
        NXLog.i(TAG, "vm image loaded (" + image.length + " bytes)");
    }

    private static void loadStringTables(Context context) throws IOException {
        AssetManager am = context.getAssets();
        String[] names = am.list(PAYLOAD_DIR);
        if (names == null) {
            return;
        }
        int loaded = 0;
        for (String name : names) {
            if (!name.endsWith(".str")) {
                continue;
            }
            byte[] table = NXCrypto.decrypt(readAsset(am, PAYLOAD_DIR + "/" + name), sKey);
            NXStrings.registerTable(table);
            loaded++;
        }
        NXLog.i(TAG, "string tables loaded: " + loaded);
    }

    private static byte[] readAsset(AssetManager am, String path) throws IOException {
        InputStream in = null;
        try {
            in = am.open(path);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                bos.write(buf, 0, n);
            }
            return bos.toByteArray();
        } finally {
            if (in != null) {
                in.close();
            }
        }
    }

    private static void writeFile(File file, byte[] data) throws IOException {
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(file);
            fos.write(data);
            fos.flush();
        } finally {
            if (fos != null) {
                fos.close();
            }
        }
    }
}
