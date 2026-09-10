package com.nxshield.runtime;

import android.util.Log;

/** Lightweight logging facade used by the runtime stub. */
public final class NXLog {

    private static final String PREFIX = "NXShield/";
    private static boolean sVerbose = false;

    private NXLog() {
    }

    public static void setVerbose(boolean verbose) {
        sVerbose = verbose;
    }

    public static void i(String tag, String msg) {
        Log.i(PREFIX + tag, msg);
    }

    public static void w(String tag, String msg) {
        Log.w(PREFIX + tag, msg);
    }

    public static void e(String tag, String msg) {
        Log.e(PREFIX + tag, msg);
    }

    public static void e(String tag, String msg, Throwable t) {
        Log.e(PREFIX + tag, msg, t);
    }

    public static void d(String tag, String msg) {
        if (sVerbose) {
            Log.d(PREFIX + tag, msg);
        }
    }
}
