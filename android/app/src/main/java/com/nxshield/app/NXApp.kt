package com.nxshield.app

import android.app.Application

class NXApp : Application() {
    override fun onCreate() {
        super.onCreate()
        com.nxshield.runtime.NXLog.LogHelper.sink = { tag, level, msg ->
            android.util.Log.println(
                if (level == "error") android.util.Log.ERROR
                else if (level == "warn") android.util.Log.WARN
                else android.util.Log.INFO,
                "NXShield/$tag", msg,
            )
        }
    }
}