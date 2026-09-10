package com.nxshield.app

import android.app.Application
import java.io.File
import java.util.Date

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
        installCrashHandler()
    }

    private fun installCrashHandler() {
        val prev = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            runCatching {
                val f = File(filesDir, "nxshield/crash.log")
                f.parentFile?.mkdirs()
                f.appendText(
                    "[${Date()}] ${thread.name}\n" +
                        android.util.Log.getStackTraceString(throwable) + "\n\n",
                )
            }
            prev?.uncaughtException(thread, throwable)
        }
    }
}