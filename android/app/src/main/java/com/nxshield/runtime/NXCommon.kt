package com.nxshield.runtime

import android.content.Context

/** 运行时日志（对接 NxLogger 或直接 logcat） */
object NXLog {
    fun i(tag: String, msg: String) = LogHelper.log(tag, "info", msg)
    fun w(tag: String, msg: String) = LogHelper.log(tag, "warn", msg)
    fun e(tag: String, msg: String) = LogHelper.log(tag, "error", msg)

    object LogHelper {
        var sink: ((String, String, String) -> Unit)? = null
        fun log(tag: String, level: String, msg: String) {
            sink?.invoke(tag, level, msg)
            android.util.Log.println(levelToAndroid(level), "NXShield/$tag", msg)
        }
        private fun levelToAndroid(level: String): Int = when (level) {
            "error" -> android.util.Log.ERROR
            "warn" -> android.util.Log.WARN
            else -> android.util.Log.INFO
        }
    }
}

/** 反射工具（运行时按签名定位被保护方法） */
object NXReflect {
    fun callStatic(cls: String, method: String, vararg args: Any?): Any? {
        val clazz = Class.forName(cls)
        val m = clazz.methods.firstOrNull { it.name == method } ?: throw NoSuchMethodException(cls + "#" + method)
        m.isAccessible = true
        return m.invoke(null, *args)
    }

    fun invoke(instance: Any, method: String, vararg args: Any?): Any? {
        val m = instance.javaClass.methods.firstOrNull { it.name == method } ?: throw NoSuchMethodException(method)
        m.isAccessible = true
        return m.invoke(instance, *args)
    }

    /** 设备端加固引擎入口（Packer 位置留作导航说明） */
    fun engineClass(): String = "com.nxshield.engine.Packer"
}