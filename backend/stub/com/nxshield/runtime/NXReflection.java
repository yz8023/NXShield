package com.nxshield.runtime;

import java.lang.reflect.Method;

/**
 * Reflection bridge used by {@code OP_INVOKE}. The offline packer emits the
 * resolved target index; here we resolve it lazily against the registry that the
 * host instrumentation installs.
 */
public final class NXReflection {

    private static volatile Resolver sResolver;

    private NXReflection() {
    }

    public interface Resolver {
        Object invoke(int invokeKind, int targetIndex, Object[] registers);
    }

    public static void setResolver(Resolver resolver) {
        sResolver = resolver;
    }

    public static Object invoke(int kind, int target, Object[] registers) {
        Resolver r = sResolver;
        if (r != null) {
            return r.invoke(kind, target, registers);
        }
        throw new IllegalStateException("no NXReflection resolver installed");
    }

    public static Object callStatic(Class<?> owner, String name, Class<?>[] sig, Object[] args) {
        try {
            Method m = owner.getDeclaredMethod(name, sig);
            m.setAccessible(true);
            return m.invoke(null, args);
        } catch (Exception e) {
            NXLog.e("NXReflection", "callStatic failed: " + name, e);
            return null;
        }
    }
}
