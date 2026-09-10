package com.nxshield.runtime;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.HashMap;
import java.util.Map;

/**
 * NX-VM interpreter (self-developed).
 *
 * The offline packer translates selected Dalvik methods into a compact custom
 * instruction set and stores the encrypted image in {@code assets/nxshield/vm.bin}.
 * This interpreter registers the decoded image and exposes {@link #call} so the
 * rewritten method stubs can dispatch into the VM.
 */
public final class NXVM {

    private static final String TAG = "NXVM";

    private static final int OP_NOP = 0x00;
    private static final int OP_CONST = 0x01;
    private static final int OP_MOVE = 0x02;
    private static final int OP_ADD = 0x03;
    private static final int OP_SUB = 0x04;
    private static final int OP_MUL = 0x05;
    private static final int OP_XOR = 0x06;
    private static final int OP_AND = 0x07;
    private static final int OP_OR = 0x08;
    private static final int OP_IFZ = 0x09;
    private static final int OP_GOTO = 0x0A;
    private static final int OP_INVOKE = 0x0B;
    private static final int OP_RETURN = 0x0C;
    private static final int OP_SGET = 0x0D;
    private static final int OP_SPUT = 0x0E;
    private static final int OP_IGET = 0x0F;
    private static final int OP_IPUT = 0x10;
    private static final int OP_CSTR = 0x11;
    private static final int OP_RAW = 0x7F;

    private static final Map<Integer, Function> FUNCTIONS = new HashMap<Integer, Function>();

    private NXVM() {
    }

    private static final class Function {
        final int methodIdx;
        final int registers;
        final int insSize;
        final byte[] bytecode;

        Function(int methodIdx, int registers, int insSize, byte[] bytecode) {
            this.methodIdx = methodIdx;
            this.registers = registers;
            this.insSize = insSize;
            this.bytecode = bytecode;
        }
    }

    public static synchronized void registerImage(byte[] image) {
        if (image == null || image.length < 8) {
            return;
        }
        ByteBuffer buf = ByteBuffer.wrap(image).order(ByteOrder.LITTLE_ENDIAN);
        byte[] magic = new byte[5];
        buf.get(magic);
        int count = buf.getInt();
        for (int i = 0; i < count; i++) {
            int methodIdx = buf.getInt();
            int regs = buf.getShort() & 0xFFFF;
            int insSize = buf.getShort() & 0xFFFF;
            int nameLen = buf.getInt();
            byte[] name = new byte[nameLen];
            buf.get(name);
            int bcLen = buf.getInt();
            byte[] bc = new byte[bcLen];
            buf.get(bc);
            FUNCTIONS.put(methodIdx, new Function(methodIdx, regs, insSize, bc));
        }
        NXLog.i(TAG, "registered " + FUNCTIONS.size() + " functions");
    }

    public static boolean hasFunction(int methodIdx) {
        return FUNCTIONS.containsKey(methodIdx);
    }

    public static Object call(int methodIdx, Object... args) {
        Function fn = FUNCTIONS.get(methodIdx);
        if (fn == null) {
            throw new IllegalStateException("no vm function for " + methodIdx);
        }
        return execute(fn, args);
    }

    private static Object execute(Function fn, Object[] args) {
        Object[] registers = new Object[Math.max(fn.registers, fn.insSize + 1)];
        System.arraycopy(args, 0, registers, 0, Math.min(args.length, registers.length));
        byte[] bc = fn.bytecode;
        int pc = 0;
        Object result = null;
        while (pc + 4 <= bc.length) {
            int op = bc[pc] & 0xFF;
            int a = bc[pc + 1] & 0xFF;
            int b = bc[pc + 2] & 0xFF;
            int c = bc[pc + 3] & 0xFF;
            pc += 4;
            switch (op) {
                case OP_NOP:
                    break;
                case OP_CONST:
                    registers[a & 0x0F] = (b | (c << 8));
                    break;
                case OP_MOVE:
                    registers[a & 0x0F] = registers[b & 0x0F];
                    break;
                case OP_ADD:
                    registers[a & 0x0F] = asInt(registers[b & 0x0F]) + asInt(registers[c & 0x0F]);
                    break;
                case OP_SUB:
                    registers[a & 0x0F] = asInt(registers[b & 0x0F]) - asInt(registers[c & 0x0F]);
                    break;
                case OP_MUL:
                    registers[a & 0x0F] = asInt(registers[b & 0x0F]) * asInt(registers[c & 0x0F]);
                    break;
                case OP_XOR:
                    registers[a & 0x0F] = asInt(registers[b & 0x0F]) ^ asInt(registers[c & 0x0F]);
                    break;
                case OP_AND:
                    registers[a & 0x0F] = asInt(registers[b & 0x0F]) & asInt(registers[c & 0x0F]);
                    break;
                case OP_OR:
                    registers[a & 0x0F] = asInt(registers[b & 0x0F]) | asInt(registers[c & 0x0F]);
                    break;
                case OP_IFZ:
                    if (asInt(registers[a & 0x0F]) == 0) {
                        pc += (short) (b | (c << 8)) * 4;
                    }
                    break;
                case OP_GOTO:
                    pc += (short) (a | (b << 8)) * 4;
                    break;
                case OP_CSTR:
                    registers[a & 0x0F] = NXStrings.get(b | (c << 8));
                    break;
                case OP_RETURN:
                    result = registers[a & 0x0F];
                    return result;
                case OP_INVOKE:
                    result = NXReflection.invoke(a, (b | (c << 8)), registers);
                    break;
                case OP_RAW:
                    NXLog.w(TAG, "raw opcode passthrough at " + (pc - 4));
                    break;
                default:
                    NXLog.w(TAG, "unknown vm opcode " + op);
                    break;
            }
        }
        return result;
    }

    private static int asInt(Object o) {
        if (o == null) {
            return 0;
        }
        if (o instanceof Number) {
            return ((Number) o).intValue();
        }
        return 0;
    }
}
