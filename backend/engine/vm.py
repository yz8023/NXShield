from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List

from .crypto import encrypt_blob
from .dex import CodeItem, EncodedMethod
from .obfuscate import method_key


OP_NOP = 0x00
OP_MOVE = 0x01
OP_MOVE_RESULT = 0x0A
OP_RETURN_VOID = 0x0E
OP_RETURN = 0x0F
OP_CONST4 = 0x12
OP_CONST16 = 0x13
OP_CONST = 0x14
OP_CONST_STRING = 0x1A
OP_IGET = 0x52
OP_IPUT = 0x59
OP_SGET = 0x60
OP_SPUT = 0x67
OP_INVOKE_VIRTUAL = 0x6E
OP_INVOKE_SUPER = 0x6F
OP_INVOKE_DIRECT = 0x70
OP_INVOKE_STATIC = 0x71
OP_INVOKE_INTERFACE = 0x72
OP_ADD_INT = 0x90
OP_SUB_INT = 0x91
OP_MUL_INT = 0x92
OP_DIV_INT = 0x93
OP_AND_INT = 0x95
OP_OR_INT = 0x96
OP_XOR_INT = 0x97
OP_IF_EQZ = 0x38
OP_IF_NEZ = 0x39
OP_GOTO = 0x28

INSN_SIZE = {
    0x00: 1, 0x01: 1, 0x02: 1, 0x03: 2, 0x04: 1, 0x05: 1, 0x06: 1, 0x07: 1,
    0x08: 2, 0x09: 1, 0x0A: 1, 0x0B: 1, 0x0C: 1, 0x0D: 1, 0x0E: 1, 0x0F: 1,
    0x10: 1, 0x11: 1, 0x12: 1, 0x13: 2, 0x14: 3, 0x15: 2, 0x16: 2, 0x17: 3,
    0x18: 5, 0x19: 2, 0x1A: 2, 0x1B: 3, 0x1C: 2, 0x1D: 1, 0x1E: 1, 0x1F: 2,
    0x20: 2, 0x21: 1, 0x22: 2, 0x23: 2, 0x24: 3, 0x25: 3, 0x26: 3, 0x27: 1,
    0x28: 1, 0x29: 2, 0x2A: 3, 0x2B: 3, 0x2C: 3, 0x2D: 2, 0x2E: 2, 0x2F: 2,
    0x30: 2, 0x31: 2, 0x32: 2, 0x33: 2, 0x34: 2, 0x35: 2, 0x36: 2, 0x37: 2,
    0x38: 2, 0x39: 2, 0x3A: 2, 0x3B: 2, 0x3C: 2, 0x3D: 2, 0x44: 2, 0x45: 2,
    0x46: 2, 0x47: 2, 0x48: 2, 0x49: 2, 0x4A: 2, 0x4B: 2, 0x4C: 2, 0x4D: 2,
    0x4E: 2, 0x4F: 2, 0x50: 2, 0x51: 2, 0x52: 2, 0x53: 2, 0x54: 2, 0x55: 2,
    0x56: 2, 0x57: 2, 0x58: 2, 0x59: 2, 0x5A: 2, 0x5B: 2, 0x5C: 2, 0x5D: 2,
    0x5E: 2, 0x5F: 2, 0x60: 2, 0x61: 2, 0x62: 2, 0x63: 2, 0x64: 2, 0x65: 2,
    0x66: 2, 0x67: 2, 0x68: 2, 0x69: 2, 0x6A: 2, 0x6B: 2, 0x6C: 2, 0x6D: 2,
    0x6E: 3, 0x6F: 3, 0x70: 3, 0x71: 3, 0x72: 3, 0x74: 3, 0x75: 3, 0x76: 3,
    0x77: 3, 0x78: 3, 0x7B: 1, 0x7C: 1, 0x7D: 1, 0x7E: 1, 0x7F: 1, 0x80: 1,
    0x81: 1, 0x82: 1, 0x83: 1, 0x84: 1, 0x85: 1, 0x86: 1, 0x87: 1, 0x88: 1,
    0x89: 1, 0x8A: 1, 0x8B: 1, 0x8C: 1, 0x8D: 1, 0x8E: 1, 0x8F: 1, 0x90: 2,
    0x91: 2, 0x92: 2, 0x93: 2, 0x94: 2, 0x95: 2, 0x96: 2, 0x97: 2, 0x98: 2,
    0x99: 2, 0x9A: 2, 0x9B: 2, 0x9C: 2, 0x9D: 2, 0x9E: 2, 0x9F: 2, 0xA0: 2,
    0xA1: 2, 0xA2: 2, 0xA3: 2, 0xA4: 2, 0xA5: 2, 0xA6: 2, 0xA7: 2, 0xA8: 2,
    0xA9: 2, 0xAA: 2, 0xAB: 2, 0xAC: 2, 0xAD: 2, 0xAE: 2, 0xAF: 2, 0xB0: 1,
    0xB1: 1, 0xB2: 1, 0xB3: 1, 0xB4: 1, 0xB5: 1, 0xB6: 1, 0xB7: 1, 0xB8: 1,
    0xB9: 1, 0xBA: 1, 0xBB: 1, 0xBC: 1, 0xBD: 1, 0xBE: 1, 0xBF: 1, 0xC0: 1,
    0xC1: 1, 0xC2: 1, 0xC3: 1, 0xC4: 1, 0xC5: 1, 0xC6: 1, 0xC7: 1, 0xC8: 1,
    0xC9: 1, 0xCA: 1, 0xCB: 1, 0xCC: 1, 0xCD: 1, 0xCE: 1, 0xCF: 1, 0xD0: 2,
    0xD1: 2, 0xD2: 2, 0xD3: 2, 0xD4: 2, 0xD5: 2, 0xD6: 2, 0xD7: 2, 0xD8: 2,
    0xD9: 2, 0xDA: 2, 0xDB: 2, 0xDC: 2, 0xDD: 2, 0xDE: 2, 0xDF: 2, 0xE0: 2,
    0xE1: 2, 0xE2: 2, 0xFA: 4, 0xFB: 4, 0xFC: 3, 0xFD: 3, 0xFE: 2, 0xFF: 2,
}

NX_NOP = 0x00
NX_CONST = 0x01
NX_MOVE = 0x02
NX_ADD = 0x03
NX_SUB = 0x04
NX_MUL = 0x05
NX_XOR = 0x06
NX_AND = 0x07
NX_OR = 0x08
NX_IFZ = 0x09
NX_GOTO = 0x0A
NX_INVOKE = 0x0B
NX_RETURN = 0x0C
NX_SGET = 0x0D
NX_SPUT = 0x0E
NX_IGET = 0x0F
NX_IPUT = 0x10
NX_CSTR = 0x11
NX_RAW = 0x7F


@dataclass
class VmFunction:
    method_idx: int
    key: str
    class_name: str
    name: str
    proto: str
    registers: int
    ins_size: int
    outs_size: int
    bytecode: bytes
    original_insns: bytes
    opcode_stats: dict = field(default_factory=dict)


@dataclass
class VmImage:
    functions: List[VmFunction] = field(default_factory=list)
    blob: bytes = b""


def _u16(insns: bytes, unit: int) -> int:
    off = unit * 2
    if off + 2 > len(insns):
        return 0
    return insns[off] | (insns[off + 1] << 8)


def translate_insns(code: CodeItem) -> tuple[bytes, dict]:
    insns = code.insns
    units = code.insns_size
    out = bytearray()
    stats: dict = {}
    pc = 0
    while pc < units:
        word = _u16(insns, pc)
        op = word & 0xFF
        size = INSN_SIZE.get(op, 1)
        stats[op] = stats.get(op, 0) + 1
        a = (word >> 8) & 0xFF
        if op == 0x00:
            out += bytes([NX_NOP, 0, 0, 0])
        elif op == 0x01:
            out += bytes([NX_MOVE, a & 0x0F, (a >> 4) & 0x0F, 0])
        elif op in (0x0E, 0x0F, 0x10, 0x11):
            out += bytes([NX_RETURN, a, 0, 0])
        elif op == 0x12:
            dest = a & 0x0F
            val = (a >> 4) & 0x0F
            if val & 0x8:
                val -= 16
            out += bytes([NX_CONST, dest, val & 0xFF, 0])
        elif op == 0x13:
            dest = a
            lit = _u16(insns, pc + 1)
            out += bytes([NX_CONST, dest, lit & 0xFF, (lit >> 8) & 0xFF])
        elif op == 0x1A:
            dest = a
            sidx = _u16(insns, pc + 1)
            out += bytes([NX_CSTR, dest, sidx & 0xFF, (sidx >> 8) & 0xFF])
        elif op in (0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D):
            dest = a
            off = _u16(insns, pc + 1)
            out += bytes([NX_IFZ, dest, off & 0xFF, (off >> 8) & 0xFF])
        elif op == 0x28:
            out += bytes([NX_GOTO, a, 0, 0])
        elif 0x90 <= op <= 0x9F:
            dest = a
            bc = _u16(insns, pc + 1)
            src1 = bc & 0xFF
            src2 = (bc >> 8) & 0xFF
            nx = {0x90: NX_ADD, 0x91: NX_SUB, 0x92: NX_MUL, 0x95: NX_AND, 0x96: NX_OR, 0x97: NX_XOR}.get(op, NX_ADD)
            out += bytes([nx, dest, src1, src2])
        elif op in (0x6E, 0x6F, 0x70, 0x71, 0x72):
            argc = a
            method = _u16(insns, pc + 1)
            out += bytes([NX_INVOKE, argc, method & 0xFF, (method >> 8) & 0xFF])
        elif 0x52 <= op <= 0x5F:
            dest = a
            field = _u16(insns, pc + 1)
            nx = NX_IGET if op < 0x59 else NX_IPUT
            out += bytes([nx, dest, field & 0xFF, (field >> 8) & 0xFF])
        elif 0x60 <= op <= 0x6D:
            dest = a
            field = _u16(insns, pc + 1)
            nx = NX_SGET if op < 0x67 else NX_SPUT
            out += bytes([nx, dest, field & 0xFF, (field >> 8) & 0xFF])
        else:
            raw = insns[pc * 2: (pc + size) * 2]
            out += bytes([NX_RAW, len(raw) & 0xFF, 0, 0]) + raw
            pad = (4 - (len(raw) % 4)) % 4
            out += b"\x00" * pad
        pc += size
    return bytes(out), stats


def compile_function(method: EncodedMethod) -> VmFunction:
    assert method.code is not None
    bytecode, stats = translate_insns(method.code)
    proto = method.method.proto
    sig = f"({''.join(proto.parameters)}){proto.return_type}"
    return VmFunction(
        method_idx=method.method.index,
        key=method_key(method),
        class_name=method.method.class_name,
        name=method.method.name,
        proto=sig,
        registers=method.code.registers_size,
        ins_size=method.code.ins_size,
        outs_size=method.code.outs_size,
        bytecode=bytecode,
        original_insns=method.code.insns,
        opcode_stats=stats,
    )


def build_image(functions: List[VmFunction], key: bytes) -> VmImage:
    body = bytearray(b"NXVM1")
    body += struct.pack("<I", len(functions))
    for fn in functions:
        name = fn.key.encode("utf-8")
        body += struct.pack("<I", fn.method_idx)
        body += struct.pack("<H", fn.registers)
        body += struct.pack("<H", fn.ins_size)
        body += struct.pack("<I", len(name))
        body += name
        body += struct.pack("<I", len(fn.bytecode))
        body += fn.bytecode
    blob = encrypt_blob(bytes(body), key)
    return VmImage(functions=functions, blob=blob)
