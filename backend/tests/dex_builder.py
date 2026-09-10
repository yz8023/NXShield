"""Build a minimal but structurally valid DEX for offline engine tests.

This is a test fixture only: it emits a single class with a single static
method whose body contains a const-string and a return-void, plus a class
initializer is omitted to stay compact.
"""
from __future__ import annotations

import struct


def uleb128(value: int) -> bytes:
    out = bytearray()
    value &= 0xFFFFFFFF
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def mutf8(s: str) -> bytes:
    out = bytearray()
    for ch in s:
        cp = ord(ch)
        if cp == 0:
            out.extend(b"\xc0\x80")
        elif cp < 0x80:
            out.append(cp)
        elif cp < 0x800:
            out.append(0xC0 | (cp >> 6))
            out.append(0x80 | (cp & 0x3F))
        else:
            out.append(0xE0 | (cp >> 12))
            out.append(0x80 | ((cp >> 6) & 0x3F))
            out.append(0x80 | (cp & 0x3F))
    return bytes(out)


class DexBuilder:
    def __init__(self):
        self.strings: list[str] = []
        self.types: list[int] = []
        self.protos: list[tuple[int, int, tuple]] = []
        self.methods: list[tuple[int, int, int]] = []

    def _intern(self, s: str) -> int:
        if s not in self.strings:
            self.strings.append(s)
        return self.strings.index(s)

    def add_type(self, desc: str) -> int:
        sidx = self._intern(desc)
        if sidx not in self.types:
            self.types.append(sidx)
        return self.types.index(sidx)

    def add_proto(self, ret: str, params: tuple = ()) -> int:
        shorty = "V" if ret == "V" else ""
        ret_idx = self.add_type(ret)
        proto = (self._intern(shorty), ret_idx, tuple(self.add_type(p) for p in params))
        if proto not in self.protos:
            self.protos.append(proto)
        return self.protos.index(proto)

    def add_method(self, cls: str, proto_idx: int, name: str) -> int:
        cls_idx = self.add_type(cls)
        name_idx = self._intern(name)
        m = (cls_idx, proto_idx, name_idx)
        if m not in self.methods:
            self.methods.append(m)
        return self.methods.index(m)

    def build(self) -> bytes:
        # one class: LTest; extends Ljava/lang/Object; with method test()V
        class_idx = self.add_type("LTest;")
        super_idx = self.add_type("Ljava/lang/Object;")
        source_idx = self._intern("Test.java")
        proto_idx = self.add_proto("V", ())
        method_idx = self.add_method("LTest;", proto_idx, "test")
        sensitive_idx = self._intern("hello vip premium secret")
        plain_idx = self._intern("普通字符串")
        method_name_idx = self.methods[method_idx][2]

        header_size = 0x70
        off = header_size
        string_ids_off = off
        off += len(self.strings) * 4
        type_ids_off = off
        off += len(self.types) * 4
        proto_ids_off = off
        off += len(self.protos) * 12
        field_ids_off = off
        method_ids_off = off
        off += len(self.methods) * 8
        class_defs_off = off
        off += 32
        data_off = (off + 3) & ~3

        data = bytearray()

        # --- string data ---
        str_offsets = []
        for s in self.strings:
            str_offsets.append(data_off + len(data))
            payload = mutf8(s)
            utf16_len = len(s)
            data += uleb128(utf16_len) + payload + b"\x00"

        while len(data) % 4:
            data.append(0x00)

        # --- code item (aligned 4) ---
        code_off = data_off + len(data)
        insns = struct.pack("<HH", (0x1A) | (0 << 8), sensitive_idx)
        insns += struct.pack("<H", 0x000E)
        code = struct.pack("<HHHHII", 1, 0, 0, 0, 0, 3) + insns
        code += struct.pack("<H", 0)  # padding (insns_size odd)
        data += code

        while len(data) % 4:
            data.append(0x00)

        # --- class data ---
        class_data_off = data_off + len(data)
        cd = uleb128(0) + uleb128(0) + uleb128(1) + uleb128(0)
        cd += uleb128(method_idx) + uleb128(0x9) + uleb128(code_off)  # public|static
        data += cd

        while len(data) % 4:
            data.append(0x00)

        # --- map list ---
        map_off = data_off + len(data)
        items = [
            (0x0000, 1, 0),
            (0x0001, len(self.strings), string_ids_off),
            (0x0002, len(self.types), type_ids_off),
            (0x0003, len(self.protos), proto_ids_off),
            (0x0005, len(self.methods), method_ids_off),
            (0x0006, 1, class_defs_off),
        ]
        map_list = struct.pack("<I", len(items))
        for t, size, o in items:
            map_list += struct.pack("<HHII", t, 0, size, o)
        data += map_list
        data += struct.pack("<I", 0)

        # --- assemble fixed section ---
        fixed = bytearray()
        for o in str_offsets:
            fixed += struct.pack("<I", o)
        for tidx in self.types:
            fixed += struct.pack("<I", tidx)
        for shorty, ret, params in self.protos:
            if params:
                p_off = 0
            else:
                p_off = 0
            fixed += struct.pack("<III", shorty, ret, p_off)
        for cls_idx, proto_idx2, name_idx in self.methods:
            fixed += struct.pack("<HHI", cls_idx, proto_idx2, name_idx)
        # class def
        fixed += struct.pack(
            "<8I",
            class_idx,
            0x1,
            super_idx,
            0,
            source_idx,
            0,
            class_data_off,
            0,
        )

        file_size = data_off + len(data)
        header = bytearray(header_size)
        header[0:8] = b"dex\n035\x00"
        struct.pack_into("<I", header, 8, 0)  # checksum placeholder
        struct.pack_into("<20s", header, 12, b"0" * 20)  # signature placeholder
        struct.pack_into("<I", header, 32, file_size)
        struct.pack_into("<I", header, 36, header_size)
        struct.pack_into("<I", header, 40, 0x12345678)
        struct.pack_into("<I", header, 44, 0)
        struct.pack_into("<I", header, 48, 0)
        struct.pack_into("<I", header, 52, map_off)
        struct.pack_into("<I", header, 56, len(self.strings))
        struct.pack_into("<I", header, 60, string_ids_off)
        struct.pack_into("<I", header, 64, len(self.types))
        struct.pack_into("<I", header, 68, type_ids_off)
        struct.pack_into("<I", header, 72, len(self.protos))
        struct.pack_into("<I", header, 76, proto_ids_off)
        struct.pack_into("<I", header, 80, 0)
        struct.pack_into("<I", header, 84, 0)
        struct.pack_into("<I", header, 88, len(self.methods))
        struct.pack_into("<I", header, 92, method_ids_off)
        struct.pack_into("<I", header, 96, 1)
        struct.pack_into("<I", header, 100, class_defs_off)
        struct.pack_into("<I", header, 104, len(data))
        struct.pack_into("<I", header, 108, data_off)

        # fill signature + checksum
        import hashlib
        import zlib

        full = bytes(header) + bytes(fixed) + bytes(data)
        sig = hashlib.sha1(full[32:]).digest()
        out = bytearray(full)
        out[12:32] = sig
        checksum = zlib.adler32(bytes(out[12:])) & 0xFFFFFFFF
        struct.pack_into("<I", out, 8, checksum)
        return bytes(out)
