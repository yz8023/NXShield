from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


NO_INDEX = 0xFFFFFFFF

ACC_PUBLIC = 0x1
ACC_PRIVATE = 0x2
ACC_PROTECTED = 0x4
ACC_STATIC = 0x8
ACC_FINAL = 0x10
ACC_SYNCHRONIZED = 0x20
ACC_NATIVE = 0x100
ACC_ABSTRACT = 0x400
ACC_CONSTRUCTOR = 0x10000


def uleb128(data: bytes, off: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    while True:
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
        if shift > 35:
            raise ValueError("uleb128 overflow")
    return result, off


def sleb128(data: bytes, off: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    b = 0
    while True:
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if (b & 0x80) == 0:
            break
        if shift > 35:
            raise ValueError("sleb128 overflow")
    if b & 0x40:
        result |= -(1 << shift)
    return result, off


def encode_uleb128(value: int) -> bytes:
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


def mutf8_decode(data: bytes, off: int, size: int) -> str:
    end = off + size
    chars: List[str] = []
    i = off
    while i < end:
        c = data[i]
        i += 1
        if c == 0:
            break
        if c < 0x80:
            chars.append(chr(c))
        elif (c & 0xE0) == 0xC0 and i < end:
            d = data[i]
            i += 1
            chars.append(chr(((c & 0x1F) << 6) | (d & 0x3F)))
        elif (c & 0xF0) == 0xE0 and i + 1 < end:
            d = data[i]
            e = data[i + 1]
            i += 2
            chars.append(chr(((c & 0x0F) << 12) | ((d & 0x3F) << 6) | (e & 0x3F)))
        else:
            chars.append("?")
    return "".join(chars)


def mutf8_encode(s: str) -> bytes:
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


@dataclass
class StringItem:
    index: int
    value: str
    offset: int


@dataclass
class TypeItem:
    index: int
    descriptor: str
    string_idx: int


@dataclass
class ProtoItem:
    index: int
    shorty: str
    return_type: str
    parameters: List[str]


@dataclass
class FieldItem:
    index: int
    class_name: str
    type_name: str
    name: str


@dataclass
class MethodItem:
    index: int
    class_name: str
    proto: ProtoItem
    name: str


@dataclass
class EncodedField:
    field: FieldItem
    access_flags: int


@dataclass
class EncodedMethod:
    method: MethodItem
    access_flags: int
    code_off: int
    code: Optional["CodeItem"] = None


@dataclass
class CodeItem:
    registers_size: int
    ins_size: int
    outs_size: int
    tries_size: int
    debug_info_off: int
    insns_size: int
    insns: bytes
    tries_and_handlers: bytes
    offset: int


@dataclass
class ClassDef:
    index: int
    class_name: str
    access_flags: int
    superclass: Optional[str]
    source_file: Optional[str]
    class_data_off: int
    static_fields: List[EncodedField] = field(default_factory=list)
    instance_fields: List[EncodedField] = field(default_factory=list)
    direct_methods: List[EncodedMethod] = field(default_factory=list)
    virtual_methods: List[EncodedMethod] = field(default_factory=list)


@dataclass
class DexFile:
    raw: bytearray
    version: str
    endian_tag: int
    strings: List[StringItem]
    types: List[TypeItem]
    protos: List[ProtoItem]
    fields: List[FieldItem]
    methods: List[MethodItem]
    classes: List[ClassDef]
    map_off: int
    data_off: int
    data_size: int

    def string_at(self, idx: int) -> str:
        if idx < 0 or idx >= len(self.strings):
            return ""
        return self.strings[idx].value

    def type_at(self, idx: int) -> str:
        if idx < 0 or idx >= len(self.types):
            return ""
        return self.types[idx].descriptor

    def all_methods(self) -> List[EncodedMethod]:
        out: List[EncodedMethod] = []
        for cls in self.classes:
            out.extend(cls.direct_methods)
            out.extend(cls.virtual_methods)
        return out


class DexParser:
    def parse(self, data: bytes) -> DexFile:
        if len(data) < 0x70:
            raise ValueError("dex too small")
        if data[0:4] != b"dex\n":
            raise ValueError("not a dex file")
        version = data[4:8].decode("ascii", errors="replace").rstrip("\x00")
        endian = struct.unpack_from("<I", data, 40)[0]
        if endian != 0x12345678:
            raise ValueError("unsupported endian")
        (
            _file_size,
            header_size,
            _endian,
            _link_size,
            _link_off,
            map_off,
            string_ids_size,
            string_ids_off,
            type_ids_size,
            type_ids_off,
            proto_ids_size,
            proto_ids_off,
            field_ids_size,
            field_ids_off,
            method_ids_size,
            method_ids_off,
            class_defs_size,
            class_defs_off,
            data_size,
            data_off,
        ) = struct.unpack_from("<20I", data, 32)

        strings = self._parse_strings(data, string_ids_size, string_ids_off)
        types = self._parse_types(data, type_ids_size, type_ids_off, strings)
        protos = self._parse_protos(data, proto_ids_size, proto_ids_off, strings, types)
        fields = self._parse_fields(data, field_ids_size, field_ids_off, strings, types)
        methods = self._parse_methods(
            data, method_ids_size, method_ids_off, strings, types, protos
        )
        classes = self._parse_classes(
            data, class_defs_size, class_defs_off, strings, types, fields, methods
        )
        return DexFile(
            raw=bytearray(data),
            version=version,
            endian_tag=endian,
            strings=strings,
            types=types,
            protos=protos,
            fields=fields,
            methods=methods,
            classes=classes,
            map_off=map_off,
            data_off=data_off,
            data_size=data_size,
        )

    def _parse_strings(self, data: bytes, size: int, off: int) -> List[StringItem]:
        items: List[StringItem] = []
        for i in range(size):
            str_off = struct.unpack_from("<I", data, off + i * 4)[0]
            utf16_size, pos = uleb128(data, str_off)
            start = pos
            while pos < len(data) and data[pos] != 0:
                pos += 1
            value = mutf8_decode(data, start, pos - start)
            items.append(StringItem(index=i, value=value, offset=str_off))
        return items

    def _parse_types(
        self, data: bytes, size: int, off: int, strings: List[StringItem]
    ) -> List[TypeItem]:
        items: List[TypeItem] = []
        for i in range(size):
            sidx = struct.unpack_from("<I", data, off + i * 4)[0]
            desc = strings[sidx].value if sidx < len(strings) else ""
            items.append(TypeItem(index=i, descriptor=desc, string_idx=sidx))
        return items

    def _parse_protos(
        self,
        data: bytes,
        size: int,
        off: int,
        strings: List[StringItem],
        types: List[TypeItem],
    ) -> List[ProtoItem]:
        items: List[ProtoItem] = []
        for i in range(size):
            shorty_idx, return_idx, params_off = struct.unpack_from("<III", data, off + i * 12)
            shorty = strings[shorty_idx].value if shorty_idx < len(strings) else ""
            ret = types[return_idx].descriptor if return_idx < len(types) else ""
            params: List[str] = []
            if params_off:
                count = struct.unpack_from("<I", data, params_off)[0]
                for j in range(count):
                    tidx = struct.unpack_from("<H", data, params_off + 4 + j * 2)[0]
                    params.append(types[tidx].descriptor if tidx < len(types) else "")
            items.append(ProtoItem(index=i, shorty=shorty, return_type=ret, parameters=params))
        return items

    def _parse_fields(
        self,
        data: bytes,
        size: int,
        off: int,
        strings: List[StringItem],
        types: List[TypeItem],
    ) -> List[FieldItem]:
        items: List[FieldItem] = []
        for i in range(size):
            cls, typ, name = struct.unpack_from("<HHI", data, off + i * 8)
            items.append(
                FieldItem(
                    index=i,
                    class_name=types[cls].descriptor if cls < len(types) else "",
                    type_name=types[typ].descriptor if typ < len(types) else "",
                    name=strings[name].value if name < len(strings) else "",
                )
            )
        return items

    def _parse_methods(
        self,
        data: bytes,
        size: int,
        off: int,
        strings: List[StringItem],
        types: List[TypeItem],
        protos: List[ProtoItem],
    ) -> List[MethodItem]:
        items: List[MethodItem] = []
        for i in range(size):
            cls, proto, name = struct.unpack_from("<HHI", data, off + i * 8)
            proto_item = protos[proto] if proto < len(protos) else ProtoItem(proto, "", "", [])
            items.append(
                MethodItem(
                    index=i,
                    class_name=types[cls].descriptor if cls < len(types) else "",
                    proto=proto_item,
                    name=strings[name].value if name < len(strings) else "",
                )
            )
        return items

    def _parse_classes(
        self,
        data: bytes,
        size: int,
        off: int,
        strings: List[StringItem],
        types: List[TypeItem],
        fields: List[FieldItem],
        methods: List[MethodItem],
    ) -> List[ClassDef]:
        classes: List[ClassDef] = []
        for i in range(size):
            (
                class_idx,
                access_flags,
                superclass_idx,
                _interfaces_off,
                source_file_idx,
                _annotations_off,
                class_data_off,
                _static_values_off,
            ) = struct.unpack_from("<8I", data, off + i * 32)
            class_name = types[class_idx].descriptor if class_idx < len(types) else ""
            super_name = (
                types[superclass_idx].descriptor
                if superclass_idx != NO_INDEX and superclass_idx < len(types)
                else None
            )
            source = (
                strings[source_file_idx].value
                if source_file_idx != NO_INDEX and source_file_idx < len(strings)
                else None
            )
            cls = ClassDef(
                index=i,
                class_name=class_name,
                access_flags=access_flags,
                superclass=super_name,
                source_file=source,
                class_data_off=class_data_off,
            )
            if class_data_off:
                self._parse_class_data(data, cls, class_data_off, fields, methods)
            classes.append(cls)
        return classes

    def _parse_class_data(
        self,
        data: bytes,
        cls: ClassDef,
        off: int,
        fields: List[FieldItem],
        methods: List[MethodItem],
    ) -> None:
        static_fields_size, off = uleb128(data, off)
        instance_fields_size, off = uleb128(data, off)
        direct_methods_size, off = uleb128(data, off)
        virtual_methods_size, off = uleb128(data, off)

        def read_fields(count: int) -> List[EncodedField]:
            nonlocal off
            items: List[EncodedField] = []
            idx = 0
            for _ in range(count):
                diff, off = uleb128(data, off)
                flags, off = uleb128(data, off)
                idx += diff
                field = fields[idx] if idx < len(fields) else FieldItem(idx, "", "", "")
                items.append(EncodedField(field=field, access_flags=flags))
            return items

        def read_methods(count: int) -> List[EncodedMethod]:
            nonlocal off
            items: List[EncodedMethod] = []
            idx = 0
            for _ in range(count):
                diff, off = uleb128(data, off)
                flags, off = uleb128(data, off)
                code_off, off = uleb128(data, off)
                idx += diff
                method = methods[idx] if idx < len(methods) else MethodItem(
                    idx, "", ProtoItem(0, "", "", []), ""
                )
                code = self._parse_code(data, code_off) if code_off else None
                items.append(
                    EncodedMethod(
                        method=method,
                        access_flags=flags,
                        code_off=code_off,
                        code=code,
                    )
                )
            return items

        cls.static_fields = read_fields(static_fields_size)
        cls.instance_fields = read_fields(instance_fields_size)
        cls.direct_methods = read_methods(direct_methods_size)
        cls.virtual_methods = read_methods(virtual_methods_size)

    def _parse_code(self, data: bytes, off: int) -> Optional[CodeItem]:
        if off <= 0 or off + 16 > len(data):
            return None
        registers_size, ins_size, outs_size, tries_size = struct.unpack_from("<HHHH", data, off)
        debug_info_off, insns_size = struct.unpack_from("<II", data, off + 8)
        insns_off = off + 16
        insns_bytes = insns_size * 2
        insns = data[insns_off: insns_off + insns_bytes]
        rest_off = insns_off + insns_bytes
        if insns_size & 1:
            rest_off += 2
        end = rest_off
        if tries_size:
            tries_bytes = tries_size * 8
            end = rest_off + tries_bytes
            if end < len(data):
                handlers_size, pos = uleb128(data, end)
                for _ in range(handlers_size):
                    size, pos = sleb128(data, pos)
                    catch_count = abs(size)
                    for _c in range(catch_count):
                        _, pos = uleb128(data, pos)
                        _, pos = uleb128(data, pos)
                    if size <= 0:
                        _, pos = uleb128(data, pos)
                end = pos
        tries = data[rest_off:end] if end > rest_off else b""
        return CodeItem(
            registers_size=registers_size,
            ins_size=ins_size,
            outs_size=outs_size,
            tries_size=tries_size,
            debug_info_off=debug_info_off,
            insns_size=insns_size,
            insns=bytes(insns),
            tries_and_handlers=bytes(tries),
            offset=off,
        )
