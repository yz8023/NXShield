from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Optional, Tuple


RES_XML_TYPE_START_NAMESPACE = 0x0100
RES_XML_TYPE_END_NAMESPACE = 0x0101
RES_XML_TYPE_START_ELEMENT = 0x0102
RES_XML_TYPE_END_ELEMENT = 0x0103
RES_XML_TYPE_CDATA = 0x0104
RES_STRING_POOL = 0x0001
RES_XML = 0x0003


def _u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def _u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def decode_utf16_string(data: bytes, off: int) -> Tuple[str, int]:
    if off + 2 > len(data):
        return "", off
    char_count = struct.unpack_from("<H", data, off)[0]
    pos = off + 2
    if char_count & 0x8000:
        high = char_count & 0x7FFF
        if pos + 2 > len(data):
            return "", pos
        low = struct.unpack_from("<H", data, pos)[0]
        char_count = (high << 16) | low
        pos += 2
    end = pos + char_count * 2
    if end > len(data):
        end = len(data)
    raw = data[pos:end]
    try:
        text = raw.decode("utf-16-le", errors="replace").rstrip("\x00")
    except Exception:
        text = ""
    pos = end + 2
    return text, pos


def decode_utf8_string(data: bytes, off: int) -> Tuple[str, int]:
    pos = off

    def read_len(p: int) -> Tuple[int, int]:
        if p >= len(data):
            return 0, p
        b0 = data[p]
        p += 1
        if b0 & 0x80:
            if p >= len(data):
                return b0 & 0x7F, p
            b1 = data[p]
            p += 1
            return ((b0 & 0x7F) << 8) | b1, p
        return b0, p

    utf16_len, pos = read_len(pos)
    utf8_len, pos = read_len(pos)
    end = pos + utf8_len
    if end > len(data):
        end = len(data)
    text = data[pos:end].decode("utf-8", errors="replace")
    if end < len(data) and data[end] == 0:
        end += 1
    return text, end


@dataclass
class ManifestInfo:
    package: str = ""
    version_name: str = ""
    version_code: str = ""
    application_class: str = ""
    activities: List[str] = None
    permissions: List[str] = None
    strings: List[str] = None

    def __post_init__(self):
        if self.activities is None:
            self.activities = []
        if self.permissions is None:
            self.permissions = []
        if self.strings is None:
            self.strings = []


def parse_manifest(data: bytes) -> ManifestInfo:
    info = ManifestInfo()
    if len(data) < 8:
        return info
    if data[:2] == b"<?" or data[:1] == b"<":
        return _parse_text_manifest(data, info)
    if _u16(data, 0) != RES_XML:
        return info
    strings = _parse_string_pool(data)
    info.strings = strings
    pos = 8
    file_size = _u32(data, 4) if len(data) >= 8 else len(data)
    file_size = min(file_size, len(data))
    current_name = ""
    attrs: dict = {}
    while pos + 8 <= file_size:
        chunk_type = _u16(data, pos)
        header_size = _u16(data, pos + 2)
        chunk_size = _u32(data, pos + 4)
        if chunk_size < 8 or pos + chunk_size > file_size:
            break
        if chunk_type == RES_XML_TYPE_START_ELEMENT:
            ns_idx = _u32(data, pos + 16) if header_size >= 20 else 0xFFFFFFFF
            name_idx = _u32(data, pos + 20) if header_size >= 24 else 0xFFFFFFFF
            current_name = _str(strings, name_idx)
            attr_start = _u16(data, pos + 24) if pos + 26 <= file_size else 20
            attr_size = _u16(data, pos + 26) if pos + 28 <= file_size else 20
            attr_count = _u16(data, pos + 28) if pos + 30 <= file_size else 0
            attr_base = pos + 16 + attr_start
            attrs = {}
            for i in range(attr_count):
                aoff = attr_base + i * max(attr_size, 20)
                if aoff + 20 > pos + chunk_size:
                    break
                aname = _u32(data, aoff + 4)
                raw = _u32(data, aoff + 8)
                dtype = _u32(data, aoff + 16)
                key = _str(strings, aname)
                if (dtype >> 24) == 0x03:
                    attrs[key] = _str(strings, raw)
                elif (dtype >> 24) == 0x10:
                    attrs[key] = str(raw)
                else:
                    attrs[key] = _str(strings, raw) or str(raw)
            if current_name == "manifest":
                info.package = attrs.get("package", info.package)
                info.version_name = attrs.get("versionName", info.version_name)
                info.version_code = attrs.get("versionCode", info.version_code)
            elif current_name == "application":
                info.application_class = attrs.get("name", info.application_class)
            elif current_name == "activity":
                n = attrs.get("name", "")
                if n:
                    info.activities.append(n)
            elif current_name == "uses-permission":
                n = attrs.get("name", "")
                if n:
                    info.permissions.append(n)
        pos += chunk_size
    return info


def _str(strings: List[str], idx: int) -> str:
    if idx == 0xFFFFFFFF:
        return ""
    if 0 <= idx < len(strings):
        return strings[idx]
    return ""


def _parse_string_pool(data: bytes) -> List[str]:
    pos = 8
    file_size = min(_u32(data, 4) if len(data) >= 8 else len(data), len(data))
    while pos + 8 <= file_size:
        chunk_type = _u16(data, pos)
        chunk_size = _u32(data, pos + 4)
        if chunk_type == RES_STRING_POOL:
            return _read_pool(data, pos)
        if chunk_size < 8:
            break
        pos += chunk_size
    return []


def _read_pool(data: bytes, off: int) -> List[str]:
    if off + 28 > len(data):
        return []
    string_count = _u32(data, off + 8)
    flags = _u32(data, off + 16)
    strings_start = _u32(data, off + 20)
    utf8 = bool(flags & (1 << 8))
    offsets_off = off + 28
    base = off + strings_start
    out: List[str] = []
    for i in range(string_count):
        ooff = offsets_off + i * 4
        if ooff + 4 > len(data):
            break
        rel = _u32(data, ooff)
        abs_off = base + rel
        if abs_off >= len(data):
            out.append("")
            continue
        if utf8:
            text, _ = decode_utf8_string(data, abs_off)
        else:
            text, _ = decode_utf16_string(data, abs_off)
        out.append(text)
    return out


def _parse_text_manifest(data: bytes, info: ManifestInfo) -> ManifestInfo:
    text = data.decode("utf-8", errors="replace")
    import re

    m = re.search(r'package="([^"]+)"', text)
    if m:
        info.package = m.group(1)
    m = re.search(r'android:versionName="([^"]+)"', text)
    if m:
        info.version_name = m.group(1)
    m = re.search(r'android:versionCode="([^"]+)"', text)
    if m:
        info.version_code = m.group(1)
    m = re.search(r'<application[^>]*android:name="([^"]+)"', text)
    if m:
        info.application_class = m.group(1)
    info.activities = re.findall(r'<activity[^>]*android:name="([^"]+)"', text)
    info.permissions = re.findall(r'<uses-permission[^>]*android:name="([^"]+)"', text)
    return info
