from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Pattern, Sequence, Set

from .crypto import rolling_xor
from .dex import DexFile


DEFAULT_KEYWORDS = (
    "vip",
    "premium",
    "pro",
    "license",
    "licence",
    "trial",
    "subscribe",
    "subscription",
    "unlock",
    "paywall",
    "purchase",
    "billing",
    "iap",
    "in-app",
    "membership",
    "member",
    "gold",
    "diamond",
    "secret",
    "password",
    "passwd",
    "token",
    "apikey",
    "api_key",
    "private_key",
    "aes",
    "rsa",
    "encrypt",
    "decrypt",
    "http://",
    "https://",
)

CHINESE_RE = re.compile(r"[\u4e00-\u9fff]")
ASCII_SENSITIVE = re.compile(
    r"(vip|premium|pro\b|license|licence|trial|subscribe|unlock|paywall|"
    r"purchase|billing|\biap\b|membership|secret|password|passwd|token|"
    r"api[_-]?key|private[_-]?key)",
    re.IGNORECASE,
)


@dataclass
class StringHit:
    index: int
    original: str
    reason: str
    encoded: bytes = b""


@dataclass
class StringProtectResult:
    hits: List[StringHit] = field(default_factory=list)
    dex_patched: int = 0
    table: bytes = b""


def contains_cjk(text: str) -> bool:
    return bool(CHINESE_RE.search(text))


def is_sensitive(
    text: str,
    extra_keywords: Sequence[str] | None = None,
    encrypt_all_cjk: bool = True,
) -> str | None:
    if not text or len(text) > 4096:
        return None
    if encrypt_all_cjk and contains_cjk(text):
        return "cjk"
    if ASCII_SENSITIVE.search(text):
        return "keyword"
    if extra_keywords:
        low = text.lower()
        for kw in extra_keywords:
            if kw and kw.lower() in low:
                return "custom"
    return None


def collect_hits(
    dex: DexFile,
    extra_keywords: Sequence[str] | None = None,
    encrypt_all_cjk: bool = True,
    skip_class_descriptors: bool = True,
) -> List[StringHit]:
    skip: Set[int] = set()
    if skip_class_descriptors:
        for t in dex.types:
            skip.add(t.string_idx)
        for m in dex.methods:
            pass
    hits: List[StringHit] = []
    for item in dex.strings:
        if item.index in skip:
            continue
        value = item.value
        if value.startswith("L") and value.endswith(";") and "/" in value:
            continue
        if value.startswith("(") and ")" in value:
            continue
        reason = is_sensitive(value, extra_keywords, encrypt_all_cjk)
        if reason:
            hits.append(StringHit(index=item.index, original=value, reason=reason))
    return hits


def xor_keystream(seed: bytes, index: int) -> bytes:
    mix = seed + index.to_bytes(4, "little")
    out = bytearray()
    acc = 0x5A
    for i, b in enumerate(mix * 8):
        acc = (acc + b + i * 13) & 0xFF
        out.append(acc)
    return bytes(out[:32])


def encode_string(text: str, seed: bytes, index: int) -> bytes:
    raw = text.encode("utf-8")
    key = xor_keystream(seed, index)
    return rolling_xor(raw, key)


def patch_string_payload(dex_raw: bytearray, str_off: int, new_text: str) -> bool:
    from .dex import encode_uleb128, mutf8_encode, uleb128

    utf16_size, pos = uleb128(bytes(dex_raw), str_off)
    start = pos
    end = start
    while end < len(dex_raw) and dex_raw[end] != 0:
        end += 1
    payload = mutf8_encode(new_text)
    old_len = end - start
    if len(payload) > old_len:
        payload = payload[:old_len]
    dex_raw[start:start + len(payload)] = payload
    for i in range(start + len(payload), end):
        dex_raw[i] = 0x20
    return True


def protect_strings(
    dex: DexFile,
    seed: bytes,
    extra_keywords: Sequence[str] | None = None,
    encrypt_all_cjk: bool = True,
    placeholder_mode: str = "keep-length",
) -> StringProtectResult:
    result = StringProtectResult()
    hits = collect_hits(dex, extra_keywords, encrypt_all_cjk)
    table_parts = [b"NXSTR1"]
    for hit in hits:
        encoded = encode_string(hit.original, seed, hit.index)
        hit.encoded = encoded
        if placeholder_mode == "keep-length":
            placeholder = "\u3000" * min(len(hit.original), 64) if contains_cjk(hit.original) else (
                "*" * min(len(hit.original), 64)
            )
            if not placeholder:
                placeholder = "*"
            patch_string_payload(dex.raw, dex.strings[hit.index].offset, placeholder)
            dex.strings[hit.index].value = placeholder
            result.dex_patched += 1
        table_parts.append(
            hit.index.to_bytes(4, "little")
            + len(encoded).to_bytes(4, "little")
            + encoded
        )
        result.hits.append(hit)
    result.table = b"".join(table_parts)
    return result
