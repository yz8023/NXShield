from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Set

from .dex import ACC_NATIVE, DexFile, EncodedMethod


KEEP_PREFIXES = (
    "Landroid/",
    "Ljava/",
    "Ljavax/",
    "Lkotlin/",
    "Lkotlinx/",
    "Landroidx/",
    "Lcom/google/",
    "Lcom/android/",
    "Ldalvik/",
    "Lorg/json/",
    "Lorg/xmlpull/",
    "Lkotlin/jvm/",
)

KEEP_METHOD_NAMES = {
    "<init>",
    "<clinit>",
    "onCreate",
    "onStart",
    "onResume",
    "onPause",
    "onStop",
    "onDestroy",
    "onCreateView",
    "attachBaseContext",
    "main",
}


@dataclass
class RenameMap:
    classes: Dict[str, str] = field(default_factory=dict)
    methods: Dict[str, str] = field(default_factory=dict)
    fields: Dict[str, str] = field(default_factory=dict)


def _hash_name(seed: bytes, text: str, prefix: str, length: int = 8) -> str:
    digest = hashlib.sha1(seed + text.encode("utf-8")).hexdigest()
    return prefix + digest[:length]


def should_keep_class(desc: str) -> bool:
    if not desc.startswith("L"):
        return True
    for p in KEEP_PREFIXES:
        if desc.startswith(p):
            return True
    if "R$" in desc or desc.endswith("/R;") or desc.endswith("/BuildConfig;"):
        return True
    return False


def method_key(m: EncodedMethod) -> str:
    proto = m.method.proto
    params = "".join(proto.parameters)
    return f"{m.method.class_name}->{m.method.name}({params}){proto.return_type}"


def is_extractable(m: EncodedMethod) -> bool:
    if m.code is None or m.code.insns_size == 0:
        return False
    if m.access_flags & ACC_NATIVE:
        return False
    if m.method.name in KEEP_METHOD_NAMES:
        return False
    if should_keep_class(m.method.class_name):
        return False
    if m.code.tries_size:
        return False
    if m.code.insns_size < 2:
        return False
    if m.code.insns_size > 2048:
        return False
    return True


def select_methods(dex: DexFile, ratio: float, seed: bytes) -> List[EncodedMethod]:
    candidates = [m for m in dex.all_methods() if is_extractable(m)]
    ranked = sorted(
        candidates,
        key=lambda m: hashlib.sha1(seed + method_key(m).encode()).digest(),
    )
    if ratio >= 1:
        return ranked
    n = max(0, int(len(ranked) * max(0.0, min(1.0, ratio))))
    return ranked[:n]


NOP = 0x00
RETURN_VOID = 0x0E
CONST_STRING = 0x1A
CONST_STRING_JUMBO = 0x1B
INVOKE_VIRTUAL = 0x6E
INVOKE_SUPER = 0x6F
INVOKE_DIRECT = 0x70
INVOKE_STATIC = 0x71
INVOKE_INTERFACE = 0x72


def nop_fill(code_bytes: bytearray) -> None:
    for i in range(0, len(code_bytes), 2):
        code_bytes[i] = NOP
        if i + 1 < len(code_bytes):
            code_bytes[i + 1] = 0


def replace_code_with_return(dex_raw: bytearray, code_off: int, insns_size: int) -> None:
    insns_off = code_off + 16
    total = insns_size * 2
    if insns_off + total > len(dex_raw):
        return
    for i in range(total):
        dex_raw[insns_off + i] = 0
    if total >= 2:
        dex_raw[insns_off] = RETURN_VOID
        dex_raw[insns_off + 1] = 0


def scramble_identifiers(dex: DexFile, seed: bytes, enabled: bool) -> RenameMap:
    mapping = RenameMap()
    if not enabled:
        return mapping
    used: Set[str] = set()
    for item in dex.strings:
        original = item.value
        if not original or original in used:
            continue
        if should_keep_class(original if original.startswith("L") else f"L{original};"):
            continue
        if re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]{2,}", original) and original[0].islower():
            new_name = _hash_name(seed, original, "n")
            if new_name == original:
                continue
            from .strings import patch_string_payload

            patch_string_payload(dex.raw, item.offset, new_name)
            mapping.methods[original] = new_name
            item.value = new_name
            used.add(new_name)
    return mapping
