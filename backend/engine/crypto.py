from __future__ import annotations

import hashlib
import hmac
import os
import struct


MAGIC = b"NXS1"


def derive_key(password: bytes, salt: bytes, rounds: int = 4096) -> bytes:
    dk = password + salt
    for _ in range(rounds):
        dk = hashlib.sha256(dk).digest()
    return dk


def rolling_xor(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    out = bytearray(len(data))
    klen = len(key)
    acc = 0xA5
    for i, b in enumerate(data):
        k = key[i % klen]
        acc = (acc + k + (i & 0xFF) + 1) & 0xFF
        out[i] = b ^ k ^ (acc & 0xFF)
    return bytes(out)


def encrypt_blob(plain: bytes, key: bytes) -> bytes:
    salt = os.urandom(8)
    dk = derive_key(key, salt)
    xored = rolling_xor(plain, dk)
    digest = hmac.new(dk, xored, hashlib.sha256).digest()[:16]
    return MAGIC + salt + digest + xored


def decrypt_blob(blob: bytes, key: bytes) -> bytes:
    if len(blob) < 28 or blob[:4] != MAGIC:
        raise ValueError("invalid nxshield blob")
    salt = blob[4:12]
    digest = blob[12:28]
    xored = blob[28:]
    dk = derive_key(key, salt)
    check = hmac.new(dk, xored, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(check, digest):
        raise ValueError("blob mac mismatch")
    return rolling_xor(xored, dk)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def pack_u32(n: int) -> bytes:
    return struct.pack("<I", n & 0xFFFFFFFF)


def pack_u16(n: int) -> bytes:
    return struct.pack("<H", n & 0xFFFF)
