from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from .crypto import encrypt_blob
from .zipio import ApkArchive


SKIP_PREFIXES = (
    "META-INF/",
    "lib/",
    "kotlin/",
    "okhttp3/",
    "org/",
    "assets/nxshield/",
)

SKIP_NAMES = {
    "AndroidManifest.xml",
    "resources.arsc",
    "classes.dex",
}

SKIP_SUFFIXES = (
    ".dex",
    ".so",
    ".arsc",
)


@dataclass
class AssetHit:
    name: str
    size: int
    encrypted: bool
    stored_as: str


@dataclass
class AssetProtectResult:
    hits: List[AssetHit] = field(default_factory=list)
    encrypted_count: int = 0


def should_encrypt_asset(name: str) -> bool:
    if name.endswith("/"):
        return False
    if name in SKIP_NAMES:
        return False
    if name.startswith(SKIP_PREFIXES):
        return False
    if name.startswith("classes") and name.endswith(".dex"):
        return False
    if not name.startswith("assets/"):
        return False
    lower = name.lower()
    if lower.endswith(SKIP_SUFFIXES):
        return False
    return True


def protect_assets(archive: ApkArchive, key: bytes, enabled: bool) -> AssetProtectResult:
    result = AssetProtectResult()
    if not enabled:
        return result
    names = list(archive.list_prefix("assets/"))
    for name in names:
        data = archive.get(name)
        if data is None:
            continue
        if not should_encrypt_asset(name):
            result.hits.append(AssetHit(name=name, size=len(data), encrypted=False, stored_as=name))
            continue
        blob = encrypt_blob(data, key)
        stored = name + ".nxs"
        archive.delete(name)
        archive.set(stored, blob)
        result.hits.append(AssetHit(name=name, size=len(data), encrypted=True, stored_as=stored))
        result.encrypted_count += 1
    return result
