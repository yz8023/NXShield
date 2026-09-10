from __future__ import annotations

import io
import os
import zipfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


STORED = zipfile.ZIP_STORED
DEFLATED = zipfile.ZIP_DEFLATED


@dataclass
class ZipEntry:
    name: str
    data: bytes
    compress_type: int = DEFLATED
    extra: bytes = b""
    comment: bytes = b""
    date_time: Tuple[int, int, int, int, int, int] = (1980, 1, 1, 0, 0, 0)
    create_system: int = 0
    flag_bits: int = 0
    external_attr: int = 0
    is_dir: bool = False


@dataclass
class ApkArchive:
    entries: Dict[str, ZipEntry] = field(default_factory=dict)
    comment: bytes = b""
    source_path: str = ""

    def names(self) -> List[str]:
        return list(self.entries.keys())

    def get(self, name: str) -> Optional[bytes]:
        e = self.entries.get(name)
        return None if e is None else e.data

    def set(self, name: str, data: bytes, compress_type: Optional[int] = None) -> None:
        old = self.entries.get(name)
        ct = compress_type
        if ct is None:
            ct = old.compress_type if old else DEFLATED
        if old:
            old.data = data
            old.compress_type = ct
        else:
            self.entries[name] = ZipEntry(name=name, data=data, compress_type=ct)

    def delete(self, name: str) -> None:
        self.entries.pop(name, None)

    def list_prefix(self, prefix: str) -> List[str]:
        return [n for n in self.entries if n.startswith(prefix) and not n.endswith("/")]

    def dex_files(self) -> List[str]:
        names = [n for n in self.entries if n == "classes.dex" or (
            n.startswith("classes") and n.endswith(".dex")
        )]
        names.sort(key=_dex_sort_key)
        return names


def _dex_sort_key(name: str) -> Tuple[int, str]:
    if name == "classes.dex":
        return (0, name)
    digits = "".join(ch for ch in name[7:] if ch.isdigit())
    try:
        return (int(digits) if digits else 1, name)
    except ValueError:
        return (999, name)


def read_apk(path: str) -> ApkArchive:
    archive = ApkArchive(source_path=path)
    with zipfile.ZipFile(path, "r") as zf:
        archive.comment = zf.comment or b""
        for info in zf.infolist():
            data = b"" if info.is_dir() else zf.read(info.filename)
            archive.entries[info.filename] = ZipEntry(
                name=info.filename,
                data=data,
                compress_type=info.compress_type,
                extra=info.extra or b"",
                comment=info.comment or b"",
                date_time=info.date_time,
                create_system=info.create_system,
                flag_bits=info.flag_bits,
                external_attr=info.external_attr,
                is_dir=info.is_dir(),
            )
    return archive


def write_apk(archive: ApkArchive, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.comment = archive.comment
        for name in archive.names():
            entry = archive.entries[name]
            info = zipfile.ZipInfo(filename=name, date_time=entry.date_time)
            info.compress_type = zipfile.ZIP_STORED if entry.is_dir else entry.compress_type
            info.extra = entry.extra
            info.comment = entry.comment
            info.create_system = entry.create_system
            info.flag_bits = entry.flag_bits
            info.external_attr = entry.external_attr
            zf.writestr(info, entry.data)
    with open(path, "wb") as f:
        f.write(buf.getvalue())
