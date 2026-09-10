from __future__ import annotations

import hashlib
import json
import os
import time
import traceback
import zipfile
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .assets import protect_assets
from .crypto import encrypt_blob, sha256_file
from .dex import DexParser
from .jni import generate_jni, generate_report
from .logger import JobLogger
from .manifest import parse_manifest
from .obfuscate import replace_code_with_return, scramble_identifiers, select_methods
from .strings import protect_strings
from .vm import VmFunction, build_image, compile_function
from .zipio import ApkArchive, read_apk, write_apk


ProgressFn = Callable[[int, str, dict], None]


DEFAULT_FEATURES = {
    "extract_methods": True,
    "vm_protect": True,
    "string_protect": True,
    "encrypt_cjk": True,
    "encrypt_vip_keywords": True,
    "asset_encrypt": True,
    "name_obfuscate": False,
    "keep_signature": False,
    "inject_stub_meta": True,
}


@dataclass
class PackOptions:
    extract_methods: bool = True
    vm_protect: bool = True
    string_protect: bool = True
    encrypt_cjk: bool = True
    encrypt_vip_keywords: bool = True
    extra_keywords: List[str] = field(default_factory=list)
    asset_encrypt: bool = True
    name_obfuscate: bool = False
    extract_ratio: float = 0.45
    keep_signature: bool = False
    inject_stub_meta: bool = True
    password: str = "nxshield"

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> "PackOptions":
        data = data or {}
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore
        kwargs = {k: v for k, v in data.items() if k in known}
        if "extra_keywords" in kwargs and isinstance(kwargs["extra_keywords"], str):
            kwargs["extra_keywords"] = [
                x.strip() for x in kwargs["extra_keywords"].replace("\n", ",").split(",") if x.strip()
            ]
        return cls(**kwargs)


class Packer:
    def __init__(self, logger: JobLogger, progress: Optional[ProgressFn] = None):
        self.logger = logger
        self.progress = progress or (lambda *_a, **_k: None)

    def _p(self, pct: int, stage: str, **extra: Any) -> None:
        self.progress(pct, stage, extra)
        self.logger.info(stage, **extra)

    def pack(self, input_path: str, output_path: str, options: PackOptions) -> dict:
        started = time.time()
        summary: Dict[str, Any] = {
            "input": os.path.basename(input_path),
            "output": os.path.basename(output_path),
            "features": asdict(options),
            "dex": [],
            "strings": 0,
            "methods_extracted": 0,
            "assets_encrypted": 0,
            "ok": False,
        }
        try:
            self._p(2, "读取 APK", size=os.path.getsize(input_path))
            if not zipfile.is_zipfile(input_path):
                raise ValueError("输入文件不是有效的 ZIP/APK")
            archive = read_apk(input_path)
            self.logger.info("APK 条目扫描完成", entries=len(archive.entries))

            manifest_raw = archive.get("AndroidManifest.xml")
            manifest = parse_manifest(manifest_raw or b"")
            summary["package"] = manifest.package
            summary["version_name"] = manifest.version_name
            summary["version_code"] = manifest.version_code
            summary["application"] = manifest.application_class
            summary["activities"] = manifest.activities[:20]
            self._p(
                8,
                "解析 AndroidManifest",
                package=manifest.package or "(未知)",
                version=manifest.version_name or "",
            )

            dex_names = archive.dex_files()
            if not dex_names:
                raise ValueError("APK 中未找到 classes*.dex")
            self.logger.info("发现 DEX", files=dex_names)

            key = options.password.encode("utf-8") or b"nxshield"
            seed = hashlib.sha256(key + os.path.basename(input_path).encode()).digest()
            parser = DexParser()
            all_vm_fns: List[VmFunction] = []
            string_total = 0
            extracted_total = 0
            dex_reports: List[dict] = []

            n_dex = len(dex_names)
            for i, name in enumerate(dex_names):
                base = 12 + int(70 * i / max(n_dex, 1))
                data = archive.get(name) or b""
                self._p(base, f"解析 {name}", bytes=len(data))
                dex = parser.parse(data)
                self.logger.info(
                    f"{name} 结构",
                    strings=len(dex.strings),
                    types=len(dex.types),
                    methods=len(dex.methods),
                    classes=len(dex.classes),
                )

                extracted = []
                if options.extract_methods or options.vm_protect:
                    ratio = options.extract_ratio if options.extract_methods else 0.0
                    extracted = select_methods(dex, ratio, seed)
                    self.logger.info(f"{name} 选定抽函数目标", count=len(extracted))
                    if options.vm_protect:
                        for m in extracted:
                            all_vm_fns.append(compile_function(m))
                    for m in extracted:
                        if m.code:
                            replace_code_with_return(dex.raw, m.code.offset, m.code.insns_size)
                    extracted_total += len(extracted)

                str_result = None
                extra_kw = list(options.extra_keywords)
                if options.encrypt_vip_keywords:
                    extra_kw.extend(["vip", "premium", "pro"])
                if options.string_protect:
                    str_result = protect_strings(
                        dex,
                        seed,
                        extra_keywords=extra_kw,
                        encrypt_all_cjk=options.encrypt_cjk,
                    )
                    string_total += len(str_result.hits)
                    self.logger.info(
                        f"{name} 敏感字符串",
                        count=len(str_result.hits),
                        cjk=sum(1 for h in str_result.hits if h.reason == "cjk"),
                        keyword=sum(1 for h in str_result.hits if h.reason == "keyword"),
                    )

                rename = scramble_identifiers(dex, seed, options.name_obfuscate)
                if options.name_obfuscate:
                    self.logger.info(f"{name} 标识符混淆", renamed=len(rename.methods))

                archive.set(name, bytes(dex.raw), compress_type=zipfile.ZIP_STORED)
                dex_reports.append(
                    {
                        "name": name,
                        "classes": len(dex.classes),
                        "methods": len(dex.methods),
                        "strings": len(dex.strings),
                        "extracted": len(extracted),
                        "string_hits": 0 if str_result is None else len(str_result.hits),
                        "renamed": len(rename.methods),
                    }
                )
                if str_result is not None and str_result.table:
                    table_name = f"assets/nxshield/{name}.str"
                    archive.set(table_name, encrypt_blob(str_result.table, key))

            summary["dex"] = dex_reports
            summary["strings"] = string_total
            summary["methods_extracted"] = extracted_total

            if options.vm_protect and all_vm_fns:
                self._p(82, "编译 NX-VM 镜像", functions=len(all_vm_fns))
                image = build_image(all_vm_fns, key)
                archive.set("assets/nxshield/vm.bin", image.blob)
                index = [
                    {
                        "idx": fn.method_idx,
                        "key": fn.key,
                        "class": fn.class_name,
                        "name": fn.name,
                        "proto": fn.proto,
                        "regs": fn.registers,
                        "bc": len(fn.bytecode),
                    }
                    for fn in all_vm_fns
                ]
                archive.set(
                    "assets/nxshield/vm.index.json",
                    encrypt_blob(json.dumps(index, ensure_ascii=False).encode("utf-8"), key),
                )
                summary["vm_functions"] = len(all_vm_fns)
            else:
                summary["vm_functions"] = 0

            if all_vm_fns:
                try:
                    jni_path = output_path + ".jni.c"
                    report_path = output_path + ".report.md"
                    with open(jni_path, "w", encoding="utf-8") as f:
                        f.write(generate_jni(all_vm_fns))
                    with open(report_path, "w", encoding="utf-8") as f:
                        f.write(generate_report(all_vm_fns))
                    summary["jni_source"] = os.path.basename(jni_path)
                    summary["report"] = os.path.basename(report_path)
                    self.logger.info(
                        "生成 NX-VM 桥接源码",
                        jni=os.path.basename(jni_path),
                        report=os.path.basename(report_path),
                        functions=len(all_vm_fns),
                    )
                except Exception as exc:
                    self.logger.warn("生成桥接源码失败", error=str(exc))

            self._p(88, "处理 assets/")
            asset_result = protect_assets(archive, key, options.asset_encrypt)
            summary["assets_encrypted"] = asset_result.encrypted_count
            summary["assets_seen"] = len(asset_result.hits)
            self.logger.info(
                "assets 加密完成",
                encrypted=asset_result.encrypted_count,
                seen=len(asset_result.hits),
            )

            if not options.keep_signature:
                removed = []
                for n in list(archive.names()):
                    if n.startswith("META-INF/") and (
                        n.upper().endswith(".SF")
                        or n.upper().endswith(".RSA")
                        or n.upper().endswith(".DSA")
                        or n.upper().endswith(".EC")
                        or n.endswith("MANIFEST.MF")
                    ):
                        archive.delete(n)
                        removed.append(n)
                if removed:
                    self.logger.info("移除原签名", files=removed)

            if options.inject_stub_meta:
                meta = {
                    "engine": "NXShield",
                    "version": "1.0.0",
                    "job_id": self.logger.job_id,
                    "package": manifest.package,
                    "features": {
                        "extract_methods": options.extract_methods,
                        "vm_protect": options.vm_protect,
                        "string_protect": options.string_protect,
                        "asset_encrypt": options.asset_encrypt,
                        "name_obfuscate": options.name_obfuscate,
                    },
                    "stats": {
                        "methods_extracted": extracted_total,
                        "strings": string_total,
                        "vm_functions": summary.get("vm_functions", 0),
                        "assets_encrypted": asset_result.encrypted_count,
                    },
                }
                archive.set(
                    "assets/nxshield/meta.json",
                    json.dumps(meta, ensure_ascii=False, indent=2).encode("utf-8"),
                )

            self._p(94, "写出加固 APK")
            write_apk(archive, output_path)
            summary["output_size"] = os.path.getsize(output_path)
            summary["output_sha256"] = sha256_file(output_path)
            summary["input_sha256"] = sha256_file(input_path)
            summary["elapsed_ms"] = int((time.time() - started) * 1000)
            summary["ok"] = True
            self._p(100, "加固完成", output=output_path, elapsed_ms=summary["elapsed_ms"])
            return summary
        except Exception as exc:
            summary["ok"] = False
            summary["error"] = str(exc)
            summary["traceback"] = traceback.format_exc()
            self.logger.error("加固失败", error=str(exc))
            raise
