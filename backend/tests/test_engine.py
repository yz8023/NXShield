import io
import os
import sys
import unittest
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from engine.crypto import decrypt_blob, encrypt_blob, rolling_xor  # noqa: E402
from engine.dex import DexParser  # noqa: E402
from engine.logger import JobLogger  # noqa: E402
from engine.packer import PackOptions, Packer  # noqa: E402
from engine.strings import is_sensitive, protect_strings  # noqa: E402
from tests.dex_builder import DexBuilder  # noqa: E402


class CryptoTest(unittest.TestCase):
    def test_roundtrip(self):
        key = b"nxshield"
        data = "敏感字符串 vip premium".encode("utf-8") * 10
        blob = encrypt_blob(data, key)
        self.assertEqual(decrypt_blob(blob, key), data)

    def test_wrong_key_fails(self):
        blob = encrypt_blob(b"hello vip", b"key-a")
        with self.assertRaises(Exception):
            decrypt_blob(blob, b"key-b")

    def test_rolling_xor_roundtrip(self):
        data = bytes(range(256))
        key = b"abc"
        self.assertEqual(rolling_xor(rolling_xor(data, key), key), data)


class SensitiveTest(unittest.TestCase):
    def test_cjk(self):
        self.assertEqual(is_sensitive("会员功能"), "cjk")

    def test_vip(self):
        self.assertEqual(is_sensitive("VIP_ONLY_FLAG"), "keyword")

    def test_premium(self):
        self.assertEqual(is_sensitive("premium_user"), "keyword")

    def test_plain_not_hit(self):
        self.assertIsNone(is_sensitive("com.example.app"))


class DexParserTest(unittest.TestCase):
    def setUp(self):
        self.data = DexBuilder().build()

    def test_parse(self):
        dex = DexParser().parse(self.data)
        self.assertEqual(dex.version, "035")
        self.assertTrue(any(c.class_name == "LTest;" for c in dex.classes))
        self.assertTrue(any(m.name == "test" for m in dex.methods))
        methods = dex.all_methods()
        self.assertEqual(len(methods), 1)
        self.assertIsNotNone(methods[0].code)
        self.assertEqual(methods[0].code.registers_size, 1)

    def test_string_protect_patches(self):
        dex = DexParser().parse(self.data)
        result = protect_strings(dex, b"seed", encrypt_all_cjk=True)
        reasons = {h.reason for h in result.hits}
        self.assertIn("cjk", reasons)
        self.assertIn("keyword", reasons)
        self.assertGreater(result.dex_patched, 0)
        self.assertTrue(result.table.startswith(b"NXSTR1"))


class PackerTest(unittest.TestCase):
    def _make_apk(self) -> bytes:
        dex = DexBuilder().build()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("AndroidManifest.xml", b'<manifest package="com.example.test"/>')
            zf.writestr("classes.dex", dex)
            zf.writestr("assets/config.json", b'{"vip":true,"flag":"premium"}')
            zf.writestr("assets/logo.bin", b"\x01\x02\x03\x04")
            zf.writestr("META-INF/CERT.SF", b"old signature")
        return buf.getvalue()

    def test_full_pack(self):
        tmp = os.path.join("/tmp/opencode", "nxshield-test")
        os.makedirs(tmp, exist_ok=True)
        apk_path = os.path.join(tmp, "input.apk")
        out_path = os.path.join(tmp, "output.apk")
        with open(apk_path, "wb") as f:
            f.write(self._make_apk())

        logger = JobLogger(os.path.join(tmp, "logs"), "testjob")
        packer = Packer(logger)
        opts = PackOptions(password="nxshield", extract_ratio=1.0, keep_signature=False)
        summary = packer.pack(apk_path, out_path, opts)

        self.assertTrue(summary["ok"])
        self.assertGreaterEqual(summary["methods_extracted"], 1)
        self.assertGreaterEqual(summary["vm_functions"], 1)
        self.assertGreaterEqual(summary["strings"], 1)
        self.assertGreaterEqual(summary["assets_encrypted"], 2)
        self.assertGreater(os.path.getsize(out_path), 0)

        with zipfile.ZipFile(out_path) as zf:
            names = zf.namelist()
            self.assertIn("assets/nxshield/vm.bin", names)
            self.assertIn("assets/nxshield/meta.json", names)
            self.assertIn("assets/config.json.nxs", names)
            self.assertNotIn("assets/config.json", names)
            self.assertNotIn("META-INF/CERT.SF", names)

        log_text = logger.read_text()
        self.assertIn("加固完成", log_text)
        self.assertIn("sensitive".upper() if False else "敏感字符串", log_text)


if __name__ == "__main__":
    unittest.main()
