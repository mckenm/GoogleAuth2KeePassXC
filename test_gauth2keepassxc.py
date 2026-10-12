import base64
import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from urllib.parse import quote

import gauth2keepassxc as g

# RFC 6238 test secret "12345678901234567890"
RFC_SECRET = b"12345678901234567890"
RFC_BASE32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        out.append(byte | (0x80 if n else 0))
        if not n:
            return bytes(out)


def field_varint(field: int, value: int) -> bytes:
    return varint(field << 3) + varint(value)


def field_bytes(field: int, value: bytes) -> bytes:
    return varint(field << 3 | 2) + varint(len(value)) + value


def otp_params(secret, name, issuer="", algorithm=1, digits=1, kind=2, counter=0) -> bytes:
    body = field_bytes(1, secret) + field_bytes(2, name.encode()) + field_bytes(3, issuer.encode())
    body += field_varint(4, algorithm) + field_varint(5, digits) + field_varint(6, kind)
    if counter:
        body += field_varint(7, counter)
    return body


def migration_url(*params: bytes, batch_size=1, batch_index=0, batch_id=7, quote_data=True) -> str:
    payload = b"".join(field_bytes(1, p) for p in params)
    payload += field_varint(2, 1) + field_varint(3, batch_size)
    payload += field_varint(4, batch_index) + field_varint(5, batch_id)
    data = base64.b64encode(payload).decode()
    return f"otpauth-migration://offline?data={quote(data, safe='') if quote_data else data}"


class DecodeTests(unittest.TestCase):
    def test_decodes_totp_account(self):
        url = migration_url(otp_params(RFC_SECRET, "alice@example.com", "Example"))
        (acct,) = g.parse_migration_url(url).accounts
        self.assertEqual(acct.secret_base32, RFC_BASE32)
        self.assertEqual((acct.name, acct.issuer), ("alice@example.com", "Example"))
        self.assertEqual((acct.kind, acct.algorithm, acct.digits), ("totp", "SHA1", 6))
        self.assertEqual(
            acct.otpauth_uri(),
            f"otpauth://totp/Example:alice@example.com?secret={RFC_BASE32}"
            "&issuer=Example&algorithm=SHA1&digits=6&period=30",
        )

    def test_algorithm_and_digits(self):
        url = migration_url(otp_params(RFC_SECRET, "bob", "X", algorithm=3, digits=2))
        (acct,) = g.parse_migration_url(url).accounts
        self.assertEqual((acct.algorithm, acct.digits), ("SHA512", 8))

    def test_legacy_issuer_prefix_not_repeated(self):
        url = migration_url(otp_params(RFC_SECRET, "GitHub:alice", "GitHub"))
        (acct,) = g.parse_migration_url(url).accounts
        self.assertEqual(acct.issuer_and_user(), ("GitHub", "alice"))
        self.assertIn("otpauth://totp/GitHub:alice?", acct.otpauth_uri())

    def test_issuer_taken_from_name_when_missing(self):
        url = migration_url(otp_params(RFC_SECRET, "GitHub:alice", ""))
        (acct,) = g.parse_migration_url(url).accounts
        self.assertEqual(acct.issuer_and_user(), ("GitHub", "alice"))

    def test_label_is_url_escaped(self):
        url = migration_url(otp_params(RFC_SECRET, "a b&c", "My Co"))
        (acct,) = g.parse_migration_url(url).accounts
        self.assertIn("otpauth://totp/My%20Co:a%20b%26c?", acct.otpauth_uri())
        self.assertIn("issuer=My%20Co", acct.otpauth_uri())

    def test_unescaped_plus_and_slash_in_data(self):
        # Repeated 0xFB bytes make the base64 contain both '+' and '/'.
        secret = bytes([0xFB] * 18)
        for quote_data in (True, False):
            url = migration_url(otp_params(secret, "n", "i"), quote_data=quote_data)
            if not quote_data:
                self.assertTrue("+" in url and "/" in url.split("data=")[1])
            (acct,) = g.parse_migration_url(url).accounts
            self.assertEqual(acct.secret, secret)

    def test_multiple_accounts_and_batch_fields(self):
        url = migration_url(otp_params(RFC_SECRET, "a", "A"), otp_params(b"abcdefghij", "b", "B"),
                            batch_size=3, batch_index=1, batch_id=42)
        batch = g.parse_migration_url(url)
        self.assertEqual([a.name for a in batch.accounts], ["a", "b"])
        self.assertEqual((batch.batch_size, batch.batch_index, batch.batch_id), (3, 1, 42))

    def test_hotp_kept_but_flagged(self):
        url = migration_url(otp_params(RFC_SECRET, "h", "H", kind=1, counter=5))
        (acct,) = g.parse_migration_url(url).accounts
        self.assertEqual(acct.kind, "hotp")
        self.assertTrue(acct.otpauth_uri().startswith("otpauth://hotp/H:h?"))
        self.assertTrue(acct.otpauth_uri().endswith("&counter=5"))

    def test_bad_input_raises(self):
        for bad in ("https://example.com", "otpauth-migration://offline",
                    "otpauth-migration://offline?data=!!!"):
            with self.assertRaises(ValueError, msg=bad):
                g.parse_migration_url(bad)
        good = migration_url(otp_params(RFC_SECRET, "a", "A"))
        data = base64.b64decode(good.split("data=")[1].replace("%2B", "+").replace("%2F", "/").replace("%3D", "="))
        truncated = "otpauth-migration://offline?data=" + quote(base64.b64encode(data[:-3]).decode(), safe="")
        with self.assertRaises(ValueError):
            g.parse_migration_url(truncated)


class OutputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: [p.unlink() for p in self.tmp.iterdir()] and self.tmp.rmdir())
        self.url = migration_url(otp_params(RFC_SECRET, "alice", "Example"),
                                 otp_params(RFC_SECRET, "hotp-acct", "Old", kind=1))

    def run_main(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = g.main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_csv_and_uris(self):
        csv_path, uri_path = self.tmp / "out.csv", self.tmp / "out.txt"
        code, out, err = self.run_main(self.url, "--csv", str(csv_path), "--uris", str(uri_path))
        self.assertEqual(code, 0)
        self.assertIn(RFC_BASE32, out)
        lines = csv_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(lines[0], "Group,Title,Username,Password,URL,Notes,TOTP")
        self.assertEqual(len(lines), 2)  # header + TOTP only; HOTP skipped
        self.assertIn("Example,alice,,,,otpauth://totp/Example:alice?", lines[1])
        self.assertIn("skipping 'Old'", err)
        self.assertEqual(len(uri_path.read_text(encoding="utf-8").splitlines()), 2)

    def test_quiet_hides_secrets(self):
        code, out, _ = self.run_main(self.url, "-q")
        self.assertEqual((code, out), (0, ""))

    def test_refuses_overwrite_without_force(self):
        path = self.tmp / "out.csv"
        path.write_text("keep me")
        code, _, err = self.run_main(self.url, "--csv", str(path))
        self.assertEqual(code, 1)
        self.assertIn("already exists", err)
        self.assertEqual(path.read_text(), "keep me")
        self.assertEqual(self.run_main(self.url, "--csv", str(path), "--force")[0], 0)

    def test_duplicates_and_missing_batch_warning(self):
        url = migration_url(otp_params(RFC_SECRET, "a", "A"), batch_size=2, batch_index=0)
        code, out, err = self.run_main(url, url)
        self.assertEqual(code, 0)
        self.assertEqual(out.count("secret:"), 1)
        self.assertIn("spans 2 QR codes but only 1", err)

    def test_version_flag(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as cm:
            g.main(["--version"])
        self.assertEqual(cm.exception.code, 0)
        self.assertIn(g.__version__, out.getvalue())

    def test_reads_text_file_of_urls(self):
        path = self.tmp / "urls.txt"
        path.write_text(f"# note\n{self.url}\n", encoding="utf-8")
        code, out, _ = self.run_main(str(path))
        self.assertEqual(code, 0)
        self.assertIn("Example / alice", out)


class QrImageTests(unittest.TestCase):
    def test_roundtrip_through_qr_image(self):
        try:
            import cv2
        except ImportError:
            self.skipTest("opencv-python not installed")
        url = migration_url(otp_params(RFC_SECRET, "alice", "Example"))
        qr = cv2.QRCodeEncoder.create().encode(url)
        qr = cv2.resize(qr, None, fx=6, fy=6, interpolation=cv2.INTER_NEAREST)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "export.png"
            ok, buf = cv2.imencode(".png", qr)
            path.write_bytes(buf.tobytes())
            (acct,) = g.decode_all(g.collect_urls([str(path)]))
        self.assertEqual(acct.secret_base32, RFC_BASE32)


if __name__ == "__main__":
    unittest.main()
