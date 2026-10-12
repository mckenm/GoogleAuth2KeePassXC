#!/usr/bin/env python3
"""Decode Google Authenticator "Export accounts" QR codes for use in KeePassXC.

The export QR holds an ``otpauth-migration://offline?data=...`` URL whose
``data`` is a base64 protobuf. This script decodes it offline into the
accounts' Base32 secrets and standard ``otpauth://`` URIs, and can write a
CSV that KeePassXC's Database > Import > CSV can read.

Each SOURCE can be:
  * an ``otpauth-migration://...`` URL
  * a QR code image (png/jpg/...; needs ``pip install opencv-python``)
  * a text file with one migration URL per line
  * ``-`` to read URLs from stdin

Output contains plaintext 2FA secrets: keep it local, delete it afterwards.
"""
import argparse
import base64
import binascii
import csv
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, quote, urlencode, urlsplit

__version__ = "0.1.0"

MIGRATION_SCHEME = "otpauth-migration"
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp", ".tif", ".tiff"}

ALGORITHMS = {0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512", 4: "MD5"}
DIGITS = {0: 6, 1: 6, 2: 8}
OTP_TYPES = {1: "hotp", 2: "totp"}
DEFAULT_PERIOD = 30  # not part of the migration format


@dataclass(frozen=True)
class Account:
    secret: bytes
    name: str
    issuer: str
    algorithm: str
    digits: int
    kind: str  # "totp", "hotp" or "unknown"
    counter: int

    @property
    def secret_base32(self) -> str:
        return base64.b32encode(self.secret).decode("ascii").rstrip("=")

    def issuer_and_user(self) -> tuple[str, str]:
        """Split a legacy "Issuer:user" name so the issuer isn't repeated."""
        issuer, name = self.issuer, self.name
        if ":" in name:
            prefix, rest = (part.strip() for part in name.split(":", 1))
            issuer = issuer or prefix
            if prefix == issuer:
                name = rest
        return issuer, name

    @property
    def title(self) -> str:
        issuer, name = self.issuer_and_user()
        return issuer or name

    def otpauth_uri(self) -> str:
        if self.kind not in ("totp", "hotp"):
            raise ValueError(f"unsupported OTP type for {self.name!r}")
        issuer, name = self.issuer_and_user()
        label = quote(f"{issuer}:{name}" if issuer else name, safe=":@")
        params = [("secret", self.secret_base32)]
        if issuer:
            params.append(("issuer", issuer))
        params += [("algorithm", self.algorithm), ("digits", str(self.digits))]
        params.append(("period", str(DEFAULT_PERIOD)) if self.kind == "totp"
                      else ("counter", str(self.counter)))
        return f"otpauth://{self.kind}/{label}?{urlencode(params, quote_via=quote)}"


@dataclass(frozen=True)
class Batch:
    accounts: list
    batch_size: int
    batch_index: int
    batch_id: int


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        if pos >= len(buf):
            raise ValueError("truncated data (varint)")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            raise ValueError("malformed varint")


def _fields(buf: bytes):
    """Yield (field_number, value) pairs from a protobuf message."""
    pos = 0
    while pos < len(buf):
        key, pos = _read_varint(buf, pos)
        field, wire = key >> 3, key & 7
        if wire == 0:
            value, pos = _read_varint(buf, pos)
        elif wire == 2:
            length, pos = _read_varint(buf, pos)
            if pos + length > len(buf):
                raise ValueError("truncated data (length-delimited field)")
            value, pos = buf[pos:pos + length], pos + length
        elif wire in (1, 5):
            size = 8 if wire == 1 else 4
            if pos + size > len(buf):
                raise ValueError("truncated data (fixed-width field)")
            value, pos = buf[pos:pos + size], pos + size
        else:
            raise ValueError(f"unsupported protobuf wire type {wire}")
        yield field, value


def _parse_otp_parameters(buf: bytes) -> Account:
    secret, name, issuer = b"", "", ""
    algorithm, digits, kind, counter = 0, 0, 0, 0
    for field, value in _fields(buf):
        if field == 1:
            secret = value
        elif field == 2:
            name = value.decode("utf-8", errors="replace")
        elif field == 3:
            issuer = value.decode("utf-8", errors="replace")
        elif field == 4:
            algorithm = value
        elif field == 5:
            digits = value
        elif field == 6:
            kind = value
        elif field == 7:
            counter = value
    return Account(
        secret=secret,
        name=name,
        issuer=issuer,
        algorithm=ALGORITHMS.get(algorithm, "SHA1"),
        digits=DIGITS.get(digits, 6),
        kind=OTP_TYPES.get(kind, "unknown"),
        counter=counter,
    )


def parse_migration_url(url: str) -> Batch:
    parts = urlsplit(url.strip())
    if parts.scheme != MIGRATION_SCHEME:
        raise ValueError(f"not an {MIGRATION_SCHEME}:// URL")
    values = parse_qs(parts.query).get("data")
    if not values:
        raise ValueError("URL has no 'data' parameter")
    # parse_qs turns a raw '+' into a space; also accept URL-safe base64.
    data = values[0].replace(" ", "+").replace("-", "+").replace("_", "/")
    data += "=" * (-len(data) % 4)
    try:
        payload = base64.b64decode(data, validate=True)
    except binascii.Error as exc:
        raise ValueError(f"'data' is not valid base64: {exc}") from None

    accounts, batch_size, batch_index, batch_id = [], 0, 0, 0
    for field, value in _fields(payload):
        if field == 1:
            accounts.append(_parse_otp_parameters(value))
        elif field == 3:
            batch_size = value
        elif field == 4:
            batch_index = value
        elif field == 5:
            batch_id = value
    return Batch(accounts, batch_size, batch_index, batch_id)


def _image_variants(img):
    import cv2

    padded = cv2.copyMakeBorder(img, 50, 50, 50, 50, cv2.BORDER_CONSTANT, value=(255, 255, 255))
    yield padded
    for scale in (0.5, 0.25, 2.0):
        interp = cv2.INTER_AREA if scale < 1 else cv2.INTER_CUBIC
        yield cv2.resize(padded, None, fx=scale, fy=scale, interpolation=interp)


def _detect_texts(detector, img) -> list:
    ok, texts, _, _ = detector.detectAndDecodeMulti(img)
    found = [t for t in (texts or ()) if t] if ok else []
    if not found:
        text, _, _ = detector.detectAndDecode(img)
        found = [text] if text else []
    return found


def decode_qr_image(path: Path) -> list:
    """Return the text of every QR code found in an image."""
    try:
        import cv2
        import numpy as np
    except ImportError:
        raise SystemExit(
            "Reading QR images needs OpenCV: pip install opencv-python\n"
            "(or scan the QR with another app and pass the otpauth-migration:// text instead)"
        ) from None
    img = cv2.imdecode(np.fromfile(str(path), dtype=np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("not a readable image")
    detectors = [cv2.QRCodeDetector()]
    if hasattr(cv2, "QRCodeDetectorAruco"):
        detectors.insert(0, cv2.QRCodeDetectorAruco())
    for variant in _image_variants(img):
        for detector in detectors:
            found = _detect_texts(detector, variant)
            if found:
                return found
    return []


def _urls_from_text(text: str) -> list:
    prefix = MIGRATION_SCHEME + ":"
    return [line.strip() for line in text.splitlines() if line.strip().lower().startswith(prefix)]


def collect_urls(sources) -> list:
    urls = []
    for src in sources:
        if src.lower().startswith(MIGRATION_SCHEME + ":"):
            urls.append(src)
        elif src == "-":
            urls.extend(_urls_from_text(sys.stdin.read()))
        else:
            path = Path(src)
            if not path.is_file():
                raise SystemExit(f"{src}: not a migration URL or an existing file")
            if path.suffix.lower() in IMAGE_SUFFIXES:
                texts = decode_qr_image(path)
                if not texts:
                    raise SystemExit(f"{src}: no QR code found (try a sharper or larger screenshot)")
                found = [u for text in texts for u in _urls_from_text(text)]
                if not found:
                    raise SystemExit(f"{src}: QR code is not a Google Authenticator export "
                                     f"(expected {MIGRATION_SCHEME}://)")
                urls.extend(found)
            else:
                found = _urls_from_text(path.read_text(encoding="utf-8-sig"))
                if not found:
                    raise SystemExit(f"{src}: no {MIGRATION_SCHEME}:// lines found")
                urls.extend(found)
    return urls


def decode_all(urls) -> list:
    """Decode every URL, dropping duplicates and warning about missing QR codes."""
    accounts, seen = [], set()
    indexes, sizes = {}, {}  # batch_id -> indexes given / QR codes in the export
    for url in urls:
        batch = parse_migration_url(url)
        indexes.setdefault(batch.batch_id, set()).add(batch.batch_index)
        sizes[batch.batch_id] = batch.batch_size
        for acct in batch.accounts:
            if acct not in seen:
                seen.add(acct)
                accounts.append(acct)
    for batch_id, size in sizes.items():
        if size and len(indexes[batch_id]) < size:
            print(f"warning: this export spans {size} QR codes but only "
                  f"{len(indexes[batch_id])} were given; accounts are missing.", file=sys.stderr)
    return accounts


def write_csv(path: Path, accounts, force: bool) -> int:
    """KeePassXC CSV import: tick 'First record has field names' in the dialog."""
    written = 0
    with open(path, "w" if force else "x", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["Group", "Title", "Username", "Password", "URL", "Notes", "TOTP"])
        for acct in accounts:
            if acct.kind != "totp":
                print(f"warning: skipping {acct.title!r} in CSV: KeePassXC only supports TOTP, "
                      f"not {acct.kind.upper()}.", file=sys.stderr)
                continue
            _, user = acct.issuer_and_user()
            writer.writerow(["Google Authenticator", acct.title, user, "", "", "", acct.otpauth_uri()])
            written += 1
    return written


def write_uris(path: Path, accounts, force: bool) -> int:
    uris = []
    for acct in accounts:
        try:
            uris.append(acct.otpauth_uri())
        except ValueError as exc:
            print(f"warning: {exc}", file=sys.stderr)
    with open(path, "w" if force else "x", encoding="utf-8", newline="\n") as fh:
        fh.writelines(uri + "\n" for uri in uris)
    return len(uris)


def print_accounts(accounts) -> None:
    for i, acct in enumerate(accounts, 1):
        issuer, user = acct.issuer_and_user()
        label = f"{issuer} / {user}" if issuer and user else (issuer or user or "(unnamed)")
        print(f"{i:>2}. {label}   [{acct.kind.upper()} {acct.algorithm} {acct.digits} digits]")
        print(f"    secret: {acct.secret_base32}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                     epilog="Output contains plaintext 2FA secrets; delete it after import.")
    parser.add_argument("sources", nargs="+", metavar="SOURCE",
                        help="migration URL, QR image, text file of URLs, or - for stdin")
    parser.add_argument("--csv", metavar="FILE", help="write a KeePassXC-importable CSV")
    parser.add_argument("--uris", metavar="FILE", help="write otpauth:// URIs, one per line")
    parser.add_argument("-q", "--quiet", action="store_true", help="don't print secrets to the console")
    parser.add_argument("--force", action="store_true", help="overwrite existing output files")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):  # don't crash on names the console can't encode
        sys.stdout.reconfigure(errors="replace")
    try:
        accounts = decode_all(collect_urls(args.sources))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if not accounts:
        print("error: no accounts found", file=sys.stderr)
        return 1

    try:
        if args.csv:
            n = write_csv(Path(args.csv), accounts, args.force)
            print(f"Wrote {n} TOTP entries to {args.csv}", file=sys.stderr)
        if args.uris:
            n = write_uris(Path(args.uris), accounts, args.force)
            print(f"Wrote {n} otpauth:// URIs to {args.uris}", file=sys.stderr)
    except FileExistsError as exc:
        print(f"error: {exc.filename} already exists (use --force to overwrite)", file=sys.stderr)
        return 1

    if not args.quiet:
        print_accounts(accounts)
    print(f"Decoded {len(accounts)} account(s). Output holds plaintext secrets: "
          f"delete any files and screenshots when done.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
