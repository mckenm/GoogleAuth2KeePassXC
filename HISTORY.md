# History

All notable changes to this project are recorded here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-12

First release.

### Added
- Decode Google Authenticator "Export accounts" `otpauth-migration://` URLs into account name, issuer, algorithm, digits, type and Base32 secret, using a built-in protobuf reader (no third-party protobuf dependency).
- Input from a migration URL, a QR code image (via optional OpenCV), a text file of URLs, or stdin.
- Support for exports split across several QR codes, with duplicate removal and a warning when QR codes are missing.
- `--csv FILE` to write a KeePassXC-importable CSV (TOTP accounts; HOTP skipped with a warning).
- `--uris FILE` to write standard `otpauth://` URIs.
- `-q/--quiet` to keep secrets off the console, `--force` to overwrite output files (default is to refuse), `--version`.
- Handling of legacy `Issuer:user` names and of `+`, `/` and URL-escaped characters in the base64 `data` value.
- `examples/` with a fake export (text and QR image) built from public test secrets.
- Unit tests, including a QR image round trip.
- `README.md` with step-by-step migration instructions and `.gitignore` entries that keep CSV, URI and image output out of version control.
- MIT `LICENSE`.

[Unreleased]: https://github.com/mckenm/GoogleAuth2KeePassXC/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mckenm/GoogleAuth2KeePassXC/releases/tag/v0.1.0
