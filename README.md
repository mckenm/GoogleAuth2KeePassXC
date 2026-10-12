# GoogleAuth2KeePassXC

Move your Google Authenticator accounts into [KeePassXC](https://keepassxc.org/).

Google Authenticator's **Export accounts** feature produces a QR code that only Google's own apps can read. This tool decodes that QR code **offline** into the plain Base32 secrets and standard `otpauth://` URIs that KeePassXC understands, and can write a CSV you can import in one go.

- Reads a QR screenshot, a raw `otpauth-migration://` URL, or a text file of URLs
- Handles exports split across several QR codes and drops duplicates
- Prints each account's issuer, user, algorithm, digits and Base32 secret
- Writes a KeePassXC-importable CSV (`--csv`) and/or `otpauth://` URIs (`--uris`)
- Pure Python standard library for URL decoding; no network access, ever

> **Your 2FA secrets are as sensitive as your passwords.** The QR code, the tool's output and any CSV/URI files contain them in plaintext. Run this on a machine you trust, avoid cloud sync and chat apps for the screenshot, and delete everything when you're done. See [Security notes](#security-notes).

## Requirements

- Python 3.10 or newer (tested on 3.10, 3.12 and 3.13)
- Only for reading QR **images**: [OpenCV](https://pypi.org/project/opencv-python/)

```bash
pip install opencv-python
```

Skip OpenCV if you pass the `otpauth-migration://` text instead of an image.

## Install

There is nothing to install. Clone the repo (or download `gauth2keepassxc.py`) and run it:

```bash
git clone https://github.com/mckenm/GoogleAuth2KeePassXC.git
cd GoogleAuth2KeePassXC
python gauth2keepassxc.py --version
```

On Windows use `py` instead of `python` if `python` isn't on your PATH.

## Try it first with the bundled example

[`examples/`](examples) holds a **fake** export built from public test secrets, so you can see how the tool works without touching your real accounts.

```bash
python gauth2keepassxc.py examples/sample-export.png
```

```text
Decoded 2 account(s). Output holds plaintext secrets: delete any files and screenshots when done.
 1. Example / alice@example.com   [TOTP SHA1 6 digits]
    secret: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
 2. Demo Co / bob@example.org   [TOTP SHA1 6 digits]
    secret: JBSWY3DPEHPK3PXP
```

(The "Decoded…" line goes to stderr, so it may appear before or after the list.)

The same data is available as text in [`examples/sample-export.txt`](examples/sample-export.txt), and the `--csv` / `--uris` options produce:

```bash
python gauth2keepassxc.py examples/sample-export.txt -q --csv accounts.csv --uris uris.txt
```

```text
otpauth://totp/Example:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&algorithm=SHA1&digits=6&period=30
otpauth://totp/Demo%20Co:bob@example.org?secret=JBSWY3DPEHPK3PXP&issuer=Demo%20Co&algorithm=SHA1&digits=6&period=30
```

## Step by step: migrate your real accounts

### 1. Export from Google Authenticator

1. Open Google Authenticator on your phone.
2. Open the menu (⋮ or your profile icon, depending on the app version) → **Transfer accounts** → **Export accounts**.
3. Select the accounts to move and continue. A QR code appears.
   If you have many accounts, Google splits them over several QR codes; you'll need all of them.

### 2. Get the QR code onto your computer

Take a screenshot of the QR code and copy it to your computer **directly** (USB cable or local transfer). Avoid email, chat apps and cloud photo sync, which would leave a copy of your secrets on someone else's servers.

If the app blocks screenshots, photograph the screen with another device instead, or read the QR with a scanner you trust and save the `otpauth-migration://...` text to a file.

### 3. Decode it

```bash
python gauth2keepassxc.py export.png
```

For several QR codes, pass them all at once so duplicates are removed and missing codes are detected:

```bash
python gauth2keepassxc.py export1.png export2.png
```

### 4. Add the accounts to KeePassXC

**Option A: one account at a time (most reliable)**

1. In KeePassXC, open or create the entry for the site.
2. Right-click the entry → **TOTP** → **Set up TOTP…**
3. Paste the account's Base32 `secret:` from the tool's output into **Secret Key**. Keep the defaults (SHA-1, 6 digits, 30 seconds) unless the tool shows otherwise.
4. Save. Press <kbd>Ctrl</kbd>+<kbd>T</kbd> on the entry to copy the current code.

**Option B: bulk import from CSV**

```bash
python gauth2keepassxc.py export.png -q --csv accounts.csv
```

1. In KeePassXC choose **Database → Import → CSV File…** and select `accounts.csv`.
2. Tick **First record has field names** and check that each column is mapped to the field of the same name (Group, Title, Username, Password, URL, Notes, TOTP).
3. KeePassXC creates a **new** database from the CSV. To move the entries into your main database, open both and use **Database → Merge From Database…**, or copy the entries across.

> **Status:** decoding is covered by the unit tests, but importing the CSV into KeePassXC has not been verified against every KeePassXC version. Try it with one or two accounts first and confirm the codes match; if they don't, use Option A.

### 5. Verify, then clean up

1. For every account, compare the code in KeePassXC with the code in Google Authenticator. They must match.
2. Only then remove the account from Google Authenticator (and re-enroll with each service if you want a fresh secret).
3. Securely delete the screenshot, `accounts.csv`, `uris.txt` and anything else you created.

## Usage reference

```text
python gauth2keepassxc.py [-h] [--csv FILE] [--uris FILE] [-q] [--force] [--version]
                          SOURCE [SOURCE ...]
```

`SOURCE` can be any mix of:

| Source | Meaning |
| --- | --- |
| `otpauth-migration://offline?data=...` | the URL itself (quote it in your shell) |
| `*.png`, `*.jpg`, `*.jpeg`, `*.bmp`, `*.gif`, `*.webp`, `*.tif` | an image containing the QR code (needs OpenCV) |
| any other file | text with one migration URL per line (other lines are ignored) |
| `-` | read migration URLs from stdin |

| Option | Meaning |
| --- | --- |
| `--csv FILE` | write a KeePassXC-importable CSV (TOTP accounts only) |
| `--uris FILE` | write standard `otpauth://` URIs, one per line |
| `-q`, `--quiet` | don't print secrets to the console |
| `--force` | overwrite existing output files (the default is to refuse) |
| `--version` | print the version and exit |

Exit status is `0` on success and `1` when nothing could be decoded or an output file already exists.

## How it works

The export QR contains `otpauth-migration://offline?data=<base64>`. The `data` value is a base64-encoded [Protocol Buffers](https://protobuf.dev/) message with a list of accounts (secret, name, issuer, algorithm, digits, type, counter) plus batch information for multi-QR exports. The tool decodes it with a small built-in protobuf reader, so no third-party protobuf package is needed. The migration format has no "period" field, so TOTP accounts get the standard 30 seconds.

## Limitations

- **HOTP (counter-based) accounts** are decoded and shown, and are written to the `--uris` file, but are left out of the CSV because KeePassXC only supports time-based (TOTP) codes.
- **Non-default periods** (anything but 30 seconds) can't be detected from the export. Check any unusual service by comparing codes (step 5).
- **Steam Guard** and other non-standard authenticators are not part of Google Authenticator exports.
- **Image decoding** depends on OpenCV's QR detector. If an image isn't recognised, try a sharper, larger or tighter-cropped screenshot, or use the text route.

## Troubleshooting

| Problem | Try |
| --- | --- |
| `Reading QR images needs OpenCV` | `pip install opencv-python`, or pass the URL text instead |
| `no QR code found` | a larger, sharper screenshot with the whole QR visible and plain margins |
| `QR code is not a Google Authenticator export` | the QR is something else (e.g. a normal `otpauth://` code); this tool only reads `otpauth-migration://` |
| `warning: this export spans N QR codes but only M were given` | export again and include every QR code in one run |
| `already exists (use --force to overwrite)` | choose another filename or add `--force` |
| Codes don't match Google Authenticator | check the device clock; check the service didn't use a non-default period/digits |

## Security notes

- The tool never touches the network and writes only the files you ask for with `--csv` / `--uris`.
- Output (console, CSV, URI file) and screenshots contain your secrets in plaintext. Treat them like passwords and delete them after use.
- Anyone with an `otpauth-migration://` URL or QR image can generate your codes. Don't paste it into websites, issue trackers or chats, and don't commit it to git (the bundled `.gitignore` excludes typical output and image files outside `examples/`).
- Once your accounts are in KeePassXC, consider regenerating 2FA secrets for important services, since the old secrets existed in Google Authenticator and in your export.

## Development

```bash
python -m unittest -v
```

The tests build synthetic migration payloads, so they need no real accounts. The QR image round-trip test is skipped automatically if OpenCV isn't installed.

Version history is in [HISTORY.md](HISTORY.md). The version number lives in `__version__` at the top of `gauth2keepassxc.py` and follows [Semantic Versioning](https://semver.org/).

## License

Released under the [MIT License](LICENSE). This project is not affiliated with Google or KeePassXC.
