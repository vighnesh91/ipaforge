#IPAForge

IPAForge is a dependency-free Python command-line tool for unpacking, inspecting, editing, and rebuilding iOS `.ipa` archives.

It extracts the complete archive, converts editable Apple plist and localization formats into readable XML, preserves opaque and binary content byte-for-byte, and records every conversion in `ipaforge.yml` so the framework can be rebuilt faithfully.

> **Use responsibly:** IPAForge is intended for interoperability, security research, and legitimate application analysis. Respect applicable laws, licenses, and terms of service.

## Features

- Decode and rebuild standard iOS `.ipa` archives.
- Extract 100% of archive contents; nothing is silently skipped or dropped.
- Convert binary plists with any file extension into readable XML.
- Convert legacy text `.strings` files into editable XML.
- Re-encode converted files into their original native formats during build.
- Preserve Mach-O binaries and Apple proprietary formats such as `.car`, `.nib`, and `.mom`.
- Extract embedded entitlements and provisioning profile information as readable references.
- Generate per-file classification and conversion metadata in `ipaforge.yml`.
- Built-in ad-hoc signing with no external signing utility required.
- Optional real certificate signing using PKCS#12 certificates and provisioning profiles.
- Standard-library only; no third-party Python packages are required.

## Requirements

- Python 3.6 or newer is recommended.
- Python 2.7 and Python 3.2+ are supported by the script's compatibility layer.
- A valid `.ipa` archive containing a `Payload/<AppName>.app` bundle.

## Installation

IPAForge can be used directly as a single Python file:

```bash
python3 ipaforge.py --help
```

To install the `ipaforge` command on your `PATH`:

```bash
python3 ipaforge.py --install
```

To extract the bundled distribution files without installing them:

```bash
python3 ipaforge.py --extract
```

## Quick start

### Decode an IPA

```bash
ipaforge -d MyApp.ipa
```

This creates a framework directory in the current working directory, normally `./MyApp/`.

### Edit the decoded files

Modify readable XML files inside the generated framework. The original archive data and references are kept in `original/`; files that were converted are tracked in `ipaforge.yml`.

### Build a new IPA

```bash
ipaforge -b MyApp
```

The default output is `./MyApp-signed.ipa` in the current working directory.

### Use explicit paths

```bash
ipaforge -d MyApp.ipa decoded-framework
ipaforge -b decoded-framework rebuilt.ipa
```

## Command-line reference

```text
ipaforge -d, --decode INPUT [OUTPUT]
ipaforge -b, --build  INPUT [OUTPUT]
```

| Option | Description |
| --- | --- |
| `-d`, `--decode` | Decode an IPA into an editable framework directory. |
| `-b`, `--build` | Build an IPA from a decoded framework directory. |
| `-f`, `--force` | Overwrite an existing output directory or file. |
| `--no-meta` | Do not write `ipaforge.yml` during decode. |
| `--keep-binary` | Keep all files binary during decode; disable XML conversion. |
| `-c 0-9`, `--compression-level 0-9` | Set ZIP compression level. Default: `9`. |
| `--no-sign` | Build an intentionally unsigned archive. |
| `--entitlements FILE` | Embed entitlements in the built signature. |
| `--p12 FILE` | Sign with a real PKCS#12 developer certificate. |
| `--p12-password PASS` | Password for the PKCS#12 certificate. |
| `--provision FILE` | Embed and use a provisioning profile with `--p12`. |
| `-v`, `--verbose` | Enable debug logging. |
| `-q`, `--quiet` | Print only errors. |
| `--version` | Display the IPAForge version. |
| `-h`, `--help` | Display help. |

On Windows, the mode can be inferred automatically: an `.ipa` input is decoded and a framework directory is built.

## Signing

Build mode signs bundles with the built-in ad-hoc signer by default. It creates CodeDirectory data for Mach-O binaries and fresh `_CodeSignature/CodeResources` files for application bundles.

For installation on stock iOS devices, use a real developer certificate and a compatible provisioning profile:

```bash
ipaforge -b MyApp \
  --p12 developer.p12 \
  --p12-password 'your-password' \
  --provision embedded.mobileprovision
```

To embed custom entitlements:

```bash
ipaforge -b MyApp --entitlements entitlements.plist
```

To intentionally create an unsigned archive:

```bash
ipaforge -b MyApp --no-sign
```

Unsigned archives generally cannot be installed by iOS.

## Decode output structure

A decoded framework commonly contains:

```text
MyApp/
├── Payload/
│   └── MyApp.app/
├── original/       # reference copies of signatures, profiles, and entitlements
├── readable/       # human-readable summaries for opaque formats and binaries
└── ipaforge.yml    # file classifications and conversion metadata
```

The `original/` directory and `ipaforge.yml` are never packaged into the rebuilt IPA.

## File handling

IPAForge classifies extracted files into categories including:

- `native-bplist` — binary property lists converted to XML and rebuilt as binary plists.
- `legacy-strings` — classic `.strings` files converted to XML and rebuilt as UTF-16 text.
- `xml-plist` — existing XML plist files preserved as text.
- `opaque-compiled` — proprietary compiled Apple formats preserved byte-for-byte.
- `native-binary` — Mach-O executables and libraries preserved byte-for-byte.
- `other-binary` — images, audio, DER data, and other resources preserved byte-for-byte.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Successful operation. |
| `1` | Runtime error, such as an invalid archive or signing failure. |
| `2` | Command-line usage error. |
| `141` | Standard output closed early by a pipe consumer. |

## Security notes

IPAForge processes untrusted archive contents. The tool applies defensive limits to individual archive members and total uncompressed archive size, but you should still inspect unknown files in an isolated environment.

Do not distribute or install applications unless you have the legal right to analyze and sign them.

## Version

This README describes IPAForge `1.24.0`.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
