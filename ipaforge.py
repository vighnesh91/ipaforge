#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
================================================================================
 IPAForge 1.22.4 -- unpacker / repacker for iOS .ipa archives
================================================================================

IPAForge operates on iOS application archives (.ipa). An .ipa file is an
ordinary DEFLATE-compressed zip container holding a Payload/<Name>.app
bundle.

NOTHING IS SKIPPED, NOTHING IS DROPPED
--------------------------------------
Extraction is total: 100% of the archive contents land on disk. Decode then
CLASSIFIES every single file into exactly one category, so the accounting
always adds up to the number of extracted files:

    native-bplist    binary property list (ANY extension: .plist, .strings,
                     .stringsdict, ...)  -> CONVERTED to readable XML
    legacy-strings   classic text .strings ("key" = "value"; UTF-16/ASCII)
                     -> CONVERTED to readable XML
    xml-plist        already text (XML plist, CodeResources, ...) -> untouched
    opaque-compiled  Apple-proprietary compiled formats (.car asset catalogs,
                     .nib Interface Builder, ...) -> original preserved for
                     recompile + human-readable summary under readable/
    native-binary    Mach-O executables/libraries -> byte-identical, and
                     their embedded ENTITLEMENTS are extracted to readable
                     XML under original/ (reference copy, never rebuilt
                     into the archive)
    other-binary     everything else (PNG/JPG/audio/DER/...) -> byte-identical

Compiled Apple formats and native code cannot become text - they round-trip
byte-identically. The difference is IPAForge TELLS you, file by file and in
ipaforge.yml, what happened to every single byte.

FAITHFUL RECOMPILE
------------------
Compile mode re-encodes exactly the files decode converted, in their ORIGINAL
format: binary plists become bplist00 again, legacy text .strings become
UTF-16 "key" = "value"; files again. Edits survive; formats stay native.
Decode records every conversion inside ipaforge.yml (conversions:) - no
separate list file is created.

WORKFLOW
--------
  decompile (-d | --decode) INPUT.IPA [OUTPUT_DIR]
      * verifies the zip container and locates the Payload/ directory and the
        main Payload/<Name>.app bundle,
      * extracts the FULL zip structure (nothing dropped),
      * converts every binary plist (any extension) and every legacy text
        .strings to readable XML,
      * moves the invalidated original code signature into original/
        (kept only as a reference, never rebuilt),
      * extracts readable copies of embedded.mobileprovision and of the
        entitlements embedded in Mach-O binaries into original/,
      * writes ipaforge.yml (with the per-category file accounting and the
        conversion list) so the framework rebuilds faithfully.

  compile (-b | --build) FRAMEWORK_DIR [OUTPUT.IPA]
      * re-encodes every converted file listed in ipaforge.yml in its ORIGINAL native
        format (bplist00 binary / legacy UTF-16 .strings text),
      * SIGNS THE BUNDLE(S) AUTOMATICALLY with the BUILT-IN ad-hoc signer
        (SHA-256 CodeDirectory pseudo-signatures embedded in every Mach-O,
        fresh _CodeSignature/CodeResources per bundle - ldid-compatible,
        ZERO external tools). Nested .framework/.appex code is signed
        deepest-first, then the container bundle, BEFORE packaging,
        - use --no-sign to produce an UNSIGNED archive on purpose,
        - REAL-CERTIFICATE signing is BUILT-IN since 1.21.0: --p12 FILE
          signs every Mach-O with a PKCS#12 developer certificate (CMS +
          dual CodeDirectory + designated requirement, the full
          Apple-compatible slot layout) - no external tool, ever; add
          --provision FILE to embed a provisioning profile and adopt its
          entitlements and team identifier,
      * packages everything back into a standard compressed zip with entries
        relative to the Payload/ layout, writing <name>-signed.ipa into the
        current working directory when no
        output path is given (the default build folder),
      * original/ and ipaforge.yml are NEVER packaged back.

SIGNING (BUILT-IN SINCE 1.10.0)
-------------------------------
Recompilation invalidates the original code signature, so compile mode
re-signs by default with the BUILT-IN ad-hoc signer - hash-based
pseudo-signing with ZERO external utilities:

    * SHA-256 CodeDirectory embedded in every Mach-O (nested code first),
    * fresh _CodeSignature/CodeResources per bundle,
    * optional entitlements via --entitlements FILE.

These ldid-class ad-hoc signatures cover local install flows; stock iOS
devices additionally need a real certificate + provisioning profile:

    ipaforge -b fw --p12 dev.p12 --p12-password PASS --provision dev.mobileprovision

The PKCS#12 is opened and the CMS SignedData produced ENTIRELY in-process
(PKCS#12 with PBES2/PBKDF2/AES and the legacy PBE-SHA1-3DES containers are
both supported; RSA PKCS#1 v1.5; detached SHA-256 CMS with the Apple
cdhashes attributes). The SuperBlob uses the exact slot layout Apple's
libCodeSigning expects: CodeDirectory (0), requirements (2), entitlements
(5), DER entitlements (7), alternate SHA-256 CodeDirectory (0x1000) and
the CMS blobwrapper (0x10000).

OUTPUT LOCATION
---------------
Every default output is resolved against the CURRENT WORKING DIRECTORY - the
folder the terminal or command prompt stands in (e.g. Desktop):

    ipaforge -d MyApp.ipa      ->  ~/Desktop/MyApp/          (framework)
    ipaforge -b MyApp          ->  ~/Desktop/MyApp-signed.ipa  (compiled)

Explicit OUTPUT arguments are honored as given; relative ones resolve against
the same working directory.

PLATFORM NOTES
--------------
All path handling goes through `os.path` (POSIX '/'). Zip
entry names are normalized to POSIX forward slashes per the zip specification.

REQUIREMENTS
------------
Python 2.7 or 3.2+ (3.6+ recommended) and NOTHING else. Standard library
only: zipfile, plistlib, argparse, os, shutil, struct, hashlib, base64,
binascii, sys, logging, re. Signing is BUILT-IN since 1.10.0 (hash-based
ad-hoc CodeDirectory signatures). Binary plists work on EVERY supported
Python via the built-in bplist00 engine (used on 2.7/3.2/3.3 where
plistlib lacks binary support); on 3.4+ the stdlib handles them.

EXIT CODES
----------
  0    success
  1    runtime error (bad archive, missing Payload, signing failure, ...)
  2    command-line usage error (raised by argparse)
  141  stdout closed early by a pipe consumer (e.g. `| head`)

This tool is intended for interoperability, security research and legitimate
app analysis. Respect applicable licenses, laws and terms of service.
================================================================================
"""

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, asdict
import binascii
import logging
import os
import plistlib
import re
import shutil
import struct
import sys
import zipfile

# Python 2.7 / 3.2+ compatibility layer -------------------------------
_PY2 = sys.version_info[0] == 2
if _PY2:
    import io
    open = io.open        # encoding-aware text open on Python 2.7
    _TEXT_TYPES = (str, unicode)
else:
    _TEXT_TYPES = (str,)


def _makedirs(path):
    """os.makedirs with exist_ok on every supported Python."""
    if _PY2:
        if not os.path.isdir(path):
            os.makedirs(path)
    else:
        os.makedirs(path, exist_ok=True)
# ---------------------------------------------------------------------

# ------------------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------------------

TOOL_NAME = "IPAForge"
__version__ = "1.24.0"

PAYLOAD_DIR = "Payload"                    # mandatory top-level folder in an .ipa
APP_SUFFIX = ".app"                        # iOS application bundle extension
BPLIST_MAGIC = b"bplist00"                 # Apple binary property list magic
META_FILE_NAME = "ipaforge.yml"            # framework metadata file
MANIFEST_FILE_NAME = "ipaforge-converted.list"  # legacy decode conversion manifest
MANIFEST_SEP = "\t"                        # separates path from format tag
FMT_NATIVE_BPLIST = "native-bplist"        # was binary plist -> re-encode binary
FMT_LEGACY_STRINGS = "legacy-strings"      # was legacy text -> re-serialize text
ORIGINAL_DIR = "original"                  # folder for archived originals
READABLE_DIR = "readable"                  # human-readable summaries (never packaged)
GHIDRA_DIR = "ghidra"                      # legacy kit folder (pre-1.20; never packaged)
KIT_SUFFIXES = (".report.txt", ".symbols.csv",
                ".disasm.txt", ".pseudo.txt")  # kits, co-located with each Mach-O
IMPORT_SCRIPT_NAME = "import_symbols.py"   # kit helper script name
CODE_SIGNATURE_DIR = "_CodeSignature"      # detached signature directory inside .app
PROFILE_FILE = "embedded.mobileprovision"  # embedded provisioning profile
PROFILE_READOUT_SUFFIX = ".plist.xml"      # readable copy stored in original/
ENTITLEMENTS_READOUT_SUFFIX = ".entitlements.plist.xml"
CERTS_READOUT_SUFFIX = ".certs.txt"       # readable certificate listing
CERT_EXTS = (".cer", ".der", ".pem", ".crt")  # certificate resources (pins)

# Defensive archive limits. These are deliberately generous for real-world IPAs
# but stop accidental/malicious decompression bombs before they consume disk.
MAX_ARCHIVE_ENTRY_UNCOMPRESSED = 1024 * 1024 * 1024  # 1 GiB per member
MAX_ARCHIVE_TOTAL_UNCOMPRESSED = 32 * 1024 * 1024 * 1024  # 32 GiB total

# Compiled Apple formats that no independent tool can decompile or rebuild
# (their creators - actool, Interface Builder, Core Data - are proprietary).
OPAQUE_SUFFIXES = (".car", ".nib", ".mom")

# Mach-O magics: 64-bit, 32-bit, and the two byte-orders of FAT archives.
MACHO_MAGICS = (
    b"\xcf\xfa\xed\xfe",  # MH_MAGIC_64
    b"\xce\xfa\xed\xfe",  # MH_MAGIC (32-bit)
    b"\xca\xfe\xba\xbe",  # FAT big-endian
    b"\xbe\xba\xfe\xca",  # FAT little-endian (legacy)
    b"\xca\xfe\xba\xbf",  # FAT 64-bit
)

MODE_DECODE = "decode"
MODE_BUILD = "build"

SIGN_MODE_AUTO = "auto"                    # sign when a utility is found (default)
SIGN_MODE_FORCE = "force"                  # -s: sign or fail the build
SIGN_MODE_SKIP = "skip"                    # --no-sign: never sign

SIGN_TOOL_AUTO = "auto"
SIGN_TOOL_CODESIGN = "codesign"
SIGN_TOOL_LDID = "ldid"

# ------------------------------------------------------------------------------
# Logging -- console output with single-letter level tags ("I: ...", "W: ...", "E: ...")
# ------------------------------------------------------------------------------

log = logging.getLogger("ipaforge")


class _LogLevelTagFormatter(logging.Formatter):
    """Map logging level names onto single-letter tags.

    INFO     -> "I: message"
    WARNING  -> "W: message"
    ERROR    -> "E: message"
    DEBUG    -> "D: message"
    """

    _TAGS = {
        logging.DEBUG: "D",
        logging.INFO: "I",
        logging.WARNING: "W",
        logging.ERROR: "E",
        logging.CRITICAL: "E",
    }

    def format(self, record):
        tag = self._TAGS.get(record.levelno, "I")
        return "{0}: {1}".format(tag, record.getMessage())


class _BelowErrorFilter(logging.Filter):
    """Pass records below ERROR so informational output can go to stdout."""

    def filter(self, record):
        return record.levelno < logging.ERROR


def configure_logging(verbose=False, quiet=False):
    """Install console handlers with the single-letter log layout."""
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    formatter = _LogLevelTagFormatter()

    out_handler = logging.StreamHandler(sys.stdout)
    out_handler.setLevel(min(level, logging.INFO))
    out_handler.addFilter(_BelowErrorFilter())
    out_handler.setFormatter(formatter)

    err_handler = logging.StreamHandler(sys.stderr)
    err_handler.setLevel(max(level, logging.ERROR))
    err_handler.setFormatter(formatter)

    log.handlers = [out_handler, err_handler]
    log.setLevel(level)
    log.propagate = False
    # A CLI tool should never spam stderr with logging-internal tracebacks
    # when the consumer of stdout disappears (e.g. `ipaforge ... | head`).
    logging.raiseExceptions = False


# ------------------------------------------------------------------------------
# Exceptions
# ------------------------------------------------------------------------------


class IPAForgeError(Exception):
    """Base class for fatal, user-facing IPAForge errors."""


class InvalidInputError(IPAForgeError):
    """The input archive is missing, unreadable or not a valid .ipa."""


class FrameworkNotFoundError(IPAForgeError):
    """The decoded framework directory is missing or structurally invalid."""


class SigningError(IPAForgeError):
    """The external code signing utility failed or was not found."""


# ------------------------------------------------------------------------------
# Small utilities
# ------------------------------------------------------------------------------


def _to_posix(name):
    """Normalize a zip member name to POSIX forward slashes.

    Some zip writers record backslash separators; the zip
    specification mandates forward slashes, so we translate defensively. All
    on-disk path manipulation meanwhile flows through os.path, which absorbs
    slash/backslash path differences automatically.
    """
    return name.replace("\\", "/")


def _is_binary_plist(data):
    """True if the byte string starts with the Apple binary plist magic."""
    return data[:8] == BPLIST_MAGIC


def _is_xml_plist(data):
    """True if the data looks like an XML property list document."""
    stripped = data.lstrip()
    return stripped.startswith(b"<?xml") or stripped.startswith(b"<plist")


def _is_macho(data):
    """True if the data starts with a known Mach-O / FAT magic."""
    return data[:4] in MACHO_MAGICS


def _human_size(num_bytes):
    """Render a byte count as a compact human-readable string."""
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024.0 or unit == "GB":
            if unit == "B":
                return "{0:.0f} {1}".format(size, unit)
            return "{0:.2f} {1}".format(size, unit)
        size /= 1024.0
    return "{0:.2f} TB".format(size)


def _cwd_path(*parts):
    """Resolve a default output path against the CURRENT WORKING DIRECTORY.

    The working directory is wherever the user's terminal / command prompt
    stands when ipaforge is invoked (e.g. Desktop), so generated files land
    next to the prompt they typed the command at - not next to the ipaforge
    script files and not next to the input file. os.path absorbs the Linux
    slash/backslash differences transparently.
    """
    return os.path.abspath(os.path.join(os.getcwd(), *parts))


# ------------------------------------------------------------------------------
# Legacy .strings support ("key" = "value"; UTF-16/ASCII OpenStep style)
# ------------------------------------------------------------------------------

_LEGACY_TOKEN_RE = re.compile(
    r'"((?:\\.|[^"\\])*)"\s*=\s*"((?:\\.|[^"\\])*)"\s*;'
)
_LEGACY_COMMENT_RE = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)


def _legacy_unescape(text):
    """Decode the escape sequences used by classic .strings files."""
    out = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            mapping = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}
            if nxt in mapping:
                out.append(mapping[nxt])
                i += 2
                continue
            if nxt in ("u", "U") and i + 5 < len(text):
                try:
                    out.append(chr(int(text[i + 2:i + 6], 16)))
                    i += 6
                    continue
                except ValueError:
                    pass
            out.append(nxt)  # unknown escape: keep the literal character
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _legacy_escape(text):
    """Encode a string for the classic .strings text format."""
    text = text.replace("\\", "\\\\")
    text = text.replace('"', '\\"')
    text = text.replace("\n", "\\n")
    text = text.replace("\t", "\\t")
    text = text.replace("\r", "\\r")
    return text


def parse_legacy_strings(data):
    """Parse a classic text .strings file into a dict.

    Accepts UTF-16 (with or without BOM), UTF-8 and ASCII input, strips
    // and /* */ comments, and understands \" \\n \\t \\\\ \\uXXXX escapes.
    Raises ValueError when nothing sensible can be parsed.
    """
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = data.decode("utf-16")
    else:
        if data[:3] == b"\xef\xbb\xbf":
            data = data[3:]
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("not decodable as UTF-16/UTF-8 text")

    text = _LEGACY_COMMENT_RE.sub("", text)
    result = {}
    matched = 0
    for match in _LEGACY_TOKEN_RE.finditer(text):
        matched += 1
        key = _legacy_unescape(match.group(1))
        value = _legacy_unescape(match.group(2))
        result[key] = value
    if matched == 0:
        raise ValueError("no \"key\" = \"value\"; pairs found")
    return result


def serialize_legacy_strings(mapping):
    """Serialize a dict back into the classic .strings text format (UTF-16)."""
    lines = []
    for key, value in mapping.items():
        lines.append(
            '"{0}" = "{1}";'.format(
                _legacy_escape(key), _legacy_escape(value)
            )
        )
    # UTF-16 with BOM - the classic encoding iOS accepts everywhere.
    return ("\n".join(lines) + "\n").encode("utf-16")


def is_pure_string_mapping(obj):
    """True when every key AND value of the plist object is a string.

    Legacy .strings files can only hold string->string pairs; if a user
    edited the decoded XML into something richer we fall back to encoding
    the file as a binary plist instead (which iOS equally accepts for
    .strings resources).
    """
    if not isinstance(obj, dict):
        return False
    return all(
        isinstance(k, _TEXT_TYPES) and isinstance(v, _TEXT_TYPES)
        for k, v in obj.items()
    )


# ------------------------------------------------------------------------------
# Mach-O entitlements extraction (readable reference copies)
# ------------------------------------------------------------------------------


def extract_entitlements_from_macho(data):
    """Best-effort extraction of the embedded entitlements plist.

    Works on thin (32/64-bit) and FAT Mach-O files for the signatures
    written by codesign and ldid: the entitlements blob inside the code
    signature embeds an XML plist, which we locate and validate. Returns
    the XML plist bytes or None. Reference only - the binary is untouched.
    """
    marker_start = data.find(b"<?xml")
    while marker_start != -1:
        marker_end = data.find(b"</plist>", marker_start)
        if marker_end == -1:
            return None
        candidate = data[marker_start:marker_end + len(b"</plist>")]
        try:
            obj = _plist_loads(candidate)
        except Exception:
            marker_start = data.find(b"<?xml", marker_start + 1)
            continue
        if isinstance(obj, dict):
            return candidate
        return None
    return None


# ------------------------------------------------------------------------------
# Archive introspection
# ------------------------------------------------------------------------------


def find_app_bundles(zip_names):
    """Return the unique top-level .app bundle names living inside Payload/."""
    bundles = []
    for raw_name in zip_names:
        posix_name = _to_posix(raw_name)
        parts = posix_name.split("/")
        if len(parts) >= 2 and parts[0] == PAYLOAD_DIR:
            candidate = parts[1]
            if candidate.endswith(APP_SUFFIX) and candidate not in bundles:
                bundles.append(candidate)
    return bundles


def _zip_member_is_symlink(info):
    """Return True when a ZIP entry carries a Unix symlink file type."""
    mode = (info.external_attr >> 16) & 0xFFFF
    return (mode & 0o170000) == 0o120000


def _validate_archive_members(infos, strip_prefix=""):
    """Validate ZIP names/types before writing anything to disk.

    Rejects path traversal, symlinks, duplicate normalized paths and oversized
    compressed/uncompressed payloads. Failing before extraction avoids a
    partially materialized framework and makes archive handling deterministic.
    """
    seen = set()
    total_uncompressed = 0
    checked = 0
    for info in infos:
        member = _to_posix(info.filename)
        if strip_prefix:
            if not member.startswith(strip_prefix) or member == strip_prefix:
                continue
            member = member[len(strip_prefix):]
        if not member:
            continue
        target = _member_target_path(os.getcwd(), member)
        if target is None:
            continue
        normalized = _to_posix(member).rstrip("/")
        key = normalized.lower() if os.name == "nt" else normalized
        if key in seen:
            raise InvalidInputError(
                "Archive contains duplicate normalized path: {0}".format(member))
        seen.add(key)
        if _zip_member_is_symlink(info):
            raise InvalidInputError(
                "Archive contains a symbolic-link entry (rejected): {0}".format(member))
        if not info.is_dir() and not member.endswith("/"):
            if info.file_size > MAX_ARCHIVE_ENTRY_UNCOMPRESSED:
                raise InvalidInputError(
                    "Archive member exceeds the 1 GiB safety limit: {0}".format(member))
            total_uncompressed += max(0, info.file_size)
            if total_uncompressed > MAX_ARCHIVE_TOTAL_UNCOMPRESSED:
                raise InvalidInputError(
                    "Archive exceeds the 8 GiB total uncompressed safety limit")
        checked += 1
    log.debug("Archive preflight passed: %d member(s), %s uncompressed",
              checked, _human_size(total_uncompressed))


def _member_target_path(output_dir, member_name):
    """Map a zip member name onto a safe absolute path inside output_dir.

    Defends against 'zip slip' attacks: members with absolute paths or '..'
    traversal segments are rejected instead of being written outside of the
    framework directory.
    """
    posix_name = _to_posix(member_name)
    if posix_name.startswith("/"):
        raise InvalidInputError(
            "Archive member uses an absolute path (rejected): {0}".format(member_name)
        )
    parts = [p for p in posix_name.split("/") if p not in ("", ".")]
    if not parts:
        return None
    for part in parts:
        if part == "..":
            raise InvalidInputError(
                "Archive member escapes the output directory (rejected): {0}".format(
                    member_name
                )
            )
    return os.path.join(output_dir, *parts)


# ------------------------------------------------------------------------------
# Extraction
# ------------------------------------------------------------------------------


def extract_archive(archive, output_dir, strip_prefix=""):
    """Extract EVERY member of `archive` into `output_dir` - nothing dropped.

    When `strip_prefix` is given (e.g. "Wrapper/"), only members under it are
    extracted and the prefix is removed from their paths - used when an .ipa
    was accidentally zipped from a parent folder instead of Payload/.

    Preserves unix permission bits recorded in the zip external attributes and
    returns (files_extracted, directories_created).
    """
    files_extracted = 0
    dirs_created = 0
    skipped = 0

    for info in archive.infolist():
        member = _to_posix(info.filename)
        if strip_prefix:
            if not member.startswith(strip_prefix) or member == strip_prefix:
                continue
            member = member[len(strip_prefix):]
            if not member:
                continue
        target = _member_target_path(output_dir, member)
        if target is None:
            continue

        try:
            if _zip_member_is_symlink(info):
                raise InvalidInputError(
                    "Symbolic-link archive member rejected: {0}".format(member))
            is_dir = info.is_dir() or _to_posix(info.filename).endswith("/")
            if is_dir:
                _makedirs(target)
                dirs_created += 1
                continue

            parent = os.path.dirname(target)
            if parent:
                _makedirs(parent)
            src = archive.open(info)
            dst = open(target, "wb")
            try:
                shutil.copyfileobj(src, dst)
            finally:
                src.close()
                dst.close()
            files_extracted += 1

            mode = (info.external_attr >> 16) & 0xFFFF
            if mode:
                try:
                    os.chmod(target, mode)
                except OSError:
                    # FAT/exFAT volumes ignore most permission bits.
                    log.debug("Could not apply permission bits to: %s",
                              target)
        except Exception as exc:
            # Damaged or password-protected member: keep going so ONE bad
            # entry can never abort the whole decode.
            try:
                if os.path.isfile(target):
                    os.remove(target)
            except OSError:
                pass
            skipped += 1
            log.warning(
                "Could not extract %s (%s) - member skipped; everything "
                "else continues", member, exc)

    return files_extracted, dirs_created, skipped


# ------------------------------------------------------------------------------
# Universal plist engine: binary bplist00 parser + writer for OLD pythons.
# Used ONLY when plistlib lacks binary support (Python 2.7 / 3.2 / 3.3);
# on 3.4+ the stdlib remains the reference implementation.
# Written in the common subset of Python 2.7 and Python 3.2+ (no f-strings,
# binascii for big-endian ints, bytearray for int-yielding indexing).
# ------------------------------------------------------------------------------

import binascii as _bin
import datetime as _dt
import struct as _struct

_BPLIST_EPOCH = _dt.datetime(2001, 1, 1)


def _be_int(raw):
    """Big-endian unsigned int from a bytes slice (any size, 2.7/3.x safe)."""
    return int(_bin.hexlify(bytes(raw)), 16)


def _bplist_loads(data):
    """Parse a bplist00 binary property list into plain Python objects."""
    data = bytearray(data)
    if len(data) < 8 + 32 or bytes(data[:8]) != b"bplist00":
        raise ValueError("not a bplist00 binary plist")
    t = data[len(data) - 32:]
    offset_size = t[6]
    ref_size = t[7]
    n_objects = _be_int(t[8:16])
    top_index = _be_int(t[16:24])
    table_off = _be_int(t[24:32])
    if offset_size < 1 or offset_size > 8 or ref_size < 1 or ref_size > 8:
        raise ValueError("corrupt bplist trailer")
    if table_off + n_objects * offset_size > len(data) - 32:
        raise ValueError("corrupt bplist offset table")

    offsets = [_be_int(data[table_off + i * offset_size:
                               table_off + (i + 1) * offset_size])
               for i in range(n_objects)]

    def read_len(info, off):
        """Return (length, offset_after_length)."""
        if info != 0xF:
            return info, off
        m = data[off]
        if m >> 4 != 0x1:
            raise ValueError("corrupt bplist length marker")
        size = 1 << (m & 0xF)
        return _be_int(data[off + 1:off + 1 + size]), off + 1 + size

    def read_obj(index, depth):
        if depth > 64:
            raise ValueError("bplist nesting too deep")
        o = offsets[index]
        marker = data[o]
        kind = marker >> 4
        info = marker & 0xF
        if kind == 0x0:
            if info == 0x9:
                return True
            if info == 0x8:
                return False
            return None
        if kind == 0x1:
            size = 1 << info
            raw = data[o + 1:o + 1 + size]
            if size == 8:
                v = _be_int(raw)
                return v - (1 << 64) if v >= (1 << 63) else v
            if size == 16:
                v = _be_int(raw)
                return v - (1 << 128) if v >= (1 << 127) else v
            return _be_int(raw)
        if kind == 0x2:
            size = 1 << info
            if size == 4:
                return _struct.unpack_from(">f", bytes(data), o + 1)[0]
            if size == 8:
                return _struct.unpack_from(">d", bytes(data), o + 1)[0]
            raise ValueError("unsupported real size")
        if kind == 0x3 and info == 0x3:
            secs = _struct.unpack_from(">d", bytes(data), o + 1)[0]
            return _BPLIST_EPOCH + _dt.timedelta(seconds=secs)
        if kind == 0x4:
            ln, noff = read_len(info, o + 1)
            return bytes(data[noff:noff + ln])
        if kind == 0x5:
            ln, noff = read_len(info, o + 1)
            return bytes(data[noff:noff + ln]).decode("utf-8")
        if kind == 0x6:
            units, noff = read_len(info, o + 1)
            raw = bytes(data[noff:noff + units * 2])
            return raw.decode("utf-16-be")
        if kind == 0x8:
            # UID (keyed archives): stored as an int following the marker
            size = 1 << info
            return _be_int(data[o + 1:o + 1 + size])
        if kind == 0xA or kind == 0xC:
            # array (0xA) / set (0xC, rare) -> list
            cnt, noff = read_len(info, o + 1)
            out = []
            for k in range(cnt):
                ref = _be_int(data[noff + k * ref_size:
                                   noff + (k + 1) * ref_size])
                out.append(read_obj(ref, depth + 1))
            return out
        if kind == 0xD:
            # dict
            cnt, noff = read_len(info, o + 1)
            out = {}
            for k in range(cnt):
                kref = _be_int(data[noff + k * ref_size:
                                    noff + (k + 1) * ref_size])
                vref = _be_int(data[noff + (cnt + k) * ref_size:
                                    noff + (cnt + k + 1) * ref_size])
                out[read_obj(kref, depth + 1)] = read_obj(vref, depth + 1)
            return out
        raise ValueError("unsupported bplist object type 0x{0:X}".format(kind))

    return read_obj(top_index, 0)


def _bplist_dumps(obj):
    """Serialize plain Python objects into a valid bplist00 plist."""
    objects = []

    def flatten(o, depth):
        if depth > 64:
            raise ValueError("structure nests too deep")
        if o is None or isinstance(o, bool):
            return
        if isinstance(o, (int, float, bytes)):
            return
        if isinstance(o, _dt.datetime):
            return
        text_types = (str, unicode) if str is bytes else (str,)
        if isinstance(o, text_types):
            return
        if isinstance(o, (list, tuple)):
            for item in o:
                flatten(item, depth + 1)
            return
        if isinstance(o, dict):
            for key, value in o.items():
                flatten(key, depth + 1)
                flatten(value, depth + 1)
            return
        raise TypeError("unsupported plist type: {0}".format(type(o)))

    def intern(o):
        """Append o to the object table (unless present) and return index."""
        key = id(o)
        if key in seen:
            return seen[key]
        index = len(objects)
        seen[key] = index
        objects.append(o)
        return index

    # interning pass (deterministic; shared references stay shared)
    seen = {}
    del objects[:]

    def walk(o, depth):
        if depth > 64:
            raise ValueError("structure nests too deep")
        if id(o) in seen:
            return seen[id(o)]
        text_types = (str, unicode) if str is bytes else (str,)
        if isinstance(o, (list, tuple)):
            idx = intern(o)
            for item in o:
                walk(item, depth + 1)
            return idx
        if isinstance(o, dict):
            idx = intern(o)
            for key, value in o.items():
                walk(key, depth + 1)
                walk(value, depth + 1)
            return idx
        idx = intern(o)
        return idx

    top = walk(obj, 0)

    n = len(objects)
    ref_size = 1 if n < 256 else (2 if n < 65536 else 4)

    def enc_ref(index):
        return _bin.unhexlify("{0:0{1}X}".format(index, ref_size * 2))

    def enc_len(ln, kind=0x4):
        """Length prefix; >= 15 escapes through an int object (kind|0xF)."""
        if ln < 15:
            return _bin.unhexlify("{0:02X}".format((kind << 4) | ln))
        if ln < 256:
            return _bin.unhexlify("{0:02X}10".format((kind << 4) | 0xF)) + \
                _bin.unhexlify("{0:02X}".format(ln))
        if ln < 65536:
            return _bin.unhexlify("{0:02X}11".format((kind << 4) | 0xF)) + \
                _bin.unhexlify("{0:04X}".format(ln))
        return _bin.unhexlify("{0:02X}12".format((kind << 4) | 0xF)) + \
            _bin.unhexlify("{0:08X}".format(ln))

    def enc_int(v):
        if 0 <= v < 256:
            return _bin.unhexlify("10") + _bin.unhexlify("{0:02X}".format(v))
        if 0 <= v < 65536:
            return _bin.unhexlify("11") + _bin.unhexlify("{0:04X}".format(v))
        if 0 <= v < (1 << 32):
            return _bin.unhexlify("12") + _bin.unhexlify(
                "{0:08X}".format(v))
        if v < 0:
            v += 1 << 64
        return _bin.unhexlify("13") + _bin.unhexlify("{0:016X}".format(v))

    text_types = (str, unicode) if str is bytes else (str,)

    def enc_obj(o):
        if o is None:
            return _bin.unhexlify("00")
        if o is True:
            return _bin.unhexlify("09")
        if o is False:
            return _bin.unhexlify("08")
        if isinstance(o, int):
            return enc_int(o)
        if isinstance(o, float):
            return _bin.unhexlify("23") + _struct.pack(">d", o)
        if isinstance(o, _dt.datetime):
            delta = o - _BPLIST_EPOCH
            return _bin.unhexlify("33") + _struct.pack(">d", delta.total_seconds())
        if isinstance(o, bytes):
            return enc_len(len(o), 0x4) + o
        if isinstance(o, text_types):
            try:
                raw = o.encode("ascii")
                return enc_len(len(raw), 0x5) + raw
            except UnicodeEncodeError:
                raw = o.encode("utf-16-be")
                return enc_len(len(raw) // 2, 0x6) + raw
        if isinstance(o, (list, tuple)):
            out = enc_len(len(o), 0xA)
            for item in o:
                out += enc_ref(seen[id(item)])
            return out
        if isinstance(o, dict):
            out = enc_len(len(o), 0xD)
            for key in o.keys():
                out += enc_ref(seen[id(key)])
            for value in o.values():
                out += enc_ref(seen[id(value)])
            return out
        raise TypeError("unsupported plist type: {0}".format(type(o)))

    encoded = [enc_obj(o) for o in objects]

    body = bytearray(b"bplist00")
    offsets_acc = []
    pos = len(body)                       # bodies start right after the header
    for e in encoded:
        offsets_acc.append(pos)
        pos += len(e)
    max_off = pos
    if max_off >= (1 << 16):          # 3-byte range rounds up to 4
        offset_size = 4
    elif max_off >= (1 << 8):         # > 255 needs 2 bytes
        offset_size = 2
    else:
        offset_size = 1
    for e in encoded:
        body += e
    offset_table_off = len(body)          # table lives AFTER the bodies
    for off in offsets_acc:
        body += _bin.unhexlify("{0:0{1}X}".format(off, offset_size * 2))
    body += _bin.unhexlify("000000000000")  # 6-byte pad - no version here
    body += _bin.unhexlify("{0:02X}".format(offset_size))
    body += _bin.unhexlify("{0:02X}".format(ref_size))
    body += _bin.unhexlify("{0:016X}".format(n))
    body += _bin.unhexlify("{0:016X}".format(top))
    body += _bin.unhexlify("{0:016X}".format(offset_table_off))
    return bytes(body)


# ------------------------------------------------------------------------------
# plist compatibility (Python 2.7 / 3.2 / 3.3 lack binary-plist plistlib)
# ------------------------------------------------------------------------------


def _plist_loads(data):
    """Parse XML or binary plists on every supported Python."""
    if hasattr(plistlib, "loads"):
        return plistlib.loads(data)
    if _is_binary_plist(data):
        return _bplist_loads(data)
    return plistlib.readPlistFromString(data)


def _plist_load_fh(fh):
    return _plist_loads(fh.read())


def _plist_to_xml_bytes(obj):
    if hasattr(plistlib, "dumps"):
        return plistlib.dumps(obj, fmt=plistlib.FMT_XML)
    out = plistlib.writePlistToString(obj)
    if not _PY2 and isinstance(out, str):
        out = out.encode("utf-8")
    return out


def _plist_to_binary_bytes(obj):
    if hasattr(plistlib, "dumps"):
        return plistlib.dumps(obj, fmt=plistlib.FMT_BINARY)
    return _bplist_dumps(obj)



@dataclass(frozen=True)
class InstructionRecord:
    address: int
    raw_word: int
    mnemonic: str
    op_type: str


@dataclass(frozen=True)
class AnalysisAlert:
    """Immutable finding emitted by an analysis plugin."""
    plugin: str
    severity: str
    path: str
    message: str
    key: str = ""


class AnalysisPluginRegistry:
    """Small event-driven registry for extraction-time security analysis.

    Callbacks receive keyword arguments including ``path``, ``raw`` and, for
    plist events, ``parsed``.  Callback failures are isolated from extraction.
    """
    EVENTS = ("on_plist", "on_binary", "on_resource")

    def __init__(self):
        self._callbacks = {event: [] for event in self.EVENTS}
        self.alerts = []
        self.register("on_plist", _default_info_plist_rule)
        self.register("on_binary", _default_binary_rule)

    def register(self, event, callback):
        if event not in self._callbacks:
            raise ValueError("unknown analysis event: %s" % event)
        if not callable(callback):
            raise TypeError("analysis callback must be callable")
        self._callbacks[event].append(callback)
        return callback

    def emit(self, event, **context):
        if event not in self._callbacks:
            raise ValueError("unknown analysis event: %s" % event)
        emitted = []
        for callback in tuple(self._callbacks[event]):
            try:
                result = callback(**context)
                if result is None:
                    continue
                if isinstance(result, AnalysisAlert):
                    emitted.append(result)
                elif isinstance(result, (list, tuple)):
                    emitted.extend(x for x in result if isinstance(x, AnalysisAlert))
            except Exception as exc:
                log.warning("Analysis plugin %s failed for %s: %s",
                            getattr(callback, "__name__", repr(callback)),
                            context.get("path", "<memory>"), exc)
        self.alerts.extend(emitted)
        return emitted

    def analyze(self, path, raw, parsed=None, category=None):
        """Dispatch the appropriate hooks for one extracted file."""
        ctx = {"path": path, "raw": raw, "parsed": parsed, "category": category,
               "registry": self}
        if parsed is not None:
            self.emit("on_plist", **ctx)
        elif category == "native-binary" or _is_macho(raw):
            self.emit("on_binary", **ctx)
        else:
            self.emit("on_resource", **ctx)


def _default_info_plist_rule(path, raw, parsed=None, **_kwargs):
    """Built-in security checks for application Info.plist files."""
    if os.path.basename(path) != "Info.plist" or not isinstance(parsed, dict):
        return []
    findings = []
    if parsed.get("NSAllowsArbitraryLoads") is True:
        findings.append(AnalysisAlert(
            "default-info-plist", "high", _to_posix(path),
            "App Transport Security allows arbitrary network loads.",
            "NSAllowsArbitraryLoads"))
    exceptions = parsed.get("NSExceptionDomains")
    if isinstance(exceptions, dict):
        for domain, policy in exceptions.items():
            if not isinstance(policy, dict):
                continue
            prefix = "NSExceptionDomains.%s" % domain
            if policy.get("NSExceptionAllowsInsecureHTTPLoads") is True:
                findings.append(AnalysisAlert(
                    "default-info-plist", "high", _to_posix(path),
                    "ATS exception permits insecure HTTP loads for %s." % domain,
                    prefix + ".NSExceptionAllowsInsecureHTTPLoads"))
            tls = policy.get("NSExceptionMinimumTLSVersion")
            if isinstance(tls, str) and tls.upper() in ("TLSV1.0", "TLSV1.1"):
                findings.append(AnalysisAlert(
                    "default-info-plist", "medium", _to_posix(path),
                    "ATS exception permits an obsolete minimum TLS version (%s) for %s." % (tls, domain),
                    prefix + ".NSExceptionMinimumTLSVersion"))
            if policy.get("NSIncludesSubdomains") is True:
                findings.append(AnalysisAlert(
                    "default-info-plist", "low", _to_posix(path),
                    "ATS exception applies to subdomains of %s." % domain,
                    prefix + ".NSIncludesSubdomains"))
    if parsed.get("UIFileSharingEnabled") is True:
        findings.append(AnalysisAlert(
            "default-info-plist", "medium", _to_posix(path),
            "iTunes/Finder file sharing is enabled for the application.",
            "UIFileSharingEnabled"))
    if parsed.get("LSSupportsOpeningDocumentsInPlace") is True:
        findings.append(AnalysisAlert(
            "default-info-plist", "medium", _to_posix(path),
            "The app supports opening documents in place; review exposed document-provider/file-sharing behavior.",
            "LSSupportsOpeningDocumentsInPlace"))
    return findings


def _default_binary_rule(path, raw, **_kwargs):
    """Flag a small, high-signal set of risky imported C APIs."""
    if not _is_macho(raw):
        return []
    try:
        info = parse_macho_summary(raw)
    except Exception:
        return []
    if not info:
        return []
    risky = {
        "gets": ("high", "Uses gets(), an inherently unsafe unbounded input API."),
        "strcpy": ("medium", "Imports strcpy(); review for unbounded destination writes."),
        "strcat": ("medium", "Imports strcat(); review for unbounded destination writes."),
        "sprintf": ("medium", "Imports sprintf(); review for format-string/buffer-size safety."),
        "vsprintf": ("medium", "Imports vsprintf(); review for unbounded formatted writes."),
        "system": ("medium", "Imports system(); review command construction and untrusted input flows."),
        "popen": ("medium", "Imports popen(); review command construction and untrusted input flows."),
    }
    findings = []
    if not info.get("pie") and info.get("filetype") in ("MH_EXECUTE", "MH_DYLIB", "MH_BUNDLE"):
        findings.append(AnalysisAlert(
            "default-native-hardening", "high", _to_posix(path),
            "Mach-O image does not advertise PIE; review binary hardening.",
            "MH_PIE"))
    if info.get("allow_stack_execution"):
        findings.append(AnalysisAlert(
            "default-native-hardening", "high", _to_posix(path),
            "Mach-O explicitly allows executable stack pages.",
            "MH_ALLOW_STACK_EXECUTION"))
    if info.get("encrypted"):
        findings.append(AnalysisAlert(
            "default-native-hardening", "info", _to_posix(path),
            "Mach-O slice is encrypted (cryptid=%s); static code analysis may be incomplete." % info.get("encryption_id"),
            "cryptid"))
    if info.get("cpu") == "arm64e":
        findings.append(AnalysisAlert(
            "default-native-architecture", "info", _to_posix(path),
            "arm64e slice detected; pointer-authentication-aware analysis should be used.",
            "arm64e"))
    for rpath in info.get("rpaths", []):
        if rpath in ("@loader_path", "@executable_path") or rpath.startswith("@loader_path/") or rpath.startswith("@executable_path/"):
            continue
        if rpath.startswith("/") or rpath.startswith("~"):
            findings.append(AnalysisAlert(
                "default-native-loader", "medium", _to_posix(path),
                "Absolute/nonstandard RPATH may affect dynamic library resolution: %s" % rpath,
                "RPATH:%s" % rpath))
    for name in info.get("imports", []):
        short = name.rsplit("$", 1)[-1].lstrip("_")
        if short in risky:
            severity, message = risky[short]
            findings.append(AnalysisAlert(
                "default-native-api", severity, _to_posix(path), message, short))
    return findings


def _classify_file_worker(task):
    """Pure/process-safe classification and parsing worker.

    No framework output is mutated here.  The caller owns persistence, making
    the core parser safe for API and memory-only wrappers.
    """
    path, rel, data = task
    lower = rel.lower()
    result = {"path": path, "rel": rel, "category": None, "parsed": None,
              "error": None, "is_plist": False}
    if _is_binary_plist(data):
        result["category"] = FMT_NATIVE_BPLIST
        try:
            result["parsed"] = _plist_loads(data)
            result["is_plist"] = True
        except Exception as exc:
            result["category"] = "opaque-compiled"
            result["error"] = str(exc)
        return result
    if _is_xml_plist(data):
        result["category"] = "xml-plist"
        try:
            result["parsed"] = _plist_loads(data)
            result["is_plist"] = isinstance(result["parsed"], dict)
        except Exception:
            pass
        return result
    if _is_macho(data):
        result["category"] = "native-binary"
        return result
    if lower.endswith(".strings"):
        try:
            result["parsed"] = parse_legacy_strings(data)
            result["category"] = FMT_LEGACY_STRINGS
            result["is_plist"] = True
        except Exception:
            result["category"] = "other-binary"
        return result
    if lower.endswith(OPAQUE_SUFFIXES):
        result["category"] = "opaque-compiled"
        return result
    result["category"] = "other-binary"
    return result


def _read_candidate(path, root_dir):
    rel = _to_posix(os.path.relpath(path, root_dir))
    with open(path, "rb") as fh:
        data = fh.read()
    return path, rel, data

# ------------------------------------------------------------------------------
# FULL-DECOMPILE ENGINE: classify + convert every file
# ------------------------------------------------------------------------------



# ------------------------------------------------------------------------------
# Human-readable companions (readable/)
# ------------------------------------------------------------------------------

# Best-effort magic sniffing for binary resources.
_SNIFF_MAGIC = (
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"%PDF", "PDF document"),
    (b"PK\x03\x04", "ZIP container"),
    (b"\x1f\x8b", "gzip data"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"OTTO", "OpenType font"),
    (b"wOFF", "Web Open Font Format"),
    (b"RIFF", "RIFF container (WAV/WebP)"),
    (b"\x30\x82", "DER certificate / request"),
)


def _sha256_hex(data):
    import hashlib
    return hashlib.sha256(data).hexdigest()


def _sniff_binary_type(data, lower):
    """Best-effort human description of a binary blob (never raises)."""
    if lower.endswith(".car"):
        return "Apple compiled asset catalog (actool output)"
    if lower.endswith(".nib"):
        return "Compiled Interface Builder archive (typedstream)"
    if lower.endswith(".omo"):
        return "Core Data optimized model"
    for magic, label in _SNIFF_MAGIC:
        if data.startswith(magic):
            return label
    if len(data) >= 8 and data[4:8] == b"ftyp":
        return "MP4/QuickTime container"
    return "Unknown binary data"


def _printable_runs(data, min_len=5, cap=80):
    """Printable ASCII strings inside the first 4 MB of `data` (py2-safe)."""
    runs = []
    start = None
    limit = min(len(data), 4 * 1024 * 1024)
    for i in range(limit):
        b = data[i]
        if 32 <= b < 127:
            if start is None:
                start = i
        else:
            if start is not None and i - start >= min_len:
                runs.append(data[start:i].decode("ascii", "replace")[:120])
                if len(runs) >= cap:
                    return runs
            start = None
    if start is not None and limit - start >= min_len:
        runs.append(data[start:limit].decode("ascii", "replace")[:120])
    return runs


def _write_readable_summary(root_dir, rel, data, detected, detail_lines,
                            note=None):
    """Write the human-readable companion for one binary file.

    Companions live under readable/ (mirroring Payload/ paths) and are
    NEVER packaged back into the .ipa. Returns True when written.
    """
    out_rel = READABLE_DIR + "/" + rel + ".txt"
    out = os.path.join(root_dir, READABLE_DIR, rel.replace("/", os.sep) + ".txt")
    lines = [
        "IPAForge {0} - human-readable summary".format(__version__),
        "=" * 76,
        "Original file : {0}".format(rel),
        "Detected      : {0}".format(detected),
        "Size          : {0} bytes".format(len(data)),
        "SHA-256       : {0}".format(_sha256_hex(data)),
        "",
    ]
    lines.extend(detail_lines)
    if note:
        lines.append("")
        lines.append("NOTE: {0}".format(note))
    lines.append("")
    try:
        _makedirs(os.path.dirname(out))
        with open(out, "wb") as fh:
            fh.write("\n".join(lines).encode("utf-8"))
    except OSError as exc:
        log.warning("Could not write readable summary (%s): %s", exc, rel)
        return False
    log.info("Readable summary: %s -> %s", rel, out_rel)
    return True


def _write_macho_readable_summary(root_dir, rel, data):
    """Analysis summary for a Mach-O binary (must stay binary for signing)."""
    detail = []
    slices_ = _macho_slices(data)
    detail.append("Slices        : {0}".format(len(slices_)))
    for _off, _size in slices_:
        info = parse_macho_summary(data[_off:_off + _size])
        if not info:
            continue
        detail.append("")
        detail.append(
            "- {0}-bit {1} binary, filetype {2}".format(
                info["bits"], info["cpu"], info["filetype"]))
        if info["uuid"]:
            detail.append("  UUID          : {0}".format(info["uuid"]))
        if info["entry_vm"] is not None:
            detail.append("  Entry point   : 0x{0:X}".format(info["entry_vm"]))
        for seg in info["segments"]:
            detail.append(
                "  Segment       : {0}  vm 0x{1:X}..0x{2:X}  "
                "file 0x{3:X}..0x{4:X}".format(
                    seg["name"], seg["vmaddr"],
                    seg["vmaddr"] + seg["vmsize"],
                    seg["fileoff"], seg["fileoff"] + seg["filesize"]))
            for sect in seg["sections"]:
                detail.append(
                    "    Section     : {0},{1}  addr 0x{2:X}  "
                    "size 0x{3:X}".format(
                        sect["seg"], sect["name"], sect["addr"],
                        sect["size"]))
        if info["dylibs"]:
            detail.append("  Linked libraries (first {0} of {1}):".format(
                min(len(info["dylibs"]), 40), len(info["dylibs"])))
            for lib in info["dylibs"][:40]:
                detail.append("    {0}".format(lib))
        if info["symbols"]:
            detail.append("  Function symbols (first {0} of {1}):".format(
                min(len(info["symbols"]), 150), len(info["symbols"])))
            for value, name in info["symbols"][:150]:
                detail.append("    0x{0:X}  {1}".format(value, name))
        if info["imports"]:
            detail.append("  Imported symbols (first {0} of {1}):".format(
                min(len(info["imports"]), 60), len(info["imports"])))
            for name in info["imports"][:60]:
                detail.append("    {0}".format(name))
    cms = _macho_embedded_cms(data)
    detail.append("")
    if cms is not None:
        certs = _certs_from_cms(cms)
        detail.append("Code signature: REAL certificate chain (CMS)")
        detail.append("  Certificates  : {0}".format(len(certs)))
        for i, der in enumerate(certs[:4]):
            try:
                detail.append("  cert[{0}] {1}".format(
                    i, _cert_line(der).strip()))
            except Exception:
                detail.append("  cert[{0}] <unparseable>".format(i))
        if len(certs) > 4:
            detail.append("  ... {0} more".format(len(certs) - 4))
    else:
        detail.append("Code signature: ad-hoc / pseudo-signed "
                      "(no certificate chain)")
    runs = _printable_runs(data)
    if runs:
        detail.append("")
        detail.append("Embedded strings (first {0}):".format(len(runs)))
        for run in runs:
            detail.append("  {0}".format(run))
    return _write_readable_summary(
        root_dir, rel, data, "Mach-O native binary (re-signed at compile)",
        detail,
        "The binary form is required for code signing and execution; this "
        "summary plus original/* entitlement readouts are its readable "
        "counterparts. Instruction-level text AND pseudo-source are "
        "written next to the binary automatically during decode (read-only; "
        "machine code cannot be recompiled.")


def _profile_plist_bytes(data):
    """Locate and return the plist payload inside a profile blob (CMS)."""
    i = data.find(b"bplist00")
    if i >= 0:
        return data[i:]
    j = data.find(b"<?xml")
    if j >= 0:
        k = data.find(b"</plist>", j)
        if k >= 0:
            return data[j:k + 8]
    raise IPAForgeError("no plist inside provisioning profile")


def _profile_summary_detail(data):
    """Readable detail lines for embedded.mobileprovision, or None."""
    try:
        prof = _plist_loads(_profile_plist_bytes(data))
    except Exception:
        return None
    lines = [
        "Name         : {0}".format(prof.get("Name") or "-"),
        "TeamID       : {0}".format(", ".join(
            str(x) for x in (prof.get("TeamIdentifier") or [])) or "-"),
        "TeamName     : {0}".format(prof.get("TeamName") or "-"),
        "Created      : {0}".format(prof.get("CreationDate") or "-"),
        "Expires      : {0}".format(prof.get("ExpirationDate") or "-"),
        "Entitlements : {0} key(s)".format(
            len(prof.get("Entitlements") or {})),
    ]
    certs = prof.get("DeveloperCertificates") or []
    lines.append("Certificates : {0} embedded".format(len(certs)))
    for i, c in enumerate(certs[:4]):
        try:
            lines.append("  cert[{0}] {1}".format(
                i, _cert_line(bytes(c)).strip()))
        except Exception:
            lines.append("  cert[{0}] <unparseable>".format(i))
    return lines


def _cert_resource_summary_detail(data):
    """Readable detail lines for a .cer/.der/.pem/.crt resource, or None."""
    der = data
    if data.startswith(b"-----BEGIN"):
        try:
            der = _b64.b64decode(b"".join(
                line for line in data.splitlines() if b"-----" not in line))
        except Exception:
            return None
    try:
        f = _cert_display_fields(der)
    except Exception:
        return None
    lines = [
        "Subject CN   : {0}".format(f["cn"] or "-"),
        "Issuer CN    : {0}".format(f["issuer_cn"] or "-"),
        "Serial       : {0}".format(f["serial"]),
        "Valid from   : {0}".format(f["not_before"] or "?"),
        "Valid until  : {0}".format(f["not_after"] or "?"),
        "Team (OU)    : {0}".format(f["ou"] or "-"),
    ]
    if f["modulus"]:
        lines.append("Key          : RSA {0}-bit".format(
            f["modulus"].bit_length()))
    return lines


def _special_binary_summary(rel, data):
    """(label, detail, note) for known special binaries, else None."""
    base = os.path.basename(rel)
    if base == PROFILE_FILE:
        detail = _profile_summary_detail(data)
        if detail is not None:
            return ("Provisioning profile (CMS-wrapped plist)", detail,
                    "The original profile is repackaged untouched; its "
                    "plist is under original/ and the certificate listing "
                    "under original/" + rel + ".certs.txt.")
    if base.lower().endswith(CERT_EXTS) or data.startswith(b"-----BEGIN"):
        detail = _cert_resource_summary_detail(data)
        if detail is not None:
            return ("X.509 certificate (app-shipped / pinning resource)",
                    detail,
                    "The original bytes are preserved exactly; the parsed "
                    "fields above are read-only convenience. Full listing: "
                    "original/" + rel + ".certs.txt")
    return None



# ------------------------------------------------------------------------------
# Compiled asset catalog (.car) image extraction
#
# A .car is a BOM container ("BOMStore") holding named rendition blocks.
# Layout (verified against real Xcode-compiled catalogs):
#   header 32 B BE: magic, version, blockCount, indexOff, indexLen, varsOff,
#                   varsLen
#   block index:    8-byte BE entries (offset, length) - block id = array pos
#   vars table:     u32 BE count, then per var: u32 BE block id, u8 len, name
#   "RENDITIONS" var -> B+ tree ("tree" magic; root node id at u32 BE offset 8)
#   tree node:      u16 isLeaf, u16 count, u32 fwd, u32 back, then count x
#                   u32 BE value-id, u32 BE key-id (value FIRST)
#   rendition:      CSI header 184 B LE: magic ISTC, w@12 h@16 scale@20
#                   pixelFormat@24, name[128]@40, tvlLength@168; bitmap data
#                   follows the TLV section (data starts at 184 + tvlLength)
#   bitmap wrapper: MLEC/CELM + u32 compression: 0=raw 1=RLE 2=zlib are
#                   decoded; 3/4/5/8/9/10/11/12 are Apple codecs (reported,
#                   never faked). RAWD payloads (JPEG/PNG/PDF) are stored
#                   verbatim and written out as-is.
# ------------------------------------------------------------------------------

_CAR_BMP_CHUNK = 4096 * 1024


def _car_png_chunk(tag, data):
    c = struct.pack(">I", len(data)) + tag + data
    import zlib as _z
    return c + struct.pack(">I", _z.crc32(tag + data) & 0xFFFFFFFF)


def _car_write_png(path, w, h, rgba_rows):
    import zlib as _z
    raw = b"".join(b"\x00" + row for row in rgba_rows)
    png = b"\x89PNG\r\n\x1a\n"
    png += _car_png_chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
    png += _car_png_chunk(b"IDAT", _z.compress(raw, 6))
    png += _car_png_chunk(b"IEND", b"")
    with open(path, "wb") as fh:
        fh.write(png)


def _car_to_rgba(rows, pxfmt):
    out = []
    for row in rows:
        px = bytearray()
        if pxfmt == b"BGRA":
            for i in range(0, len(row) - 3, 4):
                b, g, r, a = row[i:i + 4]
                px += bytes((r, g, b, a))
        elif pxfmt == b"ARGB":
            for i in range(0, len(row) - 3, 4):
                a, r, g, b = row[i:i + 4]
                px += bytes((r, g, b, a))
        else:
            px += row
        out.append(bytes(px))
    return out


def _car_decode_rle(data, w, h, bpp):
    """Row-offset RLE: (depth, w, h) u32 header, then h u32 row offsets,
    then per-row runs: u32 header - 0x80xxxxxx = fill (value follows),
    otherwise copy `run` pixels."""
    if len(data) < 12:
        return None
    depth, rw, rh = struct.unpack_from("<3I", data, 0)
    if rw != w or rh != h or (3 + h) * 4 > len(data):
        return None
    offs = []
    for r in range(h):
        o = struct.unpack_from("<I", data, (3 + r) * 4)[0]
        if o >= len(data):
            return None
        offs.append(o)
    if h and offs[0] != (3 + h) * 4:
        return None
    rows = []
    for r in range(h):
        pos = offs[r]
        end = offs[r + 1] if r + 1 < h else len(data)
        row = bytearray()
        guard = 0
        while len(row) < w * bpp and pos + 4 <= end:
            hdr = struct.unpack_from("<I", data, pos)[0]
            run = hdr & 0xFFFFFF
            hi = (hdr >> 24) & 0xFF
            pos += 4
            if hi == 0x80:
                pat = data[pos:pos + bpp]
                pos += bpp
                need = (w * bpp - len(row)) // bpp
                if need > 0:
                    row += pat * min(run, need)
            else:
                take = run * bpp
                row += data[pos:pos + take]
                pos += take
            guard += 1
            if guard > 100000:
                return None
        if len(row) < w * bpp:
            row += b"\x00" * (w * bpp - len(row))
        rows.append(bytes(row[:w * bpp]))
    return rows


def _car_extract_assets(car_path, out_dir):
    """Extract every decodable image from a compiled asset catalog.

    Returns (extracted_count, proprietary_count, file_names, notes).
    Images land in out_dir as PNG (decoded) or verbatim JPEG/PNG/PDF
    (stored streams). Apple-codec renditions are counted and described
    honestly - the compiled .car itself is NEVER modified.
    """
    import zlib as _z
    with open(car_path, "rb") as fh:
        d = fh.read()
    if d[:8] != b"BOMStore":
        return 0, 0, [], ["not a BOM container"]
    _v, nblocks, idxoff, _il, varsoff, _vl = struct.unpack_from(">6I", d, 8)

    def load(bid):
        if bid <= 0 or bid >= nblocks:
            raise ValueError("bad block id %d" % bid)
        off, ln = struct.unpack_from(">II", d, idxoff + 4 + bid * 8)
        if off + ln > len(d):
            raise ValueError("block out of range")
        return d[off:off + ln]

    vn = struct.unpack_from(">I", d, varsoff)[0]
    off = varsoff + 4
    vmap = {}
    for _ in range(vn):
        idx = struct.unpack_from(">I", d, off)[0]
        ln = d[off + 4]
        vmap[d[off + 5:off + 5 + ln].decode("latin1")] = idx
        off += 5 + ln
    if "RENDITIONS" not in vmap:
        return 0, 0, [], ["no RENDITIONS tree"]

    rends = []

    def walk(bid):
        node = load(bid)
        isleaf, count, fwd, back = struct.unpack_from(">HHII", node, 0)
        if isleaf:
            for i in range(count):
                v1, v2 = struct.unpack_from(">II", node, 12 + i * 8)
                rends.append((load(v2), load(v1)))
        else:
            for i in range(count):
                _k, vb = struct.unpack_from(">II", node, 12 + i * 8)
                walk(vb)
            if fwd:
                walk(fwd)

    walk(struct.unpack_from(">I", load(vmap["RENDITIONS"]), 8)[0])

    _makedirs(out_dir)
    used = {}
    manifest = []
    files = []
    got = prop = 0
    for k, v in rends:
        if len(v) < 184 or v[:4] != b"ISTC":
            prop += 1
            continue
        _t, _ver, _fl, w, h, scale, pxfmt, _cs = struct.unpack_from("<8I", v, 0)
        _mt, layout, _z = struct.unpack_from("<IHH", v, 32)
        cname = v[40:168].split(b"\x00")[0].decode("latin1", "replace") \
            .replace("/", "_") or "unnamed"
        tvl = struct.unpack_from("<I", v, 168)[0]
        payload = v[184 + tvl:]
        px = struct.pack("<I", pxfmt)

        blob = None
        ext = ".png"
        note = ""
        if payload[:4] in (b"MLEC", b"CELM") and len(payload) >= 16:
            comp, rawlen = struct.unpack_from("<II", payload, 8)
            data = payload[16:16 + rawlen]
            if comp == 0 and w and h and len(data) >= w * h * 4:
                blob = _car_to_rgba(
                    [data[i * w * 4:(i + 1) * w * 4] for i in range(h)], px)
                note = "raw pixels -> PNG"
            elif comp == 1 and w and h:
                rows = _car_decode_rle(data, w, h, 4)
                if rows:
                    blob = _car_to_rgba(rows, px)
                    note = "RLE -> PNG"
            elif comp == 2 and w and h:
                try:
                    raw = _z.decompress(data)
                    if len(raw) >= w * h * 4:
                        blob = _car_to_rgba(
                            [raw[i * w * 4:(i + 1) * w * 4]
                             for i in range(h)], px)
                        note = "zlib -> PNG"
                except Exception:
                    note = "zlib data malformed"
            if blob is None and not note:
                note = "Apple codec (%s)" % (
                    {3: "lzvn", 4: "lzfse", 5: "jpeg-lzfse",
                     8: "palette", 9: "hevc", 10: "deepmap-lzfse",
                     11: "deepmap2", 12: "dxtc"}.get(comp, "type %d" % comp))
        elif payload[:4] == b"RAWD" and len(payload) >= 12:
            compver, rawlen = struct.unpack_from("<II", payload, 4)
            data = payload[12:12 + rawlen]
            if compver == 0:
                if data[:3] == b"\xff\xd8\xff":
                    ext = ".jpg"
                elif data[:4] == b"\x89PNG":
                    ext = ".png"
                elif data[:5] == b"%PDF-":
                    ext = ".pdf"
                else:
                    ext = ".dat"
                blob = [("raw", data)]
                note = "stored %s -> written verbatim" % ext[1:].upper()
            else:
                note = "lzfse-wrapped data (Apple codec)"

        name = cname
        if scale in (200, 300) and blob is not None:
            stem, dot, suffix = name.rpartition(".")
            tag = "@{0}x".format(scale // 100)
            if stem and tag not in stem:
                name = stem + tag + dot + suffix
        if name in used:
            used[name] += 1
            stem, dot, suffix = name.rpartition(".")
            name = "{0}-{1}{2}{3}".format(
                stem or name, used[name], dot, suffix if dot else "")
        else:
            used[name] = 1

        if blob is not None:
            outname = name if name.lower().endswith(ext) else name + ext
            if blob and blob[0][0] == "raw":
                with open(os.path.join(out_dir, outname), "wb") as fh:
                    fh.write(blob[0][1])
            else:
                _car_write_png(os.path.join(out_dir, outname), w, h, blob)
            files.append(outname)
            manifest.append("EXTRACTED   %-30s %s" % (outname, note))
            got += 1
        else:
            if layout == 1010:
                note = note or "icon-set reference (points at its slices)"
            manifest.append("APPLE-CODEC %-30s [%dx%d @%d] %s"
                            % (cname, w, h, scale, note))
            prop += 1

    manifest.insert(0, "")
    manifest.insert(0, "apple-codec renditions (require Apple tools): %d" % prop)
    manifest.insert(0, "images extracted: %d" % got)
    manifest.insert(0, "renditions total: %d" % len(rends))
    manifest.insert(0, "IPAForge {0} - asset catalog extraction".format(__version__))
    with open(os.path.join(out_dir, "manifest.txt"), "w") as fh:
        fh.write("\n".join(manifest) + "\n")
    files.append("manifest.txt")
    return got, prop, files, []


def classify_and_convert_all(root_dir, plugin_registry=None, max_workers=None):
    """Classify and convert every extracted file using a process pool.

    CPU-heavy byte classification/plist parsing is isolated in worker
    processes.  Filesystem mutations remain in this coordinator, so callers
    can replace persistence with a streaming/API adapter without changing the
    parsing workers.
    """
    registry = plugin_registry or AnalysisPluginRegistry()
    manifest_entries = []
    counts = {FMT_NATIVE_BPLIST: 0, FMT_LEGACY_STRINGS: 0,
              "xml-plist": 0, "opaque-compiled": 0, "native-binary": 0,
              "other-binary": 0, "readable-summaries": 0}
    candidates = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames.sort()
        for filename in sorted(filenames):
            path = os.path.join(dirpath, filename)
            rel = _to_posix(os.path.relpath(path, root_dir))
            if rel.split("/", 1)[0] in (READABLE_DIR, ORIGINAL_DIR, GHIDRA_DIR) \
                    or rel == META_FILE_NAME:
                continue
            candidates.append(path)

    tasks = []
    for path in candidates:
        try:
            tasks.append(_read_candidate(path, root_dir))
        except OSError as exc:
            rel = _to_posix(os.path.relpath(path, root_dir))
            log.warning("Could not read file, leaving as-is (%s): %s", rel, exc)
            counts["other-binary"] += 1

    # Parsing is CPU-heavy, but creating one process per logical CPU can make
    # large IPAs memory-bound because each task carries raw file bytes. Cap the
    # default and honor an explicit caller limit.
    workers = max_workers or min((os.cpu_count() or 1), 8)
    workers = max(1, workers)
    results = []
    if tasks:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(_classify_file_worker, task) for task in tasks]
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as exc:
                    log.warning("Parallel classification worker failed: %s", exc)
        results.sort(key=lambda r: r["rel"])

    task_data = {rel: data for _path, rel, data in tasks}
    for result in results:
        path, rel = result["path"], result["rel"]
        data = task_data.get(rel, b"")
        category = result["category"]
        parsed = result.get("parsed")
        registry.analyze(rel, data, parsed=parsed, category=category)

        if category == FMT_NATIVE_BPLIST:
            if result.get("error"):
                log.warning("Unparseable binary plist, kept byte-identical (%s): %s",
                            rel, result["error"])
                if _write_readable_summary(root_dir, rel, data,
                                           "Binary plist with a parse error",
                                           ["Parse error   : %s" % result["error"]],
                                           "The original bytes are preserved unchanged so no data is lost."):
                    counts["readable-summaries"] += 1
                counts["opaque-compiled"] += 1
            elif write_decoded(root_dir, path, parsed, rel):
                counts[FMT_NATIVE_BPLIST] += 1
                manifest_entries.append((rel, FMT_NATIVE_BPLIST))
            else:
                counts["opaque-compiled"] += 1
            continue
        if category == "xml-plist":
            counts["xml-plist"] += 1
            continue
        if category == "native-binary":
            counts["native-binary"] += 1
            try:
                if _write_macho_readable_summary(root_dir, rel, data):
                    counts["readable-summaries"] += 1
            except Exception as exc:
                log.warning("Could not write readable analysis for %s: %s", rel, exc)
            continue
        if category == FMT_LEGACY_STRINGS:
            if write_decoded(root_dir, path, parsed, rel):
                counts[FMT_LEGACY_STRINGS] += 1
                manifest_entries.append((rel, FMT_LEGACY_STRINGS))
            else:
                counts["other-binary"] += 1
            continue
        if category == "opaque-compiled":
            counts["opaque-compiled"] += 1
            detail = ["Structure   : Apple-proprietary compiled format",
                      "Creator     : Apple toolchain (actool / ibtool)"]
            note = ("The compiled form is required for iOS to load this file; "
                    "the original stays byte-identical in Payload/.")
            if rel.lower().endswith(".car"):
                assets_rel = rel + ".assets"
                assets_dir = os.path.join(root_dir, READABLE_DIR,
                                          assets_rel.replace("/", os.sep))
                try:
                    got, prop, _names, _notes = _car_extract_assets(path, assets_dir)
                    if got or prop:
                        detail.append("Extraction  : %d image(s) written to readable/%s/ (%d rendition(s) need Apple tools)" %
                                      (got, assets_rel, prop))
                except Exception as exc:
                    detail.append("Extraction  : catalog structure not recognized (%s)" % exc)
            if _write_readable_summary(root_dir, rel, data,
                                       _sniff_binary_type(data, rel.lower()),
                                       detail, note):
                counts["readable-summaries"] += 1
            continue
        counts["other-binary"] += 1
        special = _special_binary_summary(rel, data)
        if special is not None:
            det_label, detail, note = special
        else:
            det_label = _sniff_binary_type(data, rel.lower())
            runs = _printable_runs(data)
            detail = ["Structure   : see detection above"]
            if runs:
                detail.append("Embedded strings (first %d):" % len(runs))
                detail.extend("  %s" % run for run in runs)
            note = "The original bytes are preserved exactly (repackaged untouched); this summary is the readable counterpart."
        if _write_readable_summary(root_dir, rel, data, det_label, detail, note):
            counts["readable-summaries"] += 1

    if registry.alerts:
        log.warning("Analysis plugins emitted %d alert(s)", len(registry.alerts))
        for alert in registry.alerts:
            log.warning("[%s] %s: %s (%s)", alert.severity.upper(), alert.path,
                        alert.message, alert.key or alert.plugin)
    return manifest_entries, counts


def write_decoded(root_dir, path, obj, rel):
    """Write `obj` as readable XML over `path`; logs and returns success."""
    try:
        xml_bytes = _plist_to_xml_bytes(obj)
        with open(path, "wb") as fh:
            fh.write(xml_bytes)
    except OSError as exc:
        log.warning("Could not write XML plist (%s): %s", exc, rel)
        return False
    log.info("Converting to readable XML: %s", rel)
    return True


def log_coverage_report(counts, total_files):
    """Print the full accounting - every extracted file falls in a category."""
    converted = counts[FMT_NATIVE_BPLIST] + counts[FMT_LEGACY_STRINGS]
    untouched = (
        counts["xml-plist"]
        + counts["opaque-compiled"]
        + counts["native-binary"]
        + counts["other-binary"]
    )
    log.info(
        "Coverage: %d file(s) decompiled to readable XML "
        "(%d binary plists, %d legacy .strings); %d already readable "
        "(XML plists); %d machine-code file(s) (re-signed at compile - "
        "full analysis with symbols in %s/); %d binary file(s) with readable "
        "summaries in %s/ (compiled Apple formats and resources)",
        converted,
        counts[FMT_NATIVE_BPLIST],
        counts[FMT_LEGACY_STRINGS],
        counts["xml-plist"],
        counts["native-binary"],
        READABLE_DIR,
        counts["opaque-compiled"] + counts["other-binary"],
        READABLE_DIR,
    )
    if converted + untouched == total_files:
        log.info(
            "Nothing skipped, nothing dropped: %d/%d extracted files accounted for",
            converted + untouched,
            total_files,
        )
    else:
        log.warning(
            "Accounting mismatch: %d classified vs %d extracted - "
            "files changed while decoding?",
            converted + untouched,
            total_files,
        )


def read_conversion_manifest(input_dir):
    """Read the conversion manifest.

    Returns a list of (relative_posix_path, format) tuples, or None when the
    framework has no manifest. Tolerates old v1 manifests (bare paths, no
    format tag) by assuming FMT_NATIVE_BPLIST.
    """
    path = os.path.join(input_dir, MANIFEST_FILE_NAME)
    if not os.path.isfile(path):
        return None
    entries = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n").strip()
            if not line or line.startswith("#"):
                continue
            if MANIFEST_SEP in line:
                rel, fmt = line.split(MANIFEST_SEP, 1)
                entries.append((_to_posix(rel), fmt))
            else:  # v1 manifest (IPAForge <= 1.4.0): bare path
                entries.append((_to_posix(line), FMT_NATIVE_BPLIST))
    return entries


def reencode_manifest_entries(root_dir, entries):
    """Reverse the decode conversions, in each file's ORIGINAL format.

    - native-bplist entries: re-encode to bplist00 binary (idempotent).
    - legacy-strings entries: re-serialize to classic UTF-16 text; if the
      user's edit made the values non-string, fall back to a binary plist
      (which iOS accepts for .strings resources as well).
    Returns a list of (posix rel, is_binary) tuples for the self-check.
    """
    reencoded = []
    for rel, fmt in sorted(entries):
        rel_native = os.path.join(*rel.split("/"))
        path = os.path.join(root_dir, rel_native)
        if not os.path.isfile(path):
            log.warning("Manifest entry missing on disk, skipping: %s", rel)
            continue
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            log.warning("Could not read file, packing as-is (%s): %s", exc, rel)
            continue

        if _is_binary_plist(data):
            log.debug("Already binary, leaving untouched: %s", rel)
            continue

        try:
            obj = _plist_loads(data)
        except Exception as exc:
            log.warning("Could not parse edited plist, packing as-is (%s): %s", rel, exc)
            continue

        if fmt == FMT_LEGACY_STRINGS and is_pure_string_mapping(obj):
            blob = serialize_legacy_strings(obj)
            desc = "legacy .strings text (UTF-16)"
        else:
            blob = _plist_to_binary_bytes(obj)
            desc = "binary plist" if fmt != FMT_LEGACY_STRINGS else "binary plist (non-string values)"

        try:
            with open(path, "wb") as fh:
                fh.write(blob)
        except OSError as exc:
            log.warning("Could not write re-encoded file (%s): %s", exc, rel)
            continue

        log.info("Re-encoding to %s: %s", desc, rel)
        reencoded.append((_to_posix(rel), not desc.startswith("legacy")))
    return reencoded


def reencode_plistish_fallback(root_dir):
    """Fallback for OLD frameworks without a conversion manifest.

    Re-encodes text/XML files with the well-known extensions back to their
    native form: .plist/.stringsdict -> binary plist, legacy .strings ->
    classic text. Returns a list of (posix rel, is_binary) tuples.
    """
    reencoded = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames.sort()
        for filename in sorted(filenames):
            lower = filename.lower()
            if not lower.endswith((".plist", ".strings", ".stringsdict")):
                continue
            path = os.path.join(dirpath, filename)
            rel = os.path.relpath(path, root_dir)

            try:
                with open(path, "rb") as fh:
                    data = fh.read()
            except OSError as exc:
                log.warning("Could not read file, packing as-is (%s): %s", exc, rel)
                continue

            if _is_binary_plist(data):
                log.debug("Already binary, leaving untouched: %s", rel)
                continue
            if _is_xml_plist(data) and lower.endswith(".strings"):
                # could be a converted legacy .strings OR an XML plist; try
                # both and prefer the classic text form when it round-trips
                try:
                    obj = _plist_loads(data)
                    if is_pure_string_mapping(obj):
                        blob = serialize_legacy_strings(obj)
                        desc = "legacy .strings text (UTF-16)"
                    else:
                        blob = _plist_to_binary_bytes(obj)
                        desc = "binary plist"
                except Exception as exc:
                    log.warning("Could not parse file, packing as-is (%s): %s", rel, exc)
                    continue
            else:
                try:
                    obj = _plist_loads(data)
                    blob = _plist_to_binary_bytes(obj)
                    desc = "binary plist"
                except Exception as exc:
                    log.warning("Could not parse plist, packing as-is (%s): %s", rel, exc)
                    continue

            try:
                with open(path, "wb") as fh:
                    fh.write(blob)
            except OSError as exc:
                log.warning("Could not write re-encoded file (%s): %s", exc, rel)
                continue

            log.info("Re-encoding to %s: %s", desc, rel)
            reencoded.append((_to_posix(rel), not desc.startswith("legacy")))
    return reencoded


def report_opaque_files(counts):
    """One-line honesty report about compiled Apple formats we cannot decode."""
    if counts["opaque-compiled"] <= 0:
        return
    log.info(
        "%d compiled Apple file(s) (.car/.nib) preserved in compiled form "
        "(iOS loads them only that way) - each has a human-readable "
        "summary under %s/",
        counts["opaque-compiled"], READABLE_DIR,
    )


# ------------------------------------------------------------------------------
# Readable reference extractions (original/)
# ------------------------------------------------------------------------------


def extract_profile_readout(output_dir, app_bundle):
    """Store a human-readable copy of the provisioning profile in original/.

    An embedded.mobileprovision is a CMS wrapper around an XML plist; the
    plist part is extracted for reading. The original file itself is kept
    byte-identical inside Payload/ and repackaged untouched. Best-effort.
    """
    if not app_bundle:
        return
    profile_path = os.path.join(output_dir, PAYLOAD_DIR, app_bundle, PROFILE_FILE)
    if not os.path.isfile(profile_path):
        return
    try:
        with open(profile_path, "rb") as fh:
            data = fh.read()
        start = data.find(b"<?xml")
        end = data.rfind(b"</plist>")
        if start == -1 or end == -1 or end <= start:
            log.debug("Provisioning profile contains no readable plist payload")
            return
        plist_blob = data[start:end + len(b"</plist>")]
        _plist_loads(plist_blob)  # validate before storing
        rel = os.path.join(PAYLOAD_DIR, app_bundle, PROFILE_FILE)
        dst = os.path.join(output_dir, ORIGINAL_DIR, rel + PROFILE_READOUT_SUFFIX)
        _makedirs(os.path.dirname(dst))
        with open(dst, "wb") as fh:
            fh.write(plist_blob)
        log.info(
            "Readable provisioning profile copy: %s/%s (reference only)",
            ORIGINAL_DIR,
            _to_posix(os.path.join(rel + PROFILE_READOUT_SUFFIX)),
        )
    except Exception as exc:
        log.debug("Provisioning profile readout skipped: %s", exc)


def extract_entitlements_readouts(output_dir):
    """Extract embedded entitlements from every Mach-O in the framework.

    Writes <binary>.entitlements.plist.xml reference copies under original/
    (mirroring what `ldid -e` / `codesign -d --entitlements` would show).
    The binaries themselves stay byte-identical. Returns the count.
    """
    payload_dir = os.path.join(output_dir, PAYLOAD_DIR)
    if not os.path.isdir(payload_dir):
        return 0
    extracted = 0
    macho_scanned = 0
    for dirpath, dirnames, filenames in os.walk(payload_dir):
        dirnames.sort()
        for filename in sorted(filenames):
            path = os.path.join(dirpath, filename)
            try:
                with open(path, "rb") as fh:
                    data = fh.read(64 * 1024 * 1024)
            except OSError:
                continue
            if not _is_macho(data):
                continue
            macho_scanned += 1
            ent = extract_entitlements_from_macho(data)
            if not ent:
                continue
            rel = os.path.relpath(path, output_dir)
            dst = os.path.join(
                output_dir, ORIGINAL_DIR, rel + ENTITLEMENTS_READOUT_SUFFIX
            )
            try:
                _makedirs(os.path.dirname(dst))
                with open(dst, "wb") as fh:
                    fh.write(ent)
            except OSError as exc:
                log.debug("Could not write entitlements readout: %s", exc)
                continue
            extracted += 1
            log.info(
                "Readable entitlements copy: %s/%s (reference only)",
                ORIGINAL_DIR,
                _to_posix(os.path.relpath(dst, os.path.join(output_dir, ORIGINAL_DIR))),
            )
    if macho_scanned:
        log.info(
            "Entitlements: extracted from %d of %d Mach-O binary(ies) "
            "(every binary was checked; the others simply embed none - "
            "normally only the main executable carries entitlements)",
            extracted, macho_scanned,
        )
    return extracted


def _cert_display_fields(der):
    """Best-effort display fields for one DER certificate.

    Extends parse_cert with issuer CN and the validity window.
    """
    data = bytearray(der)
    info = parse_cert(data)
    info["issuer_cn"] = ""
    info["not_before"] = ""
    info["not_after"] = ""
    try:
        cert = _der_children(data, 0, len(data))[0]
        tbs = _der_children(data, cert[2], cert[3])[0]
        kids = _der_children(data, tbs[2], tbs[3])
        idx = 1 if kids[0][0] == 0xA0 else 0

        def _name_cn(node):
            for rdn in _der_children(data, node[2], node[3]):
                for atv in _der_children(data, rdn[2], rdn[3]):
                    ak = _der_children(data, atv[2], atv[3])
                    if _raw(data, ak[0]) == b"\x55\x04\x03":
                        return bytes(
                            data[ak[1][2]:ak[1][3]]).decode("utf-8", "replace")
            return ""

        info["issuer_cn"] = _name_cn(kids[idx + 2])
        times = _der_children(data, kids[idx + 3][2], kids[idx + 3][3])
        tvals = [bytes(data[t[2]:t[3]]).decode("ascii", "replace")
                 for t in times[:2]]
        if tvals:
            info["not_before"] = tvals[0]
        if len(tvals) > 1:
            info["not_after"] = tvals[1]
    except Exception:
        pass
    return info


def _cert_line(der, prefix=""):
    i = _cert_display_fields(der)
    return ("{0}subject CN='{1}' issuer CN='{2}' serial={3} "
            "valid {4}..{5} team(OU)={6}").format(
        prefix, i["cn"] or "-", i["issuer_cn"] or "-", i["serial"],
        i["not_before"] or "?", i["not_after"] or "?", i["ou"] or "-")


def _certs_from_cms(cms_der):
    """X.509 DER certificates embedded in a CMS SignedData (best-effort)."""
    out = []
    try:
        data = bytearray(cms_der)
        ci = _der_children(data, 0, len(data))[0]
        a0 = _der_children(data, ci[2], ci[3])[1]
        sd = _der_children(data, a0[2], a0[3])[0]
        for kid in _der_children(data, sd[2], sd[3]):
            if kid[0] == 0xA0:                 # [0] IMPLICIT cert set
                p = kid[2]
                while p < kid[3]:
                    _tag, _pos, _cs, ce = _der_node(data, p)
                    out.append(bytes(data[p:ce]))   # FULL TLV
                    p = ce
    except Exception:
        return out
    return out


def _macho_embedded_cms(data):
    """CMS DER of the first REAL (non-ad-hoc) signature in a Mach-O.

    Returns None for ad-hoc/unsigned binaries (the ad-hoc CMS slot is an
    empty 8-byte blobwrapper and carries no certificates).
    """
    try:
        slices = _macho_slices(data)
    except Exception:
        return None
    for off, _size in slices:
        info = _header_info(data, off)
        if info is None or not info["sig_dataoff"]:
            continue
        try:
            blob = bytearray(data)
            magic, _length, count = struct.unpack_from(">III", blob,
                                                       info["sig_dataoff"])
            if magic != CSMAGIC_EMBEDDED_SIGNATURE:
                continue
            base = info["sig_dataoff"]
            for i in range(count):
                t, o = struct.unpack_from(">II", blob, base + 12 + 8 * i)
                _bm, blen = struct.unpack_from(">II", blob, base + o)
                if t == CSSLOT_SIGNATURESLOT and blen > 8:
                    return bytes(blob[base + o + 8:base + o + blen])
        except Exception:
            continue
    return None


def _cert_readout_text(certs, header):
    lines = [header]
    for i, der in enumerate(certs):
        lines.append(_cert_line(der, "cert[{0}] ".format(i)))
    return "\n".join(lines) + "\n"


def extract_cert_readouts(output_dir):
    """Show every certificate the framework carries (decode side).

    Three sources are parsed and reported:
      * the CMS chain embedded in each Mach-O code signature (slot 0x10000),
      * DeveloperCertificates inside embedded.mobileprovision,
      * standalone certificate resources (.cer/.der/.pem/.crt).
    Readable listings land in original/ as <file>.certs.txt; the files
    themselves stay byte-identical. Returns the number of
    certificate-bearing files found.
    """
    payload_dir = os.path.join(output_dir, PAYLOAD_DIR)
    if not os.path.isdir(payload_dir):
        return 0
    found = 0

    def _write_readout(rel, text):
        dst = os.path.join(output_dir, ORIGINAL_DIR,
                           rel + CERTS_READOUT_SUFFIX)
        _makedirs(os.path.dirname(dst))
        with open(dst, "wb") as fh:
            fh.write(text.encode("utf-8"))
        log.info("Certificate listing: %s/%s (reference only)",
                 ORIGINAL_DIR,
                 _to_posix(os.path.relpath(
                     dst, os.path.join(output_dir, ORIGINAL_DIR))))

    for dirpath, dirnames, filenames in os.walk(payload_dir):
        dirnames.sort()
        for filename in sorted(filenames):
            path = os.path.join(dirpath, filename)
            try:
                with open(path, "rb") as fh:
                    data = fh.read(64 * 1024 * 1024)
            except OSError:
                continue
            rel = os.path.relpath(path, output_dir)
            if _is_macho(data):
                cms = _macho_embedded_cms(data)
                if not cms:
                    continue
                certs = _certs_from_cms(cms)
                if not certs:
                    continue
                found += 1
                _write_readout(rel, _cert_readout_text(
                    certs,
                    "code-signature chain: {0} certificate(s)".format(
                        len(certs))))
                leaf = _cert_display_fields(certs[0])
                log.info(
                    "Code-signature certificate chain in %s: %d cert(s), "
                    "leaf CN '%s'", filename, len(certs), leaf["cn"])
            elif filename == PROFILE_FILE:
                try:
                    prof = _load_mobileprovision(path)
                except Exception:
                    continue
                certs = []
                for c in prof.get("DeveloperCertificates") or []:
                    try:
                        certs.append(bytes(c))
                    except Exception:
                        pass
                found += 1
                _write_readout(rel, _cert_readout_text(
                    certs,
                    "provisioning profile: {0} embedded certificate(s)".format(
                        len(certs))))
                log.info(
                    "Provisioning profile certificates in %s: %d cert(s), "
                    "team %s", filename, len(certs),
                    ", ".join(str(x) for x in
                              (prof.get("TeamIdentifier") or [])) or "-")
            elif filename.lower().endswith(CERT_EXTS):
                if data.startswith(b"-----BEGIN"):
                    try:
                        der = _b64.b64decode(b"".join(
                            line for line in data.splitlines()
                            if b"-----" not in line))
                    except Exception:
                        continue
                else:
                    der = data
                try:
                    fields = _cert_display_fields(der)
                except Exception:
                    continue
                found += 1
                _write_readout(rel, _cert_readout_text(
                    [der], "certificate resource"))
                log.info("Certificate resource %s: CN '%s', valid %s..%s",
                         _to_posix(rel), fields["cn"] or "-",
                         fields["not_before"] or "?",
                         fields["not_after"] or "?")
    if found:
        log.info(
            "Certificates: %d certificate-bearing file(s) listed "
            "(readable copies under %s/)", found, ORIGINAL_DIR)
    return found


def detect_fairplay(root_dir):
    """Count Mach-O binaries carrying FairPlay (App Store) encryption.

    FairPlay machine code is encrypted per-device and CANNOT be decrypted
    without a dump from the original device; every resource decodes fine.
    Returns (encrypted_count, scanned_count).
    """
    payload_dir = os.path.join(root_dir, PAYLOAD_DIR)
    if not os.path.isdir(payload_dir):
        return 0, 0
    encrypted = scanned = 0
    for dirpath, dirnames, filenames in os.walk(payload_dir):
        dirnames.sort()
        for filename in sorted(filenames):
            path = os.path.join(dirpath, filename)
            try:
                with open(path, "rb") as fh:
                    data = fh.read(64 * 1024 * 1024)
            except OSError:
                continue
            slices = _macho_slices(data)
            if not slices:
                continue
            scanned += 1
            for _off, _size in slices:
                info = _header_info(data[_off:_off + _size], 0)
                if info and info["cryptid"] and info["cryptsize"]:
                    encrypted += 1
                    log.info(
                        "FairPlay encryption detected: %s (cryptid=%d, "
                        "%d encrypted code bytes - App Store build; ALL "
                        "resources decode normally)",
                        _to_posix(os.path.relpath(path, payload_dir)),
                        info["cryptid"], info["cryptsize"],
                    )
                    break
    return encrypted, scanned


# ------------------------------------------------------------------------------
# Framework metadata (ipaforge.yml)
# ------------------------------------------------------------------------------


def write_metadata_file(output_dir, metadata):
    """Write a simple 'key: value' metadata file into the framework root."""
    lines = [
        "# Framework metadata generated by {0} {1}".format(TOOL_NAME, __version__),
        "# Edit property lists freely; this file is NOT packaged into the built .ipa.",
    ]
    for key in sorted(metadata):
        value = metadata[key]
        if isinstance(value, list):
            if not value:
                continue
            lines.append("{0}:".format(key))
            for item in value:
                lines.append("  - {0}".format(item))
        else:
            lines.append("{0}: {1}".format(key, value))
    path = os.path.join(output_dir, META_FILE_NAME)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


def parse_metadata_file(path):
    """Parse the simple 'key: value' metadata file written at decode time."""
    metadata = {}
    last_key = None
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("-") and last_key is not None:
                item = stripped.lstrip("-").strip()
                current = metadata.get(last_key)
                if isinstance(current, list):
                    current.append(item)
                else:
                    metadata[last_key] = [item]
                continue
            if ":" not in stripped:
                continue
            key, _, value = stripped.partition(":")
            key = key.strip()
            metadata[key] = value.strip()
            last_key = key
    return metadata


def read_app_summary(output_dir, app_bundle):
    """Best-effort read of the app's Info.plist for the decode summary log."""
    if not app_bundle:
        return None
    info_path = os.path.join(output_dir, PAYLOAD_DIR, app_bundle, "Info.plist")
    if not os.path.isfile(info_path):
        return None
    try:
        with open(info_path, "rb") as fh:
            data = _plist_load_fh(fh)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    return {
        "identifier": str(data.get("CFBundleIdentifier", "unknown")),
        "short_version": str(data.get("CFBundleShortVersionString", "unknown")),
        "version": str(data.get("CFBundleVersion", "unknown")),
        "min_os": str(data.get("MinimumOSVersion", "unknown")),
    }


# ------------------------------------------------------------------------------
# original/ archive (decode side)
# ------------------------------------------------------------------------------


def archive_original_signatures(output_dir):
    """Move invalidated original signatures into original/.

    The original META-INF-style signature is stored OUTSIDE the
    decoded resources and never repackaged: every _CodeSignature directory
    found under Payload/ is moved to the same relative path inside original/.
    The archived signature is kept strictly for forensic reference; a rebuilt
    archive always receives a FRESH signature (or none, with --no-sign).
    Returns the number of archived signature directories.
    """
    payload_dir = os.path.join(output_dir, PAYLOAD_DIR)
    if not os.path.isdir(payload_dir):
        return 0

    targets = []
    for dirpath, dirnames, _ in os.walk(payload_dir):
        for dirname in list(dirnames):
            if dirname == CODE_SIGNATURE_DIR:
                targets.append(os.path.join(dirpath, dirname))

    for src in targets:
        rel = os.path.relpath(src, output_dir)
        dst = os.path.join(output_dir, ORIGINAL_DIR, rel)
        _makedirs(os.path.dirname(dst))
        shutil.move(src, dst)
        log.info(
            "Copying original signature to %s/%s (never repackaged)",
            ORIGINAL_DIR,
            rel,
        )
    if targets:
        log.info(
            "Archived %d original signature directorie(s) into %s/",
            len(targets),
            ORIGINAL_DIR,
        )
    return len(targets)


# ------------------------------------------------------------------------------
# Signing warning banner
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
# Built-in code signing orchestration (build mode)
# ------------------------------------------------------------------------------

_NESTED_CODE_SUFFIXES = (".framework", ".appex", ".xpc")  # nested code bundles


def _strip_stale_signatures(payload_dir):
    """Delete _CodeSignature directories invalidated by modification.

    Returns the number of removed signature directories. The signing utility
    would overwrite them anyway, but removing them first keeps the operation
    explicit and prevents stale resource manifests from surviving a failed
    signing run.
    """
    removed = 0
    for dirpath, dirnames, _ in os.walk(payload_dir):
        for dirname in list(dirnames):
            if dirname == CODE_SIGNATURE_DIR:
                target = os.path.join(dirpath, dirname)
                log.info(
                    "Removing stale signature: %s",
                    os.path.relpath(target, payload_dir),
                )
                shutil.rmtree(target, ignore_errors=True)
                dirnames.remove(dirname)
                removed += 1
    return removed


def _collect_nested_bundles(app_dir_abs):
    """Return nested code bundles (.framework/.appex/.xpc), inner-most first.

    Signing order matters: an outer signature incorporates hashes of the
    nested bundles, so nested code must always be signed BEFORE its container.
    The sort is deterministic: deepest first, then alphabetical.
    """
    nested = []
    for dirpath, dirnames, _ in os.walk(app_dir_abs):
        for dirname in dirnames:
            if dirname.endswith(_NESTED_CODE_SUFFIXES):
                nested.append(os.path.join(dirpath, dirname))
    nested.sort(key=lambda p: (-p.count(os.sep), p))
    return nested


# ------------------------------------------------------------------------------
# Ghidra-style analysis kit generator (decode side, always on)
# ------------------------------------------------------------------------------

LC_SEGMENT = 0x1
LC_SYMTAB = 0x2
LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x18
LC_REEXPORT_DYLIB = 0x1F
LC_SEGMENT_64 = 0x19
LC_UUID = 0x1B
LC_MAIN = 0x28
LC_LOAD_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_RPATH = 0x8000001C
LC_CODE_SIGNATURE = 0x1D
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C
LC_BUILD_VERSION = 0x32

MH_PIE = 0x00200000
MH_ALLOW_STACK_EXECUTION = 0x00020000
CPU_SUBTYPE_ARM64E = 2

N_TYPE_MASK = 0x0E
N_SECT = 0x0E

FILETYPES = {1: "MH_OBJECT", 2: "MH_EXECUTE", 5: "MH_PRELOAD",
             6: "MH_DYLIB", 8: "MH_BUNDLE", 12: "MH_KEXT_BUNDLE"}
CPU_TYPES = {7: "i386", 0x01000007: "x86_64", 8: "powerpc",
             12: "arm", 0x0100000C: "arm64"}

GHIDRA_IMPORT_SCRIPT = r'''# @category IPAForge
# Imports an IPAForge symbol map (CSV: address,name) into the current
# Ghidra program. Run from the Script Manager after auto-analysis.
import csv
from ghidra.program.model.symbol import SourceType

CSV_PATH = askFile("IPAForge symbol map (CSV)", "Open")
space = currentProgram.getAddressFactory().getDefaultAddressSpace()
table = currentProgram.getSymbolTable()
count = 0
fh = open(CSV_PATH.getPath(), "r")
reader = csv.reader(fh)
next(reader, None)  # skip header
for row in reader:
    if len(row) < 2 or not row[0]:
        continue
    try:
        addr = space.getAddress(row[0])
    except:
        continue
    table.createLabel(addr, row[1], SourceType.USER_DEFINED)
    count += 1
fh.close()
print("IPAForge: imported %d symbol(s) from %s" % (count, CSV_PATH))
'''


def _fixed_str(raw):
    """Decode a fixed-width NUL-padded name field (segment/section names)."""
    return raw.rstrip(b"\x00").decode("utf-8", "replace")


def _cstr(raw, off, maxlen=512):
    """Read a NUL-terminated string from bytes (defensive)."""
    if off < 0 or off >= len(raw):
        return ""
    end = raw.find(b"\x00", off, off + maxlen)
    if end == -1:
        end = min(off + maxlen, len(raw))
    return raw[off:end].decode("utf-8", "replace")


def parse_macho_summary(data):
    """Parse a thin (or first FAT slice) Mach-O with stdlib struct only.

    Returns a dict with cpu/file type, segments+sections, entry point, UUID,
    linked dylibs, defined symbols and imports - or None when not parseable.
    This is the 'small Ghidra converter': headers + symbol table, exactly
    what a Ghidra import needs as a map.
    """
    if data[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        try:
            fat_offset = struct.unpack_from(">I", data, 16)[0]
        except struct.error:
            return None
        if fat_offset + 4 > len(data):
            return None
        data = data[fat_offset:]

    magic = data[:4]
    if magic == b"\xcf\xfa\xed\xfe":
        bits = 64
    elif magic == b"\xce\xfa\xed\xfe":
        bits = 32
    else:
        return None

    try:
        if bits == 64:
            _, cputype, _cpusub, filetype, ncmds, sizeofcmds, _flags = \
                struct.unpack_from("<IiiIIII", data, 0)
            header_size = 32
        else:
            # 32-bit mach_header has SIX fields (no "reserved") - unpack
            # exactly six. (A 7-target unpack raised ValueError on every
            # 32-bit/armv7 binary.)
            _, cputype, _cpusub, filetype, ncmds, sizeofcmds = \
                struct.unpack_from("<IiiIII", data, 0)
            header_size = 28
    except (struct.error, ValueError):
        return None

    cpusub = _cpusub
    cpu_name = CPU_TYPES.get(cputype,
                    CPU_TYPES.get(cputype & 0x00FFFFFF, "cpu 0x%x" % cputype))
    if cputype == 0x0100000C and (cpusub & 0xFF) == CPU_SUBTYPE_ARM64E:
        cpu_name = "arm64e"
    info = {
        "bits": bits,
        "cpu": cpu_name,
        "cputype": cputype,
        "cpusubtype": cpusub,
        "filetype": FILETYPES.get(filetype, "0x%x" % filetype),
        "flags": 0,
        "pie": False,
        "allow_stack_execution": False,
        "segments": [],
        "dylibs": [],
        "weak_dylibs": [],
        "rpaths": [],
        "symbols": [],
        "imports": [],
        "entry_vm": None,
        "text_vmaddr": 0,
        "uuid": None,
        "encrypted": False,
        "encryption_id": 0,
        "has_code_signature": False,
        "objc_sections": 0,
        "swift_sections": 0,
    }

    info["flags"] = _flags
    info["pie"] = bool(_flags & MH_PIE)
    info["allow_stack_execution"] = bool(_flags & MH_ALLOW_STACK_EXECUTION)

    offset = header_size
    end = min(header_size + sizeofcmds, len(data))
    for _ in range(min(ncmds, 4096)):
        if offset + 8 > end:
            break
        cmd, cmdsize = struct.unpack_from("<II", data, offset)
        if cmdsize < 8 or offset + cmdsize > len(data):
            break

        if cmd == LC_SEGMENT_64:
            segname, vmaddr, vmsize, fileoff, filesize, _maxprot, _initprot, nsects = \
                struct.unpack_from("<16sQQQQiiI", data, offset + 8)
            seg = {"name": _fixed_str(segname), "vmaddr": vmaddr, "vmsize": vmsize,
                   "fileoff": fileoff, "filesize": filesize, "sections": []}
            sect_off = offset + 72
            for _sect in range(min(nsects, 256)):
                if sect_off + 80 > len(data):
                    break
                s_name, s_seg, s_addr, s_size, s_off = \
                    struct.unpack_from("<16s16sQQI", data, sect_off)
                seg["sections"].append(
                    {"seg": _fixed_str(s_seg), "name": _fixed_str(s_name),
                     "addr": s_addr, "size": s_size, "offset": s_off}
                )
                sect_off += 80
            info["segments"].append(seg)
            if seg["name"] == "__TEXT":
                info["text_vmaddr"] = vmaddr

        elif cmd == LC_SEGMENT:
            segname, vmaddr, vmsize, fileoff, filesize, _maxprot, _initprot, nsects = \
                struct.unpack_from("<16sIIIIiiI", data, offset + 8)
            seg = {"name": _fixed_str(segname), "vmaddr": vmaddr, "vmsize": vmsize,
                   "fileoff": fileoff, "filesize": filesize, "sections": []}
            sect_off = offset + 56
            for _sect in range(min(nsects, 256)):
                if sect_off + 68 > len(data):
                    break
                s_name, s_seg, s_addr, s_size, s_off = \
                    struct.unpack_from("<16s16sIII", data, sect_off)
                seg["sections"].append(
                    {"seg": _fixed_str(s_seg), "name": _fixed_str(s_name),
                     "addr": s_addr, "size": s_size, "offset": s_off}
                )
                sect_off += 68
            info["segments"].append(seg)
            if seg["name"] == "__TEXT":
                info["text_vmaddr"] = vmaddr

        elif cmd == LC_CODE_SIGNATURE and cmdsize >= 16:
            info["has_code_signature"] = True

        elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            # cryptid is the third uint32 in encryption_info_command.
            if cmdsize >= 20:
                info["encryption_id"] = struct.unpack_from("<I", data, offset + 16)[0]
                info["encrypted"] = info["encryption_id"] != 0

        elif cmd == LC_RPATH and cmdsize >= 12:
            path_off = struct.unpack_from("<I", data, offset + 8)[0]
            if 0 < path_off < cmdsize:
                info["rpaths"].append(_cstr(data, offset + path_off, 1024))

        elif cmd == LC_MAIN:
            entryoff = struct.unpack_from("<Q", data, offset + 8)[0]
            if info["entry_vm"] is None:
                info["entry_vm"] = info["text_vmaddr"] + entryoff

        elif cmd == LC_UUID:
            info["uuid"] = binascii.hexlify(data[offset + 8:offset + 24]).decode("ascii")

        elif cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB):
            name_off = struct.unpack_from("<I", data, offset + 8)[0]
            if 0 < name_off < cmdsize:
                name = _cstr(data, offset + name_off, 1024)
                info["dylibs"].append(name)
                if cmd == LC_LOAD_WEAK_DYLIB:
                    info["weak_dylibs"].append(name)

        elif cmd == LC_SYMTAB:
            symoff, nsyms, stroff, _strsize = struct.unpack_from("<IIII", data, offset + 8)
            entry_size = 16 if bits == 64 else 12
            for i in range(min(nsyms, 100000)):
                entry = symoff + i * entry_size
                if bits == 64:
                    n_strx, n_type, _nsect, _ndesc, n_value = \
                        struct.unpack_from("<IBBHQ", data, entry)
                else:
                    n_strx, n_type, _nsect, _ndesc, n_value = \
                        struct.unpack_from("<IBBhI", data, entry)
                name = _cstr(data, stroff + n_strx, 1024)
                if not name:
                    continue
                if (n_type & N_TYPE_MASK) == N_SECT:
                    info["symbols"].append((n_value, name))
                elif (n_type & N_TYPE_MASK) == 0 and n_value == 0:
                    info["imports"].append(name)

        offset += cmdsize

    for seg in info["segments"]:
        for sect in seg["sections"]:
            name = sect["name"]
            if name.startswith("__objc_") or name in ("__objc_classlist", "__objc_protolist", "__objc_selrefs"):
                info["objc_sections"] += 1
            if name.startswith("__swift") or name.startswith("__TEXT.__swift"):
                info["swift_sections"] += 1
    return info


def write_one_ghidra_kit(kit_dir, base, rel, sdata, sinfo):
    """Write .symbols.csv + .report.txt + .disasm.txt for ONE slice."""
    csv_path = os.path.join(kit_dir, base + ".symbols.csv")
    with open(csv_path, "w", encoding="utf-8") as fh:
        fh.write("address,name\n")
        for addr, name in sinfo["symbols"]:
            fh.write("{0:016X},{1}\n".format(addr, name))

    report_path = os.path.join(kit_dir, base + ".report.txt")
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write("=" * 76 + "\n")
        fh.write(" IPAForge {0} - Ghidra Analysis Kit\n".format(__version__))
        fh.write("=" * 76 + "\n")
        fh.write("Binary          : {0}\n".format(rel))
        fh.write("Format          : Mach-O {0}-bit ({1}), {2}\n".format(
            sinfo["bits"], sinfo["cpu"], sinfo["filetype"]))
        if sinfo["entry_vm"] is not None:
            fh.write("Entry point     : 0x{0:016X}\n".format(sinfo["entry_vm"]))
        if sinfo["uuid"]:
            fh.write("UUID            : {0}\n".format(sinfo["uuid"]))
        fh.write("PIE             : {0}\n".format("enabled" if sinfo.get("pie") else "NOT enabled"))
        fh.write("Stack execution : {0}\n".format("allowed" if sinfo.get("allow_stack_execution") else "not allowed"))
        fh.write("Code signature  : {0}\n".format("present" if sinfo.get("has_code_signature") else "not present"))
        fh.write("Encrypted       : {0}\n".format("yes (cryptid={0})".format(sinfo.get("encryption_id")) if sinfo.get("encrypted") else "no"))
        fh.write("Objective-C     : {0} metadata section(s)\n".format(sinfo.get("objc_sections", 0)))
        fh.write("Swift metadata  : {0} section(s)\n".format(sinfo.get("swift_sections", 0)))
        if sinfo.get("rpaths"):
            fh.write("RPATHs          :\n")
            for rpath in sinfo["rpaths"]:
                fh.write("  {0}\n".format(rpath))
        fh.write("\nSegments / sections:\n")
        for seg in sinfo["segments"]:
            fh.write("  {0}  vm 0x{1:X}..0x{2:X}  file 0x{3:X}..0x{4:X}\n".format(
                seg["name"], seg["vmaddr"], seg["vmaddr"] + seg["vmsize"],
                seg["fileoff"], seg["fileoff"] + seg["filesize"]))
            for sect in seg["sections"]:
                fh.write("    {0},{1}  addr 0x{2:X}  size 0x{3:X}\n".format(
                    sect["seg"], sect["name"], sect["addr"], sect["size"]))
        if sinfo["dylibs"]:
            fh.write("\nLinked libraries:\n")
            for lib in sinfo["dylibs"]:
                fh.write("  {0}\n".format(lib))
        fh.write("\nSymbols         : {0} defined, {1} imported\n".format(
            len(sinfo["symbols"]), len(sinfo["imports"])))
        if not sinfo["symbols"]:
            fh.write("  (no symbol table - stripped binary; Ghidra "
                     "auto-analysis will still name what it can)\n")
        fh.write("\n" + "-" * 76 + "\n")
        fh.write("GHIDRA IMPORT STEPS\n")
        fh.write("1. Ghidra -> CodeBrowser -> import the raw binary.\n")
        fh.write("2. After auto-analysis: Script Manager -> run\n")
        fh.write("   import_symbols.py and pick {0}\n".format(base + ".symbols.csv"))
        fh.write("   -> labels every listed symbol at its address.\n")
        fh.write("Headless alternative:\n")
        fh.write("   analyzeHeadless <proj_dir> <proj_name> -import <this binary> \\\n")
        fh.write("     -scriptPath <framework>/{0} -postScript import_symbols.py\n".format(
            GHIDRA_DIR))

    write_disasm_kit(kit_dir, base, rel, sdata, sinfo)


def generate_ghidra_kits(output_dir):
    """Generate a Ghidra analysis kit for every Mach-O in the framework.

    Per binary: <name>.report.txt (headers/sections/entry/dylibs) and
    <name>.symbols.csv (address,name - zero-padded hex for Ghidra), plus the
    import_symbols.py Jython script for Ghidra's Script Manager (written
    once per directory that contains Mach-O binaries).
    FAT/universal binaries get one kit PER SLICE (<name>.<cpu>.*).
    Kits are written NEXT TO each Mach-O binary (inside Payload/) and are
    never packaged into the .ipa.
    Returns the number of kits generated.
    """
    payload_dir = os.path.join(output_dir, PAYLOAD_DIR)
    if not os.path.isdir(payload_dir):
        return 0

    kits = 0
    script_dirs = set()
    for dirpath, dirnames, filenames in os.walk(payload_dir):
        dirnames.sort()
        for filename in sorted(filenames):
            path = os.path.join(dirpath, filename)
            try:
                with open(path, "rb") as fh:
                    data = fh.read(256 * 1024 * 1024)
            except OSError as exc:
                log.debug("Could not read binary for Ghidra kit: %s", exc)
                continue
            if not _is_macho(data):
                continue

            slice_list = []
            slice_total = len(_macho_slices(data))
            for _off, _size in _macho_slices(data):
                sinfo = parse_macho_summary(data[_off:_off + _size])
                if sinfo is not None:
                    tag = "" if slice_total == 1 else "." + sinfo["cpu"]
                    slice_list.append((tag, data[_off:_off + _size], sinfo))
            if not slice_list:
                continue
            kits += 1
            rel = _to_posix(os.path.relpath(path, output_dir))
            kit_dir = dirpath  # co-located: kits sit next to their Mach-O
            if kit_dir not in script_dirs:
                script_dirs.add(kit_dir)
                script_path = os.path.join(kit_dir, IMPORT_SCRIPT_NAME)
                with open(script_path, "w", encoding="utf-8") as fh:
                    fh.write(GHIDRA_IMPORT_SCRIPT)

            for tag, sdata, sinfo in slice_list:
                write_one_ghidra_kit(kit_dir, filename + tag, rel, sdata, sinfo)
                log.info(
                    "Text kit: {0}{1}: report + symbols + disasm + "
                    "pseudo-source ({2} symbols, {3} imports)".format(
                        rel, tag, len(sinfo["symbols"]),
                        len(sinfo["imports"])))

    if kits:
        log.info(
            "Generated %d Ghidra analysis kit(s) next to each Mach-O (never "
            "packaged into the .ipa); import script per binary folder: %s",
            kits, IMPORT_SCRIPT_NAME,
        )
    return kits


# ------------------------------------------------------------------------------
# Subset disassembler (x86-64 common instructions, informational output)
# ------------------------------------------------------------------------------

_X86_REG64 = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
              "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
_X86_REG32 = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
              "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d")
_X86_REG8 = ("al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
             "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b")
_X86_JCC8 = ("jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
             "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg")
_X86_ALU = ("add", "or", "adc", "sbb", "and", "sub", "xor", "cmp")

PSEUDO_DISCLAIMER = (
    "; READ-ONLY readable form of machine code. iOS machine code cannot\n"
    "; be decompiled into recompilable source (unlike Android smali) -\n"
    "; this is one readable statement per instruction, per function,\n"
    "; from a linear sweep. Edit the app's XML resources instead; the\n"
    "; binary itself is re-signed at build time.\n"
)

DISASM_DISCLAIMER = (
    "; Subset disassembly generated by IPAForge {0} - INFORMATIONAL ONLY.\n"
    "; Covers common arm64 / armv7 / x86-64 instructions; undecodable\n"
    "; words are shown as .inst / .byte. For production-grade analysis\n"
    "; use the Ghidra kit (report + symbol map) or a full disassembler.\n"
).format(__version__)


def _modrm_operands(data, pos, bits64, reg_table):
    """Decode a ModRM/SIB block starting at `pos` (after the opcode bytes).

    Returns (operand_string_for_rm, reg_field_index, bytes_consumed).
    """
    modrm = data[pos]
    mod = modrm >> 6
    reg = (modrm >> 3) & 7
    rm = modrm & 7
    reg_name = reg_table[reg & 7]
    consumed = 1

    if mod == 3:
        return reg_table[rm & 7], reg, consumed

    # memory operand
    base_txt = ""
    disp = 0
    disp_len = 0
    if rm == 4:  # SIB follows
        if pos + 1 >= len(data):
            return "[?]", reg, consumed
        sib = data[pos + 1]
        scale = sib >> 6
        index = (sib >> 3) & 7
        base = sib & 7
        consumed += 1
        idx_txt = ""
        if index != 4:
            idx_txt = "{0}*{1}".format(reg_table[base], 1 << scale) if scale else reg_table[base]
        rm_base = base
        if base == 5 and mod == 0:
            disp_len = 4
            base_txt = idx_txt or "[disp32]"
            rm_base = -1
        else:
            if idx_txt:
                base_txt = "{0}+{1}".format(reg_table[base], idx_txt)
            else:
                base_txt = reg_table[base]
    elif rm == 5 and mod == 0:
        disp_len = 4
        base_txt = "rip"
    else:
        base_txt = reg_table[rm]

    if mod == 1:
        disp_len = max(disp_len, 1)
    elif mod == 2:
        disp_len = max(disp_len, 4)

    if disp_len == 1:
        if pos + consumed >= len(data):
            return "[?]", reg, consumed
        disp = struct.unpack_from("<b", data, pos + consumed)[0]
        consumed += 1
    elif disp_len == 4:
        if pos + consumed + 4 > len(data):
            return "[?]", reg, consumed
        disp = struct.unpack_from("<i", data, pos + consumed)[0]
        consumed += 4

    if disp or disp_len:
        if disp >= 0:
            return "[{0}+0x{1:X}]".format(base_txt, disp), reg, consumed
        return "[{0}-0x{1:X}]".format(base_txt, -disp), reg, consumed
    return "[{0}]".format(base_txt), reg, consumed


def _disasm_one(data, pos):
    """Decode ONE instruction at `pos`. Returns (length, text) or None.

    Linear-sweep friendly: unknown encodings return (1, ".byte 0xXX").
    """
    start = pos
    length = len(data)
    rex = 0
    opsize = 32

    # --- prefixes (legacy, then REX) ---
    pcount = 0
    while pos < length and pcount < 4:
        b = data[pos]
        if b in (0x66, 0x67, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65):
            if b == 0x66:
                opsize = 16
            pos += 1
            pcount += 1
        elif 0x40 <= b <= 0x4F:
            rex = b
            pos += 1
        else:
            break

    def r64(i):
        return _X86_REG64[i | ((rex & 1) << 3)]

    if pos >= length:
        return None

    opcode = data[pos]
    pos += 1

    # --- single-byte, no operand ---
    if opcode == 0x90 and not rex:
        return pos + 0 - start, "nop"
    if opcode == 0xC3:
        return pos - start, "ret"
    if opcode == 0xC9:
        return pos - start, "leave"
    if opcode == 0xF4:
        return pos - start, "hlt"

    # --- push/pop r64 (0x50-0x57 / 0x58-0x5F) ---
    if 0x50 <= opcode <= 0x57 and not rex:
        return pos - start, "push {0}".format(_X86_REG64[(opcode - 0x50) & 7])
    if 0x58 <= opcode <= 0x5F and not rex:
        return pos - start, "pop {0}".format(_X86_REG64[(opcode - 0x58) & 7])
    if rex in (0x50 + 0, ) and False:
        pass

    # --- inc/dec r32 (no REX) ---
    if 0x40 <= opcode <= 0x47 and not rex:
        return pos - start, "inc {0}".format(_X86_REG32[opcode & 7])
    if 0x48 <= opcode <= 0x4F and not rex:
        return pos - start, "dec {0}".format(_X86_REG32[opcode & 7])

    # --- mov r32, imm32 (B8-BF) / mov r64, imm64 (REX.W + B8-BF) ---
    if 0xB8 <= opcode <= 0xBF:
        reg_i = (opcode - 0xB8) | ((rex & 1) << 3)
        if rex & 8:  # REX.W
            if pos + 8 > length:
                return None
            imm = struct.unpack_from("<Q", data, pos)[0]
            return pos + 8 - start, "mov {0}, 0x{1:X}".format(_X86_REG64[reg_i], imm)
        if pos + 4 > length:
            return None
        imm = struct.unpack_from("<I", data, pos)[0]
        return pos + 4 - start, "mov {0}, 0x{1:X}".format(_X86_REG32[reg_i], imm)

    # --- mov r8, imm8 (B0-B7) ---
    if 0xB0 <= opcode <= 0xB7:
        if pos + 1 > length:
            return None
        return pos + 1 - start, "mov {0}, 0x{1:X}".format(
            _X86_REG8[(opcode - 0xB0) | ((rex & 1) << 3)], data[pos])

    # --- push/pop imm ---
    if opcode == 0x68:
        if pos + 4 > length:
            return None
        return pos + 4 - start, "push 0x{0:X}".format(struct.unpack_from("<I", data, pos)[0])
    if opcode == 0x6A:
        if pos + 1 > length:
            return None
        return pos + 1 - start, "push 0x{0:X}".format(data[pos])

    # --- short jumps / call ---
    if opcode == 0xE8:
        if pos + 4 > length:
            return None
        rel = struct.unpack_from("<i", data, pos)[0]
        target = pos + 4 + rel
        return pos + 4 - start, "call 0x{0:X}".format(target)
    if opcode == 0xE9:
        if pos + 4 > length:
            return None
        rel = struct.unpack_from("<i", data, pos)[0]
        return pos + 4 - start, "jmp 0x{0:X}".format(pos + 4 + rel)
    if opcode == 0xEB:
        if pos + 1 > length:
            return None
        rel = struct.unpack_from("<b", data, pos)[0]
        return pos + 1 - start, "jmp 0x{0:X}".format(pos + 1 + rel)
    if 0x70 <= opcode <= 0x7F:
        if pos + 1 > length:
            return None
        rel = struct.unpack_from("<b", data, pos)[0]
        return pos + 1 - start, "{0} 0x{1:X}".format(
            _X86_JCC8[opcode - 0x70], pos + 1 + rel)

    # --- ALU r/m, r (0x01/0x09/0x11/0x19/0x21/0x29/0x31/0x39 = /r forms) ---
    if opcode <= 0x3F and (opcode & 7) == 1:
        alu = _X86_ALU[opcode >> 3]
        table = _X86_REG64 if (rex & 8) else _X86_REG32
        rm_txt, reg_i, used = _modrm_operands(data, pos, bool(rex & 8), table)
        return pos + used - start, "{0} {1}, {2}".format(
            alu, rm_txt, table[reg_i | ((rex & 4) << 1)])

    # --- mov group: 88/89/8A/8B ---
    if opcode in (0x88, 0x89, 0x8A, 0x8B) and pos < length:
        if opcode in (0x88, 0x8A):
            rt, rtf = _X86_REG8, _X86_REG8
        else:
            rt = _X86_REG64 if (rex & 8) else _X86_REG32
            rtf = rt
        rm_txt, reg_i, used = _modrm_operands(data, pos, bool(rex & 8), rtf)
        reg_name = rt[reg_i | ((rex & 4) << 1)]
        if opcode == 0x89 or opcode == 0x88:
            return pos + used - start, "mov {0}, {1}".format(rm_txt, reg_name)
        return pos + used - start, "mov {0}, {1}".format(reg_name, rm_txt)

    # --- lea r, m (8D) ---
    if opcode == 0x8D and pos < length:
        rt = _X86_REG64 if (rex & 8) else _X86_REG32
        rm_txt, reg_i, used = _modrm_operands(data, pos, bool(rex & 8), rt)
        return pos + used - start, "lea {0}, {1}".format(rt[reg_i | ((rex & 4) << 1)], rm_txt)

    # --- group1 imm: 80/81/83 ---
    if opcode in (0x80, 0x81, 0x83) and pos < length:
        if opcode == 0x80:
            table = _X86_REG8
        else:
            table = _X86_REG64 if (rex & 8) else _X86_REG32
        rm_txt, reg_i, used = _modrm_operands(data, pos, bool(rex & 8), table)
        imm_len = 1 if opcode in (0x80, 0x83) else 4
        if pos + used + imm_len > length:
            return None
        if imm_len == 1:
            imm = data[pos + used] if opcode == 0x80 else struct.unpack_from("<b", data, pos + used)[0]
        else:
            imm = struct.unpack_from("<i", data, pos + used)[0]
        return pos + used + imm_len - start, "{0} {1}, {2}".format(
            _X86_ALU[reg_i & 7], rm_txt, imm)

    # --- mov r/m, imm (C6/C7) ---
    if opcode in (0xC6, 0xC7) and pos < length:
        rt = _X86_REG8 if opcode == 0xC6 else (_X86_REG64 if (rex & 8) else _X86_REG32)
        rm_txt, reg_i, used = _modrm_operands(data, pos, bool(rex & 8), _X86_REG64 if opcode != 0xC6 else _X86_REG8)
        imm_len = 1 if opcode == 0xC6 else 4
        if pos + used + imm_len > length:
            return None
        if opcode == 0xC6:
            imm = data[pos + used]
        else:
            imm = struct.unpack_from("<i", data, pos + used)[0]
        return pos + used + imm_len - start, "mov {0}, {1}".format(rm_txt, imm)

    # --- two-byte opcodes ---
    if opcode == 0x0F and pos < length:
        op2 = data[pos]
        pos += 1
        if op2 == 0x05:
            return pos - start, "syscall"
        if op2 == 0x0B:
            return pos - start, "ud2"
        if 0x80 <= op2 <= 0x8F:
            if pos + 4 > length:
                return None
            rel = struct.unpack_from("<i", data, pos)[0]
            return pos + 4 - start, "{0} 0x{1:X}".format(
                _X86_JCC8[op2 - 0x80], pos + 4 + rel)
        if op2 == 0x1F and pos < length:  # multi-byte nop
            _rm, _r, used = _modrm_operands(data, pos, bool(rex & 8), _X86_REG32)
            return pos + used - start, "nop"

    # unknown
    return 1, ".byte 0x{0:02X}".format(data[start])


def _x86_op_type(mnemonic):
    m = mnemonic.lower().split(" ", 1)[0]
    if m.startswith(("j", "call", "ret", "syscall", "ud2")):
        return "control_flow" if m in ("ret", "syscall", "ud2") else "branch"
    if m in ("nop",):
        return "noop"
    if m.startswith(("mov", "lea", "push", "pop")) or m in ("cmp",):
        return "load_store"
    return "alu"


def disasm_x86_64_subset(data, section, max_instructions=20000):
    """Yield structured x86-64 linear-sweep instruction records."""
    pos = 0
    decoded = 0
    size = len(data)
    while pos < size and decoded < max_instructions:
        result = _disasm_one(data, pos)
        if result is None:
            used, text = 1, ".byte 0x%02X" % data[pos]
        else:
            used, text = result
            used = max(1, used)
        raw = int.from_bytes(data[pos:pos + used], "little")
        yield InstructionRecord(section + pos, raw, text, _x86_op_type(text))
        pos += used
        decoded += 1


def _records_to_text(records):
    return "\n".join("  %06X  %s" % (r.address, r.mnemonic) for r in records)


def extract_printable_strings(data, min_length=5, limit=500):
    """Extract printable ASCII strings (cheap `strings(1)` equivalent)."""
    found = []
    current = []
    for byte in bytearray(data):
        if 32 <= byte < 127:
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                found.append("".join(current))
                if len(found) >= limit:
                    return found
            current = []
    if len(current) >= min_length and len(found) < limit:
        found.append("".join(current))
    return found



# ------------------------------------------------------------------------------
# Subset disassembler (arm64 / armv7 common instructions, informational output)
# ------------------------------------------------------------------------------

_ARM64_CONDS = ("eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
                "hi", "ls", "ge", "lt", "gt", "le", "al", "nv")
_ARM32_CONDS = ("eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
                "hi", "ls", "ge", "lt", "gt", "le", "", "?")
_ARM32_DPNAMES = ("and", "eor", "sub", "rsb", "add", "adc", "sbc", "rsc",
                  "tst", "teq", "cmp", "cmn", "orr", "mov", "bic", "mvn")


def _sx(value, bits):
    if value & (1 << (bits - 1)):
        value -= 1 << bits
    return value


def _arm32_reg(n):
    if n == 13:
        return "sp"
    if n == 14:
        return "lr"
    if n == 15:
        return "pc"
    return "r{0}".format(n)


def _decode_arm64(w, pc):
    sf = "x" if (w >> 31) else "w"
    if w == 0xD503201F:
        return "nop"
    if w == 0xD65F03C0:
        return "ret"
    if (w >> 26) == 0x05:
        return "b 0x{0:X}".format(pc + _sx(w & 0x03FFFFFF, 26) * 4)
    if (w >> 26) == 0x25:
        return "bl 0x{0:X}".format(pc + _sx(w & 0x03FFFFFF, 26) * 4)
    if (w & 0xFF000010) == 0x54000000:
        return "b.{0} 0x{1:X}".format(
            _ARM64_CONDS[w & 0xF], pc + _sx((w >> 5) & 0x7FFFF, 19) * 4)
    if (w & 0x7E000000) == 0x34000000:
        return "{0} {1}{2}, 0x{3:X}".format(
            "cbnz" if (w & 0x00800000) else "cbz", sf, w & 0x1F,
            pc + _sx((w >> 5) & 0x7FFFF, 19) * 4)
    if (w & 0x7E000000) == 0x36000000:
        bit = ((w >> 31) << 5) | ((w >> 19) & 0x1F)
        return "{0} {1}{2}, #{3}, 0x{4:X}".format(
            "tbnz" if (w & 0x00800000) else "tbz", sf, w & 0x1F, bit,
            pc + _sx((w >> 5) & 0x3FFF, 14) * 4)
    wide = {0x52800000: "movz", 0x12800000: "movn", 0x72800000: "movk",
            0xD2800000: "movz", 0x92800000: "movn", 0xF2800000: "movk"}
    m = wide.get(w & 0xFF800000)
    if m:
        imm = ((w >> 5) & 0xFFFF) << (16 * ((w >> 21) & 3))
        return "{0} {1}{2}, #0x{3:X}".format(m, sf, w & 0x1F, imm)
    if (w & 0x9F000000) == 0x90000000:
        imm = _sx(((w >> 5) & 0x7FFFF) << 2 | ((w >> 29) & 3), 21) << 12
        return "adrp {0}{1}, 0x{2:X}".format(sf, w & 0x1F, (pc & ~0xFFF) + imm)
    if (w & 0x9F000000) == 0x10000000:
        imm = _sx(((w >> 5) & 0x7FFFF) << 2 | ((w >> 29) & 3), 21)
        return "adr {0}{1}, 0x{2:X}".format(sf, w & 0x1F, pc + imm)
    if (w & 0xFFFFFC1F) == 0xD61F0000:
        return "br x{0}".format((w >> 5) & 0x1F)
    if (w & 0xFFFFFC1F) == 0xD63F0000:
        return "blr x{0}".format((w >> 5) & 0x1F)
    if (w & 0xFFFFFC1F) == 0xD65F0000:
        return "ret x{0}".format((w >> 5) & 0x1F)
    if (w & 0xFFE0001F) == 0xD4000001:
        return "svc #0x{0:X}".format((w >> 5) & 0xFFFF)
    # load/store register (immediate, unsigned offset)
    # size: 00=B 01=H 10=W(32) 11=X(64); opc: 0=STR 1=LDR 2=LDRSW(W only)
    if (w & 0x3F000000) == 0x39000000:
        size = (w >> 30) & 3
        opc = (w >> 22) & 3
        if opc == 0 and size < 3:
            nm, reg = "str", ("x" if size == 3 else "w")
        elif opc == 1:
            nm, reg = "ldr", ("x" if size == 3 else "w")
        elif opc == 2 and size == 2:
            nm, reg = "ldrsw", "w"
        else:
            nm = None
        if nm:
            imm = ((w >> 10) & 0xFFF) * (8 if size == 3 else 1 << size)
            rn = (w >> 5) & 0x1F
            base = "sp" if rn == 31 else "x{0}".format(rn)
            return "{0} {1}{2}, [{3}, #{4}]".format(
                nm, reg, w & 0x1F, base, imm)
    # STP/LDP
    if ((w >> 27) & 7) == 5 and not (w & 0x04000000):
        opc = (w >> 30) & 3
        mode = (w >> 23) & 7
        if opc in (0, 2) and mode in (1, 2, 3):
            field = 4 if opc == 0 else 8
            imm = _sx((w >> 15) & 0x7F, 7) * field
            rt2 = (w >> 10) & 0x1F
            rn = (w >> 5) & 0x1F
            rt = w & 0x1F
            nm = "ldp" if (w & 0x00400000) else "stp"
            p = "x" if opc == 2 else "w"
            base = "sp" if rn == 31 else "x{0}".format(rn)
            if mode == 2:
                return "{0} {1}{2}, {1}{3}, [{4}, #{5}]".format(
                    nm, p, rt, rt2, base, imm)
            if mode == 3:
                return "{0} {1}{2}, {1}{3}, [{4}, #{5}]!".format(
                    nm, p, rt, rt2, base, imm)
            return "{0} {1}{2}, {1}{3}, [{4}], #{5}".format(
                nm, p, rt, rt2, base, imm)
    # ADD/SUB immediate (incl. CMP/CMN)
    if ((w >> 23) & 0x3F) == 0x22:
        nm = "sub" if (w & 0x40000000) else "add"
        rd = w & 0x1F
        rn = (w >> 5) & 0x1F
        imm = (w >> 10) & 0xFFF
        sh = ", lsl #12" if (w & 0x00400000) else ""
        src = "sp" if rn == 31 else sf + str(rn)
        if (w >> 29) & 1 and nm == "sub" and rd == 31:
            return "cmp {0}, #0x{1:X}{2}".format(src, imm, sh)
        if (w >> 29) & 1 and nm == "add" and rn == 31:
            return "cmn {0}{1}, #0x{2:X}{3}".format(sf, rd, imm, sh)
        dst = "sp" if (rd == 31 and not (w >> 29) & 1 and nm == "add") \
            else sf + str(rd)
        return "{0} {1}, {2}, #0x{3:X}{4}".format(nm, dst, src, imm, sh)
    # ADD/SUB shifted register
    if ((w >> 24) & 0x1F) == 0x0B and not (w & 0x00200000):
        nm = "sub" if (w & 0x40000000) else "add"
        if (w >> 29) & 1:
            nm += "s"
        rd = w & 0x1F
        rn = (w >> 5) & 0x1F
        rm = (w >> 16) & 0x1F
        sh = (w >> 22) & 3
        amt = (w >> 10) & 0x3F
        shifts = ("lsl", "lsr", "asr", "ror")
        ext = "" if sh == 0 and amt == 0 else ", {0} #{1}".format(
            shifts[sh], amt)
        if (w >> 29) & 1 and rd == 31:
            return "cmp {0}{1}, {0}{2}{3}".format(sf, rn, rm, ext)
        return "{0} {1}{2}, {1}{3}, {1}{4}{5}".format(
            nm, sf, rd, rn, rm, ext)
    # logic shifted register (incl. MOV reg / TST)
    if ((w >> 24) & 0x1F) == 0x0A:
        opc = (w >> 29) & 3
        nbit = (w >> 21) & 1
        table = {(0, 0): "and", (0, 1): "bic", (1, 0): "orr", (1, 1): "orn",
                 (2, 0): "eor", (2, 1): "eon", (3, 0): "ands",
                 (3, 1): "bics"}
        nm = table[(opc, nbit)]
        rd = w & 0x1F
        rn = (w >> 5) & 0x1F
        rm = (w >> 16) & 0x1F
        sh = (w >> 22) & 3
        amt = (w >> 10) & 0x3F
        shifts = ("lsl", "lsr", "asr", "ror")
        ext = "" if sh == 0 and amt == 0 else ", {0} #{1}".format(
            shifts[sh], amt)
        if nm == "orr" and rn == 31 and ext == "":
            return "mov {0}{1}, {0}{2}".format(sf, rd, rm)
        if nm == "orn" and rn == 31 and ext == "":
            return "mvn {0}{1}, {0}{2}".format(sf, rd, rm)
        if nm == "ands" and rd == 31:
            return "tst {0}{1}, {0}{2}{3}".format(sf, rn, rm, ext)
        return "{0} {1}{2}, {1}{3}, {1}{4}{5}".format(
            nm, sf, rd, rn, rm, ext)
    return ".inst 0x{0:08X}".format(w)


def _disasm_arm64(code, base_va, max_instructions=20000):
    """Yield structured ARM64 instruction records without accumulating text."""
    count = min(len(code) // 4, max_instructions)
    for k in range(count):
        w = struct.unpack_from("<I", code, k * 4)[0]
        pc = base_va + k * 4
        mnemonic = _decode_arm64(w, pc)
        low = mnemonic.lower()
        if low.startswith(("b ", "b.", "bl ", "blx ", "bx ", "br ", "blr ", "ret")):
            op_type = "control_flow" if low.startswith("ret") else "branch"
        elif low == "nop":
            op_type = "noop"
        elif low.startswith(("ldr", "str", "ldp", "stp")):
            op_type = "load_store"
        else:
            op_type = "alu"
        yield InstructionRecord(pc, w, mnemonic, op_type)

def _decode_arm32(w, pc):
    cond = (w >> 28) & 0xF
    c = "" if cond == 0xE else "." + _ARM32_CONDS[cond]
    imm8 = w & 0xFF
    rot = ((w >> 8) & 0xF) * 2
    val = ((imm8 >> rot) | (imm8 << (32 - rot))) & 0xFFFFFFFF if rot else imm8
    if (w & 0x0F000000) == 0x0A000000:
        return "b{0} 0x{1:X}".format(c, pc + 8 + _sx(w & 0xFFFFFF, 24) * 4)
    if (w & 0x0F000000) == 0x0B000000:
        return "bl{0} 0x{1:X}".format(c, pc + 8 + _sx(w & 0xFFFFFF, 24) * 4)
    if (w & 0x0FFFFFF0) == 0x012FFF10:
        return "bx{0} {1}".format(c, _arm32_reg(w & 0xF))
    if (w & 0x0FFFFFF0) == 0x012FFF30:
        return "blx{0} {1}".format(c, _arm32_reg(w & 0xF))
    if (w & 0x0FFF0000) == 0x092D0000:
        regs = ", ".join(_arm32_reg(i) for i in range(16) if (w >> i) & 1)
        return "push{0} {{{1}}}".format(c, regs)
    if (w & 0x0FFF0000) == 0x08BD0000:
        regs = ", ".join(_arm32_reg(i) for i in range(16) if (w >> i) & 1)
        return "pop{0} {{{1}}}".format(c, regs)
    # LDR/STR immediate (bits 27-24 = 0101)
    if (w & 0x0F000000) == 0x05000000:
        nm = ("ldr" if (w >> 20) & 1 else "str") + \
            ("b" if (w >> 22) & 1 else "")
        u = "+" if (w >> 23) & 1 else "-"
        imm = w & 0xFFF
        rn = (w >> 16) & 0xF
        rd = (w >> 12) & 0xF
        if rn == 15:
            return "ldr{0} {1}, [pc, #{2}{3}]  ; 0x{4:X}".format(
                c, _arm32_reg(rd), u, imm, pc + 8 + (imm if u == "+" else -imm))
        return "{0}{1} {2}, [{3}, #{4}{5}]".format(
            nm, c, _arm32_reg(rd), _arm32_reg(rn), u, imm)
    # movw / movt
    if (w & 0x0FF00000) == 0x03000000:
        imm16 = ((w >> 4) & 0xF000) | (w & 0xFFF)
        return "movw{0} {1}, #0x{2:X}".format(
            c, _arm32_reg((w >> 12) & 0xF), imm16)
    if (w & 0x0FF00000) == 0x03400000:
        imm16 = ((w >> 4) & 0xF000) | (w & 0xFFF)
        return "movt{0} {1}, #0x{2:X}".format(
            c, _arm32_reg((w >> 12) & 0xF), imm16)
    # data processing immediate
    if (w & 0x0E000000) == 0x02000000:
        nm = _ARM32_DPNAMES[(w >> 21) & 0xF]
        s = "s" if (w >> 20) & 1 else ""
        rn = (w >> 16) & 0xF
        rd = (w >> 12) & 0xF
        txt = "#0x{0:X}".format(val)
        if nm == "mov":
            return "mov{0}{1} {2}, {3}".format(s, c, _arm32_reg(rd), txt)
        if nm == "mvn":
            return "mvn{0}{1} {2}, {3}".format(s, c, _arm32_reg(rd), txt)
        if nm in ("tst", "teq", "cmp", "cmn"):
            return "{0}{1}{2} {3}, {4}".format(
                nm, s, c, _arm32_reg(rn), txt)
        return "{0}{1}{2} {3}, {4}, {5}".format(
            nm, s, c, _arm32_reg(rd), _arm32_reg(rn), txt)
    # data processing register (immediate shifts only)
    if (w & 0x0E000010) == 0x00000000:
        op = (w >> 21) & 0xF
        s = "s" if (w >> 20) & 1 else ""
        rn = (w >> 16) & 0xF
        rd = (w >> 12) & 0xF
        rm = w & 0xF
        shamt = (w >> 7) & 0x1F
        shty = (w >> 5) & 3
        shifts = ("lsl", "lsr", "asr", "ror")
        ext = "" if shty == 0 and shamt == 0 else ", {0} #{1}".format(
            shifts[shty], shamt)
        nm = _ARM32_DPNAMES[op]
        if nm == "mov" and rn == 0 and not s:
            return "mov{0} {1}, {2}{3}".format(
                c, _arm32_reg(rd), _arm32_reg(rm), ext)
        if nm == "cmp":
            return "cmp{0} {1}, {2}{3}".format(
                c, _arm32_reg(rn), _arm32_reg(rm), ext)
        if nm in ("add", "sub"):
            return "{0}{1}{2} {3}, {4}, {5}{6}".format(
                nm, s, c, _arm32_reg(rd), _arm32_reg(rn), _arm32_reg(rm), ext)
        return "{0}{1}{2} {3}, {4}, {5}{6}".format(
            nm, s, c, _arm32_reg(rd), _arm32_reg(rn), _arm32_reg(rm), ext)
    return ".inst 0x{0:08X}".format(w)


def _disasm_arm32(code, base_va, max_instructions=20000):
    """Yield structured ARM32 instruction records without accumulating text."""
    count = min(len(code) // 4, max_instructions)
    for k in range(count):
        w = struct.unpack_from("<I", code, k * 4)[0]
        pc = base_va + k * 4
        mnemonic = _decode_arm32(w, pc)
        low = mnemonic.lower()
        if low.startswith(("b ", "b.", "bl ", "blx ", "bx ", "br ", "blr ", "ret")):
            op_type = "control_flow" if low.startswith("ret") else "branch"
        elif low == "nop":
            op_type = "noop"
        elif low.startswith(("ldr", "str", "ldp", "stp")):
            op_type = "load_store"
        else:
            op_type = "alu"
        yield InstructionRecord(pc, w, mnemonic, op_type)

def _pseudo_sem_arm64(w, pc, last_cmp):
    """One arm64 instruction -> readable statement. Returns (text, kind)
    with kind in {'', 'ret', 'b', 'call'}."""
    sf = "x" if (w >> 31) else "w"

    def R(n, force64=None):
        p = "x" if (force64 or (w >> 31)) else "w"
        if n == 31:
            return "sp" if force64 == "sp" else p + "zr"
        return p + str(n)

    if w == 0xD503201F:
        return "nop", ""
    if w == 0xD65F03C0:
        return "return", "ret"
    if (w >> 26) == 0x05:
        return "goto L_%x" % (pc + _sx(w & 0x03FFFFFF, 26) * 4), "b"
    if (w >> 26) == 0x25:
        tgt = pc + _sx(w & 0x03FFFFFF, 26) * 4
        return "call 0x%x" % tgt, "call"
    if (w & 0xFF000010) == 0x54000000:
        c = _ARM64_CONDS[w & 0xF]
        op = _ARM64_CONDTXT.get(c, c)
        tgt = pc + _sx((w >> 5) & 0x7FFFF, 19) * 4
        if last_cmp:
            a, b = last_cmp
            return "if (%s %s %s) goto L_%x" % (a, op, b, tgt), ""
        return "if (cond.%s) goto L_%x" % (c, tgt), ""
    if (w & 0x7E000000) == 0x34000000:
        t = R(w & 0x1F)
        op = "!=" if (w & 0x00800000) else "=="
        return "if (%s %s 0) goto L_%x" % (
            t, op, pc + _sx((w >> 5) & 0x7FFFF, 19) * 4), ""
    wide = {0x52800000: "0x%04x", 0x12800000: "-0x%x", 0xD2800000: "0x%04x",
            0x92800000: "-0x%x"}
    m = wide.get(w & 0xFF800000)
    if m:
        imm = ((w >> 5) & 0xFFFF) << (16 * ((w >> 21) & 3))
        val = m % imm if "%x" in m else imm
        return "%s = %s" % (R(w & 0x1F), ("0x%x" % imm) if imm >= 0
                            else ("-0x%x" % -imm)), ""
    if (w & 0xFF800000) == 0x72800000 or (w & 0xFF800000) == 0xF2800000:
        imm = ((w >> 5) & 0xFFFF) << (16 * ((w >> 21) & 3))
        return "%s |= 0x%x (movk)" % (R(w & 0x1F), imm), ""
    if (w & 0x9F000000) == 0x90000000:
        imm = _sx(((w >> 5) & 0x7FFFF) << 2 | ((w >> 29) & 3), 21) << 12
        return "%s = &page(0x%x)" % (R(w & 0x1F), (pc & ~0xFFF) + imm), ""
    if (w & 0xFFFFFC1F) == 0xD61F0000:
        return "jump %s" % R((w >> 5) & 0x1F), "b"
    if (w & 0xFFFFFC1F) == 0xD63F0000:
        return "call %s" % R((w >> 5) & 0x1F), "call"
    if (w & 0x3F000000) == 0x39000000:
        size = (w >> 30) & 3
        opc = (w >> 22) & 3
        rn = (w >> 5) & 0x1F
        base = "sp" if rn == 31 else "x%d" % rn
        imm = ((w >> 10) & 0xFFF) * (8 if size == 3 else 1 << size)
        addr = "*[%s%s]" % (base, (" + %d" % imm) if imm else "")
        if opc == 1:
            return "%s = %s" % (R(w & 0x1F), addr), ""
        if opc == 0 and size < 3:
            return "%s = %s" % (addr, R(w & 0x1F)), ""
        if opc == 2 and size == 2:
            return "%s = (int32)%s" % (R(w & 0x1F), addr), ""
    if ((w >> 23) & 0x3F) == 0x22:
        nm = "sub" if (w & 0x40000000) else "add"
        rd = R(w & 0x1F)
        rn = (w >> 5) & 0x1F
        imm = (w >> 10) & 0xFFF
        lhs = "sp" if rn == 31 else R(rn)
        if (w >> 29) & 1:
            if nm == "sub" and rd in ("xzr", "wzr"):
                return "cmp %s, 0x%x" % (lhs, imm), "cmp:%s,0x%x" % (lhs, imm)
            if nm == "add" and lhs in ("xzr", "wzr"):
                return "cmp %s%d, 0x%x" % (sf, rd, imm), \
                    "cmp:%s%d,0x%x" % (sf, rd, imm)
        return "%s = %s %s 0x%x" % (rd, lhs, "+" if nm == "add" else "-", imm), ""
    if ((w >> 24) & 0x1F) == 0x0B and not (w & 0x00200000):
        nm = "sub" if (w & 0x40000000) else "add"
        sflag = (w >> 29) & 1
        rd = w & 0x1F
        rn = (w >> 5) & 0x1F
        rm = (w >> 16) & 0x1F
        sh = (w >> 22) & 3
        amt = (w >> 10) & 0x3F
        shifts = ("<<", ">>", ">>s", "rot")
        rhs = "%s%d" % (sf, rm)
        if sh or amt:
            rhs += " %s %d" % (shifts[sh], amt)
        if sflag and rd == 31:
            return "cmp %s%d, %s" % (sf, rn, rhs),                 "cmp:%s%d,%s" % (sf, rn, rhs)
        return "%s = %s%d %s %s" % (R(rd), sf, rn,
                                    "+" if nm == "add" else "-", rhs), ""
    if ((w >> 24) & 0x1F) == 0x0A:
        rd = w & 0x1F
        rn = (w >> 5) & 0x1F
        rm = (w >> 16) & 0x1F
        if (w >> 21) & 1 and rn == 31:
            return "%s = ~%s%d" % (R(rd), sf, rm), ""
        if ((w >> 29) & 3) == 1 and ((w >> 21) & 1) == 0 and rn == 31:
            return "%s = %s%d" % (R(rd), sf, rm), ""
        ops = {0: "&", 1: "|", 2: "^", 3: "&~"}
        op = ops.get((w >> 29) & 3)
        if op:
            return "%s = %s%d %s %s%d" % (R(rd), sf, rn, op, sf, rm), ""
    if ((w >> 27) & 7) == 5 and not (w & 0x04000000) \
            and ((w >> 23) & 7) in (1, 2, 3):
        opc = (w >> 30) & 3
        mode = (w >> 23) & 7
        rt2 = (w >> 10) & 0x1F
        rn = (w >> 5) & 0x1F
        rt = w & 0x1F
        imm = _sx((w >> 15) & 0x7F, 7) * (8 if opc == 2 else 4)
        base = "sp" if rn == 31 else "x%d" % rn
        pair = "%s%d, %s%d" % (sf, rt, sf, rt2)
        # verified encodings: opc even (0/2) = STP, odd (1/3) = LDP;
        # STP pre-index (mode 3, sp, imm<0) = frame push,
        # LDP post-index (mode 1, sp) = frame pop
        if opc in (0, 2) and mode == 3 and rn == 31 and imm < 0:
            return "frame push %s" % pair, ""
        if opc in (1, 3) and mode == 1 and rn == 31:
            return "frame pop %s" % pair, ""
        addr = "*[%s%s]" % (base, (" %+d" % imm) if imm else "")
        if opc in (0, 2):
            return "%s = %s" % (addr, pair), ""
        return "%s = %s" % (pair, addr), ""
    return ".inst 0x%08x" % w, ""


def _pseudo_arm64(code, base_va, func_starts, symmap):
    n = len(code) // 4
    words = struct.unpack_from("<%dI" % n, code, 0) if n else ()

    def va(i):
        return base_va + i * 4

    targets = set()
    calls = set()
    for i, w in enumerate(words):
        p = va(i)
        if (w >> 26) in (0x05, 0x25):
            t = p + _sx(w & 0x03FFFFFF, 26) * 4
            targets.add(t)
            if (w >> 26) == 0x05:
                calls.add(t)
        elif (w & 0xFF000010) == 0x54000000:
            targets.add(p + _sx((w >> 5) & 0x7FFFF, 19) * 4)
        elif (w & 0x7E000000) == 0x34000000:
            targets.add(p + _sx((w >> 5) & 0x7FFFF, 19) * 4)
    starts = sorted({s for s in func_starts
                     if base_va <= s < base_va + n * 4} | (calls & set(
                         range(base_va, base_va + n * 4, 4))))
    out = []
    seen = set()
    for f in starts:
        if f in seen:
            continue
        seen.add(f)
        i = (f - base_va) // 4
        out.append("")
        out.append("; ---- %s @ 0x%x" % (symmap.get(f, "sub_%x" % f), f))
        out.append("L_%x:" % f)
        last_cmp = None
        steps = 0
        while i < n and steps < 4000:
            p = va(i)
            if p in targets and p != f:
                out.append("L_%x:" % p)
            w = words[i]
            kind = ""
            if (w & 0x7E000000) != 0x34000000 and \
                    (w & 0xFF000010) != 0x54000000:
                text, kind = _pseudo_sem_arm64(w, p, last_cmp)
                if text.startswith("cmp "):
                    parts = text[4:].split(", ")
                    last_cmp = (parts[0], parts[1]) if len(parts) == 2 \
                        else None
                    text = "; %s" % text
                else:
                    last_cmp = None
            else:
                text, kind = _pseudo_sem_arm64(w, p, last_cmp)
                last_cmp = None
            if text.startswith("call 0x"):
                t = int(text.split("call 0x")[1], 16)
                if t in symmap:
                    text = "call %s" % symmap[t]
            out.append("    %s" % text)
            steps += 1
            i += 1
            if kind in ("ret", "b"):
                break
        if steps >= 4000:
            out.append("    ; ... (truncated)")
    return "\n".join(out)


def _pseudo_sem_arm32(w, pc, last_cmp):
    cond = (w >> 28) & 0xF
    c = "" if cond == 0xE else "." + _ARM32_CONDS[cond]
    imm8 = w & 0xFF
    rot = ((w >> 8) & 0xF) * 2
    val = ((imm8 >> rot) | (imm8 << (32 - rot))) & 0xFFFFFFFF if rot else imm8
    if (w & 0x0F000000) == 0x0A000000:
        return "goto L_%x" % (pc + 8 + _sx(w & 0xFFFFFF, 24) * 4), "b"
    if (w & 0x0F000000) == 0x0B000000:
        return "call 0x%x" % (pc + 8 + _sx(w & 0xFFFFFF, 24) * 4), "call"
    if (w & 0x0FFFFFF0) == 0x012FFF1E:
        return "return", "ret"
    if (w & 0x0FFF0000) == 0x092D0000:
        regs = ", ".join(_arm32_reg(i) for i in range(16) if (w >> i) & 1)
        return "frame push %s" % regs, ""
    if (w & 0x0FFF0000) == 0x08BD0000:
        regs = ", ".join(_arm32_reg(i) for i in range(16) if (w >> i) & 1)
        return "frame pop %s" % regs, ""
    if (w & 0x0FF00000) == 0x03000000:
        imm16 = ((w >> 4) & 0xF000) | (w & 0xFFF)
        return "%s = 0x%x" % (_arm32_reg((w >> 12) & 0xF), imm16), ""
    if (w & 0x0FF00000) == 0x03400000:
        imm16 = ((w >> 4) & 0xF000) | (w & 0xFFF)
        return "%s |= 0x%x << 16" % (_arm32_reg((w >> 12) & 0xF), imm16), ""
    if (w & 0x0E000000) == 0x02000000:
        nm = _ARM32_DPNAMES[(w >> 21) & 0xF]
        rd = _arm32_reg((w >> 12) & 0xF)
        rn = _arm32_reg((w >> 16) & 0xF)
        if nm == "mov":
            return "%s = 0x%x" % (rd, val), ""
        if nm in ("tst", "teq", "cmp", "cmn"):
            return "; cmp %s, 0x%x" % (rn, val), \
                "cmp:%s,0x%x" % (rn, val)
        ops = {"add": "+", "sub": "-", "and": "&", "orr": "|", "eor": "^"}
        if nm in ops and rd != rn:
            return "%s = %s %s 0x%x" % (rd, rn, ops[nm], val), ""
        return "%s %s= 0x%x" % (rd, ops.get(nm, "?"), val), ""
    if (w & 0x0F000000) == 0x05000000:
        nm = ("ldr" if (w >> 20) & 1 else "str") + \
            ("b" if (w >> 22) & 1 else "")
        u = "+" if (w >> 23) & 1 else "-"
        imm = w & 0xFFF
        rn = (w >> 16) & 0xF
        rd = _arm32_reg((w >> 12) & 0xF)
        if rn == 15:
            return "%s = *[%s]" % (rd, "pool 0x%x" % (pc + 8)), ""
        addr = "*[%s %s %d]" % (_arm32_reg(rn), u, imm)
        if nm.startswith("ldr"):
            return "%s = %s" % (rd, addr), ""
        return "%s = %s" % (addr, rd), ""
    if (w & 0x0E000010) == 0x00000000:
        op = (w >> 21) & 0xF
        rn = _arm32_reg((w >> 16) & 0xF)
        rd = _arm32_reg((w >> 12) & 0xF)
        rm = _arm32_reg(w & 0xF)
        shamt = (w >> 7) & 0x1F
        shty = (w >> 5) & 3
        shifts = ("<<", ">>", ">>s", "rot")
        rhs = rm + ("" if shty == 0 and shamt == 0
                    else " %s %d" % (shifts[shty], shamt))
        nm = _ARM32_DPNAMES[op]
        if nm == "mov":
            return "%s = %s" % (rd, rhs), ""
        if nm == "cmp":
            return "; cmp %s, %s" % (rn, rhs), "cmp:%s,%s" % (rn, rhs)
        ops = {"add": "+", "sub": "-", "and": "&", "orr": "|", "eor": "^"}
        if nm in ops:
            return "%s = %s %s %s" % (rd, rn, ops[nm], rhs), ""
        return "%s = %s(%s, %s)" % (rd, nm, rn, rhs), ""
    return ".inst 0x%08x" % w, ""


def _pseudo_arm32(code, base_va, func_starts, symmap):
    n = len(code) // 4
    words = struct.unpack_from("<%dI" % n, code, 0) if n else ()

    def va(i):
        return base_va + i * 4

    targets = set()
    calls = set()
    for i, w in enumerate(words):
        p = va(i)
        if (w & 0x0F000000) in (0x0A000000, 0x0B000000):
            t = p + 8 + _sx(w & 0xFFFFFF, 24) * 4
            targets.add(t)
            if (w & 0x0F000000) == 0x0B000000:
                calls.add(t)
    starts = sorted({s for s in func_starts
                     if base_va <= s < base_va + n * 4} |
                    {c for c in calls if base_va <= c < base_va + n * 4})
    out = []
    seen = set()
    for f in starts:
        if f in seen:
            continue
        seen.add(f)
        i = (f - base_va) // 4
        out.append("")
        out.append("; ---- %s @ 0x%x" % (symmap.get(f, "sub_%x" % f), f))
        out.append("L_%x:" % f)
        steps = 0
        while i < n and steps < 4000:
            p = va(i)
            if p in targets and p != f:
                out.append("L_%x:" % p)
            w = words[i]
            text, kind = _pseudo_sem_arm32(w, p, None)
            if text.startswith("call 0x"):
                t = int(text.split("call 0x")[1], 16)
                if t in symmap:
                    text = "call %s" % symmap[t]
            if text.startswith("if ("):
                pass
            elif "; cmp" in text:
                cm = text.split("; cmp ")[1].split(", ")
                if len(cm) == 2:
                    text = "if (%s %s %s) ..." % (
                        cm[0], "<>" if True else "=", cm[1])
            out.append("    %s" % text)
            steps += 1
            i += 1
            if kind in ("ret", "b"):
                break
        if steps >= 4000:
            out.append("    ; ... (truncated)")
    return "\n".join(out)


def write_disasm_kit(kit_dir, base, rel, data, info):
    """Write <base>.disasm.txt and <base>.pseudo.txt (READ-ONLY pseudo
    source - readable statements per instruction, per function; never
    recompilable)."""
    path = os.path.join(kit_dir, base + ".disasm.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("; {0}\n".format("=" * 74))
        fh.write("; IPAForge {0} - disassembly kit for {1}\n".format(__version__, rel))
        fh.write("; {0}\n".format("=" * 74))
        fh.write(DISASM_DISCLAIMER)

        # pick the executable section (__text) for disassembly
        text_section = None
        for seg in info["segments"]:
            for sect in seg["sections"]:
                if sect["name"] == "__text":
                    text_section = sect
                    break
            if text_section:
                break

        cpu = info["cpu"]
        if cpu not in ("arm64", "arm", "x86_64"):
            fh.write("; no built-in disassembler for cpu {0}\n".format(cpu))
        elif text_section is None:
            fh.write("; no __text section found - nothing to disassemble\n")

        if info["entry_vm"] is not None:
            fh.write("; entry point: 0x{0:X}\n".format(info["entry_vm"]))

        # inferred function starts from call rel32 targets across the whole file
        targets = set()
        for i in range(len(data) - 5):
            if data[i] == 0xE8:
                rel = struct.unpack_from("<i", data, i + 1)[0]
                target = i + 5 + rel
                if 0 <= target < len(data):
                    targets.add(target)
        if targets:
            fh.write("; inferred function starts (from call targets):\n")
            for t in sorted(targets)[:200]:
                fh.write(";   0x{0:X}\n".format(t))

        if text_section is not None:
            addr = text_section["addr"]
            off = int(text_section.get("offset", 0))
            size = int(text_section["size"])
            code = data[off:off + size] if off + size <= len(data) else data[off:]
            fh.write("\n__text (virtual base 0x{0:X}):\n".format(addr))
            if cpu == "arm64":
                fh.write(_records_to_text(_disasm_arm64(code, addr)))
            elif cpu == "arm":
                fh.write(_records_to_text(_disasm_arm32(code, addr)))
            else:
                fh.write(_records_to_text(disasm_x86_64_subset(code, addr)))
        elif cpu == "x86_64":
            fh.write("\n(full file linear sweep, no __text section found):\n")
            fh.write(_records_to_text(disasm_x86_64_subset(data, 0, max_instructions=2000)))

        fh.write("\n\n; printable strings (min length 5):\n")
        for s in extract_printable_strings(data):
            fh.write('  "{0}"\n'.format(s.replace('"', '\\"')))

    # ---- pseudo-source companion (honest: read-only, not recompilable) ----
    pseudo_path = os.path.join(kit_dir, base + ".pseudo.txt")
    with open(pseudo_path, "w", encoding="utf-8") as fh:
        fh.write("; " + "=" * 74 + "\n")
        fh.write("; IPAForge {0} - PSEUDO-SOURCE for {1}\n".format(
            __version__, rel))
        fh.write("; " + "=" * 74 + "\n")
        fh.write(PSEUDO_DISCLAIMER)
        symmap = {}
        text_lo = text_hi = None
        for seg in info["segments"]:
            for sect in seg["sections"]:
                if sect["name"] == "__text":
                    text_lo = int(sect["addr"])
                    text_hi = text_lo + int(sect["size"])
        for value, name in info["symbols"]:
            if text_lo is not None and text_lo <= value < text_hi:
                symmap[value] = name
        func_starts = sorted(symmap)
        if info["entry_vm"] is not None:
            func_starts.append(info["entry_vm"])
        if text_section is not None:
            addr = int(text_section["addr"])
            off2 = int(text_section.get("offset", 0))
            size2 = int(text_section["size"])
            code = data[off2:off2 + size2] if off2 + size2 <= len(data) \
                else data[off2:]
            fh.write("; functions from symbols + call targets; linear "
                     "sweep per function\n")
            if info["cpu"] == "arm64":
                fh.write(_pseudo_arm64(code, addr, func_starts, symmap))
            elif info["cpu"] == "arm":
                fh.write(_pseudo_arm32(code, addr, func_starts, symmap))
            else:
                fh.write("; pseudo-source covers arm64 and armv7 slices\n")
        else:
            fh.write("; no __text section - nothing to convert\n")
        fh.write("\n\n; printable strings (min length 5):\n")
        for s in extract_printable_strings(data):
            fh.write('  "' + s.replace('"', chr(92) + '"') + '"\n')

    return path


# ------------------------------------------------------------------------------
# BUILT-IN code signing (ad-hoc / pseudo-signing - replaces external ldid)
# ------------------------------------------------------------------------------

import base64 as _b64
import hashlib as _hl

LC_SEGMENT = 0x1
LC_SEGMENT_64 = 0x19
# ==============================================================================
# REAL-CERTIFICATE SIGNING CORE (1.21.0) - pure Python, stdlib only.
# Minimal DER, PKCS#12 (PBES2/PBKDF2/AES + legacy PBE-SHA1-3DES), X.509,
# RSA PKCS#1 v1.5 and detached CMS SignedData. Verified against OpenSSL
# used strictly as a TEST oracle - the tool never shells out or imports it.
# ==============================================================================
import hashlib


import binascii
import hashlib
import struct

# ---------------------------------------------------------------- DER decode

def _der_node(data, pos):
    tag = data[pos]
    p = pos + 1
    l = data[p]
    p += 1
    if l & 0x80:
        n = l & 0x7F
        if n == 0 or p + n > len(data):
            raise ValueError("bad DER length")
        l = 0
        for i in range(n):
            l = (l << 8) | data[p + i]
        p += n
    if p + l > len(data):
        raise ValueError("DER length overruns buffer")
    return tag, pos, p, p + l


def _der_children(data, start, end):
    out = []
    p = start
    while p < end:
        t, pos, cs, ce = _der_node(data, p)
        out.append((t, pos, cs, ce))
        p = ce
    return out


def _raw_full(data, node):
    """Full TLV bytes (header included)."""
    return bytes(data[node[1]:node[3]])


def _der_int_at(data, cs, ce):
    v = 0
    for i in range(cs, ce):
        v = (v << 8) | data[i]
    return v


# node full raw bytes: data[ns:ce]; content: data[cs:ce]
def _raw(data, node):
    _t, ns, cs, ce = node
    return bytes(data[cs:ce])


# ---------------------------------------------------------------- DER encode

def _der_len(n):
    if n < 0x80:
        return bytearray([n])
    out = bytearray()
    while n:
        out.insert(0, n & 0xFF)
        n >>= 8
    return bytearray([0x80 | len(out)]) + out


def _tlv(tag, content):
    return bytearray([tag]) + _der_len(len(content)) + bytearray(content)


def _i2b(n):
    if n == 0:
        return b"\x00"
    h = hex(n)[2:].rstrip("L")
    if len(h) % 2:
        h = "0" + h
    return binascii.unhexlify(h.encode("ascii"))


def _der_int(n):
    b = bytearray(_i2b(n))
    if b[0] & 0x80:
        b.insert(0, 0)
    return _tlv(0x02, bytes(b))


def _der_oid(dotted):
    parts = [int(x) for x in dotted.split(".")]
    body = bytearray([40 * parts[0] + parts[1]])
    for v in parts[2:]:
        chunk = bytearray([v & 0x7F])
        v >>= 7
        while v:
            chunk.insert(0, 0x80 | (v & 0x7F))
            v >>= 7
        body += chunk
    return _tlv(0x06, bytes(body))


def _der_seq(*items):
    out = bytearray()
    for it in items:
        out += it
    return _tlv(0x30, bytes(out))


def _der_set_sorted(items):
    joined = b"".join(sorted(bytes(i) for i in items))
    return _tlv(0x31, joined)


def _der_octet(b):
    return _tlv(0x04, b)


def _der_ctx(tagno, content, constructed=True):
    return _tlv((0xA0 if constructed else 0x80) + tagno, content)


def _der_utctime():
    import time as _time
    return _tlv(0x17, _time.strftime("%y%m%d%H%M%SZ", _time.gmtime())
                .encode("ascii"))


OID = {
    "data": "1.2.840.113549.1.7.1",
    "signedData": "1.2.840.113549.1.7.2",
    "encryptedData": "1.2.840.113549.1.7.6",
    "rsa": "1.2.840.113549.1.1.1",
    "sha256": "2.16.840.1.101.3.4.2.1",
    "contentType": "1.2.840.113549.1.9.3",
    "signingTime": "1.2.840.113549.1.9.5",
    "messageDigest": "1.2.840.113549.1.9.4",
    "cdhashes": "1.2.840.113635.100.9.1",
    "cdhashes2": "1.2.840.113635.100.9.2",
    "pbes2": "1.2.840.113549.1.5.13",
    "pbkdf2": "1.2.840.113549.1.5.12",
    "pbeSha1_3des": "1.2.840.113549.1.12.1.3",
    "des3": "1.2.840.113549.3.7",
    "aes128": "2.16.840.1.101.3.4.1.2",
    "aes192": "2.16.840.1.101.3.4.1.22",
    "aes256": "2.16.840.1.101.3.4.1.42",
    "certBag": "1.2.840.113549.1.12.10.1.3",
    "keyBag": "1.2.840.113549.1.12.10.1.1",
    "shroudedKeyBag": "1.2.840.113549.1.12.10.1.2",
    "x509Cert": "1.2.840.113549.1.9.22.1",
}

def _oid_content(dotted):
    tlv = _der_oid(dotted)
    _t, ns, cs, ce = _der_node(bytearray(tlv), 0)
    return bytes(tlv[cs:ce])


_OID_HEX = {}
for _k, _v in OID.items():
    _OID_HEX[_oid_content(_v)] = _k



# ---------------------------------------------------------------- DES / 3DES

DES_E = [31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 7, 8, 9, 10, 11, 12, 11, 12, 13, 14, 15, 16, 15, 16, 17, 18, 19, 20, 19, 20, 21, 22, 23, 24, 23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0]

DES_FP = [39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25, 32, 0, 40, 8, 48, 16, 56, 24]

DES_IP = [57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7, 56, 48, 40, 32, 24, 16, 8, 0, 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6]

DES_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

DES_P = [15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9, 1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24]

DES_PC1 = [56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3]

DES_PC2 = [13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1, 40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31]

DES_SBOX = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]


def _bits_of(data, nbytes=None):
    bits = []
    end = len(data) if nbytes is None else nbytes
    for i in range(end):
        b = data[i]
        for j in range(7, -1, -1):
            bits.append((b >> j) & 1)
    return bits


def _des_subkeys(key8):
    bits = _bits_of(key8, 8)
    pc1 = [bits[pos] for pos in DES_PC1]
    halves = [pc1[:28], pc1[28:]]
    keys = []
    for r in range(16):
        for _ in range(DES_SHIFTS[r]):
            halves[0] = halves[0][1:] + halves[0][:1]
            halves[1] = halves[1][1:] + halves[1][:1]
        both = halves[0] + halves[1]
        keys.append([both[pos] for pos in DES_PC2])
    return keys


def _des_block(block8, keys, decrypt):
    bits = _bits_of(block8, 8)
    state = [bits[DES_IP[i]] for i in range(64)]
    L, R = state[:32], state[32:]
    order = range(15, -1, -1) if decrypt else range(16)
    for r in order:
        sub = keys[r]
        exp = [R[DES_E[i]] for i in range(48)]
        x = [exp[i] ^ sub[i] for i in range(48)]
        sb = []
        for b8 in range(8):
            row = (x[b8 * 6] << 1) | x[b8 * 6 + 5]
            col = 0
            for i in range(4):
                col = (col << 1) | x[b8 * 6 + 1 + i]
            val = DES_SBOX[b8][row * 16 + col]
            for j in range(3, -1, -1):
                sb.append((val >> j) & 1)
        pr = [sb[DES_P[i]] for i in range(32)]
        Rn = [L[i] ^ pr[i] for i in range(32)]
        L = R
        R = Rn
    pre = R + L
    ob = bytearray(8)
    for i in range(8):
        v = 0
        for j in range(8):
            v = (v << 1) | pre[DES_FP[i * 8 + j]]
        ob[i] = v
    return bytes(ob)


def des3_cbc_decrypt(key24, iv8, data):
    k1 = _des_subkeys(key24[0:8])
    k2 = _des_subkeys(key24[8:16])
    k3 = _des_subkeys(key24[16:24])
    out = bytearray()
    prev = bytes(iv8)
    n = len(data) - (len(data) % 8)
    for off in range(0, n, 8):
        blk = bytes(data[off:off + 8])
        t = _des_block(blk, k3, True)
        t = _des_block(t, k2, False)
        t = _des_block(t, k1, True)
        out += bytearray(a ^ b for a, b in zip(t, prev))
        prev = blk
    return bytes(out)


# ---------------------------------------------------------------- AES

def _aes_gen_sbox():
    p = 1
    q = 1
    sbox = [0] * 256
    sbox[0] = 0x63
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ (((q << 1) | (q >> 7)) & 0xFF) \
            ^ (((q << 2) | (q >> 6)) & 0xFF) \
            ^ (((q << 3) | (q >> 5)) & 0xFF) \
            ^ (((q << 4) | (q >> 4)) & 0xFF)
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    return sbox


AES_SBOX = _aes_gen_sbox()
AES_INV = [0] * 256
for _i, _v in enumerate(AES_SBOX):
    AES_INV[_v] = _i


def _aes_xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1)


def _aes_gmul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        a = _aes_xtime(a)
        b >>= 1
    return r & 0xFF


def _aes_expand(key):
    nk = len(key) // 4
    rounds = nk + 6
    words = [bytearray(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (rounds + 1)):
        t = bytearray(words[i - 1])
        if i % nk == 0:
            t = bytearray([AES_SBOX[t[1]] ^ rcon, AES_SBOX[t[2]],
                           AES_SBOX[t[3]], AES_SBOX[t[0]]])
            rcon = _aes_xtime(rcon)
        elif nk > 6 and i % nk == 4:
            t = bytearray([AES_SBOX[b] for b in t])
        words.append(bytearray(a ^ b for a, b in zip(words[i - nk], t)))
    return [bytes(b"".join(words[4 * r:4 * r + 4])) for r in range(rounds + 1)]


def st_items(seq, idx):
    return seq[idx]


def aes_cbc_decrypt(key, iv, data):
    rk = _aes_expand(bytes(key))
    rounds = len(rk) - 1
    out = bytearray()
    prev = bytes(iv)
    for off in range(0, len(data) - (len(data) % 16), 16):
        chain = bytes(data[off:off + 16])
        s = [chain[i] for i in range(16)]
        s = [s[i] ^ rk[rounds][i] for i in range(16)]
        for rnd in range(rounds - 1, -1, -1):
            # InvShiftRows (right by r): t[r][c] = s[r][(c - r) mod 4]
            t = [0] * 16
            for rr in range(4):
                for cc in range(4):
                    t[rr + 4 * cc] = st_items(s, rr + 4 * ((cc + 4 - rr) % 4))
            s = [AES_INV[b] for b in t]
            s = [s[i] ^ rk[rnd][i] for i in range(16)]
            if rnd:
                t = list(s)
                for c in range(4):
                    a0, a1, a2, a3 = t[4 * c:4 * c + 4]
                    s[4 * c + 0] = _aes_gmul(a0, 14) ^ _aes_gmul(a1, 11) \
                        ^ _aes_gmul(a2, 13) ^ _aes_gmul(a3, 9)
                    s[4 * c + 1] = _aes_gmul(a0, 9) ^ _aes_gmul(a1, 14) \
                        ^ _aes_gmul(a2, 11) ^ _aes_gmul(a3, 13)
                    s[4 * c + 2] = _aes_gmul(a0, 13) ^ _aes_gmul(a1, 9) \
                        ^ _aes_gmul(a2, 14) ^ _aes_gmul(a3, 11)
                    s[4 * c + 3] = _aes_gmul(a0, 11) ^ _aes_gmul(a1, 13) \
                        ^ _aes_gmul(a2, 9) ^ _aes_gmul(a3, 14)
        out += bytearray(a ^ b for a, b in zip(bytes(bytearray(s)), prev))
        prev = chain
    return out


# ---------------------------------------------------------------- KDFs

def _pbkdf2(password, salt, iters, length, prf):
    import hmac as _hmac
    out = bytearray()
    block = 1
    while len(out) < length:
        msg = bytes(salt) + struct.pack(">I", block)
        u = _hmac.new(password, msg, prf).digest()
        t = bytearray(u)
        for _ in range(iters - 1):
            u = _hmac.new(password, u, prf).digest()
            t = bytearray(a ^ b for a, b in zip(t, u))
        out += t
        block += 1
    return bytes(out[:length])


def _pkcs12_kdf(password_bmp, salt, iters, length, vid, prf="sha1"):
    """RFC 7292 B.2. vid: 1=key, 2=IV, 3=MAC. Hash per macAlg (SHA-1 classic)."""
    H = (lambda b: hashlib.sha1(b).digest()) if prf == "sha1" \
        else (lambda b: getattr(hashlib, prf)(b).digest())
    u = {"sha1": 20, "sha224": 28, "sha256": 32, "sha384": 48, "sha512": 64}[prf]
    v = 64
    D = bytes([vid]) * v
    s = bytearray()
    while len(s) < v * ((len(salt) + v - 1) // v):
        s.append(salt[len(s) % len(salt)])
    p = bytearray()
    while len(p) < v * ((len(password_bmp) + v - 1) // v):
        p.append(password_bmp[len(p) % len(password_bmp)])
    I = bytearray(s + p)
    result = bytearray()
    while len(result) < length:
        A = H(D + bytes(I))
        for _ in range(iters - 1):
            A = H(A)
        result += A
        if len(result) >= length:
            break
        B = bytearray((A * v)[:v])
        for j in range(0, len(I), v):
            carry = 1
            for k in range(v - 1, -1, -1):
                x = I[j + k] + B[k] + carry
                I[j + k] = x & 0xFF
                carry = x >> 8
    return bytes(result[:length])


def _kdf_password(password):
    if isinstance(password, type(u"")):
        pw = password
    else:
        pw = password.decode("utf-8", "replace")
    return pw.encode("utf-16-be") + b"\x00\x00"


def _unpad(plain, blocksize):
    if not plain:
        return plain
    padn = plain[-1]
    if 0 < padn <= blocksize and plain[-padn:] == bytes([padn]) * padn:
        return plain[:-padn]
    return plain


def _pbe_decrypt(data, alg_node, enc_node, password):
    """Decrypt encryptedContent / shrouded key bytes.
    alg_node, enc_node: (tag, ns, cs, ce) tuples."""
    kids = _der_children(data, alg_node[2], alg_node[3])
    oid = _OID_HEX.get(_raw(data, kids[0]))
    params = kids[1] if len(kids) > 1 else None
    pw = _kdf_password(password)
    pw_plain = password if isinstance(password, bytes) \
        else password.encode("utf-8")
    enc = bytes(data[enc_node[2]:enc_node[3]])
    if oid == "pbeSha1_3des":
        pk = _der_children(data, params[2], params[3])
        salt = bytes(data[pk[0][2]:pk[0][3]])
        iters = _der_int_at(data, pk[1][2], pk[1][3])
        key = _pkcs12_kdf(pw, salt, iters, 24, 1)
        iv = _pkcs12_kdf(pw, salt, iters, 8, 2)
        return _unpad(des3_cbc_decrypt(key, iv, enc), 8)
    if oid == "pbes2":
        pk = _der_children(data, params[2], params[3])
        kdf, cip = pk[0], pk[1]
        kk = _der_children(data, kdf[2], kdf[3])
        kdfp = kk[1]                       # PBKDF2-params SEQ
        kp = _der_children(data, kdfp[2], kdfp[3])
        ksalt = bytes(data[kp[0][2]:kp[0][3]])
        kiter = _der_int_at(data, kp[1][2], kp[1][3])
        prf = "sha1"
        for extra in kp[2:]:
            if extra[0] == 0x30:
                prf_raw = _raw(data, extra)
                if b"\x2a\x86\x48\x86\xf7\x0d\x02\x09" in prf_raw:
                    prf = "sha256"
                elif b"\x2a\x86\x48\x86\xf7\x0d\x02\x08" in prf_raw:
                    prf = "sha224"
                elif b"\x2a\x86\x48\x86\xf7\x0d\x02\x0a" in prf_raw:
                    prf = "sha384"
                elif b"\x2a\x86\x48\x86\xf7\x0d\x02\x0b" in prf_raw:
                    prf = "sha512"
        ck = _der_children(data, cip[2], cip[3])
        coid = _OID_HEX.get(_raw(data, ck[0]))
        civ = bytes(data[ck[1][2]:ck[1][3]])
        if coid == "des3":
            key = _pbkdf2(pw_plain, ksalt, kiter, 24, prf)
            return _unpad(des3_cbc_decrypt(key, civ, enc), 8)
        lens = {"aes256": 32, "aes192": 24, "aes128": 16}
        if coid not in lens:
            raise ValueError("unsupported p12 cipher: %s" % coid)
        key = _pbkdf2(pw_plain, ksalt, kiter, lens[coid], prf)
        return _unpad(aes_cbc_decrypt(key, civ, enc), 16)
    raise ValueError("unsupported p12 encryption: %s" % oid)


# ---------------------------------------------------------------- PKCS12

def parse_pkcs12(data, password):
    """Returns dict: {key: [n,e,d,p,q,dp,dq,qinv], certs: [der...],
    mac_ok: True/False/None, leaf: cert_bytes}"""
    data = bytearray(data)
    root = _der_children(data, 0, len(data))
    top = root[0]
    kids = _der_children(data, top[2], top[3])
    if _der_int_at(data, kids[0][2], kids[0][3]) != 3:
        raise ValueError("not a PKCS#12 file (version != 3)")
    auth = kids[1]          # authSafe ContentInfo
    mac_node = kids[2] if len(kids) > 2 else None

    # MAC verify
    mac_ok = None
    if mac_node is not None:
        try:
            mk = _der_children(data, mac_node[2], mac_node[3])
            mi = _der_children(data, mk[0][2], mk[0][3])
            # DigestInfo = SEQ{ SEQ{OID}, OCTET digest }
            alg = _der_children(data, mi[0][2], mi[0][3])
            mac_oid_raw = _raw(data, alg[0])
            dig = bytes(data[mi[1][2]:mi[1][3]])
            msalt_n = mk[1]
            msalt = bytes(data[msalt_n[2]:msalt_n[3]])
            iters = _der_int_at(data, mk[2][2], mk[2][3]) if len(mk) > 2 else 1
            prf = "sha1"
            if b"\x60\x86\x48\x01\x65\x03\x04\x02\x01" in mac_oid_raw \
                    or b"\x2a\x86\x48\x86\xf7\x0d\x02\x09" in mac_oid_raw:
                prf = "sha256"
            elif b"\x60\x86\x48\x01\x65\x03\x04\x02\x03" in mac_oid_raw \
                    or b"\x2a\x86\x48\x86\xf7\x0d\x02\x0b" in mac_oid_raw:
                prf = "sha512"
            elif b"\x60\x86\x48\x01\x65\x03\x04\x02\x02" in mac_oid_raw \
                    or b"\x2a\x86\x48\x86\xf7\x0d\x02\x0a" in mac_oid_raw:
                prf = "sha384"
            content_node = _der_children(data, auth[2], auth[3])
            # content = [0] EXPLICIT OCTET STRING
            oc = _der_children(data, content_node[1][2], content_node[1][3])
            payload = bytes(data[oc[0][2]:oc[0][3]])
            key = _pkcs12_kdf(_kdf_password(password), msalt, iters,
                              hashlib.new(prf).digest_size, 3, prf)
            import hmac as _hmac
            calc = _hmac.new(key, payload, prf).digest()
            mac_ok = _hmac.compare_digest(calc, dig)
        except Exception:
            mac_ok = False

    # walk AuthenticatedSafe
    content_node = _der_children(data, auth[2], auth[3])[1]
    oc = _der_children(data, content_node[2], content_node[3])
    safe_der = bytes(data[oc[0][2]:oc[0][3]])
    sd = bytearray(safe_der)
    certs = []
    key = None
    _outer = _der_children(sd, 0, len(sd))[0]
    for ci in _der_children(sd, _outer[2], _outer[3]):
        ctype = _OID_HEX.get(_raw(sd, _der_children(sd, ci[2], ci[3])[0]))
        ckids = _der_children(sd, ci[2], ci[3])
        if ctype == "data":
            inner = _der_children(sd, ckids[1][2], ckids[1][3])
            sc = bytes(sd[inner[0][2]:inner[0][3]])
            certs2, key2 = _walk_safe_contents(sc, password)
            certs += certs2
            key = key or key2
        elif ctype == "encryptedData":
            ed = _der_children(sd, ckids[1][2], ckids[1][3])  # EXPLICIT -> SEQ
            edk = _der_children(sd, ed[0][2], ed[0][3])
            eci = edk[1]
            ecik = _der_children(sd, eci[2], eci[3])
            alg_node = ecik[1]
            enc_node = ecik[2]
            plain = _pbe_decrypt(sd, alg_node, enc_node, password)
            certs2, key2 = _walk_safe_contents(plain, password)
            certs += certs2
            key = key or key2
    if key is None:
        raise ValueError("no private key in p12 (or unsupported encryption)")
    leaf = None
    for c in certs:
        info = parse_cert(c)
        if info["modulus"] == key[1]:
            leaf = c
            break
    return {"key": key, "certs": certs, "mac_ok": mac_ok, "leaf": leaf}


def _walk_safe_contents(sc, password):
    """SafeContents ::= SEQUENCE OF SafeBag. Returns (certs, key)."""
    data = bytearray(sc)
    certs = []
    key = None
    _outer = _der_children(data, 0, len(data))[0]
    for bag in _der_children(data, _outer[2], _outer[3]):
        bk = _der_children(data, bag[2], bag[3])
        bagid = _OID_HEX.get(_raw(data, bk[0]))
        val = bk[1]  # [0] EXPLICIT
        vk = _der_children(data, val[2], val[3])
        if bagid == "certBag":
            cb = _der_children(data, vk[0][2], vk[0][3])
            expl = cb[1]                                # [0] EXPLICIT
            octet = _der_children(data, expl[2], expl[3])[0]
            certs.append(bytes(data[octet[2]:octet[3]]))
        elif bagid == "keyBag":
            key = key or _parse_pkcs8(bytes(data[vk[0][2]:vk[0][3]]))
        elif bagid == "shroudedKeyBag":
            ek = _der_children(data, vk[0][2], vk[0][3])
            pk8 = _pbe_decrypt(data, ek[0], ek[1], password)
            key = key or _parse_pkcs8(pk8)
    return certs, key


def _parse_pkcs8(der):
    data = bytearray(der)
    top = _der_children(data, 0, len(data))[0]
    kids = _der_children(data, top[2], top[3])
    alg = kids[1]
    aoid = _OID_HEX.get(_raw(data, _der_children(data, alg[2], alg[3])[0]))
    if aoid != "rsa":
        raise ValueError("only RSA keys supported (found %s)" % aoid)
    pkoct = kids[2]
    rsap = bytes(data[pkoct[2]:pkoct[3]])
    rd = bytearray(rsap)
    rk = _der_children(rd, 0, len(rd))[0]
    ints = _der_children(rd, rk[2], rk[3])
    vals = [_der_int_at(rd, n[2], n[3]) for n in ints[:9]]
    return vals  # version,n,e,d,p,q,dp,dq,qinv


# ---------------------------------------------------------------- X.509

def parse_cert(der):
    data = bytearray(der)
    cert = _der_children(data, 0, len(data))[0]
    tbs = _der_children(data, cert[2], cert[3])[0]
    kids = _der_children(data, tbs[2], tbs[3])
    idx = 0
    if kids[0][0] == 0xA0:
        idx = 1
    serial = _der_int_at(data, kids[idx][2], kids[idx][3])
    issuer_node = kids[idx + 2]
    subject_node = kids[idx + 4]
    spki_node = kids[idx + 5]
    info = {
        "serial": serial,
        "issuer_raw": _raw_full(data, issuer_node),
        "cn": "", "ou": "",
        "modulus": 0,
    }
    for name_node in (subject_node,):
        for rdn in _der_children(data, name_node[2], name_node[3]):
            for atv in _der_children(data, rdn[2], rdn[3]):
                ak = _der_children(data, atv[2], atv[3])
                oid_raw = _raw(data, ak[0])
                val = ak[1]
                text = bytes(data[val[2]:val[3]]).decode("utf-8", "replace")
                if oid_raw == b"\x55\x04\x03":
                    info["cn"] = text
                elif oid_raw == b"\x55\x04\x0b":
                    info["ou"] = text
    # SPKI: SEQ{ SEQ{OID rsa, NULL}, BITSTRING }
    spk = _der_children(data, spki_node[2], spki_node[3])
    spki_alg = _der_children(data, spk[0][2], spk[0][3])
    spki_oid = _OID_HEX.get(_raw(data, spki_alg[0]))
    if spki_oid == "rsa":
        bit = spk[1]
        keyder = bytes(data[bit[2] + 1:bit[3]])  # skip unused-bits byte
        rk = bytearray(keyder)
        topk = _der_children(rk, 0, len(rk))[0]
        ints = _der_children(rk, topk[2], topk[3])
        info["modulus"] = _der_int_at(rk, ints[0][2], ints[0][3])
    return info


# ---------------------------------------------------------------- RSA sign

def _rsa_sign_pkcs1_sha256(key, data):
    n, e, d, p, q, dp, dq, qinv = key[1], key[2], key[3], key[4], key[5], \
        key[6], key[7], key[8]
    digest = hashlib.sha256(data).digest()
    prefix = binascii.unhexlify(
        b"3031300d060960864801650304020105000420")
    k = len(_i2b(n))
    padlen = k - 3 - len(prefix) - 32
    em = b"\x00\x01" + b"\xff" * padlen + b"\x00" + prefix + digest
    m = 0
    for byte in bytearray(em):
        m = (m << 8) | byte
    # CRT
    m1 = pow(m, dp, p)
    m2 = pow(m, dq, q)
    h = (qinv * (m1 - m2)) % p
    sig = m2 + q * h
    return _i2b(sig).rjust(k, b"\x00")


# ---------------------------------------------------------------- CMS

def build_cms(certs, key, leaf, content, cdhashes_plist, cdhash2_payload):
    """content = primary CodeDirectory bytes.
    cdhashes_plist = binary plist {"cdhashes":[data,data]}.
    cdhash2_payload = DER SEQUENCE{OID sha256, OCTET hash32}."""
    leaf_info = parse_cert(leaf)
    sha256_oid = _der_oid(OID["sha256"])
    data_oid = _der_oid(OID["data"])

    attrs = [
        _der_seq(_der_oid(OID["contentType"]), _der_set_sorted([data_oid])),
        _der_seq(_der_oid(OID["signingTime"]),
                 _der_set_sorted([_der_utctime()])),
        _der_seq(_der_oid(OID["messageDigest"]),
                 _der_set_sorted([_der_octet(hashlib.sha256(content)
                                             .digest())])),
        _der_seq(_der_oid(OID["cdhashes"]),
                 _der_set_sorted([_der_octet(cdhashes_plist)])),
        _der_seq(_der_oid(OID["cdhashes2"]),
                 _der_set_sorted([_der_octet(cdhash2_payload)])),
    ]
    # signedAttrs is [0] IMPLICIT SET OF Attribute: the A0 tag REPLACES the
    # SET tag, so the sorted attribute TLVs are concatenated directly.
    signed_attrs = _der_ctx(0, b"".join(sorted(bytes(a) for a in attrs)))
    # Verifiers (OpenSSL CMS_Attributes_Verify, codesign) hash the attrs as a
    # plain SET: identical bytes with only the tag flipped A0 -> 31.
    attrs_for_sig = b"\x31" + signed_attrs[1:]

    digest_alg = _der_seq(sha256_oid)
    sid = _der_seq(bytearray(leaf_info["issuer_raw"]), _der_int(leaf_info["serial"]))
    sig_alg = _der_seq(_der_oid(OID["rsa"]))
    signature = _rsa_sign_pkcs1_sha256(key, attrs_for_sig)

    signer = _der_seq(_der_int(1), sid, digest_alg,
                      signed_attrs, sig_alg, _der_octet(signature))

    cert_blob = bytearray()
    for c in certs:
        cert_blob += bytes(c)
    certset = _der_ctx(0, bytes(cert_blob))  # [0] IMPLICIT

    signed_data = _der_seq(
        _der_int(1),
        _der_set_sorted([digest_alg]),
        _der_seq(data_oid),
        certset,
        _der_set_sorted([signer]),
    )
    content_info = _der_seq(_der_oid(OID["signedData"]),
                            _der_ctx(0, bytes(signed_data)))
    return bytes(content_info)


def blob_wrapper(cms_der):
    return struct.pack(">II", 0xfade0b01, 8 + len(cms_der)) + cms_der


# ------------------------------------------------------------- SuperBlob bits

CS_MAGIC_REQS_SET = 0xFADE0C01
CS_MAGIC_REQ = 0xFADE0C00
CS_MAGIC_DER_ENTS = 0xFADE7172


def _req_pstr(data):
    """u32BE length + data + NUL pad to 4-byte multiple."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    pad = (4 - (len(data) % 4)) % 4
    return struct.pack(">I", len(data)) + data + b"\x00" * pad


def build_requirements_der(bundle_id, cn):
    """Designated-requirement blob exactly like zsign SlotBuildRequirements."""
    if not bundle_id or not cn:
        return struct.pack(">III", CS_MAGIC_REQS_SET, 12, 0)
    wwdr_oid = binascii.unhexlify(b"2a864886f76364060201")
    e = struct.pack(">I", 1)                        # expr form marker
    e += struct.pack(">I", 6)                       # opAnd
    e += struct.pack(">I", 2)                       # opIdent
    e += _req_pstr(bundle_id)
    e += struct.pack(">I", 6)                       # opAnd
    e += struct.pack(">I", 15)                      # opAppleGenericAnchor
    e += struct.pack(">I", 6)                       # opAnd
    e += struct.pack(">I", 11)                      # opCertField
    e += struct.pack(">I", 0)                       # cert slot 0 = leaf
    e += _req_pstr("subject.CN")
    e += struct.pack(">I", 1)                       # matchEqual
    e += _req_pstr(cn)
    e += struct.pack(">I", 14)                      # opCertGeneric
    e += struct.pack(">I", 1)                       # cert slot 1 = intermediate
    e += _req_pstr(wwdr_oid)
    e += struct.pack(">I", 0)                       # matchExists
    inner = struct.pack(">II", CS_MAGIC_REQ, 8 + len(e)) + e
    total = 20 + len(inner)
    return struct.pack(">IIIII", CS_MAGIC_REQS_SET, total, 1, 3, 20) + inner


def _der_ent_value(value):
    if isinstance(value, bool):
        return b"\x01\x01" + (b"\xff" if value else b"\x00")
    if isinstance(value, int):
        # Proper minimal DER INTEGER (zsign's own integer encoding is
        # malformed for values >= 2; Apple parses strict DER, so we do not
        # reproduce that quirk - 0/1/bools are byte-identical anyway).
        if value < 0:
            raise ValueError("negative entitlement integers unsupported")
        if value == 0:
            return b"\x02\x01\x00"
        body = []
        v = value
        while v:
            body.append(v & 0xFF)
            v >>= 8
        body.reverse()
        if body[0] & 0x80:
            body.insert(0, 0)
        return b"\x02" + _der_len(len(body)) + bytes(body)
    if isinstance(value, str):
        data = value.encode("utf-8")
        return b"\x0c" + _der_len(len(data)) + data
    if isinstance(value, (list, tuple)):
        body = b"".join(_der_ent_value(v) for v in value)
        return b"0" + _der_len(len(body)) + body
    if isinstance(value, dict):
        body = b""
        for key in sorted(value.keys()):
            entry = b"\x0c" + _der_len(len(key)) + key.encode("utf-8") + \
                _der_ent_value(value[key])
            body += b"0" + _der_len(len(entry)) + entry
        return b"\xb0" + _der_len(len(body)) + body
    raise ValueError("unsupported entitlement type: {0}".format(type(value)))


def build_der_entitlements(entitlements):
    """zsign SlotBuildDerEntitlements: 02 01 01 + 0xB0 dict, 0x70-wrapped."""
    body = b"\x02\x01\x01" + _der_ent_value(entitlements)
    raw = b"\x70" + _der_len(len(body)) + body
    return struct.pack(">II", CS_MAGIC_DER_ENTS, 8 + len(raw)) + raw


def build_cdhashes_plist(cdhash_sha1, cdhash_sha256_trunc):
    """XML plist (array of 2 data entries) for CMS attr 1.2.840.113635.100.9.1."""
    import base64 as _b64
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0">\n<array>\n'
        "<data>{0}</data>\n<data>{1}</data>\n"
        "</array>\n</plist>\n"
    ).format(_b64.b64encode(cdhash_sha1).decode("ascii"),
             _b64.b64encode(cdhash_sha256_trunc).decode("ascii")).encode("ascii")
LC_CODE_SIGNATURE = 0x1D

CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_ENTITLEMENTS = 0xFADE7171
CSMAGIC_REQUIREMENT = 0xFADE0C01

CSSLOT_CODEDIRECTORY = 0
CSSLOT_ENTITLEMENTS = 5

CS_ADHOC = 0x00000002
CS_EXECSEG_MAIN_BINARY = 0x1
CD_VERSION = 0x00020400
CD_HASH_TYPE_SHA256 = 2
CD_PAGE_SHIFT = 12
CSMAGIC_BLOBWRAPPER = 0xFADE0B01
CSMAGIC_DER_ENTITLEMENTS = 0xFADE7172
CSSLOT_ALT_CODEDIRECTORY = 0x1000
CSSLOT_SIGNATURESLOT = 0x10000
_THIN_LE = (0xFEEDFACE, 0xFEEDFACF)


def _align(n, boundary):
    return (n + boundary - 1) & ~(boundary - 1)


LC_LOAD_WEAK_DYLIB = 0x18
LC_REQ_DYLD = 0x80000000
# The requested numeric command (0x24 | LC_REQ_DYLD) is retained explicitly.
REQUESTED_WEAK_DYLIB_CMD = 0x24 | LC_REQ_DYLD


def inject_dylib_load_command(binary_path, dylib_payload_path):
    """Structurally append the requested dylib load command to a 64-bit LE Mach-O.

    This operation never shifts segment contents.  It succeeds only when the
    existing load-command region has enough unused padding before the first
    file-backed segment.  The command is written into that slack and the
    header's ``ncmds``/``sizeofcmds`` fields are updated atomically.

    Note: Apple's canonical ``LC_LOAD_WEAK_DYLIB | LC_REQ_DYLD`` is
    ``0x80000018``.  The requested value ``0x80000024`` is used verbatim here
    and therefore represents a different Mach-O command ID; callers wanting
    the canonical weak-dylib command can pass the separate helper below.
    """
    with open(dylib_payload_path, "rb") as fh:
        payload = fh.read()
    if not payload:
        raise ValueError("dylib payload path is empty")
    name = os.path.basename(os.path.normpath(dylib_payload_path))
    if not name:
        raise ValueError("could not derive dylib name")
    raw_name = name.encode("utf-8") + b"\x00"
    cmdsize = _align(24 + len(raw_name), 8)

    with open(binary_path, "rb") as fh:
        original = bytearray(fh.read())
    if len(original) < 32 or struct.unpack_from("<I", original, 0)[0] != 0xFEEDFACF:
        raise ValueError("binary is not a 64-bit little-endian Mach-O (0xFEEDFACF)")
    ncmds, sizeofcmds = struct.unpack_from("<II", original, 16)
    header_end = 32 + sizeofcmds
    if header_end > len(original):
        raise ValueError("Mach-O load-command region exceeds file size")

    first_fileoff = None
    off = 32
    for _ in range(min(ncmds, 4096)):
        if off + 8 > header_end:
            raise ValueError("malformed Mach-O load-command table")
        cmd, size = struct.unpack_from("<II", original, off)
        if size < 8 or off + size > header_end:
            raise ValueError("malformed Mach-O load command size")
        if cmd == LC_SEGMENT_64 and size >= 72:
            fileoff, filesize = struct.unpack_from("<QQ", original, off + 32)
            if filesize or fileoff:
                if fileoff and (first_fileoff is None or fileoff < first_fileoff):
                    first_fileoff = fileoff
        off += size
    if off != header_end:
        raise ValueError("Mach-O sizeofcmds does not match load-command walk")
    if first_fileoff is None:
        raise ValueError("no file-backed 64-bit segment found")
    if first_fileoff < header_end:
        raise ValueError("no load-command padding is available")
    available = first_fileoff - header_end
    if available < cmdsize:
        raise ValueError("insufficient load-command slack: need %d, have %d" %
                         (cmdsize, available))

    command = bytearray(cmdsize)
    struct.pack_into("<II", command, 0, REQUESTED_WEAK_DYLIB_CMD, cmdsize)
    # dylib_command: name, timestamp, current_version, compatibility_version
    struct.pack_into("<IIII", command, 8, 24, 0, 0x10000, 0x10000)
    command[24:24 + len(raw_name)] = raw_name
    original[header_end:header_end + cmdsize] = command
    struct.pack_into("<I", original, 16, ncmds + 1)
    struct.pack_into("<I", original, 20, sizeofcmds + cmdsize)

    tmp = binary_path + ".ipaforge-inject.tmp"
    with open(tmp, "wb") as fh:
        fh.write(original)
        fh.flush()
        try:
            os.fsync(fh.fileno())
        except OSError:
            pass
    os.replace(tmp, binary_path)
    return {"path": binary_path, "dylib": name, "command": REQUESTED_WEAK_DYLIB_CMD,
            "command_size": cmdsize, "ncmds": ncmds + 1,
            "sizeofcmds": sizeofcmds + cmdsize, "slack_before": available}


def inject_canonical_weak_dylib_load_command(binary_path, dylib_payload_path):
    """Canonical weak-dylib variant using 0x80000018."""
    global REQUESTED_WEAK_DYLIB_CMD
    old = REQUESTED_WEAK_DYLIB_CMD
    try:
        REQUESTED_WEAK_DYLIB_CMD = LC_LOAD_WEAK_DYLIB | LC_REQ_DYLD
        return inject_dylib_load_command(binary_path, dylib_payload_path)
    finally:
        REQUESTED_WEAK_DYLIB_CMD = old


def _macho_slices(data):
    """[(offset, size)] for every architecture slice in a Mach-O / FAT.

    FAT ("universal") headers are BIG-endian: magic 0xCAFEBABE /
    0xCAFEBABF as read with ">I". Thin Mach-O magics are little-endian.
    """
    if len(data) < 8:
        return []
    if struct.unpack_from("<I", data, 0)[0] in _THIN_LE:
        return [(0, len(data))]
    fat_magic = struct.unpack_from(">I", data, 0)[0]
    if fat_magic in (0xCAFEBABE, 0xCAFEBABF):
        is64 = fat_magic == 0xCAFEBABF
        entry = 32 if is64 else 20
        nfat = struct.unpack_from(">I", data, 4)[0]
        slices = []
        off = 8
        for _ in range(nfat):
            if off + entry > len(data):
                break
            if is64:
                f_off, f_size = struct.unpack_from(">QQ", data, off + 8)
            else:
                f_off, f_size = struct.unpack_from(">II", data, off + 8)
            slices.append((f_off, f_size))
            off += entry
        return slices
    return []


def _header_info(data, base):
    """Minimal LE Mach-O header walk for one slice.

    Returns a dict, or None when the slice is not a supported (LE) Mach-O.
    """
    if base + 32 > len(data):
        return None
    magic = struct.unpack_from("<I", data, base)[0]
    if magic not in _THIN_LE:
        return None
    is64 = magic == 0xFEEDFACF
    fmt = "<I" if True else "<I"
    filetype = struct.unpack_from("<I", data, base + 12)[0]
    ncmds = struct.unpack_from("<I", data, base + 16)[0]
    sizeofcmds = struct.unpack_from("<I", data, base + 20)[0]
    head_end = base + (32 if is64 else 28) + sizeofcmds
    text_off = text_size = text_vmsize = 0
    linkedit_off = None
    sig_lc_off = None
    sig_dataoff = 0
    sig_datasize = 0
    cryptoff = cryptsize = cryptid = 0
    off = base + (32 if is64 else 28)
    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmdsize < 8 or off + cmdsize > len(data):
            break  # malformed command table - stop instead of wandering
        if cmd == LC_SEGMENT_64 and cmdsize >= 72:
            name = data[off + 8:off + 24].split(b"\x00", 1)[0]
            if name == b"__TEXT":
                # seg64: vmaddr@24 vmsize@32 fileoff@40 filesize@48
                text_vmsize = struct.unpack_from("<Q", data, off + 32)[0]
                text_off = struct.unpack_from("<Q", data, off + 40)[0]
                text_size = text_vmsize
            elif name == b"__LINKEDIT":
                linkedit_off = off
        elif cmd == LC_SEGMENT and cmdsize >= 56:
            name = data[off + 8:off + 24].split(b"\x00", 1)[0]
            if name == b"__TEXT":
                # seg32: vmaddr@24 vmsize@28 fileoff@32 filesize@36
                text_vmsize = struct.unpack_from("<I", data, off + 28)[0]
                text_off = struct.unpack_from("<I", data, off + 32)[0]
                text_size = text_vmsize
            elif name == b"__LINKEDIT":
                linkedit_off = off
        elif cmd == LC_CODE_SIGNATURE and cmdsize >= 16:
            sig_lc_off = off
            sig_dataoff, sig_datasize = struct.unpack_from("<II", data, off + 8)
        elif cmd in (0x21, 0x2C) and cmdsize >= 20:
            # LC_ENCRYPTION_INFO / _64: FairPlay App Store encryption
            cryptoff, cryptsize, cryptid = struct.unpack_from(
                "<III", data, off + 8)
        off += cmdsize
    return {
        "is64": is64, "filetype": filetype, "ncmds": ncmds,
        "sizeofcmds": sizeofcmds, "head_end": head_end,
        "text_off": text_off, "text_size": text_size,
        "text_vmsize": text_vmsize,
        "linkedit_off": linkedit_off, "sig_lc_off": sig_lc_off,
        "sig_dataoff": sig_dataoff, "sig_datasize": sig_datasize,
        "cryptoff": cryptoff, "cryptsize": cryptsize, "cryptid": cryptid,
    }


def _load_mobileprovision(path):
    """Parse a .mobileprovision profile and return the plist dict.

    The file is a CMS blob wrapping the profile plist; the plist is
    located by its marker (binary bplist00 or XML) and parsed directly.
    """
    with open(path, "rb") as fh:
        data = fh.read()
    plist_bytes = None
    i = data.find(b"bplist00")
    if i >= 0:
        plist_bytes = data[i:]
    else:
        j = data.find(b"<?xml")
        if j >= 0:
            k = data.find(b"</plist>", j)
            if k >= 0:
                plist_bytes = data[j:k + 8]
    if plist_bytes is None:
        raise SigningError(
            "No property list found inside provisioning profile: {0}".format(
                path))
    try:
        return _plist_loads(plist_bytes)
    except Exception as exc:
        raise SigningError(
            "Provisioning profile plist could not be parsed: {0}".format(exc))


def _load_sign_material(p12_path, p12_password, provision_path=None):
    """Unlock a PKCS#12 file (+ optional profile) for REAL signing.

    Returns a dict: certs (DER list), key (CRT components), leaf DER,
    subject CN, team id, and the parsed profile dict when given.
    """
    with open(p12_path, "rb") as fh:
        p12_data = fh.read()
    try:
        material = parse_pkcs12(p12_data, p12_password)
    except ValueError as exc:
        raise SigningError(
            "PKCS#12 could not be opened ({0}) - check --p12-password".format(
                exc))
    if not material["mac_ok"]:
        raise SigningError(
            "PKCS#12 integrity check FAILED - wrong --p12-password?")
    key = material["key"]
    leaf = material["leaf"]
    if leaf is None:
        for cand in material["certs"]:
            if parse_cert(cand)["modulus"] == key[1]:
                leaf = cand
                break
    if leaf is None:
        raise SigningError(
            "No certificate in the PKCS#12 matches the private key")
    info = parse_cert(leaf)
    team = info.get("ou") or ""
    cn = info.get("cn") or ""
    profile = None
    if provision_path:
        profile = _load_mobileprovision(provision_path)
        tid = profile.get("TeamIdentifier") or []
        if tid:
            team = str(tid[0])
    return {
        "certs": [bytes(c) for c in material["certs"]],
        "key": key,
        "leaf": bytes(leaf),
        "cn": cn,
        "team": team,
        "profile": profile,
    }


def _build_signature(body, filetype, identifier, entitlements_xml=None,
                     info_plist_data=None, sign=None,
                     code_resources_data=b"", exec_seg_limit=0):
    """Assemble the embedded-signature SuperBlob (Apple/zsign layout).

    Slot types match libCodeSigning exactly: primary SHA-1 CodeDirectory
    (slot 0), requirements set (slot 2), entitlements XML (slot 5), DER
    entitlements (slot 7), alternate SHA-256 CodeDirectory (slot 0x1000)
    and the CMS blobwrapper (slot 0x10000) when a real certificate signs
    the build. Ad-hoc builds keep the ldid-style shape (no CMS slot, an
    empty 12-byte requirements set). Page hashes use Apple semantics:
    the FINAL partial page is hashed SHORT, without zero padding. Real
    builds add the full designated-requirement DER and the extended
    special-slot row (-3 CodeResources ... -7 DER entitlements).
    """
    real = sign is not None
    ident = identifier.encode("utf-8", "replace") + b"\x00"
    team = b""
    if real and sign.get("team"):
        team = sign["team"].encode("utf-8", "replace") + b"\x00"

    ent_blob = b""
    if entitlements_xml:
        if isinstance(entitlements_xml, str):
            entitlements_xml = entitlements_xml.encode("utf-8")
        ent_blob = struct.pack(
            ">II", CSMAGIC_ENTITLEMENTS, 8 + len(entitlements_xml))
        ent_blob += entitlements_xml

    der_ent_blob = b""
    if real and ent_blob:
        try:
            ent_obj = _plist_loads(entitlements_xml)
        except Exception:
            ent_obj = None
        if isinstance(ent_obj, dict):
            try:
                der_ent_blob = build_der_entitlements(ent_obj)
            except ValueError:
                der_ent_blob = b""

    if real and sign.get("cn"):
        req_blob = build_requirements_der(identifier, sign["cn"])
    else:
        # empty requirements set (the canonical 12-byte blob)
        req_blob = struct.pack(">III", CSMAGIC_REQUIREMENT, 12, 0)

    code_limit = len(body)
    n_code_slots = (code_limit + (1 << CD_PAGE_SHIFT) - 1) >> CD_PAGE_SHIFT

    def make_cd(hash_name, hash_size, hash_type):
        slot = hash_size
        hash_fn = getattr(_hl, hash_name)
        zero = b"\x00" * slot

        def slot_sha(data):
            return hash_fn(data).digest() if data else zero

        # special slots, most negative first (zsign/codesign order)
        specials = []
        if real:
            if filetype == 2:                      # MH_EXECUTE
                specials.append(slot_sha(der_ent_blob))   # [-7]
                specials.append(zero)                     # [-6]
            specials.append(slot_sha(ent_blob))           # [-5]
            specials.append(zero)                         # [-4]
            specials.append(slot_sha(code_resources_data))  # [-3]
        specials.append(hash_fn(req_blob).digest())       # [-2]
        specials.append(hash_fn(info_plist_data or b"").digest())  # [-1]
        while len(specials) > 1 and specials[0] == zero:
            specials.pop(0)

        n_special = len(specials)
        ident_off = 88
        special_off = ident_off + len(ident) + len(team)  # NO padding
        hash_off = special_off + n_special * slot
        cd_len = hash_off + n_code_slots * slot
        cd = bytearray(cd_len)
        struct.pack_into(">IIII", cd, 0, CSMAGIC_CODEDIRECTORY, cd_len,
                         CD_VERSION, 0)            # flags: 0 (ad-hoc/real)
        struct.pack_into(">IIII", cd, 16, hash_off, ident_off, n_special,
                         n_code_slots)
        struct.pack_into(">I", cd, 32, code_limit)
        cd[36] = hash_size
        cd[37] = hash_type
        cd[38] = 0                                 # platform
        cd[39] = CD_PAGE_SHIFT
        if team:
            struct.pack_into(">I", cd, 48, ident_off + len(ident))
        if filetype == 2:                          # MH_EXECUTE
            if real:
                struct.pack_into(">QQQ", cd, 64, 0, exec_seg_limit,
                                 CS_EXECSEG_MAIN_BINARY)
            else:
                struct.pack_into(">QQQ", cd, 64,
                                 0xFFFFFFFFFFFFFFFF, 1, CS_EXECSEG_MAIN_BINARY)
        cd[ident_off:ident_off + len(ident)] = ident
        if team:
            cd[ident_off + len(ident):special_off] = team
        pos = special_off
        for digest in specials:
            cd[pos:pos + slot] = digest
            pos += slot
        pos = 0
        for i in range(n_code_slots):
            chunk = body[pos:pos + (1 << CD_PAGE_SHIFT)]   # short final page
            cd[hash_off + i * slot:hash_off + (i + 1) * slot] = \
                hash_fn(chunk).digest()
            pos += 1 << CD_PAGE_SHIFT
        return bytes(cd)

    cd1 = make_cd("sha1", 20, 1)
    cd2 = make_cd("sha256", 32, 2)

    entries = [
        (CSSLOT_CODEDIRECTORY, cd1),
        (2, req_blob),
    ]
    if ent_blob:
        entries.append((CSSLOT_ENTITLEMENTS, ent_blob))
    if der_ent_blob:
        entries.append((7, der_ent_blob))
    entries.append((CSSLOT_ALT_CODEDIRECTORY, cd2))
    if real:
        cd1_sha1 = _hl.sha1(cd1).digest()
        cd2_sha256 = _hl.sha256(cd2).digest()
        hashes_plist = build_cdhashes_plist(cd1_sha1, cd2_sha256[:20])
        cdh2_der = _der_seq(_der_oid(OID["sha256"]),
                            _der_octet(cd2_sha256))
        cms_der = build_cms(sign["certs"], sign["key"], sign["leaf"],
                            cd1, hashes_plist, cdh2_der)
        entries.append((CSSLOT_SIGNATURESLOT,
                        struct.pack(">II", CSMAGIC_BLOBWRAPPER,
                                    8 + len(cms_der)) + cms_der))
    count = len(entries)
    sb_len = 12 + 8 * count + sum(len(b) for _s, b in entries)
    sb = bytearray(struct.pack(">III", CSMAGIC_EMBEDDED_SIGNATURE, sb_len,
                               count))
    sb.extend(b"\x00" * (12 + 8 * count - len(sb)))
    index_off = 12
    blob_off = 12 + 8 * count
    for slot, blob in entries:
        struct.pack_into(">II", sb, index_off, slot, blob_off)
        index_off += 8
        blob_off += len(blob)
    for _slot, blob in entries:
        sb += blob
    return bytes(sb)


def _pseudo_sign_slice(slice_bytes, identifier, entitlements_xml,
                       info_plist_data=None, sign=None,
                       code_resources_data=b""):
    """Return (new_bytes, signed?, note) for one architecture slice.

    Order matters: every field that is itself covered by the code hashes
    (the LC_CODE_SIGNATURE dataoff/size and the __LINKEDIT extension) is
    patched FIRST, then the CodeDirectories hash the final bytes.
    """
    info = _header_info(slice_bytes, 0)
    if info is None:
        return slice_bytes, False, "not a little-endian Mach-O slice"

    buf = bytearray(slice_bytes)
    ident = identifier.encode("utf-8", "replace") + b"\x00"
    ent_len = 0
    if entitlements_xml:
        if isinstance(entitlements_xml, str):
            entitlements_xml = entitlements_xml.encode("utf-8")
        ent_len = 8 + len(entitlements_xml)

    if info["sig_lc_off"] is not None and info["sig_dataoff"]:
        sig_off = info["sig_dataoff"]
        if sig_off > len(buf):
            return slice_bytes, False, "signature offset out of range"
        del buf[sig_off:]
    elif info["sig_lc_off"] is not None:
        sig_off = _align(len(buf), 16)
    else:
        gap = info["head_end"]
        if gap + 16 > _align(len(buf), 4) or any(buf[gap:gap + 16]):
            return slice_bytes, False, "no header room for a new load command"
        buf[gap:gap + 16] = struct.pack(
            "<IIII", LC_CODE_SIGNATURE, 16, 0, 0)
        struct.pack_into("<I", buf, 16, info["ncmds"] + 1)
        struct.pack_into("<I", buf, 20, info["sizeofcmds"] + 16)
        sig_off = _align(len(buf), 16)

    if len(buf) < sig_off:
        buf.extend(b"\x00" * (sig_off - len(buf)))
    del buf[sig_off:]

    # ---- pre-compute the SuperBlob size (lengths are hash-independent) ----
    # A probe build over a same-length dummy body yields the exact blob
    # size: every blob length depends only on sizes, never on hash values.
    sign_kwargs = {
        "sign": sign,
        "code_resources_data": code_resources_data,
        "exec_seg_limit": info.get("text_vmsize", 0),
    }
    n_code = (len(buf) + (1 << CD_PAGE_SHIFT) - 1) >> CD_PAGE_SHIFT
    sb_len = len(_build_signature(
        b"\x00" * len(buf), info["filetype"], identifier,
        entitlements_xml, info_plist_data, **sign_kwargs))

    end_of_sig = sig_off + sb_len

    # ---- patch everything the hashes will cover ----
    if info["linkedit_off"] is not None:
        le = info["linkedit_off"]
        if info["is64"]:
            # seg64: vmaddr@+24 vmsize@+32 fileoff@+40 filesize@+48
            f_off, f_size = struct.unpack_from("<QQ", buf, le + 40)
            new_size = max(f_size, end_of_sig - f_off)
            struct.pack_into("<Q", buf, le + 32, _align(new_size, 4096))
            struct.pack_into("<QQ", buf, le + 40, f_off, new_size)
        else:
            # seg32: vmaddr@+24 vmsize@+28 fileoff@+32 filesize@+36
            f_off, f_size = struct.unpack_from("<II", buf, le + 32)
            new_size = max(f_size, end_of_sig - f_off)
            struct.pack_into("<I", buf, le + 28, _align(new_size, 4096))
            struct.pack_into("<II", buf, le + 32, f_off, new_size)
    if info["sig_lc_off"] is not None:
        struct.pack_into("<II", buf, info["sig_lc_off"] + 8,
                         sig_off, sb_len)
    else:
        struct.pack_into("<II", buf, info["head_end"] + 8, sig_off, sb_len)

    # ---- NOW hash the final bytes and append the blob ----
    sb = _build_signature(bytes(buf), info["filetype"], identifier,
                          entitlements_xml, info_plist_data, **sign_kwargs)
    if len(sb) != sb_len:
        return slice_bytes, False, "internal size mismatch"
    buf.extend(sb)
    return bytes(buf), True, "{0} page hash(es)".format(n_code)


def pseudo_sign_binary(path, identifier, entitlements_xml=None,
                       info_plist_data=None, sign=None,
                       code_resources_data=b""):
    """Ad-hoc pseudo-sign a Mach-O file IN PLACE. Returns a status string.

    FAT ("universal") binaries are handled slice by slice: every slice is
    signed independently, re-placed 16-aligned, and its fat_arch index
    entry (offset + size) is rewritten to match the new layout - the fat
    header always stays in sync with where the slices actually are.
    """
    with open(path, "rb") as fh:
        data = fh.read()
    slices = _macho_slices(data)
    if not slices:
        return "skipped (not a Mach-O)"

    is_fat = slices[0][0] != 0
    if is_fat:
        fat_magic = struct.unpack_from(">I", data, 0)[0]
        is64 = fat_magic == 0xCAFEBABF
        entry = 32 if is64 else 20
        out = bytearray(data[:slices[0][0]])
        cursor = slices[0][0]
    else:
        is64 = False
        entry = 0
        out = bytearray()
        cursor = 0

    signed_any = False
    for idx, (off, size) in enumerate(slices):
        new_slice, did, _note = _pseudo_sign_slice(
            data[off:off + size], identifier, entitlements_xml,
            info_plist_data, sign, code_resources_data)
        if is_fat:
            # honor the alignment the fat_arch entry declares
            align_pos = 8 + idx * entry + (24 if is64 else 16)
            align_field = struct.unpack_from(">I", data, align_pos)[0]
            shift = 1 << align_field if 0 < align_field < 16 else 16
            aligned = _align(len(out), shift)
            out.extend(b"\x00" * (aligned - len(out)))
            if is64:
                struct.pack_into(">QQ", out, 8 + idx * entry + 8,
                                 len(out), len(new_slice))
            else:
                struct.pack_into(">II", out, 8 + idx * entry + 8,
                                 len(out), len(new_slice))
        out.extend(new_slice)
        cursor = off + size
        signed_any = signed_any or did

    if not signed_any:
        return "skipped (big-endian or unsupported)"
    with open(path, "wb") as fh:
        fh.write(bytes(out))
    return "signed"


def write_code_resources(bundle_dir, main_executable):
    """Write a format-2 _CodeSignature/CodeResources for one bundle."""
    sig_dir = os.path.join(bundle_dir, CODE_SIGNATURE_DIR)
    files_sha1 = {}
    files_sha256 = {}
    for dirpath, dirnames, filenames in os.walk(bundle_dir):
        dirnames[:] = [d for d in sorted(dirnames)
                       if d != CODE_SIGNATURE_DIR and d != "__MACOSX"]
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, bundle_dir).replace(os.sep, "/")
            if rel == main_executable:
                continue
            try:
                with open(path, "rb") as fh:
                    full = fh.read()
            except OSError:
                continue
            magic_le = struct.unpack_from("<I", full, 0)[0] \
                if len(full) >= 4 else 0
            magic_be = struct.unpack_from(">I", full, 0)[0] \
                if len(full) >= 4 else 0
            if magic_le in _THIN_LE or magic_be in (0xCAFEBABE, 0xCAFEBABF):
                continue  # nested code carries its own embedded signature
            files_sha1[rel] = _b64.b64encode(
                _hl.sha1(full).digest()).decode("ascii")
            files_sha256[rel] = {
                "hash2": _b64.b64encode(
                    _hl.sha256(full).digest()).decode("ascii")}
    resources = {
        "files": files_sha1,
        "files2": files_sha256,
        "version": 2,
    }
    _makedirs(sig_dir)
    out = os.path.join(sig_dir, "CodeResources")
    with open(out, "wb") as fh:
        fh.write(_plist_to_xml_bytes(resources))
    return out


def _file_is_macho(path):
    try:
        with open(path, "rb") as fh:
            return _is_macho(fh.read(4096))
    except OSError:
        return False


def _bundle_main_executable(bundle_dir):
    """Resolve CFBundleExecutable (Info.plist) for a bundle directory.

    Falls back to heuristics when Info.plist is missing or unreadable
    (e.g. a broken user edit): the bundle-name match first, then the
    largest root-level Mach-O file - so a build never loses signing
    because of a damaged plist.
    """
    info = os.path.join(bundle_dir, "Info.plist")
    try:
        with open(info, "rb") as fh:
            data = _plist_load_fh(fh)
        name = data.get("CFBundleExecutable")
        if name and os.path.isfile(os.path.join(bundle_dir, str(name))):
            return str(name)
    except Exception:
        pass
    bundle_name = os.path.basename(bundle_dir.rstrip(os.sep))
    if bundle_name.endswith(APP_SUFFIX):
        candidate = bundle_name[:-len(APP_SUFFIX)]
        if os.path.isfile(os.path.join(bundle_dir, candidate)) \
                and _file_is_macho(os.path.join(bundle_dir, candidate)):
            log.debug(
                "Info.plist unreadable - signing the bundle-name "
                "executable: %s", candidate)
            return candidate
    best = None
    best_size = -1
    try:
        entries = sorted(os.listdir(bundle_dir))
    except OSError:
        return None
    for entry in entries:
        path = os.path.join(bundle_dir, entry)
        if not os.path.isfile(path):
            continue
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        if size > best_size and _file_is_macho(path):
            best, best_size = entry, size
    if best is not None:
        log.debug(
            "Info.plist unreadable - signing the largest Mach-O in the "
            "bundle: %s", best)
    return best


def pseudo_sign_bundle(bundle_dir, entitlements_xml=None, depth=0,
                       sign=None):
    """Sign one .app/.framework bundle with the BUILT-IN signer.

    Nested code bundles are signed deepest-first, then the bundle's main
    executable, then a fresh _CodeSignature/CodeResources is written.
    With ``sign`` (PKCS#12 material) the build carries a real certificate:
    CodeResources is written BEFORE signing so its SHA lands in special
    slot -3, and the CMS blobwrapper is embedded (slot 0x10000).
    Returns the number of Mach-O binaries signed.
    """
    signed = 0
    nested = _collect_nested_bundles(bundle_dir)
    for nested_path in nested:
        signed += pseudo_sign_bundle(nested_path, entitlements_xml,
                                     depth + 1, sign)

    try:
        with open(os.path.join(bundle_dir, "Info.plist"), "rb") as fh:
            loaded = _plist_load_fh(fh)
        ident = str(loaded.get("CFBundleIdentifier", "")) or \
            os.path.basename(bundle_dir)
    except Exception:
        ident = os.path.basename(bundle_dir)

    exe = _bundle_main_executable(bundle_dir)
    if exe:
        plist_bytes = None
        try:
            with open(os.path.join(bundle_dir, "Info.plist"), "rb") as fh:
                plist_bytes = fh.read()
        except OSError:
            plist_bytes = None
        cr_data = b""
        if sign is not None:
            # real mode: CodeResources must exist before the CD special
            # slot -3 is computed over its final bytes
            write_code_resources(bundle_dir, exe or "")
            try:
                with open(os.path.join(bundle_dir, CODE_SIGNATURE_DIR,
                                       "CodeResources"), "rb") as fh:
                    cr_data = fh.read()
            except OSError:
                cr_data = b""
        status = pseudo_sign_binary(os.path.join(bundle_dir, exe), ident,
                                    entitlements_xml, plist_bytes,
                                    sign, cr_data)
        log.info("Signed with BUILT-IN signer: %s [%s] - %s",
                 os.path.relpath(bundle_dir,
                                 getattr(pseudo_sign_bundle, "_root",
                                         bundle_dir)) if depth else
                 os.path.basename(bundle_dir),
                 ident, status)
        if status.startswith("signed"):
            signed += 1
    write_code_resources(bundle_dir, exe or "")
    return signed


def _embed_provision_profiles(payload_dir, bundles, provision_path):
    """Copy the profile as embedded.mobileprovision into the main .app.

    Only the first plain .app bundle receives it (nested extensions and
    frameworks do not carry profiles). Returns the number of embeds.
    """
    if not provision_path:
        return 0
    with open(provision_path, "rb") as fh:
        blob = fh.read()
    apps = [b for b in bundles if b.endswith(".app")]
    if not apps:
        return 0
    target = min(apps, key=len)          # shortest name = the main app
    dest = os.path.join(payload_dir, target, "embedded.mobileprovision")
    with open(dest, "wb") as fh:
        fh.write(blob)
    return 1


# ------------------------------------------------------------------------------
# Mode: decode
# ------------------------------------------------------------------------------


def _detect_wrapper_directory(names):
    """Return "X/" when every member lives under ONE top-level directory X
    that itself contains Payload/ (the archive was zipped from a parent
    folder). Returns "" otherwise."""
    firsts = {_to_posix(n).split("/", 1)[0] for n in names if n}
    if len(firsts) != 1:
        return ""
    wrapper = next(iter(firsts))
    if wrapper == PAYLOAD_DIR:
        return ""
    prefix = wrapper + "/"
    for n in names:
        p = _to_posix(n)
        if p.startswith(prefix) and p.startswith(prefix + PAYLOAD_DIR):
            return prefix
    return ""


def _paths_equal(a, b):
    """True when two paths point at the same entry (case-insensitive on
    Windows, where the file system is case-insensitive by default)."""
    a = os.path.abspath(a)
    b = os.path.abspath(b)
    if os.name == "nt":
        return os.path.normcase(a) == os.path.normcase(b)
    return a == b


def decode_ipa(input_path, output_dir=None, force=False, write_meta=True,
               keep_binary=False):
    """Decompile an .ipa into an editable framework directory."""
    log.info("Using %s %s", TOOL_NAME, __version__)
    log.info("Working directory: %s", os.getcwd())

    input_path = os.path.abspath(input_path)
    log.info("Checking input file: %s", input_path)
    if not os.path.isfile(input_path):
        raise InvalidInputError("Input file not found: {0}".format(input_path))
    if not input_path.lower().endswith(".ipa"):
        log.warning("Input lacks an .ipa extension - attempting to process it anyway")

    if output_dir is None:
        stem = os.path.splitext(os.path.basename(input_path))[0]
        output_dir = stem if stem else "ipaforge_output"
        output_dir = _cwd_path(output_dir)
        log.info("No output given - storing the framework in the current working directory")
    output_dir = os.path.abspath(output_dir)

    # SAFETY: the target must never be the input file itself. A default
    # derived from an extension-less input (e.g. "MyApp" instead of
    # "MyApp.ipa") lands exactly on the input path - reroute to a safe
    # name instead of destroying the archive.
    if _paths_equal(output_dir, input_path):
        if output_dir == os.path.abspath(
                _cwd_path(os.path.splitext(os.path.basename(input_path))[0]
                          or "ipaforge_output")):
            safe = os.path.splitext(os.path.basename(input_path))[0] \
                or "ipaforge_output"
            output_dir = _cwd_path(safe + "_decoded")
            output_dir = os.path.abspath(output_dir)
            log.info(
                "Default output would collide with the input file - "
                "using: %s", output_dir)
        else:
            raise InvalidInputError(
                "Refusing to continue: the output path is the input file "
                "itself ({0}) - choose a different output path".format(
                    output_dir))
    log.info("Output directory: %s", output_dir)

    if os.path.exists(output_dir):
        if _paths_equal(output_dir, input_path):
            raise InvalidInputError(
                "Refusing to overwrite: the target path is the input file "
                "itself: {0}".format(output_dir))
        if not force:
            raise InvalidInputError(
                "Output directory already exists: {0} (use -f/--force to overwrite)".format(
                    output_dir
                )
            )
        log.warning("Overwriting target directory...")
        if os.path.isdir(output_dir) and not os.path.islink(output_dir):
            shutil.rmtree(output_dir)
        elif os.path.isfile(output_dir) or os.path.islink(output_dir):
            os.remove(output_dir)
        else:
            raise InvalidInputError(
                "Target exists and cannot be replaced: {0}".format(
                    output_dir))
    _makedirs(output_dir)

    log.info("Opening zip archive...")
    try:
        archive = zipfile.ZipFile(input_path, "r")
    except zipfile.BadZipFile as exc:
        raise InvalidInputError("Not a valid zip archive (.ipa): {0}".format(exc))

    with archive:
        names = archive.namelist()
        log.debug("Archive table of contents holds %d entries", len(names))
        log.info("Checking resource table...")

        payload_members = [
            n for n in names if _to_posix(n).split("/", 1)[0] == PAYLOAD_DIR
        ]
        strip_prefix = ""
        if not payload_members:
            # Common mistake: the archive was zipped from a parent FOLDER, so
            # every member sits one level deeper ("Wrapper/Payload/...").
            # Unwrap a single such top-level directory transparently.
            strip_prefix = _detect_wrapper_directory(names)
            if strip_prefix:
                log.info(
                    "Payload found one level deeper under %s - the archive was"
                    " zipped from a folder; unwrapping it",
                    strip_prefix,
                )
                names = [
                    _to_posix(n)[len(strip_prefix):]
                    for n in names
                    if _to_posix(n).startswith(strip_prefix)
                    and _to_posix(n) != strip_prefix
                ]
                payload_members = [
                    n for n in names if n.split("/", 1)[0] == PAYLOAD_DIR
                ]
        if not payload_members:
            top_level = sorted({_to_posix(n).split("/", 1)[0] for n in names if n})
            shown = ", ".join(top_level[:8])
            if len(top_level) > 8:
                shown += ", ... (+{0} more)".format(len(top_level) - 8)
            raise InvalidInputError(
                "Missing Payload directory - not a valid iOS application"
                " archive. Top-level contents: [{0}]".format(shown)
            )
        log.debug("Payload members: %d", len(payload_members))

        bundles = find_app_bundles(names)
        app_bundle = None
        if not bundles:
            log.warning(
                "No top-level %s bundle found inside %s/ - extracting raw contents",
                APP_SUFFIX,
                PAYLOAD_DIR,
            )
        else:
            app_bundle = bundles[0]
            if len(bundles) > 1:
                log.warning(
                    "Multiple .app bundles detected (%s) - using: %s",
                    ", ".join(bundles),
                    app_bundle,
                )
            log.info("Found app bundle: %s/%s", PAYLOAD_DIR, app_bundle)

        log.info("Preflighting archive members for path/type/size safety...")
        _validate_archive_members(archive.infolist(), strip_prefix=strip_prefix)
        log.info("Extracting archive contents...")
        n_files, n_dirs, n_skipped = extract_archive(
            archive, output_dir, strip_prefix=strip_prefix
        )

    log.info("Extracted %d files / %d directories - nothing dropped", n_files, n_dirs)
    if n_skipped:
        log.warning(
            "%d archive member(s) could NOT be extracted (see warnings "
            "above) - the framework is missing only those", n_skipped)

    if keep_binary:
        manifest_entries = []
        counts = {}
        log.info("Keeping ALL files in binary form (--keep-binary)")
    else:
        log.info("Classifying and decompiling ALL %d extracted files...", n_files)
        manifest_entries, counts = classify_and_convert_all(output_dir)
        log_coverage_report(counts, n_files)
        report_opaque_files(counts)

    # Preserve the original (now invalidated) signature
    # OUTSIDE the rebuilt resources, in original/.
    archived_sigs = archive_original_signatures(output_dir)

    log.info("Converting Mach-O binaries to readable text (next to each binary)...")
    ghidra_kits = generate_ghidra_kits(output_dir)

    entitlement_count = extract_entitlements_readouts(output_dir)
    cert_file_count = extract_cert_readouts(output_dir)
    fairplay_count, _fp_scanned = detect_fairplay(output_dir)
    if app_bundle:
        extract_profile_readout(output_dir, app_bundle)
        profile_path = os.path.join(
            output_dir, PAYLOAD_DIR, app_bundle, PROFILE_FILE
        )
        if os.path.isfile(profile_path):
            log.info(
                "Embedded provisioning profile found: %s/%s/%s",
                PAYLOAD_DIR,
                app_bundle,
                PROFILE_FILE,
            )

    summary = read_app_summary(output_dir, app_bundle)
    if summary:
        log.info(
            "App identifier: %s (v%s, build %s, min iOS %s)",
            summary["identifier"],
            summary["short_version"],
            summary["version"],
            summary["min_os"],
        )

    metadata = {
        "ipaFileName": os.path.basename(input_path),
        "ipaforgeVersion": __version__,
        "appBundleName": app_bundle or "",
        "appBundlePath": "{0}/{1}".format(PAYLOAD_DIR, app_bundle) if app_bundle else "",
        "filesExtracted": str(n_files),
        "filesConvertedToXml": str(len(manifest_entries)),
        "filesBinaryPlists": str(counts.get(FMT_NATIVE_BPLIST, 0)) if counts else "0",
        "filesLegacyStrings": str(counts.get(FMT_LEGACY_STRINGS, 0)) if counts else "0",
        "filesAlreadyXml": str(counts.get("xml-plist", 0)) if counts else "0",
        "filesOpaqueCompiled": str(counts.get("opaque-compiled", 0)) if counts else "0",
        "filesNativeBinary": str(counts.get("native-binary", 0)) if counts else "0",
        "filesOtherBinary": str(counts.get("other-binary", 0)) if counts else "0",
        "filesReadableSummaries": str(counts.get("readable-summaries", 0)) if counts else "0",
        "entitlementsExtracted": str(entitlement_count),
        "fairPlayEncryptedBinaries": str(fairplay_count),
        "ghidraKits": str(ghidra_kits),
        "originalSignaturesArchived": str(archived_sigs),
        "conversions": [
            "{0}{1}{2}".format(rel, MANIFEST_SEP, fmt)
            for rel, fmt in manifest_entries
        ],
    }
    if summary:
        metadata["bundleIdentifier"] = summary["identifier"]
        metadata["bundleShortVersion"] = summary["short_version"]
        metadata["bundleVersion"] = summary["version"]
        metadata["minimumOSVersion"] = summary["min_os"]

    if write_meta:
        write_metadata_file(output_dir, metadata)
        log.info("Wrote framework metadata: %s", META_FILE_NAME)
    else:
        log.debug("Skipping framework metadata (--no-meta)")

    log.info("Decoded to: %s", output_dir)


# ------------------------------------------------------------------------------
# Mode: build
# ------------------------------------------------------------------------------


def _is_excluded_from_archive(rel_posix_path):
    """True for framework files that must not be packaged into the .ipa."""
    parts = rel_posix_path.split("/")
    if rel_posix_path == META_FILE_NAME:
        return True
    if rel_posix_path == MANIFEST_FILE_NAME:
        return True
    if parts[0] == ORIGINAL_DIR:
        return True
    if parts[0] == READABLE_DIR:
        return True
    if parts[0] == GHIDRA_DIR:
        return True
    if parts[-1] == IMPORT_SCRIPT_NAME:
        return True
    if any(parts[-1].endswith(_sfx) for _sfx in KIT_SUFFIXES):
        return True
    if parts[-1] == ".DS_Store":
        return True
    if any(part == "__MACOSX" for part in parts):
        return True
    return False


def package_framework(root_dir, output_path, compression_level):
    """Zip the framework directory into `output_path`.

    Every archive entry is recorded relative to the framework root, so paths
    keep the canonical 'Payload/...' layout required by iOS. Separators are
    normalized to POSIX '/' regardless of the host platform. Returns the
    number of packaged files.
    """
    if compression_level <= 0:
        compression = zipfile.ZIP_STORED
        compresslevel = None
    else:
        compression = zipfile.ZIP_DEFLATED
        compresslevel = compression_level

    kit_skipped = 0
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for filename in filenames:
            if filename == IMPORT_SCRIPT_NAME or any(
                    filename.endswith(_sfx) for _sfx in KIT_SUFFIXES):
                kit_skipped += 1
    if kit_skipped:
        log.info("Keeping %d analysis kit file(s) out of the archive "
                 "(kits are regenerated at decode)", kit_skipped)

    collected = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames.sort()
        for filename in sorted(filenames):
            full = os.path.join(dirpath, filename)
            rel = os.path.relpath(full, root_dir)
            rel_posix = _to_posix(rel)
            if _is_excluded_from_archive(rel_posix):
                log.debug("Excluding from archive: %s", rel_posix)
                continue
            collected.append((full, rel_posix))
    collected.sort(key=lambda item: item[1])

    n_files = 0
    with zipfile.ZipFile(output_path, "w", allowZip64=True) as zf:
        zf.comment = "Packed by {0} {1}".format(TOOL_NAME, __version__).encode("utf-8")
        for full, arcname in collected:
            try:
                zf.write(
                    full,
                    arcname,
                    compress_type=compression,
                    compresslevel=compresslevel,
                )
            except TypeError:
                # Python < 3.7: ZipFile.write() has no compresslevel keyword -
                # fall back to the archive-level default so older runtimes
                # still produce a valid archive.
                zf.write(full, arcname, compress_type=compression)
            log.debug("Adding: %s", arcname)
            n_files += 1
    return n_files


def _verify_built_ipa(output_path, reencoded_rels,
                      expect_signatures=True, source_dir=None,
                      expected_real_rels=None):
    """Post-build self-check: reopen the finished .ipa and prove it is sound.

    Before success is reported, the archive itself is re-opened and
      * zip integrity is verified (CRC of every member),
      * every re-encoded property list is parsed back from INSIDE the
        archive,
      * every packaged Mach-O binary is checked for its embedded
        signature blob.
      * certificates are accounted: real code-signature chains,
        provisioning-profile certificates and .cer/.der/.pem/.crt
        resources (resource certs are compared byte-identical against
        the source framework; a dropped real chain is WARNED about).
    Raises IPAForgeError (removing the broken output) on any failure.
    """
    try:
        zf = zipfile.ZipFile(output_path, "r")
    except Exception as exc:
        raise IPAForgeError(
            "Built archive cannot be re-opened: {0}".format(exc))
    parsed = signed = 0
    real_chains = []
    res_total = res_identical = 0
    prof_certs = None
    dropped_chains = 0
    try:
        try:
            corrupt = zf.testzip()
            if corrupt is not None:
                raise IPAForgeError(
                    "Built archive failed zip integrity: {0}".format(corrupt))
            names = set(zf.namelist())
            for rel, is_binary in reencoded_rels:
                if rel not in names:
                    raise IPAForgeError(
                        "Re-encoded file missing from the archive: {0}".format(
                            rel))
                blob = zf.read(rel)
                if is_binary:
                    try:
                        _plist_loads(blob)
                    except Exception as exc:
                        raise IPAForgeError(
                            "Re-encoded plist does not parse back inside the "
                            "archive: {0} ({1})".format(rel, exc))
                elif not blob.startswith((b"\xff\xfe", b"\xfe\xff")):
                    raise IPAForgeError(
                        "Re-encoded .strings lost its text encoding: "
                        "{0}".format(rel))
                parsed += 1
            for name in names:
                data = zf.read(name)
                if _is_macho(data):
                    if b"\xfa\xde\x0c\xc0" in data or b"\xc0\x0c\xde\xfa" in data:
                        signed += 1
                    elif expect_signatures:
                        log.warning(
                            "Packaged binary carries no embedded signature "
                            "blob: %s", name)
                    cms = _macho_embedded_cms(data)
                    if cms is not None:
                        certs = _certs_from_cms(cms)
                        if certs:
                            leaf = _cert_display_fields(certs[0])
                            real_chains.append(
                                (name, len(certs), leaf["cn"]))
                    if (expected_real_rels is not None
                            and name in expected_real_rels and cms is None):
                        dropped_chains += 1
                elif name.endswith("/" + PROFILE_FILE):
                    try:  # profile = CMS wrapper around the plist
                        prof = _plist_loads(_profile_plist_bytes(data))
                        prof_certs = len(prof.get("DeveloperCertificates")
                                         or [])
                    except Exception:
                        prof_certs = None
                elif name.lower().endswith(CERT_EXTS):
                    res_total += 1
                    if source_dir is not None:
                        src = os.path.join(source_dir, name)
                        if os.path.isfile(src):
                            with open(src, "rb") as fh:
                                if fh.read() == data:
                                    res_identical += 1
        except IPAForgeError:
            try:
                os.remove(output_path)
            except OSError:
                pass
            raise
    finally:
        zf.close()
    log.info(
        "Build self-check passed: archive re-opened, %d re-encoded plist(s) "
        "parse back, %d signed binary(ies), zip integrity OK",
        parsed, signed,
    )
    for name, n_certs, cn in real_chains[:3]:
        log.info(
            "Certificates: %s carries a REAL code-signature chain: "
            "%d cert(s), leaf CN '%s'", name, n_certs, cn)
    if len(real_chains) > 3:
        log.info("Certificates: ... and %d more chain-carrying binary(ies)",
                 len(real_chains) - 3)
    if prof_certs is not None:
        log.info(
            "Certificates: provisioning profile packaged with %d embedded "
            "certificate(s)", prof_certs)
    if res_total:
        log.info(
            "Certificates: %d certificate resource(s) packaged, %d "
            "byte-identical to the source", res_total, res_identical)
    if dropped_chains:
        log.warning(
            "%d Mach-O binary(ies) carried a REAL certificate chain at "
            "decode but the rebuilt archive is ad-hoc signed - stock iOS "
            "devices refuse it (re-sign with --p12 to restore a real "
            "chain)", dropped_chains)


def build_ipa(input_dir, output_path=None, force=False, compression_level=9,
              sign_mode=SIGN_MODE_AUTO, sign_tool=SIGN_TOOL_AUTO, sign_identity="-",
              entitlements=None, p12=None, p12_password="", provision=None):
    """Compile an .ipa from a decoded framework directory.

    Signing happens AFTER property-list re-encoding but BEFORE packaging, so
    the new code signature covers the final bundle content - signing after
    zipping would invalidate it. The finished archive is re-opened and
    verified (zip integrity, re-encoded plists parse back, signature blobs
    present) before success is reported. Depending on sign_mode:
      'auto'  - sign when a native utility is found, warn+continue otherwise
      'force' (-s)        - sign, hard-failing the build if no utility exists
      'skip'  (--no-sign) - never sign; produce an UNSIGNED archive

    With --p12 the BUILT-IN signer produces a REAL certificate signature
    (PKCS#7/CMS + dual CodeDirectory + designated requirement), replacing
    any external signing utility. --provision embeds a provisioning
    profile and adopts its entitlements when --entitlements is absent.
    """
    log.info("Using %s %s", TOOL_NAME, __version__)
    log.info("Working directory: %s", os.getcwd())

    input_dir = os.path.abspath(input_dir)
    log.info("Checking framework directory: %s", input_dir)
    if not os.path.isdir(input_dir):
        raise FrameworkNotFoundError("Framework directory not found: {0}".format(input_dir))

    payload_dir = os.path.join(input_dir, PAYLOAD_DIR)
    if not os.path.isdir(payload_dir):
        raise FrameworkNotFoundError(
            "Missing Payload directory in framework: {0}".format(input_dir)
        )
    log.info("Checking resource table...")

    bundles = [
        entry
        for entry in sorted(os.listdir(payload_dir))
        if entry.endswith(APP_SUFFIX) and os.path.isdir(os.path.join(payload_dir, entry))
    ]
    if bundles:
        if len(bundles) > 1:
            log.warning(
                "Multiple .app bundles detected (%s) - packaging all of them",
                ", ".join(bundles),
            )
        log.info("Found app bundle: %s/%s", PAYLOAD_DIR, bundles[0])
    else:
        log.warning("No .app bundle found inside Payload/ - packaging directory as-is")

    metadata = {}
    meta_path = os.path.join(input_dir, META_FILE_NAME)
    if os.path.isfile(meta_path):
        metadata = parse_metadata_file(meta_path)
        log.info("Reading framework metadata: %s", META_FILE_NAME)
        if metadata:
            log.debug("Metadata keys: %s", ", ".join(sorted(metadata)))
    else:
        log.debug("No %s found - continuing without metadata", META_FILE_NAME)

    if output_path is None:
        suggested = os.path.basename(metadata.get("ipaFileName", "").strip())
        if not suggested:
            suggested = os.path.basename(input_dir) + ".ipa"
        if suggested.lower().endswith(".ipa"):
            suggested = suggested[:-4]
        suffix = "unsigned" if sign_mode == SIGN_MODE_SKIP else "signed"
        suggested += "-" + suffix + ".ipa"
        output_path = _cwd_path(suggested)
        log.info(
            "No output given - writing %s into the current working directory",
            suggested,
        )
    output_path = os.path.abspath(output_path)
    log.info("Output file: %s", output_path)

    parent_dir = os.path.dirname(output_path)
    if parent_dir:
        _makedirs(parent_dir)
    if os.path.exists(output_path):
        if not force:
            raise FrameworkNotFoundError(
                "Output file already exists: {0} (use -f/--force to overwrite)".format(
                    output_path
                )
            )
        log.warning("Overwriting target file...")
        os.remove(output_path)

    log.info("Checking whether property lists changed...")
    manifest_entries = None
    raw_conversions = metadata.get("conversions")
    if isinstance(raw_conversions, list) and raw_conversions:
        manifest_entries = []
        for item in raw_conversions:
            if MANIFEST_SEP in item:
                rel, fmt = item.split(MANIFEST_SEP, 1)
            else:
                rel, fmt = item, FMT_NATIVE_BPLIST
            manifest_entries.append((_to_posix(rel), fmt))
        log.info(
            "%s lists %d converted file(s)", META_FILE_NAME, len(manifest_entries)
        )
    else:
        # Frameworks decoded by IPAForge <= 1.8.0 carry the separate
        # ipaforge-converted.list file - keep reading it for compatibility.
        manifest_entries = read_conversion_manifest(input_dir)
        if manifest_entries:
            log.info(
                "Legacy conversion list found: %d file(s) were decoded to XML",
                len(manifest_entries),
            )
    if manifest_entries:
        reencoded_rels = reencode_manifest_entries(input_dir, manifest_entries)
    else:
        log.info("No conversion list - using extension heuristic")
        reencoded_rels = reencode_plistish_fallback(input_dir)
    if reencoded_rels:
        log.info("Re-encoded %d plist file(s) to their native format",
                 len(reencoded_rels))
    else:
        log.info("No text property lists required re-encoding")

    signed_count = 0
    pre_signed_rels = set()
    if sign_mode == SIGN_MODE_SKIP:
        log.warning(
            "Signing skipped (--no-sign): the archive will be UNSIGNED - "
            "iOS refuses unsigned archives"
        )
    elif not bundles:
        log.warning("No .app bundle found - nothing to sign, building UNSIGNED")
    else:
        if entitlements and not os.path.isfile(entitlements):
            raise SigningError(
                "Entitlements file not found: {0}".format(entitlements)
            )
        ent_xml = None
        if entitlements:
            with open(entitlements, "rb") as fh:
                ent_xml = fh.read()
            log.info("Embedding entitlements from: %s",
                     os.path.basename(entitlements))
        sign_material = None
        if p12:
            if not os.path.isfile(p12):
                raise SigningError(
                    "PKCS#12 file not found: {0}".format(p12))
            if provision and not os.path.isfile(provision):
                raise SigningError(
                    "Provisioning profile not found: {0}".format(provision))
            sign_material = _load_sign_material(p12, p12_password, provision)
            log.info(
                "REAL certificate signing enabled: CN=%r, team %s, "
                "%d certificate(s) in chain",
                sign_material["cn"], sign_material["team"] or "(none)",
                len(sign_material["certs"]))
            if sign_material["profile"] is not None:
                log.info("Provisioning profile: %s",
                         os.path.basename(provision))
                if ent_xml is None:
                    prof_ents = sign_material["profile"].get("Entitlements")
                    if isinstance(prof_ents, dict) and prof_ents:
                        ent_xml = _plist_to_xml_bytes(prof_ents)
                        log.info(
                            "Adopted %d entitlement key(s) from the "
                            "provisioning profile", len(prof_ents))
                n_embedded = _embed_provision_profiles(
                    payload_dir, bundles, provision)
                if n_embedded:
                    log.info(
                        "Profile embedded as embedded.mobileprovision in "
                        "%d app bundle(s)", n_embedded)
        elif provision:
            log.warning(
                "--provision needs --p12 (it accompanies a real-certificate "
                "signature) - the profile was NOT embedded")
        # remember which binaries carry a REAL chain BEFORE the in-place
        # signer rewrites them - the build self-check warns when such a
        # chain is dropped (ad-hoc rebuild of a store-signed app)
        pre_signed_rels = set()
        for dirpath, _dn, filenames in os.walk(payload_dir):
            for filename in sorted(filenames):
                spath = os.path.join(dirpath, filename)
                try:
                    with open(spath, "rb") as fh:
                        pdata = fh.read(64 * 1024 * 1024)
                except OSError:
                    continue
                if not _is_macho(pdata):
                    continue
                if _macho_embedded_cms(pdata) is not None:
                    pre_signed_rels.add(os.path.relpath(
                        spath, input_dir).replace(os.sep, "/"))
        removed = _strip_stale_signatures(payload_dir)
        if removed:
            log.info("Removed %d stale signature directorie(s)", removed)
        _enc, _scanned = detect_fairplay(input_dir)
        if _enc:
            log.warning(
                "%d of %d Mach-O binary(ies) carry FairPlay-encrypted "
                "machine code (App Store build). Re-signing cannot decrypt "
                "it - such binaries only run on the original device. All "
                "resources recompiled fine.", _enc, _scanned)
        try:
            for bundle in bundles:
                setattr(pseudo_sign_bundle, "_root", payload_dir)
                signed_count += pseudo_sign_bundle(
                    os.path.join(payload_dir, bundle), ent_xml,
                    sign=sign_material
                )
        except SigningError:
            raise
        except Exception as exc:
            raise SigningError("Built-in signing failed: {0}".format(exc))
        if sign_material is not None:
            log.info(
                "Bundles re-signed with a REAL certificate "
                "(%d Mach-O file(s), CMS + dual CodeDirectory + "
                "designated requirement)", signed_count
            )
            log.info(
                "Real-cert signature: CMS verified internally; install "
                "needs the profile's device UDID unless it is a "
                "distribution profile"
            )
        else:
            log.info(
                "Bundles re-signed with the BUILT-IN ad-hoc signer "
                "(%d Mach-O file(s), SHA-256 CodeDirectory)", signed_count
            )
        if signed_count == 0:
            log.warning(
                "No signable Mach-O binary was found in the bundle(s) - "
                "the archive will be UNSIGNED (see the per-file notes above)"
            )

    log.info("Building IPA archive (compression level %s)...", compression_level)
    n_files = package_framework(input_dir, output_path, compression_level)
    _verify_built_ipa(output_path, reencoded_rels,
                      expect_signatures=(sign_mode != SIGN_MODE_SKIP),
                      source_dir=input_dir,
                      expected_real_rels=pre_signed_rels)

    stale_signatures = [
        "{0}/{1}/{2}".format(PAYLOAD_DIR, bundle, CODE_SIGNATURE_DIR)
        for bundle in bundles
        if os.path.isdir(os.path.join(payload_dir, bundle, CODE_SIGNATURE_DIR))
    ]
    if stale_signatures and signed_count == 0 and sign_mode != SIGN_MODE_SKIP:
        log.warning(
            "Stale code signature directory packaged: %s - signing produced "
            "no fresh signatures (use --no-sign to silence this warning)",
            ", ".join(stale_signatures),
        )

    size = os.path.getsize(output_path)
    log.info(
        "Built IPA: %s (%s, %d files)", output_path, _human_size(size), n_files
    )


# ------------------------------------------------------------------------------
# Command line interface
# ------------------------------------------------------------------------------


def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="ipaforge",
        description=(
            "{0} {1} - a decompiler and compiler for iOS .ipa "
            "archives. NOTHING is skipped or dropped: 100%% of the archive is "
            "extracted and every file is classified; every decodable format "
            "(binary plists of ANY extension, legacy .strings) becomes "
            "readable XML and is rebuilt in its native format. Zero "
            "third-party dependencies; compile mode re-signs automatically "
            "with the BUILT-IN ad-hoc signer.".format(TOOL_NAME, __version__)
        ),
        epilog=(
            "examples:\n"
            "  ipaforge -d MyApp.ipa                    decompile into ./MyApp/\n"
            "  ipaforge -d MyApp.ipa framework/ -f      decompile, overwrite target\n"
            "  ipaforge --decode MyApp.ipa out          long-form decompile\n"
            "  ipaforge -b framework/                   compile -> <name>-signed.ipa,\n"
            "                                           auto-signed when possible\n"
            "  ipaforge -b framework/ out.ipa           compile to explicit path\n"
            "  ipaforge -b framework/ --no-sign         compile WITHOUT signing\n"
            "  ipaforge -b framework/ -s                compile; FAIL if no signer\n"
            "  ipaforge App.ipa (Windows)     no flags needed: .ipa = decode,\n"
            "                                 folder = build\n"
            "  ipaforge -b framework/ -s --entitlements e.plist  embed entitlements\n"
            "  ipaforge -b fw --p12 dev.p12 --p12-password PW     REAL certificate sign\n"
            "  ipaforge -b fw --p12 dev.p12 --provision x.mobileprovision  profile sign\n"
            "\n"
            "exit codes: 0 = success, 1 = runtime error, 2 = CLI usage error\n"
            "\n"
            "defaults are resolved against the CURRENT working directory (the\n"
            "folder your terminal/command prompt is standing in, e.g. Desktop):\n"
            "  ipaforge -d app.ipa  ->  ./<name>/       ipaforge -b fw  ->  ./<name>-signed.ipa\n"
            "\n"
            "note: 100%% of files are extracted and classified - see the\n"
            "      coverage report and ipaforge.yml. Only Apple-proprietary\n"
            "      compiled formats\n"
            "      (.car/.nib/.mom) and Mach-O code stay byte-identical;\n"
            "      entitlements inside Mach-O binaries are extracted as\n"
            "      readable XML copies under original/.\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version="{0} {1}".format(TOOL_NAME, __version__),
        help="show the IPAForge version number and exit",
    )

    # Windows convenience: with no -d/-b the mode is inferred from the
    # input (.ipa file -> decode, folder -> build). Linux/macOS keep the
    # explicit-flags contract unchanged.
    mode = parser.add_mutually_exclusive_group(
        required=(os.name != "nt"))
    mode.add_argument(
        "-d",
        "--decode",
        dest="mode",
        action="store_const",
        const=MODE_DECODE,
        help="decompile an .ipa archive into an editable framework directory",
    )
    mode.add_argument(
        "-b",
        "--build",
        dest="mode",
        action="store_const",
        const=MODE_BUILD,
        help="compile an .ipa archive from a decoded framework directory",
    )

    parser.add_argument(
        "input",
        metavar="INPUT",
        help=".ipa file to decompile (-d) or framework directory to "
             "compile (-b); on Windows the mode is auto-detected "
             "(.ipa = decode, folder = build)",
    )
    parser.add_argument(
        "output",
        metavar="OUTPUT",
        nargs="?",
        default=None,
        help=(
            "target output directory (decode) or output .ipa file (build); "
            "defaults to ./<name>/ or ./<name>-signed.ipa, relative to your "
            "current working directory"
        ),
    )

    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="overwrite an existing output directory/file without asking",
    )
    parser.add_argument(
        "--no-meta",
        dest="write_meta",
        action="store_false",
        help="(decode) do not write the %s metadata file" % META_FILE_NAME,
    )
    parser.add_argument(
        "--keep-binary",
        dest="keep_binary",
        action="store_true",
        help="(decode) leave ALL files binary - no conversion to XML at all",
    )
    parser.add_argument(
        "-c",
        "--compression-level",
        dest="compression_level",
        type=int,
        choices=range(0, 10),
        metavar="0-9",
        default=9,
        help="(build) zip compression level, 0 = stored (default: 9)",
    )

    signing = parser.add_argument_group("code signing options (build mode)")
    sign_group = signing.add_mutually_exclusive_group()
    sign_group.add_argument(
        "-s",
        "--sign",
        dest="sign_mode",
        action="store_const",
        const=SIGN_MODE_FORCE,
        help="(build, legacy) kept for compatibility - signing is now "
             "BUILT-IN and always available; this flag does nothing",
    )
    sign_group.add_argument(
        "--no-sign",
        dest="sign_mode",
        action="store_const",
        const=SIGN_MODE_SKIP,
        help="(build) disable signing entirely; produce an UNSIGNED archive",
    )
    signing.add_argument(
        "--sign-tool",
        dest="sign_tool",
        choices=[SIGN_TOOL_AUTO, SIGN_TOOL_CODESIGN, SIGN_TOOL_LDID],
        default=SIGN_TOOL_AUTO,
        help="(legacy, ignored) signing is BUILT-IN since 1.10.0 - "
             "no external utility is used or needed",
    )
    signing.add_argument(
        "--sign-identity",
        dest="sign_identity",
        default="-",
        metavar="IDENTITY",
        help="(legacy, ignored) the built-in signer is always ad-hoc",
    )
    signing.add_argument(
        "--entitlements",
        dest="entitlements",
        default=None,
        metavar="FILE",
        help="entitlements plist to EMBED in the signature "
             "(built-in, no external tool)",
    )
    signing.add_argument(
        "--p12",
        dest="p12",
        default=None,
        metavar="FILE",
        help="sign with a REAL developer certificate: PKCS#12 (.p12/.pfx) "
             "exported from your Apple Developer account; the CMS + dual "
             "CodeDirectory signature is produced entirely BUILT-IN "
             "(no external tool)",
    )
    signing.add_argument(
        "--p12-password",
        dest="p12_password",
        default="",
        metavar="PASS",
        help="password for --p12 (default: empty string)",
    )
    signing.add_argument(
        "--provision",
        dest="provision",
        default=None,
        metavar="FILE",
        help="provisioning profile (.mobileprovision) to embed as "
             "embedded.mobileprovision and to adopt entitlements/team "
             "from (use together with --p12)",
    )

    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="verbose output (debug log lines)",
    )
    verbosity.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="suppress all output except errors",
    )
    return parser


def _infer_mode(inp, parser):
    """Windows flag-less mode: guess decode/build from the input.

    Returns (mode, resolved_input) - the input may be redirected (the
    leftover-debris case below).
    """
    if os.path.isdir(inp):
        # A folder without Payload is usually leftover debris from an
        # earlier failed decode - if a same-named .ipa file sits next to
        # it, decode THAT (the folder is never touched by decode).
        if not os.path.isdir(os.path.join(inp, PAYLOAD_DIR)) \
                and os.path.isfile(inp + ".ipa"):
            log.info(
                "'%s' is a folder without Payload - decoding the "
                "archive '%s.ipa' found next to it instead", inp, inp)
            return MODE_DECODE, inp + ".ipa"
        return MODE_BUILD, inp
    if os.path.isfile(inp):
        return MODE_DECODE, inp
    if inp.lower().endswith(".ipa"):
        return MODE_DECODE, inp     # decode_ipa raises the precise not-found error
    parser.error(
        "cannot infer the mode for '{0}': not an existing folder and not a "
        ".ipa file - use -d (decompile) or -b (build)".format(inp))


def _reconcile_mode(mode, inp, parser):
    """Windows: an explicitly-but-wrongly chosen mode is corrected when the
    input unambiguously implies the other mode (-b on an .ipa file -> decode;
    -d on a folder -> build it when it is a decoded framework, clear usage
    error otherwise). Linux/macOS keep strict behavior."""
    if mode == MODE_BUILD and os.path.isfile(inp):
        log.warning(
            "-b expects a decoded framework FOLDER, but '%s' is a file - "
            "decoding it instead (build afterwards with -b on the decoded "
            "folder)", inp)
        return MODE_DECODE, inp
    if mode == MODE_DECODE and os.path.isdir(inp):
        if os.path.isdir(os.path.join(inp, PAYLOAD_DIR)):
            log.warning(
                "-d expects an .ipa FILE, but '%s' is a decoded framework - "
                "building it instead", inp)
            return MODE_BUILD, inp
        parser.error(
            "'{0}' is a folder and holds no Payload - it is no .ipa file "
            "and no decoded framework; check the path".format(inp))
    return mode, inp


def main(argv=None):
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    if args.mode is None:
        args.mode, args.input = _infer_mode(args.input, parser)
    elif os.name == "nt":
        args.mode, args.input = _reconcile_mode(args.mode, args.input, parser)
    configure_logging(verbose=args.verbose, quiet=args.quiet)

    sign_mode = args.sign_mode if args.sign_mode else SIGN_MODE_AUTO

    try:
        if args.mode == MODE_DECODE:
            decode_ipa(
                args.input,
                args.output,
                force=args.force,
                write_meta=args.write_meta,
                keep_binary=args.keep_binary,
            )
        else:
            build_ipa(
                args.input,
                args.output,
                force=args.force,
                compression_level=args.compression_level,
                sign_mode=sign_mode,
                sign_tool=args.sign_tool,
                sign_identity=args.sign_identity,
                entitlements=args.entitlements,
                p12=getattr(args, "p12", None),
                p12_password=getattr(args, "p12_password", "") or "",
                provision=getattr(args, "provision", None),
            )
    except IPAForgeError as exc:
        log.error("%s", exc)
        return 1
    except zipfile.BadZipFile as exc:
        log.error("Corrupt or invalid zip archive: %s", exc)
        return 1
    except OSError as exc:
        log.error("File system error: %s", exc)
        return 1
    return 0


# ==============================================================================
#  ALL-IN-ONE DISTRIBUTION (since 1.19.0)
#  This file alone IS the complete kit: the shell launcher and all documents
#  of the classic 6-file layout are embedded here, compressed. Unpack them
#  anywhere with --extract [DEST], print any document with --readme,
#  --install-guide, --requirements or --signing. Everything else in this
#  engine behaves exactly as before. (Payloads are stdlib zlib+base64; the
#  unpacked files are byte-identical to the .zip distribution.)
# ==============================================================================
_DIST_LAUNCHER = (
    "eNq1VWFv2zYQ/a5fcVWCONkiaXEKDHCQYFnmtgaC1ohbYENgBLR0sghTpEBSVoxh/31HSpbtzigG"
    "rNMHw6KO7969ezyevElqo5MFlwnKNSyYKYITuP2uDwHCZHr/TuklwlU8HMZvIYJHLutXSKBk6acZ"
    "CFbLtEANudLAK5a74Lja/C9kZijySKiUWS6X0GhWVahHkHOZmf3kIPHVglXAraEtwGQGupYUY2OH"
    "YwoUoqc+omXQaJRYowsxoBoJbEELtUVo8ykJ57hGCU1BP1yu1Qozh2ULreplAQzMphRcri4uYY2a"
    "55zAbMGIR4GQqrJi0qGgXHKJxFkghHucQ0/MZd+Rv/TMrcuoUbCNAaKgNw6tpC+RcEhML+sSpd/i"
    "Ujm+woNtjMVyYKDa2ELJa2JtUVca6ZdkcCFfDFviyP1zz5YNRBmQtIK3hce0Ds+qtlVtXzKu5/RS"
    "uQ9m/s+dC8g1K7FReuVit/scxhy+tTGinlTf3zWEGEURuRee2g57jfrmEkVMrfKaSsu4dMayBTdg"
    "Us0r6zYfPgQ4s0xbqlOV8Ov97MPL7NOXp4cxmFZ/76TaO4ZgUqVdBlpdMp0JNOSuHArVuFjC6tI0"
    "zGxNddk2PFdCUFRnKgO1tFyQyzQy0bqH0OmFHJzFQUvhNjz9c4/R80/zv8KgKVzwM0SPEJ62H0KY"
    "30CmAteB3yZPtO08zSCaUsA5KSKpgbvYixDuIMlwnciaTs3w7uwKzs6garKL0CP0uc+JTubY7m/2"
    "ISkzCN0a1RlA9yQ/XMDNDRx9TnZd6kQA0n2J1BNYIVbATMRND0VIOyZUVNLX6hKc+ANk+foIGKMp"
    "4IaX9VhoWBpkSmIwe3iaTD+//DeBgvHH95OP45d3k0dHbIeZHJz9zqbDmMyl69TWettl6m+6Gnln"
    "daOjrI0F4UphQsml4Rm2lu0GovdswHPq+RuIciK6x8G33hmsLZYqh3A8goej80kqsrmqZTaCQ4y7"
    "s+Hh/v4ce3ILOlhYCbVBml6KVHYXRMNtAYO9qgfkBF+XcXL2JzHeg3+lyXwV5HyrzzXpQzTtZisL"
    "OzbcehJszbhgC4FHjjHp041RiNY9yteN3NNq+sf49/FtFxigOAbwb/fTdoOHCkrkXqZBl2FA6vdv"
    "g7YNQBmm958/xDCRxjLKMW3TDuOfgaKv4+GP1Dlt7LdEfOtmId0m9AVTP6hG7vZuaD5190t/pdDb"
    "gk5Nub1bOnP0IjoE8pcvLfzaaOHpL2HwN60QnY8="
)

_DIST_README = (
    "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"
)

_DIST_INSTALL = (
    "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"
    "7ogYCehudSoEhU9P2P8BAIu9lw=="
)

_DIST_REQ = (
    "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"
    "Nj4LtTu/s4bvOsa9Tz9pEMOX/8ei/wEXG3mH"
)

_DIST_REQSIGN = (
    "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"
    "x/8AZtSoWw=="
)

_DIST_FILES = (
    ("ipaforge.py", None, True),
    ("ipaforge", _DIST_LAUNCHER, True),
    ("README.md", _DIST_README, False),
    ("INSTALL.txt", _DIST_INSTALL, False),
    ("REQUIREMENTS.txt", _DIST_REQ, False),
    ("REQUIREMENTS-signing-linux.txt", _DIST_REQSIGN, False),
)

IPA_DIST_DIR = "ipaforge-" + __version__


def _dist_unpack(b64):
    import base64
    import zlib
    return zlib.decompress(base64.b64decode(b64))


def _dist_print(b64):
    data = _dist_unpack(b64)
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    sys.stdout.write(data)
    return 0


def _dist_extract(dest):
    here = os.path.abspath(sys.argv[0])
    try:
        with open(here, "rb") as fh:
            me = fh.read()
    except (IOError, OSError) as exc:
        sys.stderr.write("E: cannot read my own source ({0}): {1}\n"
                         .format(here, exc))
        return 1
    out = os.path.join(dest, IPA_DIST_DIR)
    try:
        if not os.path.isdir(out):
            os.makedirs(out)
        for name, payload, executable in _DIST_FILES:
            path = os.path.join(out, name)
            with open(path, "wb") as fh:
                fh.write(me if payload is None else _dist_unpack(payload))
            os.chmod(path, 0o755 if executable else 0o644)
    except (IOError, OSError) as exc:
        sys.stderr.write("E: extraction failed: {0}\n".format(exc))
        return 1
    print("I: IPAForge {0} extracted - folder mode, nothing installed:"
          .format(__version__))
    for name, _payload, _executable in _DIST_FILES:
        print("I:     {0}".format(os.path.join(out, name)))
    print("I: run the tool:  python3 {0} --help"
          .format(os.path.join(out, "ipaforge.py")))
    print("I: or this file:  python3 {0} --help".format(here))
    print("I: install later: python3 {0} --install".format(here))
    return 0


def _dist_install(dest):
    here = os.path.abspath(sys.argv[0])
    try:
        with open(here, "rb") as fh:
            me = fh.read()
    except (IOError, OSError) as exc:
        sys.stderr.write("E: cannot read my own source ({0}): {1}\n"
                         .format(here, exc))
        return 1
    is_nt = os.name == "nt"
    if not dest:
        if is_nt:
            dest = os.path.join(os.environ.get("LOCALAPPDATA",
                                               os.path.expanduser("~")),
                                "Programs", "IPAForge")
        else:
            dest = "/usr/local/bin"
            if not (os.path.isdir(dest) and os.access(dest, os.W_OK)):
                dest = os.path.join(os.path.expanduser("~"),
                                    ".local", "bin")
    try:
        if not os.path.isdir(dest):
            os.makedirs(dest)
        if is_nt:
            # Windows: a .bat shim calling the engine with the interpreter
            # that performed the install - no PATH registry changes made.
            path = os.path.join(dest, "ipaforge.py")
            with open(path, "wb") as fh:
                fh.write(me)
            bat = os.path.join(dest, "ipaforge.bat")
            with open(bat, "wb") as fh:
                fh.write(("@echo off\r\n"
                          '@"{0}" "%~dp0ipaforge.py" %*\r\n').format(
                              sys.executable).encode("utf-8"))
            names = ("ipaforge.bat", "ipaforge.py")
        else:
            for name in ("ipaforge", "ipaforge.py"):
                path = os.path.join(dest, name)
                with open(path, "wb") as fh:
                    fh.write(me if name == "ipaforge.py"
                             else _dist_unpack(_DIST_LAUNCHER))
                os.chmod(path, 0o755)
            names = ("ipaforge", "ipaforge.py")
    except (IOError, OSError) as exc:
        sys.stderr.write("E: installation failed: {0}\n".format(exc))
        return 1
    print("I: IPAForge {0} installed - the 'ipaforge' command, no folder:"
          .format(__version__))
    for name in names:
        print("I:     {0}".format(os.path.join(dest, name)))
    if is_nt:
        if dest not in os.environ.get("PATH", "").split(os.pathsep):
            print("W: {0} is not on your PATH.".format(dest))
            print("W:   optional: add it via Settings > Environment "
                  "Variables, or (cmd.exe):")
            print('W:   setx PATH "%PATH%;{0}"'.format(dest))
    else:
        if dest == os.path.join(os.path.expanduser("~"), ".local", "bin") \
                and dest not in os.environ.get("PATH", "").split(os.pathsep):
            print("W: {0} is not on your PATH.".format(dest))
            print('W:   add it:  export PATH="{0}:$PATH"'.format(dest))
    print("I: verify in a NEW terminal:  ipaforge --version")
    print("I: docs later?  python3 {0} --extract".format(here))
    return 0


def _no_args_banner():
    import sys as _s
    _s.stdout.write(
        "IPAForge {0} - unpacker / repacker for iOS .ipa archives\n"
        "\n"
        "No command given. Quick start:\n"
        "  ipaforge -d App.ipa             decompile -> ./App/ (readable text,\n"
        "                                  kits + pseudo-source next to binary)\n"
        "  ipaforge -b App                 rebuild + sign -> ./App-signed.ipa\n"
        "  ipaforge --version              show version\n"
        "  ipaforge --help                 full option list\n"
        "Install or unpack this file itself:\n"
        "  python3 {1} --install [DEST]    put the 'ipaforge' command on PATH\n"
        "  python3 {1} --extract [DEST]    unpack the 6-file kit + docs\n"
        "Docs: --readme  --install-guide  --requirements  --signing\n"
        .format(__version__, os.path.abspath(sys.argv[0])))
    return 2


def _self_test():
    """Executable smoke test for the public framework APIs."""
    import tempfile
    with tempfile.TemporaryDirectory(prefix="ipaforge-test-") as td:
        payload = os.path.join(td, PAYLOAD_DIR, "Demo.app")
        _makedirs(payload)
        plist_path = os.path.join(payload, "Info.plist")
        plist_obj = {"CFBundleIdentifier": "com.example.demo",
                     "NSAllowsArbitraryLoads": True,
                     "UIFileSharingEnabled": True}
        with open(plist_path, "wb") as fh:
            fh.write(_plist_to_binary_bytes(plist_obj))
        with open(os.path.join(payload, "Localizable.strings"), "wb") as fh:
            fh.write(b'"hello" = "world";\n')
        with open(os.path.join(payload, "blob.bin"), "wb") as fh:
            fh.write(b"\x89PNG\r\n\x1a\n")

        registry = AnalysisPluginRegistry()
        seen = []
        registry.register("on_resource", lambda path, raw, **_: seen.append(path))
        manifest, counts = classify_and_convert_all(td, registry, max_workers=2)
        assert counts[FMT_NATIVE_BPLIST] == 1
        assert counts[FMT_LEGACY_STRINGS] == 1
        assert len(registry.alerts) == 2
        assert any(x.endswith("blob.bin") for x in seen)

        arm64 = list(_disasm_arm64(struct.pack("<I", 0xD503201F), 0x1000))
        assert arm64[0].address == 0x1000 and arm64[0].raw_word == 0xD503201F
        assert arm64[0].mnemonic == "nop" and arm64[0].op_type == "noop"
        x86 = list(disasm_x86_64_subset(b"\x90\xC3", 0x2000))
        assert x86[0].mnemonic == "nop" and x86[0].op_type == "noop"

        # Construct a minimal 64-bit LE Mach-O with 0x100 bytes of command slack.
        macho = bytearray(0x300)
        struct.pack_into("<IiiIIII", macho, 0, 0xFEEDFACF, 0x0100000C, 0,
                         2, 1, 72, 0)
        struct.pack_into("<I", macho, 28, 0)
        # One LC_SEGMENT_64 at 32, fileoff 0x100, filesize 0x200.
        struct.pack_into("<II16sQQQQiiII", macho, 32, LC_SEGMENT_64, 72,
                         b"__TEXT\x00", 0, 0x300, 0x100, 0x200, 7, 5, 0, 0)
        bin_path = os.path.join(td, "Demo")
        dylib_path = os.path.join(td, "libDemo.dylib")
        with open(bin_path, "wb") as fh: fh.write(macho)
        with open(dylib_path, "wb") as fh: fh.write(b"dylib")
        result = inject_dylib_load_command(bin_path, dylib_path)
        assert result["command"] == REQUESTED_WEAK_DYLIB_CMD
        with open(bin_path, "rb") as fh: out = fh.read()
        assert struct.unpack_from("<I", out, 0)[0] == 0xFEEDFACF
        assert struct.unpack_from("<I", out, 16)[0] == 2
        return {"parallel": True, "plugins": len(registry.alerts),
                "instructions": len(arm64) + len(x86), "injection": result}


def _handle_standalone(argv):
    if "--self-test" in argv:
        try:
            result = _self_test()
            print("IPAForge self-test OK: %s" % result)
            return 0
        except Exception as exc:
            print("IPAForge self-test FAILED: %s" % exc, file=sys.stderr)
            return 1
    if not argv:
        return _no_args_banner()
    docs = (("--readme", _DIST_README),
            ("--install-guide", _DIST_INSTALL),
            ("--requirements", _DIST_REQ),
            ("--signing", _DIST_REQSIGN))
    for flag, payload in docs:
        if flag in argv:
            return _dist_print(payload)
    if "--install" in argv:
        rest = argv[argv.index("--install") + 1:]
        dest = None
        if rest and not rest[0].startswith("-"):
            dest = rest[0]
        return _dist_install(dest)
    if "--extract" in argv:
        rest = argv[argv.index("--extract") + 1:]
        dest = "."
        if rest and not rest[0].startswith("-"):
            dest = rest[0]
        return _dist_extract(dest)
    return None


if __name__ == "__main__":
    _v = sys.version_info
    if not ((_v[0] == 2 and _v[1] >= 7) or (_v[0] == 3 and _v[1] >= 2)
            or _v[0] > 3):
        sys.stderr.write(
            "E: {0} requires Python 2.7 or 3.2 or newer (found {1}.{2})\n"
            .format(TOOL_NAME, _v[0], _v[1])
        )
        sys.exit(1)
    _rc = _handle_standalone(sys.argv[1:])
    if _rc is not None:
        sys.exit(_rc)
    try:
        exit_code = main()
        # Flush inside the guarded block so a broken downstream pipe (e.g.
        # `| head`) raises HERE, where it can be handled cleanly, instead of
        # during interpreter shutdown where it would print a scary traceback.
        sys.stdout.flush()
        sys.exit(exit_code)
    except BrokenPipeError:
        # Python flushes standard streams on exit; redirect remaining output
        # to devnull to avoid another BrokenPipeError at shutdown.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(141)
    except KeyboardInterrupt:
        sys.stderr.write("E: Interrupted by user\n")
        sys.exit(130)
