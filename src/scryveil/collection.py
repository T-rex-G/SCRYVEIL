"""Bounded ZIP inventory; never extracts paths, follows links or recurses.

Original archive bytes and each regular member are independently retained by
the store. ZIP times are container metadata, never device event times.
"""

import io
import stat
import struct
import time
import unicodedata
import zipfile
import zlib
from collections.abc import Callable
from typing import Any

from .diagnostics import parse_diagnostic
from .models import ScryveilError
from .parse import MAX_BYTES, MAX_LINE, digest, load_json, parse

ZIP = "scryveil_zip_collection_v1"
OPAQUE = "scryveil_preserved_bytes_v1"
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_EXPANDED = 64 * 1024 * 1024
MAX_MEMBERS = 1000
MAX_ARTIFACTS = 1024
# Preserve the previous reader's maximum 32 x 8 MiB original-byte capacity.
MAX_CASE_BYTES = 256 * 1024 * 1024


def preserved(data: bytes, aid: str, synthetic: bool) -> tuple[list[Any], list[Any], str]:
    return [], [{"line": 0, "code": "preserved_without_interpretation"}], OPAQUE


def interpret(data: bytes, name: str, synthetic: bool) -> dict[str, Any]:
    """Conservative detection; unsupported/malformed input is still evidence."""
    aid = "artifact-" + digest(data)
    head = data.partition(b"\n")[0]
    meta: Any = None
    if len(head) <= MAX_LINE:
        try:
            meta = load_json(head)
        except ScryveilError:
            pass
    reader: (
        Callable[[bytes, str, bool], tuple[list[dict[str, Any]], list[dict[str, Any]], str]] | None
    ) = None
    if isinstance(meta, dict) and "bug_type" in meta or name.lower().endswith(".ips"):
        reader = parse_diagnostic
    elif name.lower().endswith((".ndjson", ".jsonl")) or (
        isinstance(meta, dict) and ("schema" in meta or "type" in meta)
    ):
        reader = parse
    status = "unsupported"
    reason: str | None = "no_supported_reader"
    events, warnings, family = preserved(data, aid, synthetic)
    if reader is not None:
        try:
            events, warnings, family = reader(data, aid, synthetic)
            status = "partial" if warnings else "parsed_subset"
            if any(e["attributes"].get("schema_status") == "unqualified_version" for e in events):
                status = "unqualified_version"
            if not events:
                status = "no_parsed_events"
            reason = None
        except ScryveilError as exc:
            status = "unsupported" if exc.code.startswith("unsupported_") else "malformed"
            reason = exc.code
    return {
        "artifact_id": aid,
        "format": family,
        "events": events,
        "warnings": warnings,
        "status": status,
        "reason": reason,
    }


def _name(name: str, directory: bool) -> str:
    trimmed = name[:-1] if directory else name
    if (
        not trimmed
        or len(name) > 1024
        or "\\" in name
        or ":" in name
        or unicodedata.normalize("NFC", name) != name
        or any(ord(c) < 32 or ord(c) == 127 for c in name)
        or any(p in ("", ".", "..") or p.endswith((" ", ".")) for p in trimmed.split("/"))
    ):
        raise ScryveilError("unsafe_archive_path")
    return trimmed.casefold()


def _envelope(data: bytes) -> tuple[int, int]:
    # Reject ZIP64, split/self-extracting archives and large central directories
    # before ZipFile allocates its entry objects. No permissive offset repair.
    end = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    if end < 0 or len(data) < end + 22 or len(data) > MAX_ARCHIVE:
        raise ScryveilError("invalid_collection_envelope")
    _, disk, cd_disk, count_disk, count, size, offset, comment = struct.unpack_from(
        "<4s4H2IH", data, end
    )
    if (
        disk
        or cd_disk
        or count_disk != count
        or not 1 <= count <= MAX_MEMBERS
        or size > 4 * 1024 * 1024
        or offset + size != end
        or end + 22 + comment != len(data)
        or not data.startswith(b"PK\x03\x04")
    ):
        raise ScryveilError("unsupported_or_oversized_collection")
    position = offset
    actual = 0
    while position < end:
        if position + 46 > end or data[position : position + 4] != b"PK\x01\x02":
            raise ScryveilError("invalid_collection_directory")
        namesize, extrasize, commentsize, startdisk = struct.unpack_from("<4H", data, position + 28)
        if namesize > 4096 or startdisk or actual >= MAX_MEMBERS:
            raise ScryveilError("unsupported_or_oversized_collection")
        position += 46 + namesize + extrasize + commentsize
        actual += 1
    if position != end or actual != count:
        raise ScryveilError("invalid_collection_directory")
    return count, offset


def unpack(
    data: bytes, synthetic: bool
) -> tuple[list[dict[str, Any]], list[tuple[dict[str, Any], bytes]]]:
    """Validate all members before the store makes any state change."""
    count, central_offset = _envelope(data)
    manifest: list[dict[str, Any]] = []
    members: list[tuple[dict[str, Any], bytes]] = []
    seen: dict[str, bool] = {}
    expanded, previous_end = 0, 0
    deadline = time.monotonic() + 30
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            infos = archive.infolist()
            if len(infos) != count or archive.start_dir != central_offset:
                raise ScryveilError("invalid_collection_directory")
            for index, info in enumerate(infos):
                if time.monotonic() > deadline:
                    raise ScryveilError("collection_time_limit")
                directory = info.is_dir()
                key = _name(info.orig_filename, directory)
                mode = stat.S_IFMT(info.external_attr >> 16)
                if mode not in (0, stat.S_IFDIR if directory else stat.S_IFREG):
                    raise ScryveilError("archive_special_file_not_allowed")
                if bool(info.external_attr & 0x10) and not directory:
                    raise ScryveilError("invalid_archive_directory")
                if (
                    key in seen
                    or any(not isdir and key.startswith(p + "/") for p, isdir in seen.items())
                    or (not directory and any(p.startswith(key + "/") for p in seen))
                ):
                    raise ScryveilError("ambiguous_archive_path")
                seen[key] = directory
                if info.flag_bits & ~0x80E or info.compress_type not in (
                    zipfile.ZIP_STORED,
                    zipfile.ZIP_DEFLATED,
                ):
                    raise ScryveilError("unsupported_archive_encoding")
                if (
                    info.file_size > MAX_BYTES
                    or expanded + info.file_size > MAX_EXPANDED
                    or info.file_size > max(1, info.compress_size) * 200
                ):
                    raise ScryveilError("archive_expansion_limit")
                # Local and directory declarations must agree. Decode with an
                # actual-output cap, not ZipExtFile's declared-size truncation.
                start = info.header_offset
                if start < previous_end or start + 30 > central_offset:
                    raise ScryveilError("invalid_archive_member_boundary")
                header = struct.unpack_from("<4s5H3I2H", data, start)
                if (
                    header[0] != b"PK\x03\x04"
                    or header[2] != info.flag_bits
                    or header[3] != info.compress_type
                ):
                    raise ScryveilError("inconsistent_archive_header")
                payload = start + 30 + header[-2] + header[-1]
                previous_end = payload + info.compress_size
                if previous_end > central_offset:
                    raise ScryveilError("invalid_archive_member_boundary")
                local_name = data[start + 30 : start + 30 + header[-2]].decode(
                    "utf-8" if info.flag_bits & 0x800 else "cp437"
                )
                if local_name != info.orig_filename:
                    raise ScryveilError("inconsistent_archive_header")
                compressed = data[payload:previous_end]
                if info.compress_type == zipfile.ZIP_STORED:
                    content = compressed
                else:
                    decoder = zlib.decompressobj(-15)
                    content = decoder.decompress(
                        compressed, min(MAX_BYTES, MAX_EXPANDED - expanded) + 1
                    )
                    if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                        raise ScryveilError("archive_size_mismatch")
                if len(content) != info.file_size or len(content) > MAX_BYTES:
                    raise ScryveilError("archive_size_mismatch")
                if zlib.crc32(content) != info.CRC:
                    raise ScryveilError("archive_crc_mismatch")
                expected = (info.CRC, info.compress_size, info.file_size)
                if info.flag_bits & 8:
                    descriptor = previous_end + (
                        4 if data[previous_end : previous_end + 4] == b"PK\x07\x08" else 0
                    )
                    if (
                        descriptor + 12 > central_offset
                        or struct.unpack_from("<3I", data, descriptor) != expected
                    ):
                        raise ScryveilError("inconsistent_archive_descriptor")
                    previous_end = descriptor + 12
                elif header[6:9] != expected:
                    raise ScryveilError("inconsistent_archive_header")
                expanded += len(content)
                if directory and content:
                    raise ScryveilError("invalid_archive_directory")
                entry: dict[str, Any] = {
                    "index": index,
                    "path": info.orig_filename,
                    "kind": "directory" if directory else "file",
                    "local_header_offset": start,
                    "compressed_data_offset": payload,
                    "compressed_size": info.compress_size,
                    "compression_method": info.compress_type,
                    "size": len(content),
                    "sha256": digest(content),
                    "stored_local_time": list(info.date_time),
                    "clock": "zip_local_time_offset_unknown",
                }
                if not directory:
                    if (
                        content.startswith(
                            (b"PK", b"\x1f\x8b", b"BZh", b"\xfd7z", b"7z\xbc\xaf\x27\x1c")
                        )
                        or content[257:262] == b"ustar"
                        or key.endswith((".zip", ".tar", ".tgz", ".gz", ".7z", ".bz2", ".xz"))
                    ):
                        raise ScryveilError("nested_archive_not_allowed")
                    result = interpret(content, info.orig_filename, synthetic)
                    entry.update(
                        {k: result[k] for k in ("artifact_id", "format", "status", "reason")}
                    )
                    members.append((result, content))
                manifest.append(entry)
    except (
        zipfile.BadZipFile,
        NotImplementedError,
        RuntimeError,
        EOFError,
        UnicodeError,
        struct.error,
        zlib.error,
    ) as exc:
        raise ScryveilError("malformed_collection") from exc
    return manifest, members
