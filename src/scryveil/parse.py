"""Bounded, original NDJSON parsers. No archive extraction or dynamic execution."""

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any

from .models import Event, ScryveilError

MAX_BYTES = 8 * 1024 * 1024
MAX_LINE = 64 * 1024
MAX_RECORDS = 5000
CONTROL_CHARACTER = re.compile(r"[\x00-\x1f\x7f]")
STAMP = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.(\d{1,6}))?(Z|[+-]\d\d:\d\d)$")


def canonical(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        + "\n"
    ).encode()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def text_field(value: Any, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise ScryveilError("invalid_field")
    if CONTROL_CHARACTER.search(value):
        raise ScryveilError("invalid_field")
    return value


def domain(value: Any) -> str:
    val = text_field(value)
    if val is None:
        raise ScryveilError("invalid_domain")
    try:
        result = val.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ScryveilError("invalid_domain") from exc
    if len(result) > 253 or not all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in result.split(".")
    ):
        raise ScryveilError("invalid_domain")
    return result


def timestamp(value: Any) -> tuple[str, str, str]:
    if not isinstance(value, str) or not (match := STAMP.fullmatch(value)):
        raise ScryveilError("timestamp_requires_explicit_offset")
    try:
        dt = datetime.fromisoformat(value)
        if match[2] == "-00:00":  # RFC3339: unknown offset is not UTC.
            raise ValueError
        offset = match[2]
        if offset != "Z" and (int(offset[1:3]) > 23 or int(offset[4:]) > 59):
            raise ValueError
        utc = dt.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    except (ValueError, OverflowError) as exc:
        raise ScryveilError("invalid_timestamp") from exc
    precision = "second" if match[1] is None else f"fractional_digits:{len(match[1])}"
    return utc, match[2], precision


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, val in pairs:
        if key in obj:
            raise ScryveilError("duplicate_json_key")
        obj[key] = val
    return obj


def _constant(_: str) -> None:
    raise ScryveilError("nonfinite_json")


def load_json(raw: bytes) -> Any:
    try:
        return json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ScryveilError("invalid_json") from exc


def parse(
    data: bytes, artifact_id: str, synthetic: bool
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str]:
    if len(data) > MAX_BYTES:
        raise ScryveilError("input_too_large")
    if data.startswith((b"PK", b"\x1f\x8b", b"BZh", b"\xfd7z", b"bplist", b"<?xml")):
        raise ScryveilError("unsupported_format")
    events: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    offset = 0
    families: set[str] = set()
    last_time: str | None = None
    lines = data.splitlines(keepends=True)
    if len(lines) > MAX_RECORDS:
        raise ScryveilError("too_many_records")
    for line, raw in enumerate(lines, 1):
        start = offset
        offset += len(raw)
        if len(raw) > MAX_LINE:
            raise ScryveilError("record_too_large")
        if not raw.strip():
            continue
        try:
            rec = load_json(raw)
            if not isinstance(rec, dict):
                raise ScryveilError("record_must_be_object")
            typ, stamp, attrs, parser, limits = _record(rec, synthetic)
            families.add(parser)
            utc, zone, precision = (
                timestamp(stamp) if stamp is not None else (None, None, "unknown")
            )
            if utc is not None and last_time is not None and utc < last_time:
                warnings.append({"line": line, "code": "source_order_not_chronological"})
            if utc is not None:
                last_time = utc
            if synthetic:
                limits.append("synthetic fixture; not device evidence")
            events.append(
                Event(
                    event_id="evt-" + digest(f"{artifact_id}:{line}".encode()),
                    artifact_id=artifact_id,
                    source_locator=f"line:{line}",
                    byte_offset=start,
                    byte_length=len(raw),
                    event_type=typ,
                    event_time=utc,
                    source_timestamp=stamp,
                    source_offset=zone,
                    time_precision=precision,
                    synthetic=synthetic,
                    parser=parser,
                    attributes=attrs,
                    limitations=limits,
                ).json()
            )
        except ScryveilError as exc:
            warnings.append({"line": line, "code": exc.code})
    family = next(iter(families)) if len(families) == 1 else ("mixed" if families else "unknown")
    return events, warnings, family


def _record(
    rec: dict[str, Any], synthetic: bool
) -> tuple[str, str | None, dict[str, Any], str, list[str]]:
    if rec.get("schema") == "scryveil.events/1":
        if rec.get("synthetic") is not True or not synthetic:
            raise ScryveilError("synthetic_format_requires_synthetic_import")
        typ = rec.get("event_type")
        if not isinstance(typ, str) or typ not in {
            "network.observation",
            "context.approved_sync",
            "indicator.domain",
        }:
            raise ScryveilError("unsupported_event_type")
        stamp = text_field(rec.get("timestamp"), optional=typ == "indicator.domain")
        attrs: dict[str, Any] = {"domain": domain(rec.get("domain"))}
        if typ == "indicator.domain":
            attrs.update(_indicator(rec))
        else:
            attrs["app"] = text_field(rec.get("app"), optional=True)
            if typ == "context.approved_sync":
                attrs["valid_until"] = timestamp(rec.get("valid_until"))[0]
                if attrs["valid_until"] < timestamp(stamp)[0]:
                    raise ScryveilError("invalid_context_interval")
        return typ, stamp, attrs, "synthetic_jsonl", ["source clock accuracy unknown"]
    if rec.get("schema") == "scryveil.indicators/1":
        return (
            "indicator.domain",
            None,
            {"domain": domain(rec.get("domain")), **_indicator(rec)},
            "ioc_jsonl",
            ["user-supplied indicator; trust and relevance require review"],
        )
    typ = rec.get("type")
    limits = ["experimental APR parser; hardware NOT TESTED", "source clock accuracy unknown"]
    if typ == "networkActivity":
        hits = rec.get("hits")
        if hits is not None and (type(hits) is not int or not 0 <= hits <= 10**12):
            raise ScryveilError("invalid_hits")
        attrs = {
            "app": text_field(rec.get("bundleID"), optional=True),
            "domain": domain(rec.get("domain")),
            "hits": hits,
        }
        first = text_field(rec.get("firstTimeStamp"), optional=True)
        latest = text_field(rec.get("timeStamp"), optional=True)
        attrs["first_source_timestamp"] = first
        attrs["first_recorded_time"] = timestamp(first)[0] if first is not None else None
        if first is not None and latest is not None and timestamp(first)[0] > timestamp(latest)[0]:
            raise ScryveilError("invalid_summary_interval")
        limits.append(
            "network report record, not individual packet timing; excluded from periodicity"
        )
        return (
            "network.summary",
            latest,
            attrs,
            "apple_apr_experimental",
            limits,
        )
    if typ == "access":
        accessor = rec.get("accessor")
        if not isinstance(accessor, dict):
            raise ScryveilError("invalid_accessor")
        attrs = {
            "app": text_field(accessor.get("identifier"), optional=True),
            "identifier_type": text_field(accessor.get("identifierType"), optional=True),
            "category": text_field(rec.get("category")),
            "kind": text_field(rec.get("kind"), optional=True),
        }
        return (
            "privacy.access",
            text_field(rec.get("timeStamp")),
            attrs,
            "apple_apr_experimental",
            limits,
        )
    raise ScryveilError("unsupported_record")


def _indicator(rec: dict[str, Any]) -> dict[str, Any]:
    created = timestamp(rec.get("created"))[0]
    updated = timestamp(rec.get("updated"))[0]
    if updated < created:
        raise ScryveilError("invalid_indicator_dates")
    return {
        "source": text_field(rec.get("source")),
        "license": text_field(rec.get("license")),
        "created": created,
        "updated": updated,
    }
