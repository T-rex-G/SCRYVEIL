"""Private bounded case store with serialized atomic metadata transactions."""

import contextlib
import os
import platform
import re
import stat
import tempfile
import time
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .collection import MAX_ARCHIVE, MAX_ARTIFACTS, MAX_CASE_BYTES, OPAQUE, ZIP, preserved, unpack
from .diagnostic_text import parse_resource_summary
from .diagnostics import (
    IPS,
    IPS_DIAGNOSTIC,
    IPS_RESOURCE,
    parse_diagnostic,
    parse_diagnostic_v2,
    parse_ips,
)
from .engine import DEFAULT_CONFIG, RuleConfig, analyze
from .models import SCHEMA, ScryveilError
from .parse import MAX_BYTES, canonical, digest, load_json, parse
from .state import same_json, validate_metadata

CASE_ID = re.compile(r"case-[0-9a-f]{32}\Z")
ART_ID = re.compile(r"artifact-[0-9a-f]{64}\Z")
MAX_STATE = 64 * 1024 * 1024


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _no_links(path: Path) -> None:
    for p in [path, *path.parents]:
        if p.is_symlink():
            raise ScryveilError("symlink_not_allowed")


def read_regular(path: Path, limit: int) -> bytes:
    _no_links(path)
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ScryveilError("regular_file_required")
        if info.st_size > limit:
            raise ScryveilError("input_too_large")
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise ScryveilError("input_too_large")
        return data


def _private_directory(path: Path) -> None:
    _no_links(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ScryveilError("case_directory_requires_private_permissions")


def _audit(state: dict[str, Any], operation: str, affected: list[str], result: str) -> None:
    entry = {
        "sequence": len(state["audit"]),
        "operation": operation,
        "actor": "local_operator",
        "timestamp": now(),
        "affected_ids": affected,
        "result": result,
        "previous_hash": state["audit"][-1]["hash"] if state["audit"] else None,
    }
    entry["hash"] = digest(canonical(entry))
    state["audit"].append(entry)


class CaseStore:
    def __init__(self, root: Path):
        if os.name != "posix":
            raise ScryveilError("unsupported_host")
        self.root = root.absolute()
        _private_directory(self.root)

    def path(self, case_id: str) -> Path:
        if not CASE_ID.fullmatch(case_id):
            raise ScryveilError("invalid_case_id")
        path = self.root / case_id
        _no_links(path)
        if not path.is_dir():
            raise ScryveilError("case_not_found")
        _private_directory(path)
        return path

    @contextlib.contextmanager
    def locked(self, case_id: str) -> Iterator[tuple[Path, dict[str, Any]]]:
        import fcntl

        path = self.path(case_id)
        fd = os.open(path / "lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "r+") as lock:
            if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode):
                raise ScryveilError("invalid_lock")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ScryveilError("case_busy", 3) from exc
            state = load_json(read_regular(path / "state.json", MAX_STATE))
            if (
                not isinstance(state, dict)
                or state.get("schema_version") != SCHEMA
                or state.get("case_id") != case_id
            ):
                raise ScryveilError("invalid_case_state", 4)
            validate_metadata(state)
            yield path, state

    def _save(self, path: Path, state: dict[str, Any]) -> None:
        data = canonical(state)
        if len(data) > MAX_STATE:
            raise ScryveilError("case_capacity_exceeded")
        fd, filename = tempfile.mkstemp(prefix="state-", dir=path)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(filename, path / "state.json")
            dirfd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
        finally:
            if os.path.exists(filename):
                os.unlink(filename)

    def create(self, label: str, consent: str) -> dict[str, Any]:
        if consent not in {"self", "authorized"} or not label or len(label) > 200:
            raise ScryveilError("invalid_consent_or_label")
        case_id = "case-" + uuid.uuid4().hex
        path = self.root / case_id
        path.mkdir(mode=0o700)
        (path / "originals").mkdir(mode=0o700)
        state: dict[str, Any] = {
            "schema_version": SCHEMA,
            "case_id": case_id,
            "label": label,
            "consent_scope": consent,
            "created_at": now(),
            "evidence_root": "originals",
            "retention_policy": "local_owner_managed",
            "artifacts": [],
            "events": [],
            "audit": [],
            "analysis": None,
            "rule_run": None,
            "reviews": [],
        }
        _audit(state, "case.create", [case_id], "created")
        state["created_at"] = state["audit"][0]["timestamp"]
        self._save(path, state)
        return {"case_id": case_id, "status": "created"}

    def list_cases(self) -> list[dict[str, str]]:
        return [
            {"case_id": p.name}
            for p in sorted(self.root.iterdir())
            if CASE_ID.fullmatch(p.name) and p.is_dir() and not p.is_symlink()
        ]

    def import_file(
        self, case_id: str, source: Path, synthetic: bool = False, input_format: str = "ndjson"
    ) -> dict[str, Any]:
        data = read_regular(source, MAX_BYTES)
        sha = digest(data)
        aid = "artifact-" + sha
        if input_format not in {"ndjson", "ips"}:
            raise ScryveilError("unsupported_format")
        events, warnings, family = (parse_diagnostic if input_format == "ips" else parse)(
            data, aid, synthetic
        )
        with self.locked(case_id) as (path, state):
            self.verify(path, state)
            for artifact in state["artifacts"]:
                if artifact["artifact_id"] == aid:
                    if input_format == "ips" and artifact["format"] == IPS:
                        # Reimport is idempotent under its recorded reader;
                        # upgrading the executable never migrates old evidence.
                        events, warnings, family = parse_ips(data, aid, synthetic)
                    elif input_format == "ips" and artifact["format"] == IPS_DIAGNOSTIC:
                        events, warnings, family = parse_diagnostic_v2(data, aid, synthetic)
                    if artifact["format"] != family:
                        raise ScryveilError("parser_selection_conflict")
                    if artifact["synthetic"] != synthetic:
                        raise ScryveilError("provenance_mode_conflict")
                    _audit(state, "evidence.reimport", [aid], "duplicate")
                    self._save(path, state)
                    return {
                        "artifact_id": aid,
                        "status": "duplicate",
                        "warning_count": len(artifact["warnings"]),
                    }
            if (
                len(state["artifacts"]) >= MAX_ARTIFACTS
                or len(state["events"]) + len(events) > 20000
                or sum(a["size"] for a in state["artifacts"]) + len(data) > MAX_CASE_BYTES
            ):
                raise ScryveilError("case_capacity_exceeded")
            original = path / "originals" / sha
            _no_links(original)
            if original.exists():
                if read_regular(original, MAX_BYTES) != data:
                    raise ScryveilError("orphan_original_mismatch", 4)
            else:
                fd = os.open(original, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            imported = now()
            artifact = {
                "schema_version": SCHEMA,
                "artifact_id": aid,
                "sha256": sha,
                "original_filename": source.name,
                "size": len(data),
                "format": family,
                "imported_at": imported,
                "collection_time": None,
                "collection_mode": "synthetic" if synthetic else "imported",
                "synthetic": synthetic,
                "tool_version": SCHEMA,
                "capture_interval": None,
                "source_machine": "unknown",
                "sensitivity": "private",
                "warnings": warnings,
            }
            state["artifacts"].append(artifact)
            state["events"].extend(events)
            state["analysis"] = None
            state["rule_run"] = None
            _audit(state, "evidence.import", [aid], "partial_or_failed" if warnings else "imported")
            self._save(path, state)
        return {
            "artifact_id": aid,
            "status": "partial_or_failed" if warnings else "imported",
            "event_count": len(events),
            "warning_count": len(warnings),
            "synthetic": synthetic,
        }

    def import_collection(
        self, case_id: str, source: Path, synthetic: bool = False
    ) -> dict[str, Any]:
        data = read_regular(source, MAX_ARCHIVE)
        manifest, members = unpack(data, synthetic)
        archive_sha = digest(data)
        archive_id = "artifact-" + archive_sha
        with self.locked(case_id) as (path, state):
            self.verify(path, state)
            existing = {a["artifact_id"]: a for a in state["artifacts"]}
            if archive_id in existing:
                if (
                    existing[archive_id]["format"] != ZIP
                    or existing[archive_id]["synthetic"] != synthetic
                ):
                    raise ScryveilError("provenance_mode_conflict")
                return {"status": "duplicate", "artifact_id": archive_id, "members": len(manifest)}
            pending: list[tuple[dict[str, Any], bytes]] = [
                (dict(artifact_id=archive_id, format=ZIP, events=[], warnings=[]), data)
            ]
            pending.extend(members)
            new: list[tuple[dict[str, Any], bytes]] = []
            new_event_count = 0
            imported = now()
            names = {
                m["artifact_id"]: m["path"].rsplit("/", 1)[-1]
                for m in manifest
                if m["kind"] == "file"
            }
            for result, content in pending:
                aid = result["artifact_id"]
                if aid in existing:
                    if (
                        existing[aid]["format"] != result["format"]
                        or existing[aid]["synthetic"] != synthetic
                    ):
                        raise ScryveilError("collection_parser_or_provenance_conflict")
                    continue
                artifact: dict[str, Any] = {
                    "schema_version": SCHEMA,
                    "artifact_id": aid,
                    "sha256": digest(content),
                    "original_filename": source.name if aid == archive_id else names[aid],
                    "size": len(content),
                    "format": result["format"],
                    "imported_at": imported,
                    "collection_time": None,
                    "collection_mode": "synthetic" if synthetic else "imported",
                    "synthetic": synthetic,
                    "tool_version": SCHEMA,
                    "capture_interval": None,
                    "source_machine": "unknown",
                    "sensitivity": "private",
                    "warnings": result["warnings"],
                }
                if aid == archive_id:
                    artifact["collection_manifest"] = manifest
                existing[aid] = artifact
                state["artifacts"].append(artifact)
                state["events"].extend(result["events"])
                new_event_count += len(result["events"])
                _audit(
                    state,
                    "evidence.import",
                    [aid],
                    "partial_or_failed" if result["warnings"] else "imported",
                )
                new.append((artifact, content))
            state["analysis"], state["rule_run"] = None, None
            if (
                len(state["artifacts"]) > MAX_ARTIFACTS
                or len(state["events"]) > 20000
                or sum(a["size"] for a in state["artifacts"]) > MAX_CASE_BYTES
                or len(canonical(state)) > MAX_STATE
            ):
                raise ScryveilError("case_capacity_exceeded")
            # All parsing and capacity checks precede publication. Content-addressed
            # orphans after an IO failure are harmless and checked on a later import.
            for artifact, content in new:
                original = path / "originals" / artifact["sha256"]
                _no_links(original)
                if original.exists():
                    if read_regular(original, MAX_ARCHIVE) != content:
                        raise ScryveilError("orphan_original_mismatch", 4)
                else:
                    fd = os.open(
                        original, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400
                    )
                    with os.fdopen(fd, "wb") as stream:
                        stream.write(content)
                        stream.flush()
                        os.fsync(stream.fileno())
            self._save(path, state)
        counts: dict[str, int] = {}
        for member in manifest:
            status = member.get("status", "directory")
            counts[status] = counts.get(status, 0) + 1
        return {
            "status": "collection_imported",
            "artifact_id": archive_id,
            "members": len(manifest),
            "new_artifacts": len(new),
            "event_count": new_event_count,
            "warning_count": sum(len(m[0]["warnings"]) for m in members),
            "member_status_counts": counts,
            "synthetic": synthetic,
        }

    def collection_inventory(self, case_id: str) -> dict[str, Any]:
        with self.locked(case_id) as (path, state):
            self.verify(path, state)
            return {
                "schema_version": "scryveil.collection-inventory/1",
                "case_id": case_id,
                "source_state_sha256": digest(canonical(state)),
                "archives": [
                    {
                        "artifact_id": a["artifact_id"],
                        "sha256": a["sha256"],
                        "members": a["collection_manifest"],
                    }
                    for a in state["artifacts"]
                    if a["format"] == ZIP
                ],
                "limitations": [
                    "Paths and ZIP local times are container declarations, not authenticated acquisition metadata.",
                    "No device identity, complete history, or independently authenticated custody is established.",
                ],
            }

    def verify(self, path: Path, state: dict[str, Any]) -> None:
        previous = None
        for index, entry in enumerate(state["audit"]):
            bare = {k: v for k, v in entry.items() if k != "hash"}
            if (
                entry["previous_hash"] != previous
                or entry["sequence"] != index
                or digest(canonical(bare)) != entry["hash"]
            ):
                raise ScryveilError("audit_integrity_failed", 4)
            previous = entry["hash"]
        event_index = 0
        seen = set()
        for artifact in state["artifacts"]:
            aid = artifact["artifact_id"]
            if not ART_ID.fullmatch(aid) or aid in seen or aid != "artifact-" + artifact["sha256"]:
                raise ScryveilError("invalid_artifact_identity", 4)
            seen.add(aid)
            data = read_regular(
                path / "originals" / artifact["sha256"],
                MAX_ARCHIVE if artifact["format"] == ZIP else MAX_BYTES,
            )
            if digest(data) != artifact["sha256"] or len(data) != artifact["size"]:
                raise ScryveilError("source_integrity_failed", 4)
            reader: Callable[
                [bytes, str, bool], tuple[list[dict[str, Any]], list[dict[str, Any]], str]
            ]
            if artifact["format"] == ZIP:
                manifest, members = unpack(data, artifact["synthetic"])
                if artifact["warnings"] != [] or not same_json(
                    manifest, artifact["collection_manifest"]
                ):
                    raise ScryveilError("collection_lineage_failed", 4)
                indexed = {a["artifact_id"]: a for a in state["artifacts"]}
                for result, content in members:
                    member = indexed.get(result["artifact_id"])
                    if (
                        member is None
                        or member["format"] != result["format"]
                        or member["synthetic"] != artifact["synthetic"]
                        or member["size"] != len(content)
                    ):
                        raise ScryveilError("collection_lineage_failed", 4)
                continue
            if artifact["format"] == OPAQUE:
                reader = preserved
            elif artifact["format"] == IPS:
                reader = parse_ips
            elif artifact["format"] == IPS_DIAGNOSTIC:
                reader = parse_diagnostic_v2
            elif artifact["format"] == IPS_RESOURCE:
                reader = parse_resource_summary
            else:
                reader = parse
            events, warnings, family = reader(data, aid, artifact["synthetic"])
            if not same_json(warnings, artifact["warnings"]) or family != artifact["format"]:
                raise ScryveilError("parser_integrity_failed", 4)
            if not same_json(events, state["events"][event_index : event_index + len(events)]):
                raise ScryveilError("event_lineage_failed", 4)
            event_index += len(events)
        if event_index != len(state["events"]):
            raise ScryveilError("event_lineage_failed", 4)

    def run(self, case_id: str, config: RuleConfig = DEFAULT_CONFIG) -> dict[str, Any]:
        with self.locked(case_id) as (path, state):
            self.verify(path, state)
            started_at = now()
            start = time.perf_counter()
            result = analyze(state["events"], state["artifacts"], config)
            if not same_json(result, state["analysis"]):
                state["analysis"] = result
                state["rule_run"] = {
                    "started_at": started_at,
                    "runtime_seconds": time.perf_counter() - start,
                    "runtime": platform.python_version(),
                    "tool_version": SCHEMA,
                    "input_artifact_ids": [a["artifact_id"] for a in state["artifacts"]],
                    "config_sha256": result["config_sha256"],
                }
                _audit(state, "analyze", state["rule_run"]["input_artifact_ids"], "completed")
                self._save(path, state)
            return {
                "status": "analyzed",
                "finding_count": len(result["findings"]),
                "assessment": result["overall_assessment"],
            }

    def snapshot(self, case_id: str) -> dict[str, Any]:
        with self.locked(case_id) as (path, state):
            self.verify(path, state)
            if state["analysis"] is None:
                raise ScryveilError("analysis_required", 3)
            self.verify_analysis(state)
            return state

    def verify_analysis(self, state: dict[str, Any]) -> None:
        try:
            result = analyze(
                state["events"], state["artifacts"], RuleConfig(**state["analysis"]["config"])
            )
        except (TypeError, ValueError, KeyError, ScryveilError) as exc:
            raise ScryveilError("finding_lineage_failed", 4) from exc
        if not same_json(result, state["analysis"]):
            raise ScryveilError("finding_lineage_failed", 4)

    def review(self, case_id: str, finding_id: str, decision: str) -> dict[str, str]:
        if decision not in {"review_needed", "accepted_benign", "inconclusive"}:
            raise ScryveilError("invalid_review_decision")
        with self.locked(case_id) as (path, state):
            self.verify(path, state)
            if not state["analysis"] or finding_id not in {
                f["finding_id"] for f in state["analysis"]["findings"]
            }:
                raise ScryveilError("finding_not_found")
            self.verify_analysis(state)
            state["reviews"].append(
                {"finding_id": finding_id, "decision": decision, "timestamp": now()}
            )
            _audit(state, "analyst.review", [finding_id], decision)
            self._save(path, state)
        return {"finding_id": finding_id, "review": decision}
