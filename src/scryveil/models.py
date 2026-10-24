"""Versioned data contracts. Parsers validate input; exports rederive lineage."""

from copy import deepcopy
from dataclasses import asdict, dataclass, field
from typing import Any

SCHEMA = "0.1.0"


class ScryveilError(Exception):
    """Public errors contain only fixed codes, never evidence or filenames."""

    def __init__(self, code: str, exit_code: int = 2):
        super().__init__(code)
        self.code = code
        self.exit_code = exit_code


@dataclass(frozen=True)
class Event:
    event_id: str
    artifact_id: str
    source_locator: str
    byte_offset: int
    byte_length: int
    event_type: str
    event_time: str | None
    source_timestamp: str | None
    source_offset: str | None
    time_precision: str
    synthetic: bool
    parser: str
    attributes: dict[str, Any]
    limitations: list[str] = field(default_factory=list)
    parser_version: str = SCHEMA
    schema_version: str = SCHEMA

    def json(self) -> dict[str, Any]:
        # Event scalar fields are immutable. Copy only the two mutable fields
        # instead of recursively visiting every scalar during each source reparse.
        return {
            **vars(self),
            "attributes": deepcopy(self.attributes),
            "limitations": self.limitations.copy(),
        }


@dataclass(frozen=True)
class Finding:
    finding_id: str
    title: str
    category: str
    severity: str
    assessment: str
    rule_id: str
    supporting_evidence_ids: list[str]
    contradictory_evidence_ids: list[str]
    first_observed_utc: str | None
    last_observed_utc: str | None
    explanation: str
    statistics: dict[str, Any]
    missing_evidence: list[str]
    alternative_explanations: list[str]
    limitations: list[str]
    hypotheses: list[dict[str, Any]]
    recommended_non_destructive_next_step: str = "Review original evidence and authorized context."
    analyst_review_status: str = "unreviewed"
    rule_version: str = SCHEMA

    def json(self) -> dict[str, Any]:
        return asdict(self)
