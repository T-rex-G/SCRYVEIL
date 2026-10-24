"""Private pipe protocol worker. No paths, credentials or provider connection."""

import sys
from typing import Any

from .diagnostics import bounded_json
from .investigation_tools import ID, MAX_SNAPSHOT, STRING, ReadOnlyTools, object_schema, validate
from .isolation import restrict_worker
from .models import ScryveilError
from .parse import canonical, load_json

AGENT_VERSION = "scryveil.agent/1"
TEXT = {"type": "string", "minLength": 1, "maxLength": 1024}
REFS = {"type": "array", "items": ID, "maxItems": 32}


def validate_action(action: Any) -> None:
    if not isinstance(action, dict) or action.get("version") != AGENT_VERSION:
        raise ScryveilError("invalid_agent_action")
    kind = action.get("kind")
    keys = {
        "plan": {"version", "kind", "steps"},
        "tool": {"version", "kind", "name", "arguments"},
        "final": {"version", "kind", "facts", "measurements", "hypotheses", "unanswered_questions"},
    }
    if not isinstance(kind, str) or kind not in keys or set(action) != keys[kind]:
        raise ScryveilError("invalid_agent_action")
    if kind == "plan":
        validate(action["steps"], {"type": "array", "items": TEXT, "minItems": 1, "maxItems": 8})
    elif kind == "tool":
        validate(action["name"], STRING)
        if not isinstance(action["arguments"], dict):
            raise ScryveilError("invalid_agent_action")
    else:
        facts = action["facts"]
        if not isinstance(facts, list) or len(facts) > 32:
            raise ScryveilError("invalid_agent_action")
        for fact in facts:
            if not isinstance(fact, dict) or set(fact) != {"event_id", "field", "value"}:
                raise ScryveilError("invalid_agent_action")
            validate(fact["event_id"], ID)
            validate(fact["field"], STRING)
            if len(canonical(fact["value"])) > 4096:
                raise ScryveilError("invalid_agent_action")
        validate(action["measurements"], REFS)
        validate(
            action["hypotheses"],
            {
                "type": "array",
                "maxItems": 8,
                "items": object_schema(
                    {
                        "text": TEXT,
                        "support": REFS,
                        "contradictions": REFS,
                        "confidence_justification": TEXT,
                    },
                    ["text", "support", "contradictions", "confidence_justification"],
                ),
            },
        )
        validate(action["unanswered_questions"], {"type": "array", "items": TEXT, "maxItems": 16})


class Session:
    def __init__(self, snapshot: dict[str, Any]):
        self.tools = ReadOnlyTools(snapshot)
        self.plan: list[str] = []
        self.successful_queries: set[str] = set()

    def step(self, action: dict[str, Any]) -> dict[str, Any]:
        try:
            bounded_json(action)
            validate_action(action)
            if action["kind"] == "plan":
                if self.plan:
                    raise ScryveilError("plan_already_set")
                self.plan = action["steps"]
                return {"ok": True, "plan": self.plan}
            if not self.plan:
                raise ScryveilError("plan_required")
            if action["kind"] == "tool":
                result = self.tools.call(action["name"], action["arguments"])
                if result["ok"]:
                    self.successful_queries.add(action["name"])
                return result
            if len(self.successful_queries) < 2:
                raise ScryveilError("investigation_queries_required")
            if self.tools.events:
                if not self.tools.read_events:
                    raise ScryveilError("event_retrieval_required")
                if not action["facts"]:
                    raise ScryveilError("grounded_fact_required")
            elif not action["unanswered_questions"]:
                raise ScryveilError("coverage_limitation_required")
            if self.tools.findings and not self.tools.seen_findings:
                raise ScryveilError("deterministic_review_required")
            return {"ok": True, "final": self.tools.ground_final(action)}
        except (ScryveilError, ValueError, TypeError, KeyError, RecursionError) as exc:
            return {
                "ok": False,
                "error": exc.code if isinstance(exc, ScryveilError) else "invalid_agent_action",
            }


def main() -> None:
    # Package imports finish before the OS boundary. The only inherited handles
    # are stdin/stdout pipes and stderr redirected to /dev/null by the parent.
    try:
        raw = sys.stdin.buffer.readline(MAX_SNAPSHOT + 1)
        if len(raw) > MAX_SNAPSHOT:
            raise ScryveilError("snapshot_too_large")
        snapshot = load_json(raw)
        session = Session(snapshot)
        restrict_worker()
        sys.stdout.buffer.write(
            canonical({"ok": True, "isolation": "linux_seccomp_no_files_no_network"})
        )
        sys.stdout.buffer.flush()
        for _ in range(64):
            raw = sys.stdin.buffer.readline(65537)
            if not raw:
                break
            if len(raw) > 65536:
                raise ScryveilError("agent_response_too_large")
            result = session.step(load_json(raw))
            sys.stdout.buffer.write(canonical(result))
            sys.stdout.buffer.flush()
    except (ScryveilError, OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        sys.stdout.buffer.write(
            canonical(
                {
                    "ok": False,
                    "error": exc.code if isinstance(exc, ScryveilError) else "worker_failed",
                }
            )
        )
        sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
