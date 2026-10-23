import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from scryveil.investigation import investigate
from scryveil.investigation_tools import TOOL_SCHEMAS, ReadOnlyTools, snapshot_case
from scryveil.providers import DEFAULT_CONFIG, MockProvider
from scryveil.store import CaseStore

ROOT = Path(__file__).parents[1]


def schema(name):
    value = json.loads((ROOT / "schemas" / name).read_text())
    Draft202012Validator.check_schema(value)
    return value


@pytest.mark.parametrize("identifiers", [False, True])
def test_all_tool_outputs_and_complete_report_conform(identifiers, tmp_path):
    store = CaseStore(tmp_path / "cases")
    cid = store.create("synthetic", "self")["case_id"]
    for name in (
        "diagnostic-0.ips",
        "diagnostic-1.ips",
        "diagnostic-jetsam.ips",
        "periodic.ndjson",
        "indicators.ndjson",
        "privacy_sessions.ndjson",
        "malformed.ndjson",
    ):
        store.import_file(
            cid,
            ROOT / "fixtures/synthetic" / name,
            True,
            "ips" if name.endswith(".ips") else "ndjson",
        )
    snap = snapshot_case(store, cid, identifiers)
    tools = ReadOnlyTools(snap)
    result_schema = schema("investigator-results-v1.schema.json")
    args = {
        "evidence.read_excerpt": {"event_id": snap["events"][0]["event_id"]},
        "process.inspect": {"process_ref": "process-000001"},
        "hypotheses.compare": {"finding_id": snap["findings"][0]["finding_id"]},
    }
    for name in TOOL_SCHEMAS:
        result = tools.call(name, args.get(name, {}))
        assert result["ok"], (name, result)
        contract = Draft202012Validator(dict(result_schema, **{"$ref": "#/$defs/" + name}))
        contract.validate(result)
        contract.validate(tools.call(name, {"unknown": True}))

    class CheckedMock(MockProvider):
        def next(self, messages):
            reply = super().next(messages)
            Draft202012Validator(schema("investigator-action-v1.schema.json")).validate(
                reply.action
            )
            return reply

    report = investigate(
        store,
        cid,
        "Which sources support or contradict recurring failures?",
        DEFAULT_CONFIG,
        include_identifiers=identifiers,
        provider=CheckedMock(),
    )
    assert report["status"] == "completed"
    Draft202012Validator(schema("investigation-v1.schema.json")).validate(report)


def test_provider_contract_has_no_inline_secrets_or_unknown_capabilities():
    validator = Draft202012Validator(schema("provider-v1.schema.json"))
    validator.validate(DEFAULT_CONFIG)
    validator.validate(
        {
            "adapter": "chat-completions-json",
            "mode": "local",
            "endpoint": "http://127.0.0.1:11434/v1/chat/completions",
            "model": "owner-selected-local-model",
        }
    )
    assert not validator.is_valid({**DEFAULT_CONFIG, "api_key": "not-accepted"})
    assert not validator.is_valid({**DEFAULT_CONFIG, "shell": True})


def test_extension_declarations_match_actual_read_only_allowlist():
    declarations = json.loads((ROOT / "extensions/builtins-v1.json").read_text())
    Draft202012Validator(schema("extension-v1.schema.json")).validate(declarations)
    tools = next(d for d in declarations if d["kind"] == "investigator_tools")
    assert set(tools["capabilities"]) == set(TOOL_SCHEMAS)
    assert not tools["side_effects"]
