"""Small provider contract and explicit OpenAI-compatible JSON-action adapter.

No provider SDK/framework or dynamic plugin imports. Network transport executes
in a disposable broker; responses are data and never host tool invocations.
"""

import os
import re

# Fixed internal broker only; no shell or provider-supplied argv.
import subprocess  # nosec B404
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from .models import ScryveilError
from .parse import canonical, load_json, text_field
from .store import read_regular

CONFIG_VERSION = "scryveil.provider/1"
DEFAULT_CONFIG: dict[str, Any] = {
    "schema_version": CONFIG_VERSION,
    "adapter": "mock",
    "mode": "offline",
    "max_requests": 12,
    "timeout_seconds": 15,
    "max_context_bytes": 131072,
    "max_output_tokens": 2048,
    "max_total_tokens": 131072,
}


def validate_config(config: dict[str, Any]) -> dict[str, Any]:
    extra = {"endpoint", "model", "api_key_env", "input_usd_per_million", "output_usd_per_million"}
    if not isinstance(config, dict) or set(config) - (set(DEFAULT_CONFIG) | extra):
        raise ScryveilError("invalid_provider_config")
    result = {**DEFAULT_CONFIG, **config}
    if result["schema_version"] != CONFIG_VERSION:
        raise ScryveilError("unsupported_provider_contract")
    for key, low, high in [
        ("max_requests", 1, 32),
        ("timeout_seconds", 1, 60),
        ("max_context_bytes", 4096, 262144),
        ("max_output_tokens", 128, 8192),
        ("max_total_tokens", 1024, 200000),
    ]:
        if type(result[key]) is not int or not low <= result[key] <= high:
            raise ScryveilError("invalid_provider_budget")
    if result["adapter"] == "mock":
        if result["mode"] != "offline" or set(result) & extra:
            raise ScryveilError("invalid_provider_config")
        return result
    if result["adapter"] != "chat-completions-json" or result["mode"] not in ("local", "remote"):
        raise ScryveilError("unsupported_provider")
    text_field(result.get("model"))
    endpoint = text_field(result.get("endpoint"))
    if endpoint is None:
        raise ScryveilError("invalid_provider_endpoint")
    url = urlsplit(endpoint)
    try:
        port = url.port
    except ValueError as exc:
        raise ScryveilError("invalid_provider_endpoint") from exc
    if (
        url.username
        or url.password
        or url.query
        or url.fragment
        or url.path != "/v1/chat/completions"
        or not url.hostname
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ScryveilError("invalid_provider_endpoint")
    if result["mode"] == "local":
        if url.scheme != "http" or url.hostname not in {"127.0.0.1", "::1"}:
            raise ScryveilError("local_provider_requires_loopback")
    elif url.scheme != "https" or url.hostname in {"localhost", "127.0.0.1", "::1"}:
        raise ScryveilError("remote_provider_requires_https")
    if "api_key_env" in result and (
        not isinstance(result["api_key_env"], str)
        or not re.fullmatch(r"SCRYVEIL_[A-Z0-9_]{1,64}", result["api_key_env"])
    ):
        raise ScryveilError("invalid_credential_reference")
    for key in ("input_usd_per_million", "output_usd_per_million"):
        if key in result and (
            type(result[key]) not in (int, float) or not 0 <= result[key] <= 10000
        ):
            raise ScryveilError("invalid_provider_rate")
    return result


def load_config(path: Path | None) -> dict[str, Any]:
    if path is None:
        return dict(DEFAULT_CONFIG)
    raw = read_regular(path, 65536)
    info = path.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ScryveilError("provider_config_requires_private_permissions")
    return validate_config(load_json(raw))


@dataclass(frozen=True)
class Reply:
    action: dict[str, Any]
    usage: dict[str, int] | None = None


class Provider(Protocol):
    def next(self, messages: list[dict[str, str]]) -> Reply: ...


class MockProvider:
    """Deterministic protocol demonstration; not a language model or quality test."""

    def __init__(self) -> None:
        self.step = 0

    def next(self, messages: list[dict[str, str]]) -> Reply:
        base: dict[str, Any] = {"version": "scryveil.agent/1"}
        results = [
            load_json(m["content"].encode())
            for m in messages
            if m["role"] == "user" and m["content"].startswith('{"tool_result":')
        ]
        findings: list[dict[str, Any]] = []
        events: list[dict[str, Any]] = []
        for result in results:
            data = result["tool_result"].get("data")
            if isinstance(data, list) and data and "finding_id" in data[0]:
                findings = data
            if isinstance(data, dict) and "events" in data and isinstance(data["events"], list):
                events = data["events"] or events
        sequence = [
            "case.inspect",
            "coverage.inspect",
            "diagnostics.search",
            "findings.inspect",
            "network.query",
        ]
        if self.step == 0:
            action = {
                **base,
                "kind": "plan",
                "steps": [
                    "Inspect coverage and diagnostic records",
                    "Compare deterministic recurrence observations and alternatives",
                    "Check network evidence without assuming causation",
                    "Report supported facts and missing sources",
                ],
            }
        elif self.step <= len(sequence):
            action = {**base, "kind": "tool", "name": sequence[self.step - 1], "arguments": {}}
        elif self.step == 6 and findings:
            action = {
                **base,
                "kind": "tool",
                "name": "hypotheses.compare",
                "arguments": {"finding_id": findings[0]["finding_id"]},
            }
        else:
            action = {
                **base,
                "kind": "final",
                "facts": [
                    {"event_id": e["event_id"], "field": "event_type", "value": e["event_type"]}
                    for e in events[:8]
                ],
                "measurements": [f["finding_id"] for f in findings[:8]],
                "hypotheses": [
                    {
                        "text": "A software or resource problem is a candidate explanation; the cause remains unresolved.",
                        "support": [e["event_id"] for e in events[:8]],
                        "contradictions": sorted(
                            {eid for f in findings[:8] for eid in f["contradictory_evidence_ids"]}
                        )[:32],
                        "confidence_justification": "Diagnostic recurrence does not distinguish a software defect from other causes; independent corroboration is missing.",
                    }
                ],
                "unanswered_questions": [
                    "Are these reports from the same device and software version?",
                    "What owner-observed activity coincided with the reports?",
                    "Which absent evidence sources could test the competing explanations?",
                ],
            }
        self.step += 1
        return Reply(action)


class ChatCompletionsProvider:
    def __init__(self, config: dict[str, Any]):
        self.config = validate_config(config)

    def next(self, messages: list[dict[str, str]]) -> Reply:
        credential = None
        if self.config.get("api_key_env"):
            credential = os.environ.get(self.config["api_key_env"])
            if (
                not credential
                or len(credential) > 4096
                or any(ord(c) < 33 or ord(c) > 126 for c in credential)
            ):
                raise ScryveilError("provider_credential_unavailable")
        request = {"config": self.config, "credential": credential, "messages": messages}
        if len(canonical(messages)) > self.config["max_context_bytes"]:
            raise ScryveilError("context_budget_exhausted")
        # Fixed interpreter/module and an empty credential environment.
        child = subprocess.Popen(  # nosec B603
            [sys.executable, "-I", "-m", "scryveil.provider_transport"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"LANG": "C.UTF-8"},
            close_fds=True,
        )
        try:
            output, _ = child.communicate(
                canonical(request), timeout=self.config["timeout_seconds"]
            )
        except subprocess.TimeoutExpired as exc:
            raise ScryveilError("provider_timeout") from exc
        finally:
            if child.poll() is None:
                child.kill()
            child.wait()
        if child.returncode or len(output) > 1024 * 1024:
            raise ScryveilError("provider_failed")
        response = load_json(output)
        if not isinstance(response, dict) or not response.get("ok"):
            raise ScryveilError("provider_failed")
        return Reply(response["action"], response["usage"])
