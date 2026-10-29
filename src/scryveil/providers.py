"""Small provider contract and explicitly configured wire adapters.

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
from urllib.parse import unquote, urlsplit

from .models import ScryveilError
from .parse import canonical, load_json, text_field
from .provider_messages import payload as messages_payload
from .provider_messages import safe_error
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


def provider_endpoint(config: dict[str, Any]) -> str:
    """Resolve an owner URL once; never discover, redirect or guess a provider.

    SDK-style base URLs have protocol-specific suffixes. Full endpoints permit
    custom gateway routes. The normalized endpoint is what disclosure binds.
    """
    if ("endpoint" in config) == ("base_url" in config):
        raise ScryveilError("provider_requires_one_url")
    value = config.get("base_url", config.get("endpoint"))
    # urlsplit silently removes some controls; reject them before parsing.
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 1024
        or any(ord(c) <= 32 or ord(c) >= 127 for c in value)
        or any(c in value for c in ("\\", "?", "#"))
    ):
        raise ScryveilError("invalid_provider_endpoint")
    try:
        url = urlsplit(value)
        port = url.port
    except ValueError as exc:
        raise ScryveilError("invalid_provider_endpoint") from exc
    if (
        "@" in url.netloc
        or not url.hostname
        or url.netloc.endswith(":")
        or (port is not None and not 1 <= port <= 65535)
        or re.search(r"%(?![0-9a-fA-F]{2})", url.path)
    ):
        raise ScryveilError("invalid_provider_endpoint")
    # Ambiguous routing is not necessary for a model API. Reject encoded
    # delimiters/controls and double encoding as well as dot path segments.
    decoded = unquote(url.path)
    if (
        any(ord(c) <= 32 or ord(c) >= 127 for c in decoded)
        or any(c in decoded for c in ("\\", "?", "#", "%"))
        or decoded.count("/") != url.path.count("/")
        or "//" in decoded
        or any(part in (".", "..") for part in decoded.split("/"))
    ):
        raise ScryveilError("invalid_provider_endpoint")
    if config["mode"] == "local":
        if url.scheme != "http" or url.hostname not in {"127.0.0.1", "::1"}:
            raise ScryveilError("local_provider_requires_loopback")
    elif url.scheme != "https" or url.hostname in {"localhost", "127.0.0.1", "::1"}:
        raise ScryveilError("remote_provider_requires_https")
    if "base_url" in config:
        suffix = "/v1/messages" if config["adapter"] == "messages-tools" else "/chat/completions"
        value = value.rstrip("/") + suffix
    if not urlsplit(value).path or len(value) > 1024:
        raise ScryveilError("invalid_provider_endpoint")
    return value


def validate_config(config: dict[str, Any]) -> dict[str, Any]:
    extra = {
        "endpoint",
        "base_url",
        "auth_scheme",
        "model",
        "api_key_env",
        "input_usd_per_million",
        "output_usd_per_million",
        "native_tool_layout",
        "messages_profile",
        "reasoning_effort",
    }
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
    if result["adapter"] not in ("chat-completions-json", "messages-tools") or result[
        "mode"
    ] not in ("local", "remote"):
        raise ScryveilError("unsupported_provider")
    if "native_tool_layout" in result and (
        result["adapter"] != "messages-tools"
        or result["native_tool_layout"] not in ("individual-v1", "routed-v1")
    ):
        raise ScryveilError("unsupported_native_tool_layout")
    if "messages_profile" in result and (
        result["adapter"] != "messages-tools" or result["messages_profile"] != "minimax-v1"
    ):
        raise ScryveilError("unsupported_messages_profile")
    if "reasoning_effort" in result and (
        not (
            (
                result["adapter"] == "chat-completions-json"
                and result["reasoning_effort"] in ("low", "medium", "high")
            )
            or (
                result.get("messages_profile") == "minimax-v1"
                and result["reasoning_effort"] in ("low", "medium", "high", "xhigh", "max")
            )
        )
    ):
        raise ScryveilError("unsupported_reasoning_effort")
    if result.get("messages_profile") == "minimax-v1" and "reasoning_effort" not in result:
        raise ScryveilError("explicit_reasoning_effort_required")
    text_field(result.get("model"))
    result["endpoint"] = provider_endpoint(result)
    result.pop("base_url", None)
    if "auth_scheme" in result and result["auth_scheme"] not in ("bearer", "x-api-key"):
        raise ScryveilError("unsupported_provider_auth")
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


def validate_catalog_request(config: dict[str, Any], endpoint: str, candidates: list[str]) -> str:
    """Explicit owner-only catalog address; never follow provider discovery URLs."""
    if config["adapter"] == "mock":
        raise ScryveilError("unsupported_provider")
    resolved = provider_endpoint({**config, "endpoint": endpoint})
    origin, catalog = urlsplit(config["endpoint"]), urlsplit(resolved)
    default_port = 443 if origin.scheme == "https" else 80
    if (origin.scheme, origin.hostname, origin.port or default_port) != (
        catalog.scheme,
        catalog.hostname,
        catalog.port or default_port,
    ):
        raise ScryveilError("catalog_origin_mismatch")
    if (
        not isinstance(candidates, list)
        or not 1 <= len(candidates) <= 16
        or any(
            not isinstance(value, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}", value)
            for value in candidates
        )
        or len(set(candidates)) != len(candidates)
    ):
        raise ScryveilError("invalid_catalog_candidates")
    return resolved


@dataclass(frozen=True)
class Reply:
    action: dict[str, Any]
    usage: dict[str, int] | None = None
    continuation: list[dict[str, Any]] | None = None


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


def context_bytes(config: dict[str, Any], messages: list[dict[str, str]]) -> int:
    # Native tools/schemas/history wrappers are part of the budget, not free
    # hidden context. Keep historical JSON-action reservations unchanged.
    return len(
        canonical(
            messages_payload(config, messages)
            if config["adapter"] == "messages-tools"
            else messages
        )
    )


class BrokerProvider:
    def __init__(self, config: dict[str, Any]):
        self.config = validate_config(config)

    def _credential(self) -> str | None:
        credential = None
        if self.config.get("api_key_env"):
            credential = os.environ.get(self.config["api_key_env"])
            if (
                not credential
                or len(credential) > 4096
                or any(ord(c) < 33 or ord(c) > 126 for c in credential)
            ):
                raise ScryveilError("provider_credential_unavailable")
        return credential

    def inspect_catalog(self, endpoint: str, candidates: list[str]) -> dict[str, Any]:
        """One explicit GET with no evidence/model messages; not an agent tool."""
        endpoint = validate_catalog_request(self.config, endpoint, candidates)
        response = self._exchange(
            {
                "config": self.config,
                "credential": self._credential(),
                "catalog_endpoint": endpoint,
                "candidates": candidates,
            },
            diagnostic_errors=True,
        )
        return dict(response["catalog"])

    def next(self, messages: list[dict[str, str]]) -> Reply:
        if context_bytes(self.config, messages) > self.config["max_context_bytes"]:
            raise ScryveilError("context_budget_exhausted")
        response = self._exchange(
            {"config": self.config, "credential": self._credential(), "messages": messages},
            diagnostic_errors=self.config["adapter"] == "messages-tools",
        )
        return Reply(response["action"], response["usage"], response.get("continuation"))

    def _exchange(self, request: dict[str, Any], *, diagnostic_errors: bool) -> dict[str, Any]:
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
            if (
                isinstance(response, dict)
                and safe_error(response.get("error"))
                and (
                    diagnostic_errors
                    or response["error"].startswith(
                        (
                            "provider_http_",
                            "provider_output_",
                            "provider_refused",
                            "provider_finish_",
                        )
                    )
                )
            ):
                raise ScryveilError(response["error"])
            raise ScryveilError("provider_failed")
        return response


class ChatCompletionsProvider(BrokerProvider):
    """Existing explicit JSON-action contract; no implied vendor compatibility."""


class MessagesToolsProvider(BrokerProvider):
    """Native Messages client tools; execution still belongs to the fixed worker."""
