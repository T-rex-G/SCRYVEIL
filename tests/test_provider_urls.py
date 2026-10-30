"""Custom routes remain owner configuration, never agent capabilities."""

import json

import pytest
from jsonschema import Draft202012Validator, ValidationError
from test_provider_messages import ROOT, case
from test_provider_transport import PLAN, peer, response

from scryveil.investigation import disclosure, investigate
from scryveil.investigation_tools import snapshot_case
from scryveil.models import ScryveilError
from scryveil.providers import ChatCompletionsProvider, validate_config

REMOTE = {
    "adapter": "messages-tools",
    "mode": "remote",
    "model": "fictional-model",
    "api_key_env": "SCRYVEIL_ABSENT_CUSTOM_KEY",
}


@pytest.mark.parametrize(
    "adapter,base,path",
    [
        ("messages-tools", "https://model.example.invalid", "/v1/messages"),
        ("messages-tools", "https://model.example.invalid/", "/v1/messages"),
        ("messages-tools", "https://model.example.invalid/proxy/", "/proxy/v1/messages"),
        ("chat-completions-json", "https://model.example.invalid/v1/", "/v1/chat/completions"),
        (
            "chat-completions-json",
            "https://model.example.invalid/api/v2",
            "/api/v2/chat/completions",
        ),
    ],
)
def test_base_urls_preserve_prefixes_and_normalize_to_one_disclosed_endpoint(adapter, base, path):
    supplied = {**REMOTE, "adapter": adapter, "base_url": base}
    schema = Draft202012Validator(
        json.loads((ROOT / "schemas/provider-v1.schema.json").read_text())
    )
    schema.validate(supplied)
    normalized = validate_config(supplied)
    assert normalized["endpoint"] == "https://model.example.invalid" + path
    assert "base_url" not in normalized and supplied["base_url"] == base
    assert validate_config(normalized) == normalized
    schema.validate(normalized)


@pytest.mark.parametrize("auth", ["bearer", "x-api-key"])
def test_custom_full_route_and_auth_reach_isolated_broker_without_protocol_rewriting(
    monkeypatch, auth
):
    monkeypatch.setenv("SCRYVEIL_CUSTOM_TEST", "fictional-custom-credential")
    with peer(lambda _: (200, response())) as (cfg, observed):
        cfg["endpoint"] = cfg["endpoint"].replace("/v1/chat/completions", "/custom/model/infer")
        cfg.update(auth_scheme=auth, api_key_env="SCRYVEIL_CUSTOM_TEST")
        assert (
            ChatCompletionsProvider(cfg).next([{"role": "user", "content": "fictional"}]).action
            == PLAN
        )
    path, headers, body = observed[0]
    assert path == "/custom/model/infer" and body["response_format"] == {"type": "json_object"}
    if auth == "bearer":
        assert headers["Authorization"] == "Bearer fictional-custom-credential"
        assert "x-api-key" not in headers
    else:
        assert headers["x-api-key"] == "fictional-custom-credential"
        assert "Authorization" not in headers


@pytest.mark.parametrize("field", ["endpoint", "base_url"])
@pytest.mark.parametrize(
    "url",
    [
        "https://user:secret@model.example.invalid/custom",
        "https://@model.example.invalid/custom",
        "https://model.example.invalid/custom?key=secret",
        "https://model.example.invalid/custom?",
        "https://model.example.invalid/custom#fragment",
        " https://model.example.invalid/custom",
        "https://model.example.invalid/custom\r\nAuthorization:bad",
        "https://model.example.invalid/custom\t",
        "https://model.example.invalid/custom\\route",
        "https://model.example.invalid:bad/custom",
        "https://model.example.invalid:/custom",
        "https://[broken/custom",
        "https://model.example.invalid/custom/%0d%0aInjected",
        "https://model.example.invalid/custom/%2Fother",
        "https://model.example.invalid/custom/%252fother",
        "https://model.example.invalid/custom/%ZZ",
        "https://model.example.invalid/custom/../other",
        "https://model.example.invalid/custom/%2e%2e/other",
        "https://model.example.invalid//other",
        "http://model.example.invalid/custom",
        "file:///etc/passwd",
    ],
)
def test_custom_urls_reject_credential_and_routing_ambiguity(field, url):
    with pytest.raises(ScryveilError):
        validate_config({**REMOTE, field: url})


def test_one_url_and_supported_auth_are_required_by_schema_and_runtime():
    schema = Draft202012Validator(
        json.loads((ROOT / "schemas/provider-v1.schema.json").read_text())
    )
    for cfg in (
        REMOTE,
        {
            **REMOTE,
            "endpoint": "https://model.example.invalid/infer",
            "base_url": "https://other.example.invalid",
        },
        {**REMOTE, "base_url": "https://model.example.invalid", "auth_scheme": "arbitrary-header"},
        {"auth_scheme": "bearer"},
        {"base_url": "https://model.example.invalid"},
    ):
        with pytest.raises(ScryveilError):
            validate_config(cfg)
        with pytest.raises(ValidationError):
            schema.validate(cfg)


def test_custom_routes_and_auth_are_exactly_consent_bound_before_credential_read(tmp_path):
    store, cid = case(tmp_path)
    snapshot = snapshot_case(store, cid)
    cfg = {
        **REMOTE,
        "base_url": "https://gateway.example.invalid/prefix",
        "auth_scheme": "x-api-key",
    }
    manifest = disclosure(snapshot, "fictional", cfg)
    assert manifest["provider"]["endpoint"] == "https://gateway.example.invalid/prefix/v1/messages"
    assert disclosure(snapshot, "fictional", validate_config(cfg)) == manifest
    for changed in (
        {**cfg, "base_url": "https://different.example.invalid/prefix"},
        {**cfg, "base_url": "https://gateway.example.invalid/other-prefix"},
        {**cfg, "auth_scheme": "bearer"},
    ):
        assert (
            disclosure(snapshot, "fictional", changed)["consent_sha256"]
            != manifest["consent_sha256"]
        )
        with pytest.raises(ScryveilError, match="remote_disclosure_consent_required"):
            investigate(store, cid, "fictional", changed, consent_sha256=manifest["consent_sha256"])
