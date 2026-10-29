"""Disposable destination-pinned HTTP broker; never receives case file paths."""

import http.client
import ipaddress
import socket
import ssl
import sys
from typing import Any
from urllib.parse import urlsplit

from .isolation import restrict_worker
from .models import ScryveilError
from .parse import canonical, load_json
from .provider_messages import HTTP_ERROR_DETAILS, safe_error
from .provider_messages import payload as messages_payload
from .provider_messages import response as messages_response
from .providers import validate_catalog_request, validate_config


def http_failure(status: int, raw: bytes, credential: str | None) -> str:
    """Classify a bounded error without returning provider text or identifiers."""
    fallback = f"provider_http_{status}"
    if credential and credential.encode() in raw:
        return "provider_credential_echo"
    if len(raw) > 65536:
        return fallback
    try:
        data = load_json(raw)
    except (ScryveilError, ValueError, RecursionError):
        return fallback
    error = data.get("error") if isinstance(data, dict) else None
    code = error.get("code") if isinstance(error, dict) else None
    return (
        fallback + "_" + code if isinstance(code, str) and code in HTTP_ERROR_DETAILS else fallback
    )


def catalog_result(data: Any, candidates: list[str]) -> dict[str, Any]:
    """Return only requested membership and counts, not arbitrary catalog text."""
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("data"), list)
        or len(data["data"]) > 1000
        or any(
            not isinstance(row, dict)
            or not isinstance(row.get("id"), str)
            or not 1 <= len(row["id"]) <= 256
            for row in data["data"]
        )
    ):
        raise ScryveilError("invalid_provider_catalog")
    identifiers = {row["id"] for row in data["data"]}
    return {
        "ok": True,
        "catalog": {
            "schema_version": "scryveil.provider-catalog-check/1",
            "entries_received": len(data["data"]),
            "candidate_listed": {candidate: candidate in identifiers for candidate in candidates},
            "pagination_indicated": any(data.get(k) for k in ("has_more", "next", "next_page")),
            "inference_tested": False,
            "billing_verified": False,
        },
    }


def exchange(request: dict[str, Any]) -> dict[str, Any]:
    config = validate_config(request["config"])
    native = config["adapter"] == "messages-tools"
    catalog = "catalog_endpoint" in request
    if catalog and set(request) != {"config", "credential", "catalog_endpoint", "candidates"}:
        raise ScryveilError("invalid_provider_catalog")
    endpoint = (
        validate_catalog_request(config, request["catalog_endpoint"], request["candidates"])
        if catalog
        else config["endpoint"]
    )
    payload = (
        None
        if catalog
        else canonical(
            messages_payload(config, request["messages"])
            if native
            else {
                "model": config["model"],
                "messages": request["messages"],
                "max_tokens": config["max_output_tokens"],
                "stream": False,
                "response_format": {"type": "json_object"},
            }
        )
    )
    if native and payload is not None and len(payload) > config["max_context_bytes"]:
        raise ScryveilError("context_budget_exhausted")
    url = urlsplit(endpoint)
    host, port = url.hostname, url.port or (443 if config["mode"] == "remote" else 80)
    if host is None:
        raise ScryveilError("invalid_provider_endpoint")
    # Resolve once, reject every non-public remote address, and connect to the
    # selected numeric address. TLS still verifies the configured DNS hostname.
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if config["mode"] == "remote" and not ip.is_global:
            raise ScryveilError("provider_destination_not_public")
        if config["mode"] == "local" and not ip.is_loopback:
            raise ScryveilError("provider_destination_not_loopback")
    if not addresses:
        raise ScryveilError("provider_resolution_failed")
    context = ssl.create_default_context() if config["mode"] == "remote" else None
    selected = addresses[0]
    sock = socket.socket(selected[0], selected[1], selected[2])
    sock.settimeout(config["timeout_seconds"])
    try:
        sock.connect(selected[4])
        if context is not None:
            # Construct the wrapper without consuming provider-controlled TLS
            # records. Perform the handshake only after installing the policy.
            sock = context.wrap_socket(sock, server_hostname=host, do_handshake_on_connect=False)
        restrict_worker(connected_socket=True)
        if isinstance(sock, ssl.SSLSocket):
            sock.do_handshake()
        connection = http.client.HTTPConnection(host, port, timeout=config["timeout_seconds"])
        connection.sock = sock
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Connection": "close",
        }
        if native:
            headers["anthropic-version"] = "2023-06-01"
        if request["credential"]:
            auth = config.get(
                "auth_scheme",
                "x-api-key"
                if native and config.get("messages_profile") != "minimax-v1"
                else "bearer",
            )
            if auth == "bearer":
                headers["Authorization"] = "Bearer " + request["credential"]
            else:
                headers["x-api-key"] = request["credential"]
        connection.request("GET" if catalog else "POST", url.path, body=payload, headers=headers)
        response = connection.getresponse()
        # No redirects, proxies, cookies, downloads or provider-supplied URLs.
        if response.status != 200:
            raise ScryveilError(
                http_failure(response.status, response.read(65537), request["credential"])
            )
        raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ScryveilError("provider_response_too_large")
        if request["credential"] and request["credential"].encode() in raw:
            raise ScryveilError("provider_credential_echo")
        data = load_json(raw)
        if catalog:
            return catalog_result(data, request["candidates"])
        if native:
            return messages_response(data, preserve=config.get("messages_profile") == "minimax-v1")
        content = data["choices"][0]["message"]["content"]
        if not isinstance(content, str) or len(content.encode()) > 65536:
            raise ScryveilError("invalid_provider_response")
        usage = data.get("usage")
        if usage is not None:
            if not isinstance(usage, dict):
                raise ScryveilError("invalid_provider_usage")
            values = [usage.get("prompt_tokens"), usage.get("completion_tokens")]
            if any(type(v) is not int or not 0 <= v <= 10**9 for v in values):
                raise ScryveilError("invalid_provider_usage")
            usage = {"input_tokens": values[0], "output_tokens": values[1]}
        return {"ok": True, "action": load_json(content.encode()), "usage": usage}
    finally:
        sock.close()


def main() -> None:
    try:
        raw = sys.stdin.buffer.read(524289)
        if len(raw) > 524288:
            raise ScryveilError("provider_request_too_large")
        result = exchange(load_json(raw))
    except ScryveilError as exc:
        result = {
            "ok": False,
            "error": exc.code if safe_error(exc.code) else "provider_transport_failed",
        }
    except (
        OSError,
        ValueError,
        KeyError,
        IndexError,
        TypeError,
        http.client.HTTPException,
        RecursionError,
    ):
        result = {"ok": False, "error": "provider_transport_failed"}
    sys.stdout.buffer.write(canonical(result))


if __name__ == "__main__":
    main()
