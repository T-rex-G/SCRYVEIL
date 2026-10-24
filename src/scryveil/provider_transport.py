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
from .providers import validate_config


def exchange(request: dict[str, Any]) -> dict[str, Any]:
    config = validate_config(request["config"])
    url = urlsplit(config["endpoint"])
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
        payload = canonical(
            {
                "model": config["model"],
                "messages": request["messages"],
                "max_tokens": config["max_output_tokens"],
                "stream": False,
                "response_format": {"type": "json_object"},
            }
        )
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Connection": "close",
        }
        if request["credential"]:
            headers["Authorization"] = "Bearer " + request["credential"]
        connection.request("POST", url.path, body=payload, headers=headers)
        response = connection.getresponse()
        # No redirects, proxies, cookies, downloads or provider-supplied URLs.
        if response.status != 200:
            raise ScryveilError("provider_http_error")
        raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ScryveilError("provider_response_too_large")
        data = load_json(raw)
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
    except (
        OSError,
        ScryveilError,
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
