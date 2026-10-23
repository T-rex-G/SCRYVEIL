"""Real HTTP/subprocess contract tests; synthetic loopback peer, no model or cloud."""

import json
import socket
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from scryveil.investigation import investigate
from scryveil.models import ScryveilError
from scryveil.parse import canonical
from scryveil.provider_transport import exchange
from scryveil.providers import ChatCompletionsProvider, MockProvider, validate_config
from scryveil.store import CaseStore

PLAN = {"version": "scryveil.agent/1", "kind": "plan", "steps": ["Inspect evidence"]}


def response(action=PLAN, usage=None):
    return canonical(
        {"choices": [{"message": {"content": canonical(action).decode()}}], "usage": usage}
    )


@contextmanager
def peer(callback):
    observed = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            observed.append((self.path, dict(self.headers), json.loads(body)))
            status, raw = callback(observed[-1])
            try:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Location", "http://127.0.0.1:1/forbidden-redirect")
                self.end_headers()
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
    )
    thread.start()
    config = validate_config(
        {
            "adapter": "chat-completions-json",
            "mode": "local",
            "endpoint": f"http://127.0.0.1:{server.server_port}/v1/chat/completions",
            "model": "synthetic-protocol-peer",
        }
    )
    try:
        yield config, observed
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_real_broker_protocol_headers_usage_and_no_proxy(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("SCRYVEIL_SYNTHETIC_KEY", "fictional-test-credential")
    with peer(lambda _: (200, response(usage={"prompt_tokens": 12, "completion_tokens": 3}))) as (
        config,
        observed,
    ):
        config["api_key_env"] = "SCRYVEIL_SYNTHETIC_KEY"
        reply = ChatCompletionsProvider(config).next(
            [{"role": "user", "content": "synthetic question"}]
        )
        assert reply.action == PLAN and reply.usage == {"input_tokens": 12, "output_tokens": 3}
        path, headers, body = observed[0]
        assert path == "/v1/chat/completions"
        assert headers["Authorization"] == "Bearer fictional-test-credential"
        assert "fictional-test-credential" not in canonical(body).decode()
        assert body["stream"] is False and body["response_format"] == {"type": "json_object"}


def test_full_loop_uses_configured_adapter_and_reports_usage_cost(tmp_path):
    store = CaseStore(tmp_path / "cases")
    cid = store.create("synthetic", "self")["case_id"]
    fixtures = Path(__file__).parents[1] / "fixtures/synthetic"
    for index in (0, 1):
        store.import_file(cid, fixtures / f"diagnostic-{index}.ips", True, "ips")
    mock = MockProvider()

    def respond(request):
        return 200, response(
            mock.next(request[2]["messages"]).action, {"prompt_tokens": 10, "completion_tokens": 2}
        )

    with peer(respond) as (config, observed):
        config.update(input_usd_per_million=1, output_usd_per_million=2)
        report = investigate(store, cid, "Why do these synthetic failures recur?", config)
    assert report["status"] == "completed", report["status"]
    assert len(observed) == 8 and report["usage_complete"]
    assert report["usage"]["input_tokens"] == 80 and report["usage"]["output_tokens"] == 16
    assert report["estimated_cost_usd"] == 0.000112
    assert "com.example.searchd" not in canonical(observed).decode()


@pytest.mark.parametrize(
    "status,raw",
    [
        (302, b"{}"),
        (401, b"private error content"),
        (500, b"{}"),
        (200, b"invalid JSON"),
        (200, canonical({"choices": []})),
        (200, response(usage={"prompt_tokens": True, "completion_tokens": 2})),
        (200, response(usage=[])),
        (200, b"x" * (1024 * 1024 + 1)),
    ],
)
def test_transport_fails_closed_and_does_not_follow_redirects(status, raw):
    with peer(lambda _: (status, raw)) as (config, observed):
        with pytest.raises(ScryveilError, match="provider_failed"):
            ChatCompletionsProvider(config).next([{"role": "user", "content": "synthetic"}])
        assert len(observed) == 1


def test_real_transport_timeout_terminates_broker():
    release = threading.Event()

    def blocked(_):
        release.wait(2)
        return 200, response()

    try:
        with peer(blocked) as (config, observed):
            config["timeout_seconds"] = 1
            with pytest.raises(ScryveilError, match="provider_timeout"):
                ChatCompletionsProvider(config).next([{"role": "user", "content": "synthetic"}])
            assert len(observed) == 1
    finally:
        release.set()


@pytest.mark.parametrize(
    "addresses",
    [["127.0.0.1"], ["169.254.169.254"], ["10.0.0.1"], ["93.184.215.14", "192.168.1.1"], ["::1"]],
)
def test_remote_dns_must_be_public_before_any_connection(monkeypatch, addresses):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443)) for ip in addresses
        ],
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("no connection to private or mixed DNS destinations")

    monkeypatch.setattr(socket, "socket", forbidden)
    with pytest.raises(ScryveilError, match="provider_destination_not_public"):
        exchange(
            {
                "config": {
                    "adapter": "chat-completions-json",
                    "mode": "remote",
                    "endpoint": "https://provider.example.invalid/v1/chat/completions",
                    "model": "test",
                },
                "messages": [],
                "credential": None,
            }
        )
