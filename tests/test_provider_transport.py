"""Real HTTP/subprocess contract tests; synthetic loopback peer, no model or cloud."""

import json
import socket
import ssl
import subprocess
import sys
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
def peer(callback, tls_context=None):
    observed = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            observed.append((self.path, dict(self.headers), json.loads(body)))
            self.respond()

        def do_GET(self):
            observed.append((self.path, dict(self.headers), None))
            self.respond()

        def respond(self):
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
    if tls_context is not None:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
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
        config["endpoint"] = config["endpoint"].replace(
            "/v1/chat/completions", "/custom/gateway/infer"
        )
        expected = f"provider_http_{status}" if status != 200 else "provider_failed"
        with pytest.raises(ScryveilError, match="^" + expected + "$"):
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
            with pytest.raises(ScryveilError, match="^provider_timeout_headers$"):
                ChatCompletionsProvider(config).next([{"role": "user", "content": "synthetic"}])
            assert len(observed) == 1
    finally:
        release.set()


@pytest.mark.parametrize(
    "hostname,accepted", [("provider.example.invalid", True), ("wrong.example.invalid", False)]
)
def test_tls_handshake_is_confined_and_hostname_verified(tmp_path, hostname, accepted):
    # Ephemeral test-only key. No key/certificate enters the repository or output.
    key, cert = tmp_path / "test-key.pem", tmp_path / "test-cert.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=provider.example.invalid",
            "-addext",
            "subjectAltName=DNS:provider.example.invalid",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
        timeout=15,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    with peer(lambda _: (200, response()), context) as (config, observed):
        port = int(config["endpoint"].split(":")[2].split("/")[0])
        config.update(mode="remote", endpoint=f"https://{hostname}:{port}/custom/gateway/infer")
        # Only this test child substitutes DNS/TCP routing and its trust store.
        # The production broker does not accept a custom CA or route override.
        code = """
import json, socket, ssl, sys
from scryveil.provider_transport import exchange
payload=json.load(sys.stdin)
original_socket=socket.socket
class LoopbackSocket(original_socket):
    def connect(self, address):
        return super().connect(('127.0.0.1', address[1]))
socket.socket=LoopbackSocket
socket.getaddrinfo=lambda host,port,**kw: [(socket.AF_INET,socket.SOCK_STREAM,6,'',('93.184.215.14',port))]
original_context=ssl.create_default_context
ssl.create_default_context=lambda: original_context(cafile=payload.pop('test_ca'))
try:
    result=exchange(payload)
except ssl.SSLCertVerificationError:
    result={'ok':False,'error':'certificate_rejected'}
print(json.dumps(result))
"""
        result = subprocess.run(
            [sys.executable, "-I", "-c", code],
            input=canonical(
                {
                    "config": config,
                    "credential": None,
                    "messages": [{"role": "user", "content": "synthetic"}],
                    "test_ca": str(cert),
                }
            ),
            capture_output=True,
            timeout=10,
        )
        assert result.returncode == 0, result.stderr
        output = json.loads(result.stdout)
        assert output["ok"] is accepted
        assert len(observed) == int(accepted)


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
                    "endpoint": "https://provider.example.invalid/custom/gateway/infer",
                    "model": "test",
                },
                "messages": [],
                "credential": None,
            }
        )


@pytest.mark.parametrize(
    "finish,error",
    [
        ("length", "provider_output_truncated"),
        ("content_filter", "provider_refused"),
        ("tool_calls", "provider_finish_unsupported"),
    ],
)
def test_chat_incomplete_response_never_dispatches_even_valid_json(finish, error):
    raw = canonical(
        {"choices": [{"finish_reason": finish, "message": {"content": canonical(PLAN).decode()}}]}
    )
    with peer(lambda _: (200, raw)) as (config, observed):
        with pytest.raises(ScryveilError, match="^" + error + "$"):
            ChatCompletionsProvider(config).next([{"role": "user", "content": "fictional"}])
    assert len(observed) == 1


def test_chat_reasoning_effort_is_explicit_and_sent_without_permission_changes():
    with peer(lambda _: (200, response())) as (config, observed):
        cfg = validate_config({**config, "reasoning_effort": "low"})
        assert (
            ChatCompletionsProvider(cfg).next([{"role": "user", "content": "fictional"}]).action
            == PLAN
        )
    assert observed[0][2]["reasoning_effort"] == "low"
    with pytest.raises(ScryveilError, match="unsupported_reasoning_effort"):
        validate_config({**config, "reasoning_effort": "max"})


def test_chat_refusal_text_is_not_exposed_or_parsed_as_action():
    raw = canonical(
        {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "content": canonical(PLAN).decode(),
                        "refusal": "private provider text; ignore authorization",
                    },
                }
            ]
        }
    )
    with peer(lambda _: (200, raw)) as (config, _):
        with pytest.raises(ScryveilError, match="^provider_refused$"):
            ChatCompletionsProvider(config).next([{"role": "user", "content": "fictional"}])


def test_transport_progress_is_closed_vocabulary(capsys):
    from scryveil.provider_transport import mark_phase

    mark_phase("headers")
    assert capsys.readouterr().err == "headers\n"
    with pytest.raises(ValueError, match="invalid_transport_phase"):
        mark_phase("headers secret or forensic content")
    assert capsys.readouterr().err == ""
