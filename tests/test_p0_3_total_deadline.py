"""Wall-clock deadline regressions for the P0-3 Inspect transport.

The service is an in-process loopback-only synthetic peer.  Tests call the
private already-vetted-IP seam, so no resolver policy is weakened and no
external endpoint is contacted.
"""

from dataclasses import replace
import socketserver
import sys
import threading
import time

import pytest

from ln_church_agent import inspect_transport as transport


TOTAL_TIMEOUT = 0.15
ELAPSED_TOLERANCE = 0.45
SLOW_HEADER_DURATION = 1.2
SLOW_HEADER_INTERVAL = 0.02


def _clock_float_tolerance():
    """Allow only clock resolution and large-monotonic float roundoff."""
    return max(
        time.get_clock_info("monotonic").resolution,
        4.0 * sys.float_info.epsilon * max(1.0, abs(time.monotonic())),
    )


class _SyntheticDeadlineServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False

    def __init__(self, server_address, handler_class):
        super().__init__(server_address, handler_class)
        self.calls = []
        self._calls_lock = threading.Lock()

    def record(self, method, path, body):
        with self._calls_lock:
            self.calls.append((method, path, body))


class _SyntheticDeadlineHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2.0)
        request_bytes = bytearray()
        try:
            while b"\r\n\r\n" not in request_bytes:
                chunk = self.request.recv(4096)
                if not chunk:
                    return
                request_bytes.extend(chunk)
                if len(request_bytes) > 64 * 1024:
                    return

            raw_headers, body = bytes(request_bytes).split(b"\r\n\r\n", 1)
            lines = raw_headers.split(b"\r\n")
            method_bytes, path_bytes, _version = lines[0].split(b" ", 2)
            content_length = 0
            for line in lines[1:]:
                name, separator, value = line.partition(b":")
                if separator and name.strip().lower() == b"content-length":
                    content_length = int(value.strip())
                    break
            while len(body) < content_length:
                chunk = self.request.recv(content_length - len(body))
                if not chunk:
                    return
                body += chunk

            method = method_bytes.decode("ascii")
            path = path_bytes.decode("ascii")
            self.server.record(method, path, body[:content_length])

            if path == "/redirect":
                # Consume part of the shared budget before the next hop.  The
                # second response must receive only the remaining time.
                time.sleep(TOTAL_TIMEOUT / 2.0)
                port = self.server.server_address[1]
                response = (
                    "HTTP/1.1 302 Found\r\n"
                    "Location: http://public.example:%d/slow\r\n"
                    "Content-Length: 0\r\n"
                    "Connection: close\r\n\r\n"
                ) % port
                self.request.sendall(response.encode("ascii"))
                return

            # A scalar requests read timeout never fires here: every byte
            # arrives well before TOTAL_TIMEOUT, but the header is deliberately
            # never terminated during SLOW_HEADER_DURATION.
            self.request.sendall(b"HTTP/1.1 200 OK\r\nX-Slow-Header: ")
            stop_at = time.monotonic() + SLOW_HEADER_DURATION
            while time.monotonic() < stop_at:
                self.request.sendall(b"x")
                time.sleep(SLOW_HEADER_INTERVAL)
        except (BrokenPipeError, ConnectionResetError, OSError, ValueError):
            # Deadline-driven connection shutdown is the expected exit path.
            return


@pytest.fixture
def synthetic_deadline_server():
    server = _SyntheticDeadlineServer(
        ("127.0.0.1", 0),
        _SyntheticDeadlineHandler,
    )
    worker = threading.Thread(
        target=server.serve_forever,
        name="ln-church-test-deadline-server",
        daemon=True,
    )
    worker.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=1.0)


def _target(server, path="/slow"):
    port = server.server_address[1]
    authority = "public.example:%d" % port
    return transport._CanonicalTarget(
        scheme="http",
        host="public.example",
        port=port,
        origin="http://" + authority,
        url="http://%s%s" % (authority, path),
        host_header=authority,
        addresses=("127.0.0.1",),
    )


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_slow_progressing_response_headers_obey_total_deadline(
    synthetic_deadline_server,
    method,
):
    target = _target(synthetic_deadline_server)
    started = time.monotonic()

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._exchange_once(
            target,
            "127.0.0.1",
            method,
            TOTAL_TIMEOUT,
        )

    elapsed = time.monotonic() - started
    assert caught.value.stage == "transport"
    assert caught.value.code == "transport_timeout"
    assert elapsed <= TOTAL_TIMEOUT + ELAPSED_TOLERANCE
    assert elapsed < SLOW_HEADER_DURATION / 2.0
    assert [call[0] for call in synthetic_deadline_server.calls] == [method]


def test_redirect_hops_share_the_original_total_deadline(
    synthetic_deadline_server,
    monkeypatch,
):
    initial = _target(synthetic_deadline_server, "/redirect")

    def local_test_resolution(target, timeout):
        # Windows can round a large monotonic deadline slightly above the
        # scalar budget while preserving the same absolute deadline.
        assert float(timeout) <= TOTAL_TIMEOUT + _clock_float_tolerance()
        return replace(target, addresses=("127.0.0.1",))

    monkeypatch.setattr(
        transport,
        "_validate_and_resolve",
        local_test_resolution,
    )
    started = time.monotonic()

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._inspect_request(
            initial.url,
            method="GET",
            timeout=TOTAL_TIMEOUT,
        )

    elapsed = time.monotonic() - started
    assert caught.value.stage == "transport"
    assert caught.value.code == "transport_timeout"
    assert elapsed <= TOTAL_TIMEOUT + ELAPSED_TOLERANCE
    assert elapsed < SLOW_HEADER_DURATION / 2.0
    assert [call[:2] for call in synthetic_deadline_server.calls] == [
        ("GET", "/redirect"),
        ("GET", "/slow"),
    ]


def test_observation_slow_headers_are_ambiguous_and_post_is_never_replayed(
    synthetic_deadline_server,
):
    target = _target(synthetic_deadline_server)
    wire_body = b'{"observation":"bounded"}'
    started = time.monotonic()

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._exchange_observation_once(
            target,
            "127.0.0.1",
            TOTAL_TIMEOUT,
            wire_body,
        )

    elapsed = time.monotonic() - started
    assert caught.value.stage == "transport"
    assert caught.value.code == "observation_delivery_unknown"
    assert elapsed <= TOTAL_TIMEOUT + ELAPSED_TOLERANCE
    assert elapsed < SLOW_HEADER_DURATION / 2.0

    # There is no background I/O worker.  Waiting briefly also proves that no
    # delayed retry appears after the caller has received the ambiguous result.
    time.sleep(0.05)
    assert synthetic_deadline_server.calls == [
        ("POST", "/slow", wire_body),
    ]


def test_initial_dns_budget_exhaustion_is_transport_timeout(monkeypatch):
    release = threading.Event()

    def slow_resolver(_host, _port):
        release.wait(timeout=1.0)
        return ("8.8.8.8",)

    monkeypatch.setattr(transport, "_resolve_addresses", slow_resolver)
    started = time.monotonic()
    try:
        with pytest.raises(transport.InspectTransportError) as caught:
            transport._inspect_request(
                "https://public.example/",
                timeout=TOTAL_TIMEOUT,
            )
    finally:
        release.set()

    elapsed = time.monotonic() - started
    assert caught.value.stage == "transport"
    assert caught.value.code == "transport_timeout"
    assert elapsed <= TOTAL_TIMEOUT + ELAPSED_TOLERANCE


def test_redirect_dns_budget_exhaustion_is_transport_timeout(monkeypatch):
    release = threading.Event()
    resolver_calls = []

    def resolver(host, _port):
        resolver_calls.append(host)
        if host == "public.example":
            return ("8.8.8.8",)
        release.wait(timeout=1.0)
        return ("8.8.4.4",)

    class _RedirectResponse:
        status_code = 302
        headers = {"Location": "https://redirect.example/final"}

        def close(self):
            return None

    def redirect_exchange(target, _address, _method, _timeout, _body=None):
        response = _RedirectResponse()
        response.url = target.url
        return response

    monkeypatch.setattr(transport, "_resolve_addresses", resolver)
    monkeypatch.setattr(transport, "_exchange_once", redirect_exchange)
    started = time.monotonic()
    try:
        with pytest.raises(transport.InspectTransportError) as caught:
            transport._inspect_request(
                "https://public.example/start",
                timeout=TOTAL_TIMEOUT,
            )
    finally:
        release.set()

    elapsed = time.monotonic() - started
    assert caught.value.stage == "transport"
    assert caught.value.code == "transport_timeout"
    assert elapsed <= TOTAL_TIMEOUT + ELAPSED_TOLERANCE
    assert resolver_calls == ["public.example", "redirect.example"]
