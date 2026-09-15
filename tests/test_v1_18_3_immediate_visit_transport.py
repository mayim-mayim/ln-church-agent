"""Target connector tests from audited profile §§2–5; no live site traffic."""
import dataclasses
import pickle
import socket
import ssl

import pytest

from ln_church_agent.network_fetch import (
    ControlledHTTPSConnector, FetchScope, FetchTimeouts,
    ImmediateVisitFetchError, IMMEDIATE_VISIT_BODY_LIMIT_BYTES,
    IMMEDIATE_VISIT_USER_AGENT, NetworkFetchError,
)


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class Stream:
    def __init__(self, harness, response):
        self.harness = harness
        self.response = bytearray(response)
        self.requests = []
        self.timeouts = []
        self.closed = False
        self.received = 0

    def settimeout(self, value):
        self.timeouts.append(value)

    def connect(self, endpoint):
        self.harness.connections.append(endpoint)
        self.harness.clock.now += self.harness.connect_elapsed
        if self.harness.connect_error:
            raise self.harness.connect_error

    def getpeername(self):
        return (self.harness.peer, 443)

    def sendall(self, data):
        self.requests.append(data)

    def recv(self, maximum):
        if self.harness.on_recv:
            self.harness.on_recv(self, maximum)
        if not self.response and self.harness.eof_error:
            raise self.harness.eof_error
        value = bytes(self.response[:maximum])
        del self.response[:maximum]
        self.received += len(value)
        return value

    def close(self):
        self.closed = True


class TLSContext:
    verify_mode = ssl.CERT_REQUIRED
    check_hostname = True

    def __init__(self, harness):
        self.harness = harness

    def wrap_socket(self, raw, *, server_hostname, suppress_ragged_eofs=True):
        self.harness.sni.append(server_hostname)
        self.harness.suppress_ragged_eofs = suppress_ragged_eofs
        self.harness.clock.now += self.harness.tls_elapsed
        if self.harness.tls_error:
            raise self.harness.tls_error
        self.harness.peer = self.harness.tls_peer or self.harness.peer
        return raw


class Harness:
    def __init__(self, response=b"", answers=("8.8.8.8",)):
        self.clock = Clock()
        self.answers = answers
        self.peer = sorted(answers)[0] if answers else "8.8.8.8"
        self.tls_peer = None
        self.dns = []
        self.connections = []
        self.sockets = []
        self.sni = []
        self.dns_elapsed = self.connect_elapsed = self.tls_elapsed = 0.0
        self.connect_error = self.tls_error = self.eof_error = None
        self.on_recv = None
        self.response = response
        self.context = TLSContext(self)
        self.connector = ControlledHTTPSConnector(
            resolver=self.resolve, socket_factory=self.socket,
            ssl_context_factory=lambda: self.context, monotonic=self.clock,
        )

    def resolve(self, host, port):
        self.dns.append((host, port))
        self.clock.now += self.dns_elapsed
        return self.answers

    def socket(self, *args):
        stream = Stream(self, self.response)
        self.sockets.append((args, stream))
        return stream

    def fetch(self, url="https://example.com/path?a=1&b=2"):
        return self.connector.fetch_immediate_visit(url)

    @property
    def stream(self):
        return self.sockets[0][1]


def response(body=b'{"safe":true}', *, status=200, headers=(), length=True):
    fields = [("Content-Type", "application/json")]
    if length:
        fields.append(("Content-Length", str(len(body))))
    fields.extend(headers)
    return ("HTTP/1.1 %d Result\r\n%s\r\n\r\n" % (
        status, "\r\n".join("%s: %s" % field for field in fields)
    )).encode("latin-1") + body


def expect_reason(harness, reason, **kwargs):
    with pytest.raises(ImmediateVisitFetchError) as caught:
        harness.fetch(**kwargs)
    assert caught.value.reason == reason
    assert str(caught.value) == reason
    assert all(stream.closed for _, stream in harness.sockets)
    return caught.value


def test_one_numeric_connection_original_host_sni_and_no_ambient_state(monkeypatch):
    for key in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NETRC"):
        monkeypatch.setenv(key, "http://credential:secret@127.0.0.1/")
    harness = Harness(response(headers=[("Set-Cookie", "private=secret")]),
                      answers=("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"))
    result = harness.fetch()
    assert result.body == b'{"safe":true}'
    assert harness.dns == [("example.com", 443)]
    assert harness.connections == [("1.1.1.1", 443)]
    assert harness.sni == ["example.com"]
    assert harness.suppress_ragged_eofs is False
    assert harness.sockets[0][0] == (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    assert len(harness.stream.requests) == 1
    assert harness.stream.requests[0] == (
        "GET /path?a=1&b=2 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: %s\r\n"
        "Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
    ).encode("ascii") % IMMEDIATE_VISIT_USER_AGENT.encode("ascii")
    assert ("set-cookie", "private=secret") not in result.headers
    assert harness.stream.closed


def test_all_dns_answers_checked_before_any_socket():
    for answers in (("8.8.8.8", "::1"), ("8.8.8.8", "169.254.169.254"),
                    ("2606:4700:4700::1111", "fc00::1"), ("8.8.8.8", "bad")):
        harness = Harness(answers=answers)
        expect_reason(harness, "dns_disallowed")
        assert harness.sockets == []


def test_empty_dns_and_resolver_failure_are_finite():
    harness = Harness(answers=())
    expect_reason(harness, "dns_failed")
    def fail(_host, _port):
        raise RuntimeError("RAW_DNS_SECRET")
    harness.connector._resolver = fail
    error = expect_reason(harness, "dns_failed")
    assert "RAW_DNS_SECRET" not in repr(error)


@pytest.mark.parametrize("tls", [False, True])
def test_actual_peer_mismatch_rejected_before_get(tls):
    harness = Harness(response())
    if tls:
        harness.tls_peer = "1.1.1.1"
    else:
        harness.peer = "127.0.0.1"
    expect_reason(harness, "peer_mismatch")
    assert harness.stream.requests == []


def test_ipv6_numeric_pin_and_hostname_validation_required():
    harness = Harness(response(), answers=("2606:4700:4700::1111",))
    harness.fetch()
    assert harness.connections == [("2606:4700:4700::1111", 443, 0, 0)]
    assert harness.sockets[0][0][0] == socket.AF_INET6
    for attribute, value in (("verify_mode", ssl.CERT_NONE), ("check_hostname", False)):
        harness = Harness(response())
        setattr(harness.context, attribute, value)
        expect_reason(harness, "tls_failed")
        assert harness.stream.requests == []


@pytest.mark.parametrize("url", [
    "https://example.com/#", "http://example.com/a", "https://user@example.com/",
    "https://127.0.0.1/", "https://0x7f000001/", "https://example.com:444/",
    "https://example.com/a\\b", "https://example.com/a\tb", "https://localhost./",
    "https://example.com/" + "a" * 2030,
])
def test_url_policy_before_dns(url):
    harness = Harness(response())
    expect_reason(harness, "url_disallowed", url=url)
    assert harness.dns == []


@pytest.mark.parametrize("url,target", [
    ("https://example.com/%23", "/%23"),
    ("https://example.com/?", "/?"),
    ("https://example.com/A?b=2&a=1", "/A?b=2&a=1"),
    ("https://example.com/%zz", "/%zz"),
    ("https://example.com./", "/"),
])
def test_valid_canonical_wire_target_preserved(url, target):
    harness = Harness(response())
    harness.fetch(url)
    assert harness.stream.requests[0].startswith(("GET " + target + " HTTP/1.1\r\n").encode())


@pytest.mark.parametrize("status", [200, 301, 302, 400, 402, 403, 404, 500, 599])
def test_first_final_response_body_allowed_without_redirect_or_payment(status):
    harness = Harness(response(status=status, headers=[("Location", "http://127.0.0.1/secret")]))
    result = harness.fetch()
    assert result.status_code == status
    assert result.body == b'{"safe":true}'
    assert len(harness.stream.requests) == len(harness.connections) == 1


def test_informational_heads_consumed_and_upgrade_or_no_final_is_invalid():
    harness = Harness(b"HTTP/1.1 103 Early Hints\r\nLink: <https://other.test/>\r\n\r\n" + response())
    assert harness.fetch().status_code == 200
    for raw in (b"HTTP/1.1 101 Upgrade\r\n\r\n", b"HTTP/1.1 100 Continue\r\n\r\n"):
        expect_reason(Harness(raw), "http_invalid")


def test_header_limit_inclusive_complete_and_no_hidden_smaller_limit():
    base = response(body=b"x", headers=[("X-Padding", "")])
    padding = 32768 - (len(base) - 1)
    raw = response(body=b"x", headers=[("X-Padding", "a" * padding)])
    assert raw.index(b"\r\n\r\n") + 4 == 32768
    assert Harness(raw).fetch().body == b"x"
    expect_reason(Harness(response(body=b"x", headers=[("X-Padding", "a" * (padding + 1))])),
                  "headers_limit_exceeded")


def test_content_type_multiplicity_reaches_extractor_without_raw_other_headers():
    harness = Harness(response(headers=[("Content-Type", 'APPLICATION/JSON; charset="UTF-8"'),
                                        ("X-Secret", "discard-me")]))
    result = harness.fetch()
    assert [value for name, value in result.headers if name == "content-type"] == [
        "application/json", 'APPLICATION/JSON; charset="UTF-8"']
    assert not any(name == "x-secret" for name, _ in result.headers)


@pytest.mark.parametrize("headers", [
    [("Content-Encoding", "gzip")], [("Content-Encoding", "identity, gzip")],
    [("Content-Encoding", "identity"), ("Content-Encoding", "br")],
    [("Content-Encoding", "")],
])
def test_actual_encoding_checked_before_body(headers):
    harness = Harness(response(headers=headers))
    expect_reason(harness, "content_encoding_unsupported")
    assert harness.stream.response == b'{"safe":true}'


def test_identity_multiplicity_validated_without_silent_header_selection():
    harness = Harness(response(headers=[("Content-Encoding", "identity, IDENTITY"),
                                        ("Content-Encoding", "identity")]))
    assert harness.fetch().body == b'{"safe":true}'


@pytest.mark.parametrize("status,headers", [(206, []), (304, []), (200, [("Content-Range", "bytes 0-1/3")])])
def test_partial_is_inconclusive_without_body_read(status, headers):
    harness = Harness(response(status=status, headers=headers))
    error = expect_reason(harness, "partial_response")
    assert error.status_code == status
    assert harness.stream.response == b'{"safe":true}'


@pytest.mark.parametrize("length", [True, False])
def test_complete_body_limit_inclusive_and_actual_one_byte_over(length):
    body = b"a" * IMMEDIATE_VISIT_BODY_LIMIT_BYTES
    assert Harness(response(body, length=length)).fetch().body == body
    harness = Harness(response(body + b"b", length=length))
    expect_reason(harness, "body_limit_exceeded")
    if length:
        assert harness.stream.response == body + b"b"  # Declaration stops before body.


def test_chunked_complete_framing_exact_limit_and_trailers():
    body = b"x" * IMMEDIATE_VISIT_BODY_LIMIT_BYTES
    chunked = b"200000; note=\"allowed\\\"value\"\r\n" + body + b"\r\n0\r\nX-Discard: secret\r\n\r\n"
    harness = Harness(response(chunked, length=False, headers=[("Transfer-Encoding", "chunked")]))
    assert harness.fetch().body == body
    expect_reason(Harness(response(b"200001\r\n", length=False, headers=[("Transfer-Encoding", "chunked")])),
                  "body_limit_exceeded")


@pytest.mark.parametrize("body", [b"1\r\nx", b"1\r\nx\r\n", b"0\r\n", b"+1\r\nx\r\n0\r\n\r\n",
                                  b"1\r\nx\r\n0\r\nContent-Type: text/html\r\n\r\n"])
def test_chunked_missing_or_invalid_framing_is_incomplete(body):
    expect_reason(Harness(response(body, length=False, headers=[("Transfer-Encoding", "chunked")])),
                  "body_incomplete")


def test_length_truncation_empty_and_contradictory_framing():
    harness = Harness(response(b"x", length=False, headers=[("Content-Length", "2")]))
    expect_reason(harness, "body_incomplete")
    assert expect_reason(Harness(response(b"")), "body_empty").body_bytes == 0
    for fields in ([('Content-Length', '1'), ('Content-Length', '2')],
                   [('Content-Length', '1'), ('Transfer-Encoding', 'chunked')],
                   [('Content-Length', '+1')], [('Transfer-Encoding', 'gzip, chunked')]):
        expect_reason(Harness(response(b"x", length=False, headers=fields)), "http_invalid")


def test_equivalent_repeated_content_length_is_valid():
    assert Harness(response(b"x", headers=[("Content-Length", "01, 1")])).fetch().body == b"x"


@pytest.mark.parametrize("field,delay", [("dns_elapsed", 3.0), ("connect_elapsed", 3.0), ("tls_elapsed", 3.0)])
def test_connection_budget_deadline_is_exclusive_and_includes_dns(field, delay):
    harness = Harness(response())
    setattr(harness, field, delay)
    expect_reason(harness, "fetch_timeout")
    assert not harness.sockets or harness.stream.requests == []


def test_dns_connect_tls_share_connection_and_total_deadlines():
    harness = Harness(response())
    harness.dns_elapsed = 1.0
    harness.connect_elapsed = 1.0
    harness.tls_elapsed = 1.0
    expect_reason(harness, "fetch_timeout")
    assert harness.stream.timeouts[:2] == [2.0, 1.0]


def test_head_deadline_and_total_last_body_byte_boundary():
    harness = Harness(response())
    def head_deadline(_stream, _maximum):
        harness.clock.now = 10.0
    harness.on_recv = head_deadline
    expect_reason(harness, "fetch_timeout")
    for finish, expected in ((11.999999, True), (12.0, False)):
        harness = Harness(response())
        def final_byte(stream, maximum):
            if stream.response == b'{"safe":true}':
                harness.clock.now = finish
        harness.on_recv = final_byte
        if expected:
            assert harness.fetch().body == b'{"safe":true}'
        else:
            expect_reason(harness, "fetch_timeout")


def test_total_budget_starts_at_dns_not_body():
    harness = Harness(response())
    harness.dns_elapsed = 2.0
    def body_deadline(stream, maximum):
        if stream.response == b'{"safe":true}':
            harness.clock.now = 12.0
    harness.on_recv = body_deadline
    expect_reason(harness, "fetch_timeout")


@pytest.mark.parametrize("failure,reason", [(socket.timeout("RAW_PRIVATE"), "fetch_timeout"),
                                            (OSError("RAW_PRIVATE"), "connection_failed")])
def test_one_failed_connection_does_not_retry_and_error_text_is_finite(failure, reason):
    harness = Harness(response())
    harness.connect_error = failure
    error = expect_reason(harness, reason)
    assert len(harness.connections) == 1
    assert "RAW_PRIVATE" not in repr(error)


def test_tls_error_is_finite_and_closes_socket():
    harness = Harness(response())
    harness.tls_error = ssl.SSLError("PRIVATE_CERTIFICATE")
    error = expect_reason(harness, "tls_failed")
    assert "PRIVATE_CERTIFICATE" not in repr(error)


@pytest.mark.parametrize("stage,expected", [
    ("connect", "connection_failed"), ("tls", "tls_failed"),
    ("body", "body_incomplete"), ("dns", "dns_failed"),
    ("url", "url_disallowed"), ("unexpected", "http_invalid"),
])
def test_public_fetch_errors_detach_private_exception_graph(stage, expected, monkeypatch):
    secret = "RAW_SECRET_BODY_HEADER_EXCEPTION"
    harness = Harness(response(secret.encode(), length=False))
    url = "https://example.com/"
    if stage == "connect":
        harness.connect_error = OSError(secret)
    elif stage == "tls":
        harness.tls_error = ssl.SSLError(secret)
    elif stage == "body":
        harness.eof_error = ssl.SSLError(secret)
    elif stage == "dns":
        def resolver(_host, _port):
            raise RuntimeError(secret)
        harness.connector._resolver = resolver
    elif stage == "url":
        from ln_church_agent import immediate_visit_contract
        def reject(_url):
            raise ValueError(secret)
        monkeypatch.setattr(immediate_visit_contract, "validate_endpoint_url", reject)
    else:
        def fail(_stream, _maximum):
            raise RuntimeError(secret)
        harness.on_recv = fail
    error = expect_reason(harness, expected, url=url)
    assert error.__context__ is None
    assert error.__cause__ is None
    assert set(vars(error)) == {"reason", "status_code", "body_bytes"}
    assert secret not in repr(vars(error)) + repr(error.args)
    if stage == "body":
        assert error.status_code == 200


def test_body_and_headers_are_not_generic_serialization_or_error_surfaces(caplog, capsys):
    marker = "DO_NOT_LOG_PRIVATE_BODY_OR_HEADER"
    result = Harness(response(marker.encode(), headers=[("Content-Type", marker)])).fetch()
    observations = [repr(result), str(result)]
    for operation in (lambda: vars(result), lambda: dataclasses.asdict(result), lambda: pickle.dumps(result)):
        try:
            observations.append(repr(operation()))
        except Exception as error:
            observations.append(repr(error))
    assert marker not in "\n".join(observations) + caplog.text + capsys.readouterr().out


def test_new_scope_fixed_budgets_and_old_body_zero_manifest_conditions_preserved():
    harness = Harness(response())
    assert harness.connector.fetch("https://example.com/", scope=FetchScope.IMMEDIATE_VISIT).body
    with pytest.raises(ValueError, match="fixed"):
        harness.connector.fetch("https://example.com/", scope=FetchScope.IMMEDIATE_VISIT,
                                timeouts=FetchTimeouts(3, 10, 25))
    harness = Harness(response(b"must-remain-unread"))
    assert harness.connector.fetch_target("https://example.com/").body == b""
    assert harness.stream.response == b"must-remain-unread"
    harness = Harness(response(b"must-remain-unread", status=404))
    assert harness.connector.fetch_manifest("https://example.com/").body == b""
    assert harness.stream.response == b"must-remain-unread"
    harness = Harness(response(b"a" * 32768))
    assert len(harness.connector.fetch_manifest("https://example.com/").body) == 32768
    with pytest.raises(NetworkFetchError, match="response_too_large"):
        Harness(response(b"a" * 32769)).connector.fetch_manifest("https://example.com/")
