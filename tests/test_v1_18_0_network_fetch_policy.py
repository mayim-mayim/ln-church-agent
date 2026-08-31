import dataclasses
import hashlib
import ipaddress
import json
import logging
import pickle
from pathlib import Path
import socket
import ssl
import sys

import pytest

from ln_church_agent.network_fetch import (
    ControlledHTTPSConnector,
    FetchScope,
    IANA_IPV6_SNAPSHOT_PROVENANCE,
    NetworkFetchError,
    _FORBIDDEN_HOST_SUFFIXES,
    _IANA_V6_ALLOCATED_GLOBAL_UNICAST,
    _IANA_V6_SPECIAL_PURPOSE_SNAPSHOT_ROWS,
    _address_is_allowed,
    _canonical_https_url,
    _parse_response_head,
    _resolve_public_addresses,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = (
    ROOT
    / "ln_church_agent"
    / "contracts"
    / "v18-scheduled-http-get-batch-contract-v1.json"
)


@pytest.mark.parametrize(
    "address",
    [
        "0.0.0.0",
        "10.0.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "192.0.2.1",
        "192.168.1.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "240.0.0.1",
        "::",
        "::1",
        "::ffff:127.0.0.1",
        "64:ff9b::7f00:1",
        "64:ff9b:1::1",
        "100:0:0:1::1",
        "2000::1",
        "2001:5::1",
        "2001:db8::1",
        "2002:0808:0808::1",
        "3fff::1",
        "4000::1",
        "5f00::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
    ],
)
def test_explicit_rejected_address_classes_are_version_independent(address):
    assert _address_is_allowed(address) is False


@pytest.mark.parametrize(
    "address",
    [
        "8.8.8.8",
        "1.1.1.1",
        "2606:4700:4700::1111",
        "2001:1::1",
        "2001:1::3",
        "2620:4f:8000::1",
    ],
)
def test_global_unicast_examples_are_allowed(address):
    assert _address_is_allowed(address) is True


def test_pinned_iana_ipv6_snapshot_provenance_and_normalized_table_digest():
    assert dict(IANA_IPV6_SNAPSHOT_PROVENANCE) == {
        "global_unicast_registry_url": (
            "https://www.iana.org/assignments/ipv6-unicast-address-assignments/"
            "ipv6-unicast-address-assignments.xml"
        ),
        "global_unicast_last_updated": "2025-10-10",
        "global_unicast_input_format": "IANA XML",
        "global_unicast_raw_sha256": (
            "22f9a545e020ea6b9adea9ea0276f3157e32c838682459a45bfe7760de0aefc3"
        ),
        "special_purpose_registry_url": (
            "https://www.iana.org/assignments/iana-ipv6-special-registry/"
            "iana-ipv6-special-registry.xml"
        ),
        "special_purpose_last_updated": "2025-10-09",
        "special_purpose_input_format": "IANA XML",
        "special_purpose_raw_sha256": (
            "c17f4380ba84fb2160dae82ebfd8bd155a5853cfab624ed3a9fd251638a8be02"
        ),
        "normalized_prefix_table_sha256": (
            "054b2bc053c771aedc1050f37a70176c4a2a8dc06f430453192d47890b2aba76"
        ),
    }
    lines = [
        "GLOBAL|%s|ALLOCATED" % network.compressed
        for network in _IANA_V6_ALLOCATED_GLOBAL_UNICAST
    ]
    lines.extend(
        "SPECIAL|%s|%s|%s|%s|%s" % row
        for row in _IANA_V6_SPECIAL_PURPOSE_SNAPSHOT_ROWS
    )
    normalized = ("\n".join(lines) + "\n").encode("ascii")
    assert hashlib.sha256(normalized).hexdigest() == (
        "054b2bc053c771aedc1050f37a70176c4a2a8dc06f430453192d47890b2aba76"
    )


def test_mixed_dns_answer_rejects_the_whole_set():
    def resolver(host, port):
        assert (host, port) == ("example.com", 443)
        return ["8.8.8.8", "127.0.0.1"]

    with pytest.raises(NetworkFetchError, match="^policy_rejected$"):
        _resolve_public_addresses("example.com", resolver=resolver, timeout=0.1)


def test_mixed_valid_and_invalid_ipv6_answer_set_is_rejected_before_socket():
    with pytest.raises(NetworkFetchError, match="^policy_rejected$"):
        _resolve_public_addresses(
            "example.com",
            resolver=lambda _host, _port: [
                "2606:4700:4700::1111",
                "5f00::1",
            ],
            timeout=0.1,
        )


def test_dns_answers_are_deduplicated_and_deterministically_sorted():
    value = _resolve_public_addresses(
        "example.com",
        resolver=lambda _host, _port: ["8.8.8.8", "1.1.1.1", "8.8.8.8"],
        timeout=0.1,
    )
    assert value == ("1.1.1.1", "8.8.8.8")


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/a",
        "https://EXAMPLE.com/a",
        "https://example.com:443/a",
        "https://user@example.com/a",
        "https://127.0.0.1/a",
        "https://example.com",
        "https://example.com/a#fragment",
        "https://example.com/../a",
        "https://example.com/a\\b",
        "https://example.com/é",
    ],
)
def test_noncanonical_or_non_https_url_is_rejected_without_rewrite(url):
    with pytest.raises(NetworkFetchError, match="^policy_rejected$"):
        _canonical_https_url(url)


def test_canonical_url_secret_is_slotted_redacted_and_transport_only(
    caplog, capsys
):
    token = "SIGNED_QUERY_UNIQUE_SENTINEL_5fcb36b6"
    raw = "https://example.com/a%2Fb?Policy=opaque&Signature=" + token
    parsed = _canonical_https_url(raw)
    assert parsed.transport_request_target() == (
        "/a%2Fb?Policy=opaque&Signature=" + token
    )
    assert not hasattr(parsed, "__dict__")
    observations = [repr(parsed), str(parsed)]
    for operation in (
        lambda: dataclasses.asdict(parsed),
        lambda: vars(parsed),
        lambda: pickle.dumps(parsed),
        lambda: json.dumps({"url": parsed}),
        lambda: setattr(parsed, "hostname", token),
    ):
        try:
            observations.append(repr(operation()))
        except Exception as error:
            observations.extend((type(error).__name__, str(error), repr(error)))
    try:
        raise ValueError(parsed)
    except ValueError as error:
        observations.extend((str(error), repr(error)))
    logger = logging.getLogger("ln_church_agent.v18.secret_surface")
    with caplog.at_level(logging.INFO):
        logger.info("parsed signed URL: %r", parsed)
    print(parsed)
    print(repr(parsed), file=sys.stderr)
    captured = capsys.readouterr()
    observations.extend((caplog.text, captured.out, captured.err))
    assert token not in "\n".join(observations)
    assert raw not in "\n".join(observations)


def test_response_head_rejects_duplicate_boundary_headers():
    raw = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 1\r\n"
        b"Content-Length: 1\r\n\r\n"
    )
    with pytest.raises(NetworkFetchError, match="^protocol_error$"):
        _parse_response_head(raw)


class _FakeRawSocket:
    def __init__(self, peer="8.8.8.8"):
        self.peer = peer
        self.connected = None
        self.closed = False

    def settimeout(self, _value):
        pass

    def connect(self, endpoint):
        self.connected = endpoint

    def getpeername(self):
        return (self.peer, 443)

    def close(self):
        self.closed = True


class _FakeTLSSocket(_FakeRawSocket):
    def __init__(self, response, peer="8.8.8.8"):
        super().__init__(peer)
        self.response = bytearray(response)
        self.sent = b""

    def sendall(self, value):
        self.sent += value

    def recv(self, maximum):
        if not self.response:
            return b""
        value = bytes(self.response[:maximum])
        del self.response[:maximum]
        return value


class _FakeContext:
    verify_mode = ssl.CERT_REQUIRED
    check_hostname = True

    def __init__(self, tls):
        self.tls = tls
        self.server_hostname = None

    def wrap_socket(self, _raw, *, server_hostname):
        self.server_hostname = server_hostname
        return self.tls


def _connector(response, *, peer="8.8.8.8"):
    raw = _FakeRawSocket(peer)
    tls = _FakeTLSSocket(response, peer)
    context = _FakeContext(tls)
    connector = ControlledHTTPSConnector(
        resolver=lambda _host, _port: ["8.8.8.8"],
        socket_factory=lambda *_args: raw,
        ssl_context_factory=lambda: context,
    )
    return connector, raw, tls, context


@pytest.mark.parametrize("suffix", ("nip.io", "sslip.io", "xip.io"))
def test_public_dynamic_dns_suffix_reaches_normal_pinned_https_path(suffix):
    hostname = "controlled." + suffix
    resolver_calls = []
    raw = _FakeRawSocket("8.8.8.8")
    tls = _FakeTLSSocket(
        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
        "8.8.8.8",
    )
    context = _FakeContext(tls)

    def resolver(host, port):
        resolver_calls.append((host, port))
        assert (host, port) == (hostname, 443)
        return ["8.8.8.8"]

    connector = ControlledHTTPSConnector(
        resolver=resolver,
        socket_factory=lambda *_args: raw,
        ssl_context_factory=lambda: context,
    )

    result = connector.fetch_target("https://%s/health" % hostname)

    assert result.status_code == 204
    assert result.peer_address == "8.8.8.8"
    assert resolver_calls == [(hostname, 443)]
    assert raw.connected == ("8.8.8.8", 443)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert context.server_hostname == hostname
    assert b"GET /health HTTP/1.1\r\n" in tls.sent
    assert ("Host: %s\r\n" % hostname).encode("ascii") in tls.sent
    assert b"Accept-Encoding: identity\r\n" in tls.sent
    assert b"Authorization:" not in tls.sent
    assert b"Cookie:" not in tls.sent
    assert b"Proxy-Authorization:" not in tls.sent


@pytest.mark.parametrize("suffix", ("nip.io", "sslip.io", "xip.io"))
@pytest.mark.parametrize(
    "answers",
    (
        pytest.param(["10.0.0.1"], id="private"),
        pytest.param(["168.63.129.16"], id="metadata"),
        pytest.param(["8.8.8.8", "127.0.0.1"], id="mixed-invalid"),
    ),
)
def test_public_dynamic_dns_suffix_invalid_answer_set_rejected_before_socket(
    suffix, answers
):
    hostname = "controlled." + suffix
    resolver_calls = []
    socket_calls = []

    def resolver(host, port):
        resolver_calls.append((host, port))
        assert (host, port) == (hostname, 443)
        return answers

    connector = ControlledHTTPSConnector(
        resolver=resolver,
        socket_factory=lambda *_args: socket_calls.append(_args),
    )

    with pytest.raises(NetworkFetchError, match="^policy_rejected$"):
        connector.fetch_target("https://%s/health" % hostname)

    assert resolver_calls == [(hostname, 443)]
    assert socket_calls == []


def test_dynamic_dns_change_preserves_every_other_forbidden_hostname_suffix():
    assert _FORBIDDEN_HOST_SUFFIXES == (
        ".localhost",
        ".local",
        ".localdomain",
        ".internal",
        ".home.arpa",
        ".lan",
        ".corp",
        ".intranet",
        ".private",
        ".home",
    )
    for suffix in _FORBIDDEN_HOST_SUFFIXES:
        with pytest.raises(NetworkFetchError, match="^policy_rejected$"):
            _canonical_https_url("https://controlled%s/health" % suffix)


def test_target_connection_pins_peer_and_preserves_sni_host_and_headers():
    connector, raw, tls, context = _connector(
        b"HTTP/1.1 204 No Content\r\nContent-Length: 9999\r\n\r\nSECRET-BODY"
    )
    result = connector.fetch_target("https://example.com/health?mode=full")
    assert result.status_code == 204
    assert result.body == b""
    assert raw.connected == ("8.8.8.8", 443)
    assert context.server_hostname == "example.com"
    assert b"GET /health?mode=full HTTP/1.1\r\n" in tls.sent
    assert b"Host: example.com\r\n" in tls.sent
    assert b"User-Agent: LN-Church-Scheduled-GET/1.0\r\n" in tls.sent
    assert b"Accept-Encoding: identity\r\n" in tls.sent
    assert b"Authorization:" not in tls.sent
    assert b"Cookie:" not in tls.sent
    assert b"Proxy-Authorization:" not in tls.sent


def test_connected_peer_mismatch_is_rejected_before_http_write():
    connector, _raw, tls, _context = _connector(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", peer="1.1.1.1"
    )
    # DNS pinned 8.8.8.8 while the socket reports 1.1.1.1.
    with pytest.raises(NetworkFetchError, match="^policy_rejected$"):
        connector.fetch_target("https://example.com/a")
    assert tls.sent == b""


def test_non_200_manifest_reads_zero_body_bytes():
    connector, _raw, tls, _context = _connector(
        b"HTTP/1.1 503 Busy\r\nContent-Length: 12\r\n\r\nSECRET-BODY!"
    )
    response = connector.fetch_manifest("https://example.com/release?Policy=x")
    assert response.status_code == 503
    assert response.body == b""
    assert tls.response == bytearray(b"SECRET-BODY!")


def test_policy_first_503_plus_gzip_is_encoding_error_with_zero_body_read():
    connector, _raw, tls, _context = _connector(
        b"HTTP/1.1 503 Busy\r\nContent-Encoding: gzip\r\nContent-Length: 6\r\n\r\nSECRET"
    )
    with pytest.raises(NetworkFetchError, match="^encoding_unsupported$"):
        connector.fetch_manifest("https://example.com/release?Policy=x")
    assert tls.response == bytearray(b"SECRET")


def test_manifest_body_limit_is_enforced_before_declared_body_read():
    connector, _raw, _tls, _context = _connector(
        b"HTTP/1.1 200 OK\r\nContent-Length: 32769\r\n\r\n"
    )
    with pytest.raises(NetworkFetchError, match="^response_too_large$"):
        connector.fetch_manifest("https://example.com/release?Policy=x")


def test_oversized_header_is_rejected_during_read():
    connector, _raw, _tls, _context = _connector(
        b"HTTP/1.1 200 OK\r\nX-Fill: " + b"a" * 32768 + b"\r\n\r\n"
    )
    with pytest.raises(NetworkFetchError, match="^response_too_large$"):
        connector.fetch_target("https://example.com/a")


def _canonical_network_vectors():
    fixture = json.loads(FIXTURE_PATH.read_bytes())
    return tuple(fixture["network_fetch_policy"]["required_test_vectors"])


SDK_FETCH_SCOPES = (
    FetchScope.MANIFEST_RELEASE,
    FetchScope.TARGET,
)
_DEFAULT_HEAD = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n"
_DEFAULT_RESPONSE = _DEFAULT_HEAD + b"{}"
_REDIRECT_HEAD = (
    b"HTTP/1.1 302 Found\r\n"
    b"Location: https://other.invalid/a\r\n"
    b"Content-Length: 0\r\n\r\n"
)
_GZIP_200_HEAD = (
    b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 6\r\n\r\n"
)
_GZIP_503_HEAD = (
    b"HTTP/1.1 503 Busy\r\nContent-Encoding: gzip\r\nContent-Length: 6\r\n\r\n"
)
_OVERSIZED_BODY_HEAD = b"HTTP/1.1 200 OK\r\nContent-Length: 32769\r\n\r\n"
_CHUNKED_HEAD = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
_FALSE_LENGTH_HEAD = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n"


def _matrix_oracle(vector, scope):
    counts = {"resolver": 1, "connect": 1, "send": 1, "read": 0}
    expected_result = "status_200"
    if vector in {
        "IPV4_RESERVED",
        "IPV6_RESERVED",
        "MIXED_VALID_INVALID_ANSWER_SET",
        "IPV4_MAPPED_IPV6",
    }:
        counts.update(connect=0, send=0, read=0)
        expected_result = "error:policy_rejected"
    elif vector == "CONNECTED_PEER_MISMATCH":
        counts.update(send=0, read=0)
        expected_result = "error:policy_rejected"
    elif vector == "TLS_HOSTNAME_MISMATCH":
        counts.update(send=0, read=0)
        expected_result = "error:tls_error"
    elif vector == "REDIRECT":
        counts["read"] = len(_REDIRECT_HEAD)
        expected_result = "status_302"
    elif vector == "OVERSIZED_HEADERS_BODY":
        counts["read"] = (
            len(_OVERSIZED_BODY_HEAD)
            if scope is FetchScope.MANIFEST_RELEASE
            else 32768
        )
        expected_result = "error:response_too_large"
    elif vector == "SLOW_HEAD_BODY":
        counts["read"] = (
            len(_DEFAULT_HEAD) + 1
            if scope is FetchScope.MANIFEST_RELEASE
            else 1
        )
        expected_result = "error:timeout"
    elif vector == "UNSUPPORTED_ENCODING":
        counts["read"] = len(_GZIP_200_HEAD)
        expected_result = "error:encoding_unsupported"
    elif vector == "NON_200_RETRYABLE_STATUS_WITH_UNSUPPORTED_ENCODING":
        counts["read"] = len(_GZIP_503_HEAD)
        expected_result = "error:encoding_unsupported"
    elif vector == "CHUNKED_BODY_OVERFLOW":
        counts["read"] = len(_CHUNKED_HEAD)
        if scope is FetchScope.MANIFEST_RELEASE:
            counts["read"] += 1
            expected_result = "error:response_too_large"
    elif vector == "FALSE_CONTENT_LENGTH":
        counts["read"] = len(_FALSE_LENGTH_HEAD)
        if scope is FetchScope.MANIFEST_RELEASE:
            counts["read"] += 2
            expected_result = "error:protocol_error"
    else:
        counts["read"] = len(_DEFAULT_HEAD)
        if scope is FetchScope.MANIFEST_RELEASE:
            counts["read"] += 1
    if vector == "DNS_REBINDING":
        # The first production attempt succeeds with its pinned answer.  A
        # distinct second attempt must resolve afresh and reject the changed
        # whole answer set before opening another socket.
        counts["resolver"] = 2
        expected_result = "status_200_then_error:policy_rejected"
    return {
        "vector": vector,
        "scope": scope.value,
        "production_entrypoint": "ControlledHTTPSConnector.fetch",
        "expected_result": expected_result,
        "expected_counts": counts,
    }


NETWORK_VECTOR_MATRIX = tuple(
    _matrix_oracle(vector, scope)
    for vector in _canonical_network_vectors()
    for scope in SDK_FETCH_SCOPES
)


class _MatrixRawSocket:
    def __init__(self, counters, *, peer="8.8.8.8"):
        self.counters = counters
        self.peer = peer
        self.connected = None
        self.closed = False

    def settimeout(self, _value):
        pass

    def connect(self, endpoint):
        self.counters["connect"] += 1
        self.connected = endpoint

    def getpeername(self):
        return (self.peer, 443)

    def close(self):
        self.closed = True


class _MatrixTLSSocket(_MatrixRawSocket):
    def __init__(self, counters, response, *, peer="8.8.8.8", behavior=None):
        super().__init__(counters, peer=peer)
        self.response = bytearray(response)
        self.behavior = behavior
        self.sent = b""
        self.delivered = bytearray()

    def sendall(self, value):
        self.counters["send"] += 1
        self.sent += value

    def recv(self, maximum):
        self.counters["read"] += 1
        if self.behavior == "timeout_head":
            raise socket.timeout()
        if (
            self.behavior == "timeout_body"
            and b"\r\n\r\n" in self.delivered
        ):
            raise socket.timeout()
        if not self.response:
            return b""
        value = bytes(self.response[:maximum])
        del self.response[:maximum]
        self.delivered.extend(value)
        return value


class _MatrixContext:
    verify_mode = ssl.CERT_REQUIRED
    check_hostname = True

    def __init__(self, tls, *, hostname_mismatch=False):
        self.tls = tls
        self.hostname_mismatch = hostname_mismatch
        self.server_hostname = None

    def wrap_socket(self, _raw, *, server_hostname):
        self.server_hostname = server_hostname
        if self.hostname_mismatch:
            raise ssl.CertificateError("certificate hostname mismatch")
        return self.tls


def _matrix_response_and_behavior(vector, scope):
    if vector == "REDIRECT":
        return _REDIRECT_HEAD, None
    if vector == "OVERSIZED_HEADERS_BODY":
        if scope is FetchScope.MANIFEST_RELEASE:
            return _OVERSIZED_BODY_HEAD, None
        return (
            b"HTTP/1.1 200 OK\r\nX-Fill: "
            + (b"a" * 32768)
            + b"\r\n\r\n",
            None,
        )
    if vector == "SLOW_HEAD_BODY":
        return _DEFAULT_RESPONSE, (
            "timeout_body"
            if scope is FetchScope.MANIFEST_RELEASE
            else "timeout_head"
        )
    if vector == "UNSUPPORTED_ENCODING":
        return _GZIP_200_HEAD + b"SECRET", None
    if vector == "NON_200_RETRYABLE_STATUS_WITH_UNSUPPORTED_ENCODING":
        return _GZIP_503_HEAD + b"SECRET", None
    if vector == "CHUNKED_BODY_OVERFLOW":
        return _CHUNKED_HEAD + b"8001\r\n", None
    if vector == "FALSE_CONTENT_LENGTH":
        return _FALSE_LENGTH_HEAD + b"x", None
    return _DEFAULT_RESPONSE, None


def _matrix_dns_answers(vector, resolver_call):
    if vector == "IPV4_RESERVED":
        return ["127.0.0.1"]
    if vector == "IPV6_RESERVED":
        return ["5f00::1"]
    if vector == "MIXED_VALID_INVALID_ANSWER_SET":
        return ["8.8.8.8", "100:0:0:1::1"]
    if vector == "IPV4_MAPPED_IPV6":
        return ["::ffff:8.8.8.8"]
    if vector == "DNS_REBINDING" and resolver_call > 1:
        return ["127.0.0.1"]
    return ["8.8.8.8"]


def test_network_vector_matrix_is_machine_readable_and_fixture_driven():
    fixture = json.loads(FIXTURE_PATH.read_bytes())
    vectors = fixture["network_fetch_policy"]["required_test_vectors"]
    assert fixture["network_fetch_policy"][
        "required_test_vectors_apply_to_each_scope"
    ] is True
    assert len(vectors) == 21
    assert len(NETWORK_VECTOR_MATRIX) == 42
    assert [row["vector"] for row in NETWORK_VECTOR_MATRIX[::2]] == vectors
    assert {row["scope"] for row in NETWORK_VECTOR_MATRIX} == {
        "OFFICIAL_SDK_MANIFEST_RELEASE",
        "OFFICIAL_SDK_TARGET",
    }
    assert {row["production_entrypoint"] for row in NETWORK_VECTOR_MATRIX} == {
        "ControlledHTTPSConnector.fetch"
    }
    encoded = json.dumps(NETWORK_VECTOR_MATRIX, sort_keys=True)
    assert json.loads(encoded) == list(NETWORK_VECTOR_MATRIX)


@pytest.mark.parametrize(
    "row",
    NETWORK_VECTOR_MATRIX,
    ids=lambda row: "%s-%s" % (row["vector"], row["scope"]),
)
def test_fixture_network_vector_matrix_through_production_fetch(
    row, monkeypatch, tmp_path, caplog
):
    vector = row["vector"]
    scope = FetchScope(row["scope"])
    counters = {"resolver": 0, "connect": 0, "send": 0, "read": 0}
    response, behavior = _matrix_response_and_behavior(vector, scope)
    peer = "1.1.1.1" if vector == "CONNECTED_PEER_MISMATCH" else "8.8.8.8"
    raw = _MatrixRawSocket(counters, peer=peer)
    tls = _MatrixTLSSocket(
        counters,
        response,
        peer=peer,
        behavior=behavior,
    )
    context = _MatrixContext(
        tls,
        hostname_mismatch=vector == "TLS_HOSTNAME_MISMATCH",
    )

    def resolver(host, port):
        counters["resolver"] += 1
        assert (host, port) == ("example.com", 443)
        return _matrix_dns_answers(vector, counters["resolver"])

    connector = ControlledHTTPSConnector(
        resolver=resolver,
        socket_factory=lambda *_args: raw,
        ssl_context_factory=lambda: context,
    )
    ambient_secrets = {
        "HTTP_PROXY": "http://proxy.invalid:3128/PROXY_SENTINEL",
        "HTTPS_PROXY": "http://proxy.invalid:3128/PROXY_SENTINEL",
        "ALL_PROXY": "http://proxy.invalid:3128/PROXY_SENTINEL",
        "HTTP_AUTHORIZATION": "Bearer DEFAULT_AUTH_SENTINEL",
        "AUTHORIZATION": "Bearer DEFAULT_AUTH_SENTINEL",
        "PROXY_AUTHORIZATION": "Basic PROXY_AUTH_SENTINEL",
        "COOKIE": "session=COOKIE_SENTINEL",
    }
    for name, value in ambient_secrets.items():
        monkeypatch.setenv(name, value)
    netrc_path = tmp_path / "ambient.netrc"
    netrc_path.write_text(
        "machine example.com login NETRC_SENTINEL password NETRC_SECRET\n",
        encoding="ascii",
    )
    monkeypatch.setenv("NETRC", str(netrc_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    signed_token = "MATRIX_SIGNED_QUERY_SENTINEL_8b4cda"
    raw_url = "https://example.com/vector?Signature=" + signed_token

    observed_result = None
    with caplog.at_level(logging.DEBUG):
        try:
            result = connector.fetch(raw_url, scope=scope)
        except NetworkFetchError as error:
            observed_result = "error:" + error.code
            assert signed_token not in str(error)
            assert signed_token not in repr(error)
        else:
            observed_result = "status_%d" % result.status_code
            assert result.body == (
                b"{}"
                if scope is FetchScope.MANIFEST_RELEASE
                and result.status_code == 200
                else b""
            )
            if vector == "DNS_REBINDING":
                try:
                    connector.fetch(raw_url, scope=scope)
                except NetworkFetchError as error:
                    observed_result += "_then_error:" + error.code
                    assert signed_token not in str(error)
                    assert signed_token not in repr(error)
                else:  # pragma: no cover - the matrix oracle requires rejection
                    pytest.fail("rebinding answer set was accepted")
    assert observed_result == row["expected_result"]
    assert counters == row["expected_counts"]
    assert caplog.text.find(signed_token) == -1
    if counters["connect"]:
        assert raw.connected == ("8.8.8.8", 443)
    if vector == "DNS_REBINDING":
        assert counters["resolver"] == 2
        assert counters["connect"] == 1
    if vector == "TLS_CANONICAL_HOST_SNI_CERTIFICATE_AND_HOST":
        assert context.server_hostname == "example.com"
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True
        assert b"Host: example.com\r\n" in tls.sent
    for secret in (
        b"PROXY_SENTINEL",
        b"DEFAULT_AUTH_SENTINEL",
        b"PROXY_AUTH_SENTINEL",
        b"COOKIE_SENTINEL",
        b"NETRC_SENTINEL",
        b"NETRC_SECRET",
    ):
        assert secret not in tls.sent
    assert b"Authorization:" not in tls.sent
    assert b"Proxy-Authorization:" not in tls.sent
    assert b"Cookie:" not in tls.sent
    if vector == "SIGNED_QUERY_LOG_REDACTION":
        assert tls.sent.count(signed_token.encode("ascii")) == 1
        assert (
            b"GET /vector?Signature="
            + signed_token.encode("ascii")
            + b" HTTP/1.1\r\n"
        ) in tls.sent
