"""P0-3 Inspect/MCP SSRF and keyless-boundary acceptance tests.

Every transport interaction in this module is fake.  Literal documentation
targets are policy inputs only; no socket may be opened by this suite.
"""

import base64
import copy
import gzip
import io
import inspect
import json
import os
import socket
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import requests

from ln_church_agent import inspect_transport as transport
from ln_church_agent import redaction as redaction_policy
from ln_church_agent import cli as cli_module
from ln_church_agent.cli import (
    inspect_url,
    _extract_settlement_options,
    _public_x402_pay_to,
)
from ln_church_agent.integrations import mcp_inspect
from ln_church_agent.payment_contract import sha256_prefixed
from ln_church_agent.redaction import (
    QUERY_REDACTION,
    redact_inspect_public_url,
    redact_remote_metadata,
)


PUBLIC_V4 = "8.8.8.8"
PUBLIC_V4_FALLBACK = "8.8.4.4"
PUBLIC_V6 = "2001:4860:4860::8888"
RAW_QUERY_SECRET = "DUMMY_QUERY_SECRET_P0_3"
RAW_EXCEPTION_SECRET = "DUMMY_EXCEPTION_SECRET_P0_3"
RAW_RESPONSE_SECRET = "DUMMY_RESPONSE_SECRET_P0_3"


def _fully_percent_encode(value, *, double=False):
    prefix = "%25" if double else "%"
    return "".join(prefix + format(byte, "02X") for byte in value.encode("utf-8"))


class _FakeRaw:
    def __init__(self, chunks):
        self._chunks = list(chunks)
        self.read_calls = []
        self.decode_content = True

    def read(self, amount, decode_content=False):
        self.read_calls.append((amount, decode_content))
        if not self._chunks:
            return b""
        outcome = self._chunks[0]
        if isinstance(outcome, BaseException):
            self._chunks.pop(0)
            raise outcome
        if len(outcome) <= amount:
            return self._chunks.pop(0)
        self._chunks[0] = outcome[amount:]
        return outcome[:amount]


class _FakeResponse:
    def __init__(
        self,
        status_code=200,
        *,
        headers=None,
        content=b"",
        url="https://public.example/",
        chunks=None,
    ):
        self.status_code = status_code
        self.headers = dict(headers or {})
        self.url = url
        self._content = content
        self._content_consumed = True
        self._chunks = list(chunks) if chunks is not None else [content]
        self.raw = _FakeRaw(self._chunks)
        self.closed = False

    @property
    def content(self):
        return self._content

    def json(self):
        return json.loads(self._content.decode("utf-8"))

    def iter_content(self, chunk_size=1, decode_unicode=False):
        del chunk_size, decode_unicode
        yield from self._chunks

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def _no_real_network(monkeypatch):
    """Fail loudly if a test forgets to install its fake resolver/transport."""

    def forbidden_getaddrinfo(*_args, **_kwargs):
        raise AssertionError("P0-3 focused tests must not perform real DNS")

    def forbidden_create_connection(*_args, **_kwargs):
        raise AssertionError("P0-3 focused tests must not open real sockets")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden_getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", forbidden_create_connection)


def _public_resolver(monkeypatch, addresses=(PUBLIC_V4,)):
    calls = []

    def resolve(host, port):
        calls.append((host, port))
        return tuple(addresses)

    monkeypatch.setattr(transport, "_resolve_addresses", resolve)
    return calls


def _fake_exchange(monkeypatch, responses):
    """Install a sequenced private transport seam and return captured calls."""

    calls = []
    queue = list(responses)

    def exchange(target, address, method, timeout, body=None):
        calls.append(
            {
                "target": target,
                "address": address,
                "method": method,
                "timeout": timeout,
                "body": body,
            }
        )
        if not queue:
            raise AssertionError("unexpected transport call")
        outcome = queue.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        outcome.url = target.url
        return outcome

    monkeypatch.setattr(transport, "_exchange_once", exchange)
    return calls


def _fake_observation_exchange(monkeypatch, outcomes):
    """Install the single-attempt observation seam and capture POST calls."""
    calls = []
    queue = list(outcomes)

    def exchange(target, address, timeout, body):
        calls.append({
            "target": target,
            "address": address,
            "method": "POST",
            "timeout": timeout,
            "body": body,
        })
        if not queue:
            raise AssertionError("unexpected observation transport call")
        outcome = queue.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        if isinstance(outcome, _FakeResponse):
            outcome.close()
            return int(outcome.status_code)
        return int(outcome)

    monkeypatch.setattr(transport, "_exchange_observation_once", exchange)
    return calls


def _safe_observation_input(url="https://public.example/resource"):
    return {
        "url": url,
        "method": "GET",
        "status_code": 402,
        "settlement_rails_detected": ["x402"],
        "commerce_intent": "charge",
        "settlement_options": [],
        "selected_settlement_option": None,
        "handoff_mode": None,
        "approval_required": None,
        "operator_approval_reason": None,
        "ask_site_for": [],
        "do_not": [],
        "required_evidence": [],
        "missing_information": [],
    }


def _safe_observation_payload():
    return mcp_inspect.build_mcp_observation_payload(_safe_observation_input())


@pytest.mark.parametrize(
    "url,method,expected_address",
    [
        ("http://8.8.8.8/a#discard", "GET", PUBLIC_V4),
        ("https://8.8.8.8/a", "HEAD", PUBLIC_V4),
        ("http://[2001:4860:4860::8888]/a", "GET", PUBLIC_V6),
        ("https://[2001:4860:4860::8888]/a", "HEAD", PUBLIC_V6),
    ],
)
def test_public_ipv4_ipv6_get_head_succeed_without_dns(
    monkeypatch, url, method, expected_address
):
    resolver_calls = _public_resolver(monkeypatch)
    exchange_calls = _fake_exchange(monkeypatch, [_FakeResponse(200)])

    response = transport._inspect_request(url, method=method)

    assert response.status_code == 200
    assert resolver_calls == []
    assert len(exchange_calls) == 1
    assert exchange_calls[0]["address"] == expected_address
    assert exchange_calls[0]["method"] == method
    assert "#" not in exchange_calls[0]["target"].url


def test_hostname_is_idna_canonicalized_once_before_dns_and_wire(monkeypatch):
    resolver_calls = _public_resolver(monkeypatch)
    exchange_calls = _fake_exchange(monkeypatch, [_FakeResponse(200)])

    transport._inspect_request("https://BÜCHER.example./path")

    assert resolver_calls == [("xn--bcher-kva.example", 443)]
    target = exchange_calls[0]["target"]
    assert target.host == "xn--bcher-kva.example"
    assert target.url == "https://xn--bcher-kva.example/path"


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", " get ", 1, None])
def test_non_get_head_methods_fail_before_dns_or_network(monkeypatch, method):
    resolver_calls = _public_resolver(monkeypatch)
    exchange_calls = _fake_exchange(monkeypatch, [])

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._inspect_request("https://public.example/", method=method)

    assert caught.value.stage == "url_validation"
    assert caught.value.code == "method_not_allowed"
    assert resolver_calls == []
    assert exchange_calls == []


@pytest.mark.parametrize(
    "url",
    [
        "",
        "public.example/path",
        "/relative",
        "file:///etc/passwd",
        "ftp://public.example/file",
        "gopher://public.example/1",
        "http://",
        "http://public.example:65536/",
        "http://public.example:0/",
        "http://public.example:22/",
        "http://public.example\\@127.0.0.1/",
        "http://public.example/%0d%0aHost:127.0.0.1",
        "https://public.example/path\u0085hidden",
        "https://public.example/path%C2%85hidden",
        "https://public.example/path%85hidden",
        "https://public.example/path%C0%8Dhidden",
        "https://public.example/path%FFhidden",
        "http://[fe80::1%25eth0]/",
        "http://public.example/%ZZ",
    ],
)
def test_malformed_relative_and_non_http_urls_fail_closed(monkeypatch, url):
    resolver_calls = _public_resolver(monkeypatch)
    exchange_calls = _fake_exchange(monkeypatch, [])

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._inspect_request(url)

    assert caught.value.stage == "url_validation"
    assert resolver_calls == []
    assert exchange_calls == []


@pytest.mark.parametrize(
    "url",
    [
        "https://[example.com]/",
        "https://[v1.fe80]/",
        "https://public.example:/path",
    ],
)
def test_bracketed_non_ipv6_and_explicit_empty_port_fail_before_dns(
    monkeypatch, url
):
    resolver_calls = _public_resolver(monkeypatch)
    exchange_calls = _fake_exchange(monkeypatch, [])

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._inspect_request(url)

    assert caught.value.stage == "url_validation"
    assert caught.value.code in {"invalid_url", "ambiguous_url"}
    assert resolver_calls == []
    assert exchange_calls == []


def test_valid_percent_encoded_utf8_path_remains_inspectable(monkeypatch):
    resolver_calls = _public_resolver(monkeypatch)
    exchange_calls = _fake_exchange(monkeypatch, [_FakeResponse(200)])

    response = transport._inspect_request(
        "https://public.example/%E3%81%82"
    )

    assert response.status_code == 200
    assert resolver_calls == [("public.example", 443)]
    assert exchange_calls[0]["target"].url.endswith("/%E3%81%82")


@pytest.mark.parametrize(
    "url",
    [
        "https://user@public.example/",
        "https://user:password@public.example/",
        "https://user%40name@public.example/",
    ],
)
def test_userinfo_is_rejected_before_dns_or_network(monkeypatch, url):
    resolver_calls = _public_resolver(monkeypatch)
    exchange_calls = _fake_exchange(monkeypatch, [])

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._inspect_request(url)

    assert caught.value.stage == "url_validation"
    assert caught.value.code == "userinfo_forbidden"
    assert resolver_calls == []
    assert exchange_calls == []


@pytest.mark.parametrize("timeout", [0, -1, 30.01, float("inf"), float("nan"), True, "5"])
def test_timeout_must_be_finite_positive_and_bounded(monkeypatch, timeout):
    resolver_calls = _public_resolver(monkeypatch)
    exchange_calls = _fake_exchange(monkeypatch, [])

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._inspect_request("https://public.example/", timeout=timeout)

    assert caught.value.stage == "url_validation"
    assert caught.value.code == "invalid_timeout"
    assert resolver_calls == []
    assert exchange_calls == []


def test_fragment_is_removed_on_wire_and_query_is_redacted_from_all_outputs(monkeypatch):
    raw_url = (
        "https://public.example/resource?token="
        + RAW_QUERY_SECRET
        + "&empty=#private-fragment"
    )
    _public_resolver(monkeypatch)
    exchange_calls = []

    def exchange(target, address, method, timeout, body=None):
        del address, method, timeout, body
        exchange_calls.append(target.url)
        return _FakeResponse(200, url=target.url)

    monkeypatch.setattr(transport, "_exchange_once", exchange)

    cli_result = inspect_url(raw_url)
    mcp_result = mcp_inspect.inspect_paid_surface(raw_url)
    observation = mcp_inspect.build_mcp_observation_payload(mcp_result)
    serialized = json.dumps(
        {
            "cli": cli_result.model_dump(),
            "mcp": mcp_result,
            "observation": observation,
        },
        sort_keys=True,
    )

    assert len(exchange_calls) == 2
    assert all(RAW_QUERY_SECRET in url for url in exchange_calls)
    assert all("#" not in url for url in exchange_calls)
    assert RAW_QUERY_SECRET not in serialized
    assert "private-fragment" not in serialized
    assert cli_result.url == "https://public.example/"
    assert mcp_result["url"] == cli_result.url
    assert observation["targetUrl"] == cli_result.url


@pytest.mark.parametrize(
    "credential",
    [
        "AKIA" + "1234567890ABCDEF",
        "receipt_token_opaque-token-1234567890",
        "authorization-Bearer-opaque_token_123456789",
        "cookie_session-opaque-1234567890",
    ],
)
def test_secret_shaped_query_key_is_redacted_from_public_outputs(
    monkeypatch, credential
):
    raw_url = "https://public.example/resource?" + credential + "=ignored"
    _public_resolver(monkeypatch)
    exchange_calls = _fake_exchange(
        monkeypatch,
        [_FakeResponse(200), _FakeResponse(200)],
    )

    direct = inspect_url(raw_url)
    mcp_result = mcp_inspect.inspect_paid_surface(raw_url)
    observation = mcp_inspect.build_mcp_observation_payload(mcp_result)
    serialized = json.dumps({
        "direct": direct.model_dump(),
        "mcp": mcp_result,
        "observation": observation,
    })

    assert credential in exchange_calls[0]["target"].url
    assert credential in exchange_calls[1]["target"].url
    assert credential not in serialized
    assert direct.url == "https://public.example/"
    assert observation["targetUrl"] == direct.url


@pytest.mark.parametrize(
    "standard_key",
    [
        "X-Amz-Credential",
        "X-Amz-Signature",
        "X-Goog-Credential",
        "X-Goog-Signature",
    ],
)
def test_standard_signing_query_key_names_preserve_only_the_name(
    monkeypatch, standard_key
):
    raw_url = (
        "https://public.example/resource?"
        + standard_key
        + "="
        + RAW_QUERY_SECRET
    )
    _public_resolver(monkeypatch)
    _fake_exchange(monkeypatch, [_FakeResponse(200)])

    result = inspect_url(raw_url)

    assert result.url == "https://public.example/"
    assert RAW_QUERY_SECRET not in result.model_dump_json()


@pytest.mark.parametrize(
    "suffix,leak,wire_contains",
    [
        ("/credentials/DUMMY_PATH_CREDENTIAL_123", "DUMMY_PATH_CREDENTIAL_123", True),
        ("/signature/" + ("S" * 160), "S" * 160, True),
        ("/reset/DUMMY_RESET_TOKEN_123456", "DUMMY_RESET_TOKEN_123456", True),
        ("/users/DUMMY_EMAIL%40example.com", "DUMMY_EMAIL", True),
        ("/users/DUMMY_EMAIL%2540example.com", "DUMMY_EMAIL", True),
        ("?DUMMY_QUERY_KEY=ignored", "DUMMY_QUERY_KEY", True),
        ("?DUMMY%255FQUERY_KEY=ignored", "DUMMY", True),
        ("#DUMMY_PRIVATE_FRAGMENT", "DUMMY_PRIVATE_FRAGMENT", False),
    ],
)
def test_public_url_is_origin_only_across_cli_mcp_payload_validator_and_wire(
    monkeypatch, suffix, leak, wire_contains
):
    raw_url = "https://public.example" + suffix
    _public_resolver(monkeypatch)
    get_calls = _fake_exchange(
        monkeypatch,
        [_FakeResponse(200), _FakeResponse(200)],
    )
    post_calls = _fake_observation_exchange(monkeypatch, [204])

    cli_result = inspect_url(raw_url)
    mcp_result = mcp_inspect.inspect_paid_surface(raw_url)
    payload = mcp_inspect.build_mcp_observation_payload(mcp_result)

    assert (leak in get_calls[0]["target"].url) is wire_contains
    assert (leak in get_calls[1]["target"].url) is wire_contains
    assert cli_result.url == "https://public.example/"
    assert mcp_result["url"] == "https://public.example/"
    assert payload["targetUrl"] == "https://public.example/"
    assert mcp_inspect._validate_observation_payload(payload) is None

    result = mcp_inspect.submit_mcp_observation(payload)
    serialized = json.dumps({
        "cli": cli_result.model_dump(),
        "mcp": mcp_result,
        "payload": payload,
        "submission": result,
    })
    wire_body = post_calls[0]["body"]

    assert result["status"] == "success"
    assert leak not in serialized
    assert leak.encode("utf-8") not in wire_body
    assert json.loads(wire_body)["targetUrl"] == "https://public.example/"


@pytest.mark.parametrize(
    "credential,double_encoded",
    [
        ("DUMMY_RESET_TOKEN_123456", False),
        ("DUMMY_LONG_SIGNATURE_" + ("Q" * 160), True),
    ],
)
def test_fully_encoded_credentials_never_cross_a_public_boundary(
    monkeypatch, credential, double_encoded
):
    encoded = _fully_percent_encode(credential, double=double_encoded)
    raw_url = "https://public.example/credential/" + encoded
    _public_resolver(monkeypatch)
    get_calls = _fake_exchange(
        monkeypatch,
        [_FakeResponse(200), _FakeResponse(200)],
    )
    post_calls = _fake_observation_exchange(monkeypatch, [204])

    cli_result = inspect_url(raw_url)
    mcp_result = mcp_inspect.inspect_paid_surface(raw_url)
    payload = mcp_inspect.build_mcp_observation_payload(mcp_result)
    result = mcp_inspect.submit_mcp_observation(payload)
    serialized = json.dumps({
        "cli": cli_result.model_dump(),
        "mcp": mcp_result,
        "payload": payload,
        "submission": result,
    })

    expected_wire_value = encoded if double_encoded else credential
    assert expected_wire_value in get_calls[0]["target"].url
    assert expected_wire_value in get_calls[1]["target"].url
    assert cli_result.url == "https://public.example/"
    assert mcp_result["url"] == "https://public.example/"
    assert payload["targetUrl"] == "https://public.example/"
    assert mcp_inspect._validate_observation_payload(payload) is None
    assert credential not in serialized
    assert encoded not in serialized
    assert credential.encode("utf-8") not in post_calls[0]["body"]
    assert encoded.encode("ascii") not in post_calls[0]["body"]


@pytest.mark.parametrize(
    "target",
    [
        "https://public.example/path",
        "https://public.example/?query_key=value",
        "https://public.example/#fragment",
        "HTTPS://PUBLIC.EXAMPLE/",
        "https://public.example:443/",
    ],
)
def test_observation_validator_requires_the_exact_canonical_public_origin(target):
    payload = _safe_observation_payload()
    payload["targetUrl"] = target

    assert (
        mcp_inspect._validate_observation_payload(payload)
        == "observation_schema_invalid"
    )


@pytest.mark.parametrize(
    "agent_id",
    [
        "alice@example.com",
        "opaque-agent-123456",
        "DUMMY_RESET_TOKEN_123456",
        "S" * 160,
        "alice%40example.com",
        "alice%2540example.com",
    ],
)
def test_observation_agent_id_is_fixed_by_builder_and_validator(
    monkeypatch, agent_id
):
    payload = mcp_inspect.build_mcp_observation_payload(
        _safe_observation_input(),
        agent_id=agent_id,
    )
    forged = copy.deepcopy(payload)
    forged["agentId"] = agent_id
    _public_resolver(monkeypatch)
    post_calls = _fake_observation_exchange(monkeypatch, [204])

    assert payload["agentId"] == "optional-agent-id"
    assert mcp_inspect._validate_observation_payload(payload) is None
    assert mcp_inspect._validate_observation_payload(forged) is not None

    result = mcp_inspect.submit_mcp_observation(payload)

    assert result["status"] == "success"
    assert agent_id.encode("utf-8") not in post_calls[0]["body"]


def test_observation_sdk_version_is_a_fixed_scalar():
    payload = _safe_observation_payload()
    payload["sdk_version"] = "1.16.4+alice"

    assert (
        mcp_inspect._validate_observation_payload(payload)
        == "observation_schema_invalid"
    )


def test_action_explanation_uses_finite_handoff_allowlists_only():
    hostile = "customer-alice@example.com"
    explanation = mcp_inspect.explain_recommended_action({
        "recommended_action": "observe_only",
        "handoff_mode": hostile,
        "operator_approval_reason": hostile,
        "ask_site_for": [hostile, "quote_details"],
    })

    assert explanation["handoff_mode"] is None
    assert explanation["operator_approval_reason"] is None
    assert explanation["ask_site_for"] == ["quote_details"]
    assert hostile not in json.dumps(explanation)


@pytest.mark.parametrize(
    "address",
    [
        "localhost",
        "127.0.0.1",
        "127.255.255.255",
        "0.1.2.3",
        "10.1.2.3",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "100.64.0.1",
        "100.127.255.254",
        "169.254.1.1",
        "169.254.169.254",
        "169.254.170.2",
        "100.100.100.200",
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
        "240.0.0.1",
        "224.0.0.1",
        "239.255.255.255",
        "::1",
        "::",
        "fc00::1",
        "fdff::1",
        "fe80::1",
        "ff02::1",
        "::ffff:127.0.0.1",
        "::ffff:8.8.8.8",
        "2001:db8::1",
        "fd00:ec2::254",
        "2002:a00:1::",
        "2002:7f00:1::",
        "2002:a9fe:a9fe::",
        "2002:6440:1::",
        "2002:e000:1::",
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        "64:ff9b::a00:1",
        "64:ff9b:1::a00:1",
    ],
)
def test_forbidden_literal_ip_ranges_never_reach_transport(monkeypatch, address):
    exchange_calls = _fake_exchange(monkeypatch, [])
    if address == "localhost":
        url = "http://localhost/"
        monkeypatch.setattr(transport, "_resolve_addresses", lambda _h, _p: ("127.0.0.1",))
    else:
        url = "http://[%s]/" % address if ":" in address else "http://%s/" % address

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._inspect_request(url)

    assert caught.value.stage == (
        "url_validation" if address == "localhost" else "dns_validation"
    )
    assert exchange_calls == []


@pytest.mark.parametrize(
    "hostname",
    [
        "metadata",
        "metadata.google.internal",
        "metadata.azure.internal",
        "instance-data",
        "instance-data.ec2.internal",
    ],
)
def test_metadata_hostnames_are_rejected_before_dns(monkeypatch, hostname):
    resolver_calls = _public_resolver(monkeypatch)
    exchange_calls = _fake_exchange(monkeypatch, [])

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._inspect_request("http://%s/latest" % hostname)

    assert caught.value.stage == "url_validation"
    assert caught.value.code == "forbidden_target"
    assert resolver_calls == []
    assert exchange_calls == []


@pytest.mark.parametrize("address", ["192.0.0.192", "168.63.129.16"])
def test_version_independent_metadata_addresses_are_rejected_everywhere(
    monkeypatch, address
):
    exchange_calls = _fake_exchange(monkeypatch, [])
    raw_url = "http://%s/latest" % address

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._inspect_request(raw_url)
    with pytest.raises(transport.InspectTransportError) as observation:
        transport._validate_observation_target(raw_url)

    assert caught.value.stage == "dns_validation"
    assert caught.value.code == "dns_forbidden_address"
    assert observation.value.code == "dns_forbidden_address"
    assert redaction_policy._inspect_address_is_forbidden(address) is True
    assert redact_inspect_public_url(raw_url) == QUERY_REDACTION
    assert exchange_calls == []


@pytest.mark.parametrize("address", ["192.0.0.192", "168.63.129.16"])
def test_any_special_metadata_dns_answer_rejects_the_hostname(
    monkeypatch, address
):
    resolver_calls = _public_resolver(
        monkeypatch,
        addresses=(PUBLIC_V4, address),
    )
    exchange_calls = _fake_exchange(monkeypatch, [])

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._inspect_request("https://metadata-target.example/path")

    assert caught.value.stage == "dns_validation"
    assert caught.value.code == "dns_forbidden_address"
    assert resolver_calls == [("metadata-target.example", 443)]
    assert exchange_calls == []


@pytest.mark.parametrize(
    "hostname",
    [
        "localhost", "api.localhost", "LOCALHOST.", "Api.Localhost.",
        "service.internal", "internal", "intranet",
    ],
)
def test_internal_names_are_rejected_before_a_public_fake_resolver(
    monkeypatch, hostname
):
    resolver_calls = _public_resolver(monkeypatch, addresses=(PUBLIC_V4,))
    exchange_calls = _fake_exchange(monkeypatch, [])

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._inspect_request("http://%s/private" % hostname)

    assert caught.value.stage == "url_validation"
    assert caught.value.code == "forbidden_target"
    assert redaction_policy._inspect_hostname_is_forbidden(hostname) is True
    assert resolver_calls == []
    assert exchange_calls == []


@pytest.mark.parametrize(
    "location,target_host",
    [
        ("http://192.0.0.192/latest", None),
        ("http://168.63.129.16/latest", None),
        ("http://metadata-target.example/latest", "metadata-target.example"),
    ],
)
def test_redirect_target_uses_the_same_special_address_policy(
    monkeypatch, location, target_host
):
    resolver_calls = []

    def resolve(host, port):
        resolver_calls.append((host, port))
        if host == target_host:
            return ("168.63.129.16",)
        return (PUBLIC_V4,)

    monkeypatch.setattr(transport, "_resolve_addresses", resolve)
    exchange_calls = _fake_exchange(
        monkeypatch,
        [_FakeResponse(302, headers={"Location": location})],
    )

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._inspect_request("http://public.example/start")

    assert caught.value.stage == "redirect_validation"
    assert caught.value.code == "redirect_target_forbidden"
    assert len(exchange_calls) == 1
    assert resolver_calls[0] == ("public.example", 80)
    if target_host is not None:
        assert resolver_calls[-1] == (target_host, 80)


def test_localhost_redirect_is_rejected_without_resolving_the_next_hop(
    monkeypatch,
):
    resolver_calls = _public_resolver(monkeypatch)
    exchange_calls = _fake_exchange(
        monkeypatch,
        [_FakeResponse(302, headers={"Location": "http://api.localhost/x"})],
    )

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._inspect_request("http://public.example/start")

    assert caught.value.stage == "redirect_validation"
    assert caught.value.code == "redirect_invalid"
    assert resolver_calls == [("public.example", 80)]
    assert len(exchange_calls) == 1


def test_hostname_resolving_to_private_ip_is_rejected_as_a_whole(monkeypatch):
    monkeypatch.setattr(transport, "_resolve_addresses", lambda _h, _p: ("10.0.0.7",))
    exchange_calls = _fake_exchange(monkeypatch, [])

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._inspect_request("https://public.example/")

    assert caught.value.stage == "dns_validation"
    assert caught.value.code == "dns_forbidden_address"
    assert exchange_calls == []


@pytest.mark.parametrize(
    "transition_address",
    [
        "2002:a00:1::",
        "2002:7f00:1::",
        "2002:a9fe:a9fe::",
        "64:ff9b::a00:1",
    ],
)
def test_hostname_transition_ipv6_answers_are_rejected(
    monkeypatch, transition_address
):
    monkeypatch.setattr(
        transport,
        "_resolve_addresses",
        lambda _h, _p: (transition_address,),
    )
    exchange_calls = _fake_exchange(monkeypatch, [])

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._inspect_request("https://public.example/")

    assert caught.value.stage == "dns_validation"
    assert caught.value.code == "dns_forbidden_address"
    assert exchange_calls == []


def test_rejected_transition_ipv6_literal_is_not_echoed_publicly(monkeypatch):
    raw_url = "http://[2002:a9fe:a9fe::]/metadata"
    exchange_calls = _fake_exchange(monkeypatch, [])

    result = inspect_url(raw_url)

    assert result.ok is False
    assert result.url == QUERY_REDACTION
    assert raw_url not in result.model_dump_json()
    assert result.failure_class == "dns_forbidden_address"
    assert exchange_calls == []


def test_mixed_public_and_private_dns_answers_reject_entire_target(monkeypatch):
    monkeypatch.setattr(
        transport,
        "_resolve_addresses",
        lambda _h, _p: (PUBLIC_V4, "192.168.0.9"),
    )
    exchange_calls = _fake_exchange(monkeypatch, [])

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._inspect_request("https://public.example/")

    assert caught.value.stage == "dns_validation"
    assert caught.value.code == "dns_forbidden_address"
    assert exchange_calls == []


@pytest.mark.parametrize("records", [OSError("offline failure"), []], ids=["failure", "empty"])
def test_dns_failure_and_empty_answer_fail_closed(monkeypatch, records):
    if isinstance(records, BaseException):
        def fake_getaddrinfo(*_args, **_kwargs):
            raise records
    else:
        def fake_getaddrinfo(*_args, **_kwargs):
            return records
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    exchange_calls = _fake_exchange(monkeypatch, [])

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._inspect_request("https://public.example/")

    assert caught.value.stage == "dns_validation"
    assert caught.value.code in {"dns_resolution_failed", "dns_empty"}
    assert exchange_calls == []


def test_dns_resolution_timeout_is_bounded_without_sleeping(monkeypatch):
    release = threading.Event()

    def blocked_resolver(_host, _port):
        release.wait()
        return (PUBLIC_V4,)

    monkeypatch.setattr(transport, "_resolve_addresses", blocked_resolver)
    try:
        with pytest.raises(transport.InspectTransportError) as caught:
            transport._resolve_addresses_bounded("public.example", 443, 0.0)
    finally:
        release.set()

    assert caught.value.stage == "dns_validation"
    assert caught.value.code == "dns_resolution_timeout"


def test_dns_runs_once_per_hop_and_connect_uses_only_vetted_addresses(monkeypatch):
    resolver_calls = []

    def resolve(host, port):
        resolver_calls.append((host, port))
        return (PUBLIC_V4,) if host == "one.example" else (PUBLIC_V4_FALLBACK,)

    monkeypatch.setattr(transport, "_resolve_addresses", resolve)
    exchange_calls = _fake_exchange(
        monkeypatch,
        [
            _FakeResponse(302, headers={"Location": "https://two.example/final"}),
            _FakeResponse(200),
        ],
    )

    response = transport._inspect_request("https://one.example/start")

    assert response.status_code == 200
    assert resolver_calls == [("one.example", 443), ("two.example", 443)]
    assert [call["address"] for call in exchange_calls] == [PUBLIC_V4, PUBLIC_V4_FALLBACK]
    assert [call["target"].host for call in exchange_calls] == ["one.example", "two.example"]


def test_multiple_vetted_ip_fallback_does_not_reresolve(monkeypatch):
    resolver_calls = _public_resolver(monkeypatch, (PUBLIC_V4, PUBLIC_V4_FALLBACK))
    exchange_calls = _fake_exchange(
        monkeypatch,
        [
            transport.InspectTransportError("transport", "network_error"),
            _FakeResponse(200),
        ],
    )

    response = transport._inspect_request("https://public.example/")

    assert response.status_code == 200
    assert resolver_calls == [("public.example", 443)]
    assert {call["address"] for call in exchange_calls} == {PUBLIC_V4, PUBLIC_V4_FALLBACK}


def test_https_connection_is_ip_pinned_with_original_host_sni_and_verification(monkeypatch):
    sessions = []

    class FakeSession:
        def __init__(self):
            self.trust_env = True
            self.headers = {"Authorization": "must-be-cleared"}
            self.cookies = {"session": "must-be-cleared"}
            self.mounts = []
            self.requests = []
            sessions.append(self)

        def mount(self, prefix, adapter):
            self.mounts.append((prefix, adapter))

        def request(self, method, url, **kwargs):
            self.requests.append((method, url, kwargs))
            return _FakeResponse(200)

        def close(self):
            pass

    monkeypatch.setattr(transport.requests, "Session", FakeSession)
    target = transport._CanonicalTarget(
        scheme="https",
        host="public.example",
        port=443,
        origin="https://public.example",
        url="https://public.example/path?q=wire-value",
        host_header="public.example",
        addresses=(PUBLIC_V4,),
    )

    response = transport._exchange_once(target, PUBLIC_V4, "GET", 5.0)

    assert response.status_code == 200
    assert len(sessions) == 1
    session = sessions[0]
    assert session.trust_env is False
    assert session.headers == {}
    assert session.cookies == {}
    assert len(session.mounts) == 1
    prefix, adapter = session.mounts[0]
    assert prefix == "https://"
    assert adapter.server_hostname == "public.example"
    assert adapter.poolmanager.connection_pool_kw["server_hostname"] == "public.example"
    assert adapter.poolmanager.connection_pool_kw["assert_hostname"] == "public.example"
    method, wire_url, kwargs = session.requests[0]
    assert method == "GET"
    assert wire_url == "https://8.8.8.8/path?q=wire-value"
    assert kwargs["headers"]["Host"] == "public.example"
    assert kwargs["verify"] is True
    assert kwargs["allow_redirects"] is False
    assert kwargs["stream"] is True
    assert "proxies" not in kwargs


def test_hostile_proxy_netrc_and_cookie_environment_is_ignored(monkeypatch):
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "NETRC"):
        monkeypatch.setenv(key, "http://127.0.0.1:9/" + RAW_QUERY_SECRET)

    sessions = []

    class FakeSession:
        def __init__(self):
            self.trust_env = True
            self.headers = {"Proxy-Authorization": "raw-proxy-secret"}
            self.cookies = {"Cookie": "raw-cookie-secret"}
            self.calls = []
            sessions.append(self)

        def mount(self, _prefix, _adapter):
            pass

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            return _FakeResponse(200, headers={"Set-Cookie": "server-secret=1"})

        def close(self):
            pass

    monkeypatch.setattr(transport.requests, "Session", FakeSession)
    target = transport._CanonicalTarget(
        scheme="http",
        host="public.example",
        port=80,
        origin="http://public.example",
        url="http://public.example/path",
        host_header="public.example",
        addresses=(PUBLIC_V4,),
    )

    transport._exchange_once(target, PUBLIC_V4, "GET", 5.0)
    transport._exchange_once(target, PUBLIC_V4, "GET", 5.0)

    assert len(sessions) == 2
    for session in sessions:
        assert session.trust_env is False
        assert session.headers == {}
        assert session.cookies == {}
        _method, _url, kwargs = session.calls[0]
        assert "proxies" not in kwargs
        assert "Authorization" not in kwargs["headers"]
        assert "Cookie" not in kwargs["headers"]
        assert "Proxy-Authorization" not in kwargs["headers"]


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize(
    "location,expected_url",
    [
        ("/final?x=1", "https://one.example/final?x=1"),
        ("https://one.example/final", "https://one.example/final"),
        ("https://two.example/final", "https://two.example/final"),
    ],
)
def test_public_relative_absolute_and_cross_origin_redirects(
    monkeypatch, status, location, expected_url
):
    _public_resolver(monkeypatch)
    exchange_calls = _fake_exchange(
        monkeypatch,
        [_FakeResponse(status, headers={"Location": location}), _FakeResponse(200)],
    )

    response = transport._inspect_request("https://one.example/start", method="HEAD")

    assert response.status_code == 200
    assert exchange_calls[1]["target"].url == expected_url
    assert [call["method"] for call in exchange_calls] == ["HEAD", "HEAD"]


def test_three_redirects_are_allowed_and_fourth_is_rejected(monkeypatch):
    _public_resolver(monkeypatch)
    allowed_calls = _fake_exchange(
        monkeypatch,
        [
            _FakeResponse(301, headers={"Location": "/1"}),
            _FakeResponse(302, headers={"Location": "/2"}),
            _FakeResponse(307, headers={"Location": "/3"}),
            _FakeResponse(200),
        ],
    )
    assert transport._inspect_request("https://public.example/0").status_code == 200
    assert len(allowed_calls) == 4

    too_many_calls = _fake_exchange(
        monkeypatch,
        [
            _FakeResponse(301, headers={"Location": "/1"}),
            _FakeResponse(302, headers={"Location": "/2"}),
            _FakeResponse(307, headers={"Location": "/3"}),
            _FakeResponse(308, headers={"Location": "/4"}),
        ],
    )
    with pytest.raises(transport.InspectTransportError) as caught:
        transport._inspect_request("https://public.example/0")
    assert caught.value.stage == "redirect_validation"
    assert caught.value.code == "redirect_limit_exceeded"
    assert len(too_many_calls) == 4


@pytest.mark.parametrize(
    "location,expected_code",
    [
        ("https://127.0.0.1/private", "redirect_target_forbidden"),
        ("https://169.254.169.254/latest/meta-data", "redirect_target_forbidden"),
        ("https://metadata.google.internal/computeMetadata/v1/", "redirect_invalid"),
    ],
)
def test_private_and_metadata_redirect_targets_are_never_contacted(
    monkeypatch, location, expected_code
):
    _public_resolver(monkeypatch)
    exchange_calls = _fake_exchange(
        monkeypatch,
        [_FakeResponse(302, headers={"Location": location})],
    )

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._inspect_request("https://public.example/start")

    assert caught.value.stage == "redirect_validation"
    assert caught.value.code == expected_code
    assert len(exchange_calls) == 1
    assert "127.0.0.1" not in str(caught.value)
    assert "169.254.169.254" not in str(caught.value)


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Location": ""},
        {"Location": "http://[malformed"},
        {"Location": "https://user:password@public.example/"},
        {"Location": " https://public.example/final"},
        {"Location": "\rhttps://public.example/final"},
        {"Location": "\nhttps://public.example/final"},
        {"Location": "https:///evil"},
    ],
)
def test_missing_and_malformed_redirect_locations_fail_closed(monkeypatch, headers):
    _public_resolver(monkeypatch)
    exchange_calls = _fake_exchange(monkeypatch, [_FakeResponse(302, headers=headers)])

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._inspect_request("https://public.example/start")

    assert caught.value.stage == "redirect_validation"
    assert caught.value.code == "redirect_invalid"
    assert len(exchange_calls) == 1


def test_redirect_loop_fails_closed(monkeypatch):
    _public_resolver(monkeypatch)
    exchange_calls = _fake_exchange(
        monkeypatch,
        [
            _FakeResponse(302, headers={"Location": "/two"}),
            _FakeResponse(302, headers={"Location": "/start"}),
        ],
    )

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._inspect_request("https://public.example/start")

    assert caught.value.stage == "redirect_validation"
    assert caught.value.code == "redirect_loop"
    assert len(exchange_calls) == 2


def test_https_to_http_redirect_downgrade_is_rejected(monkeypatch):
    _public_resolver(monkeypatch)
    exchange_calls = _fake_exchange(
        monkeypatch,
        [_FakeResponse(302, headers={"Location": "http://public.example/final"})],
    )

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._inspect_request("https://public.example/start")

    assert caught.value.stage == "redirect_validation"
    assert caught.value.code == "https_downgrade_forbidden"
    assert len(exchange_calls) == 1


def test_one_total_deadline_bounds_all_redirect_hops(monkeypatch):
    _public_resolver(monkeypatch)
    exchange_calls = _fake_exchange(
        monkeypatch,
        [_FakeResponse(302, headers={"Location": "/next"})],
    )
    clock_values = iter([0.0, 1.0, 2.0, 3.0, 6.0])

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._inspect_request_with_clock(
            "https://public.example/start",
            timeout=5.0,
            monotonic=lambda: next(clock_values),
        )

    assert caught.value.stage == "transport"
    assert caught.value.code == "transport_timeout"
    assert len(exchange_calls) == 1


@pytest.mark.parametrize(
    "failure,stage,code",
    [
        (requests.exceptions.Timeout("timeout " + RAW_EXCEPTION_SECRET), "transport", "transport_timeout"),
        (requests.exceptions.SSLError("tls " + RAW_EXCEPTION_SECRET), "transport", "tls_verification_failed"),
        (requests.exceptions.RequestException("network " + RAW_EXCEPTION_SECRET), "transport", "network_error"),
        (transport.InspectTransportError("response_limit", "response_too_large"), "response_limit", "response_too_large"),
    ],
)
def test_timeout_tls_network_and_limit_failures_use_fixed_redacted_codes(
    monkeypatch, failure, stage, code
):
    _public_resolver(monkeypatch)
    _fake_exchange(monkeypatch, [failure])
    raw_url = "https://public.example/path?credential=" + RAW_QUERY_SECRET

    result = inspect_url(raw_url)
    serialized = result.model_dump_json()

    assert result.ok is False
    assert result.error_stage == stage
    assert result.failure_class == code
    assert result.failure_reason == code
    assert result.recommended_action == "stop_safely"
    assert RAW_QUERY_SECRET not in serialized
    assert RAW_EXCEPTION_SECRET not in serialized
    assert result.url == "https://public.example/"


def test_identity_body_limit_allows_exactly_one_mib_and_rejects_next_byte():
    exact = _FakeResponse(
        200,
        headers={"Content-Encoding": "identity"},
        chunks=[b"a" * (512 * 1024), b"b" * (512 * 1024)],
    )
    transport._read_bounded_body(exact)
    assert len(exact.content) == transport.MAX_INSPECT_BODY_BYTES
    assert all(
        amount <= 64 * 1024 and decode_content is False
        for amount, decode_content in exact.raw.read_calls
    )

    oversized = _FakeResponse(
        200,
        headers={"Content-Encoding": "identity"},
        chunks=[b"a" * transport.MAX_INSPECT_BODY_BYTES, b"b"],
    )
    with pytest.raises(transport.InspectTransportError) as caught:
        transport._read_bounded_body(oversized)
    assert caught.value.stage == "response_limit"
    assert caught.value.code == "response_too_large"
    assert oversized.closed is True
    assert all(
        amount <= 64 * 1024 and decode_content is False
        for amount, decode_content in oversized.raw.read_calls
    )


def test_inspect_requests_identity_encoding_only():
    target = transport._canonicalize_target("https://public.example/")

    assert transport._fixed_headers(target, False)["Accept-Encoding"] == "identity"
    assert transport._fixed_headers(target, True)["Accept-Encoding"] == "identity"


@pytest.mark.parametrize(
    "content_encoding",
    ["gzip", "deflate", "br", "gzip, deflate"],
)
def test_compressed_responses_are_rejected_before_any_body_read(
    content_encoding,
):
    response = _FakeResponse(
        200,
        headers={"Content-Encoding": content_encoding},
        content=gzip.compress(b"x" * (2 * transport.MAX_INSPECT_BODY_BYTES)),
    )

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._read_bounded_body(response)

    assert caught.value.stage == "response_limit"
    assert caught.value.code == "compressed_response_rejected"
    assert response.raw.read_calls == []
    assert response.closed is True


def test_urllib3_compressed_expansion_is_rejected_without_raw_read():
    import urllib3

    class TrackingBody(io.BytesIO):
        def __init__(self, value):
            super().__init__(value)
            self.read_calls = []

        def read(self, amount=-1):
            self.read_calls.append(amount)
            return super().read(amount)

    wire_body = TrackingBody(
        gzip.compress(b"x" * (2 * transport.MAX_INSPECT_BODY_BYTES))
    )
    raw = urllib3.response.HTTPResponse(
        body=wire_body,
        headers={"Content-Encoding": "gzip"},
        preload_content=False,
        decode_content=True,
    )
    response = requests.Response()
    response.status_code = 200
    response.headers = {"Content-Encoding": "gzip"}
    response.raw = raw

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._read_bounded_body(response)

    assert caught.value.code == "compressed_response_rejected"
    assert wire_body.read_calls == []


def test_oversized_content_length_is_rejected_before_raw_read():
    response = _FakeResponse(
        200,
        headers={
            "Content-Encoding": "identity",
            "Content-Length": str(transport.MAX_INSPECT_BODY_BYTES + 1),
        },
        content=b"not-read",
    )

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._read_bounded_body(response)

    assert caught.value.code == "response_too_large"
    assert response.raw.read_calls == []


@pytest.mark.parametrize(
    "failure",
    [
        transport.InspectTransportError("response_limit", "response_too_large"),
        transport.InspectTransportError(
            "response_limit", "compressed_response_rejected"
        ),
    ],
    ids=["body-limit", "unsupported-encoding"],
)
def test_terminal_response_failures_do_not_fallback_to_another_vetted_ip(
    monkeypatch, failure
):
    target = transport._CanonicalTarget(
        scheme="https",
        host="public.example",
        port=443,
        origin="https://public.example",
        url="https://public.example/",
        host_header="public.example",
        addresses=(PUBLIC_V4, PUBLIC_V4_FALLBACK),
    )
    exchange_calls = _fake_exchange(
        monkeypatch,
        [failure, _FakeResponse(200)],
    )

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._request_target(
            target,
            "GET",
            deadline=100.0,
            monotonic=lambda: 0.0,
        )

    assert caught.value.code == failure.code
    assert len(exchange_calls) == 1


def test_unsupported_content_encoding_is_closed_with_fixed_code():
    response = _FakeResponse(
        200,
        headers={"Content-Encoding": "br"},
        content=b"compressed",
    )

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._read_bounded_body(response)

    assert caught.value.stage == "response_limit"
    assert caught.value.code == "compressed_response_rejected"
    assert response.raw.read_calls == []
    assert response.closed is True


def test_cli_and_mcp_entry_points_share_the_same_pre_network_policy(monkeypatch):
    resolver_calls = _public_resolver(monkeypatch)
    exchange_calls = _fake_exchange(monkeypatch, [])
    raw_url = "http://127.0.0.1/private?token=" + RAW_QUERY_SECRET

    cli_result = inspect_url(raw_url)
    mcp_result = mcp_inspect.inspect_paid_surface(raw_url)
    serialized = json.dumps({"cli": cli_result.model_dump(), "mcp": mcp_result})

    assert cli_result.error_stage == "dns_validation"
    assert mcp_result["error_stage"] == "dns_validation"
    assert cli_result.failure_class == mcp_result["failure_class"]
    assert cli_result.recommended_action == "stop_safely"
    assert mcp_result["recommended_action"] == "stop_safely"
    assert RAW_QUERY_SECRET not in serialized
    assert "127.0.0.1" not in serialized
    assert resolver_calls == []
    assert exchange_calls == []


def test_mcp_rejects_and_does_not_echo_an_invalid_method(monkeypatch):
    resolver_calls = _public_resolver(monkeypatch)
    exchange_calls = _fake_exchange(monkeypatch, [])
    hostile_method = "POST-" + RAW_EXCEPTION_SECRET

    result = mcp_inspect.inspect_paid_surface(
        "https://public.example/",
        method=hostile_method,
    )

    assert result["method"] == "INVALID"
    assert result["error_stage"] == "url_validation"
    assert result["failure_class"] == "method_not_allowed"
    assert RAW_EXCEPTION_SECRET not in json.dumps(result)
    assert resolver_calls == []
    assert exchange_calls == []


@pytest.mark.parametrize("scheme", ["evil-secret-scheme", "Payment"])
def test_unknown_or_unmapped_payment_scheme_stops_safely(
    monkeypatch, scheme
):
    content = json.dumps({
        "challenge": {
            "scheme": scheme,
            "network": "unknown",
            "amount": 0,
            "asset": "unknown",
            "parameters": {},
        }
    }).encode("utf-8")
    _public_resolver(monkeypatch)
    _fake_exchange(monkeypatch, [
        _FakeResponse(
            402,
            headers={"Content-Type": "application/json"},
            content=content,
        )
    ])

    result = inspect_url("https://public.example/")

    assert result.ok is True
    assert result.recommended_action == "stop_safely"
    assert result.failure_class == "unsupported_challenge_shape"
    assert result.error_stage == "parse"
    assert result.will_execute_payment is False


def test_response_adapter_failure_keeps_its_failure_domain_and_redacts(
    monkeypatch,
):
    secret = "DUMMY_ADAPTER_EXCEPTION_SECRET"
    _public_resolver(monkeypatch)
    _fake_exchange(
        monkeypatch,
        [_FakeResponse(402), _FakeResponse(402)],
    )
    monkeypatch.setattr(
        cli_module,
        "_requests_to_httpx_response",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(Exception(secret)),
    )

    cli_result = inspect_url("https://public.example/private/path")
    mcp_result = mcp_inspect.inspect_paid_surface(
        "https://public.example/private/path"
    )
    serialized = json.dumps({
        "cli": cli_result.model_dump(),
        "mcp": mcp_result,
    })

    assert cli_result.error_stage == "response_adapter"
    assert mcp_result["error_stage"] == "response_adapter"
    assert cli_result.failure_class == "requests_to_httpx_conversion_failed"
    assert mcp_result["failure_class"] == "requests_to_httpx_conversion_failed"
    assert cli_result.recommended_action == "stop_safely"
    assert secret not in serialized


def test_response_body_access_failure_keeps_response_adapter_domain(monkeypatch):
    secret = "DUMMY_BODY_ACCESS_EXCEPTION_SECRET"

    class FailingBodyResponse:
        status_code = 402
        url = "https://public.example/"
        headers = {}

        @property
        def content(self):
            raise RuntimeError(secret)

    _public_resolver(monkeypatch)
    _fake_exchange(
        monkeypatch,
        [FailingBodyResponse(), FailingBodyResponse()],
    )

    cli_result = inspect_url("https://public.example/private/path")
    mcp_result = mcp_inspect.inspect_paid_surface(
        "https://public.example/private/path"
    )
    serialized = json.dumps({
        "cli": cli_result.model_dump(),
        "mcp": mcp_result,
    })

    assert cli_result.error_stage == "response_adapter"
    assert mcp_result["error_stage"] == "response_adapter"
    assert cli_result.failure_class == "requests_to_httpx_conversion_failed"
    assert mcp_result["failure_class"] == "requests_to_httpx_conversion_failed"
    assert cli_result.recommended_action == "stop_safely"
    assert secret not in serialized


def test_challenge_parser_failure_keeps_parse_domain_and_redacts(monkeypatch):
    secret = "DUMMY_PARSE_EXCEPTION_SECRET"
    response = _FakeResponse(
        402,
        headers={"PAYMENT-REQUIRED": "malformed"},
    )
    _public_resolver(monkeypatch)
    _fake_exchange(monkeypatch, [response, copy.deepcopy(response)])
    monkeypatch.setattr(
        cli_module,
        "parse_challenge_from_response",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(Exception(secret)),
    )

    cli_result = inspect_url("https://public.example/private/path")
    mcp_result = mcp_inspect.inspect_paid_surface(
        "https://public.example/private/path"
    )
    serialized = json.dumps({
        "cli": cli_result.model_dump(),
        "mcp": mcp_result,
    })

    assert cli_result.error_stage == "parse"
    assert mcp_result["error_stage"] == "parse"
    assert cli_result.failure_class == "unexpected_error"
    assert mcp_result["failure_class"] == "unexpected_error"
    assert cli_result.recommended_action == "stop_safely"
    assert secret not in serialized


@pytest.mark.parametrize(
    "failing_function",
    ["_extract_settlement_options", "detect_commerce_surface"],
)
def test_challenge_classification_failure_keeps_parse_domain(
    monkeypatch, failing_function
):
    secret = "DUMMY_CLASSIFICATION_EXCEPTION_SECRET"
    parsed = SimpleNamespace(
        _inspect_semantically_valid=True,
        scheme="exact",
        network="eip155:1",
        asset="USDC",
        amount="1",
        payment_intent=None,
        draft_shape=None,
        source=None,
        parameters={},
    )
    _public_resolver(monkeypatch)
    _fake_exchange(
        monkeypatch,
        [_FakeResponse(402), _FakeResponse(402)],
    )
    monkeypatch.setattr(
        cli_module,
        "parse_challenge_from_response",
        lambda *_args, **_kwargs: parsed,
    )
    monkeypatch.setattr(
        cli_module,
        failing_function,
        lambda *_args, **_kwargs: (_ for _ in ()).throw(Exception(secret)),
    )

    cli_result = inspect_url("https://public.example/private/path")
    mcp_result = mcp_inspect.inspect_paid_surface(
        "https://public.example/private/path"
    )
    serialized = json.dumps({
        "cli": cli_result.model_dump(),
        "mcp": mcp_result,
    })

    assert cli_result.error_stage == "parse"
    assert mcp_result["error_stage"] == "parse"
    assert cli_result.failure_class == "classification_failure"
    assert mcp_result["failure_class"] == "classification_failure"
    assert cli_result.recommended_action == "stop_safely"
    assert secret not in serialized


def test_guidance_classification_failure_keeps_parse_domain(monkeypatch):
    secret = "DUMMY_GUIDANCE_EXCEPTION_SECRET"
    commerce_info = {
        "commerce_protocol": "ap2",
        "commerce_intent": "cart",
        "raw_detected_fields": {},
    }
    _public_resolver(monkeypatch)
    _fake_exchange(
        monkeypatch,
        [_FakeResponse(402), _FakeResponse(402)],
    )
    monkeypatch.setattr(
        cli_module,
        "detect_commerce_surface",
        lambda *_args, **_kwargs: commerce_info,
    )
    monkeypatch.setattr(
        cli_module,
        "build_commerce_guidance",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(Exception(secret)),
    )

    cli_result = inspect_url("https://public.example/private/path")
    mcp_result = mcp_inspect.inspect_paid_surface(
        "https://public.example/private/path"
    )
    serialized = json.dumps({
        "cli": cli_result.model_dump(),
        "mcp": mcp_result,
    })

    assert cli_result.error_stage == "parse"
    assert mcp_result["error_stage"] == "parse"
    assert cli_result.failure_class == "classification_failure"
    assert mcp_result["failure_class"] == "classification_failure"
    assert cli_result.recommended_action == "stop_safely"
    assert secret not in serialized


def test_unhashable_selection_reason_and_action_inputs_cannot_crash(
    monkeypatch,
):
    requirement = {
        "scheme": "exact",
        "network": "eip155:1",
        "asset": "USDC",
        "amount": "1",
    }
    parsed = SimpleNamespace(
        _inspect_semantically_valid=True,
        scheme="exact",
        payment_method=None,
        network="eip155:1",
        asset="USDC",
        amount="1",
        payment_intent=None,
        draft_shape=None,
        source=None,
        parameters={
            "_all_accepted": [requirement],
            "_raw_accepted": requirement,
            "_selection_reason": [],
        },
    )
    _public_resolver(monkeypatch)
    _fake_exchange(monkeypatch, [_FakeResponse(402)])

    with patch(
        "ln_church_agent.cli.parse_challenge_from_response",
        return_value=parsed,
    ):
        result = inspect_url("https://public.example/")
    payload = mcp_inspect.build_mcp_observation_payload({
        **_safe_observation_input(),
        "settlement_options": [{
            "network": "eip155:1",
            "asset": "USDC",
            "rail": "x402",
            "scheme": "exact",
            "selection_reason": [],
        }],
    })

    assert result.recommended_action == "observe_only"
    assert result.settlement_options[0].selection_reason == "unknown"
    assert payload["settlement_options_summary"][0]["selection_reason"] == "unknown"
    for hostile_action in ([], {}, 1):
        explanation = mcp_inspect.explain_recommended_action({
            "recommended_action": hostile_action
        })
        assert explanation["recommended_action"] == "unknown"
        assert explanation["payment_execution_available_in_this_mcp"] is False


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://kari.mayim-mayim.com/api/agent/external/mcp-observe",
        "https://kari.mayim-mayim.com/api/agent/external/mcp-observe/",
        "https://kari.mayim-mayim.com/api/agent/external/mcp-observe?x=1",
        "https://other.example/api/agent/external/mcp-observe",
        "http://127.0.0.1/collect",
    ],
)
def test_noncanonical_observation_endpoint_is_rejected_before_dns_or_network(
    monkeypatch, endpoint
):
    resolver_calls = _public_resolver(monkeypatch)
    exchange_calls = _fake_exchange(monkeypatch, [])

    result = mcp_inspect.submit_mcp_observation(
        _safe_observation_payload(), endpoint=endpoint
    )

    assert set(result) == {
        "status", "status_code", "failure_code", "recommended_action"
    }
    assert result["status"] != "success"
    assert result["status_code"] is None
    assert result["failure_code"] == "observation_endpoint_mismatch"
    assert result["recommended_action"] == "stop_safely"
    assert resolver_calls == []
    assert exchange_calls == []


def test_observation_post_rejects_redirect_and_does_not_follow(monkeypatch):
    resolver_calls = _public_resolver(monkeypatch)
    exchange_calls = _fake_observation_exchange(
        monkeypatch,
        [_FakeResponse(307, headers={"Location": "https://other.example/collect"})],
    )

    result = mcp_inspect.submit_mcp_observation(_safe_observation_payload())

    assert set(result) == {
        "status", "status_code", "failure_code", "recommended_action"
    }
    assert result["status"] != "success"
    assert result["status_code"] == 307
    assert result["failure_code"] == "observation_redirect_rejected"
    assert resolver_calls == [
        ("public.example", 443),
        ("kari.mayim-mayim.com", 443),
    ]
    assert len(exchange_calls) == 1
    assert exchange_calls[0]["method"] == "POST"


def test_observation_success_returns_no_response_body(monkeypatch):
    _public_resolver(monkeypatch)
    exchange_calls = _fake_observation_exchange(
        monkeypatch,
        [_FakeResponse(204, content=RAW_RESPONSE_SECRET.encode("utf-8"))],
    )

    result = mcp_inspect.submit_mcp_observation(_safe_observation_payload())
    serialized = json.dumps(result)

    assert result == {
        "status": "success",
        "status_code": 204,
        "failure_code": None,
        "recommended_action": "none",
    }
    assert RAW_RESPONSE_SECRET not in serialized
    assert len(exchange_calls) == 1
    submitted = json.loads(exchange_calls[0]["body"].decode("utf-8"))
    assert submitted["evidence"]["payment_performed"] is False
    assert submitted["evidence"]["proof_reference"] == "none"


def test_two_ip_observation_timeout_is_not_replayed(monkeypatch):
    resolver_calls = []

    def resolve(host, port):
        resolver_calls.append((host, port))
        if host == "kari.mayim-mayim.com":
            return (PUBLIC_V4, PUBLIC_V4_FALLBACK)
        return (PUBLIC_V4,)

    class TimeoutSession:
        def __init__(self):
            self.trust_env = True
            self.headers = {}
            self.cookies = {}
            self.request_calls = []
            self.closed = False

        def mount(self, *_args):
            return None

        def request(self, method, url, **kwargs):
            self.request_calls.append((method, url, kwargs))
            raise requests.exceptions.Timeout("ambiguous observation timeout")

        def close(self):
            self.closed = True

    session = TimeoutSession()
    monkeypatch.setattr(transport, "_resolve_addresses", resolve)
    monkeypatch.setattr(transport.requests, "Session", lambda: session)

    result = mcp_inspect.submit_mcp_observation(_safe_observation_payload())

    assert result == {
        "status": "failure",
        "status_code": None,
        "failure_code": "observation_delivery_unknown",
        "recommended_action": "stop_safely",
    }
    assert len(session.request_calls) == 1
    assert session.request_calls[0][0] == "POST"
    assert session.request_calls[0][1].startswith(
        "https://%s/" % PUBLIC_V4_FALLBACK
    )
    assert session.closed is True
    assert resolver_calls == [
        ("public.example", 443),
        ("kari.mayim-mayim.com", 443),
    ]


def test_production_observation_exchange_reads_no_body_and_closes(monkeypatch):
    class GuardedResponse:
        status_code = 204

        def __init__(self):
            self.closed = False

        @property
        def content(self):
            raise AssertionError("observation response body must not be read")

        @property
        def text(self):
            raise AssertionError("observation response body must not be read")

        @property
        def raw(self):
            raise AssertionError("observation response body must not be read")

        def json(self):
            raise AssertionError("observation response body must not be read")

        def iter_content(self, *_args, **_kwargs):
            raise AssertionError("observation response body must not be read")

        def close(self):
            self.closed = True

    class FakeSession:
        def __init__(self, response):
            self.response = response
            self.trust_env = True
            self.headers = {"unexpected": "value"}
            self.cookies = {"unexpected": "value"}
            self.closed = False
            self.request_calls = []

        def mount(self, *_args):
            return None

        def request(self, method, url, **kwargs):
            self.request_calls.append((method, url, kwargs))
            return self.response

        def close(self):
            self.closed = True

    response = GuardedResponse()
    session = FakeSession(response)
    monkeypatch.setattr(transport.requests, "Session", lambda: session)
    target = transport._canonicalize_target(
        transport.CANONICAL_OBSERVATION_ENDPOINT
    )

    status = transport._exchange_observation_once(
        target,
        PUBLIC_V4,
        5.0,
        b"{}",
    )

    assert status == 204
    assert response.closed is True
    assert session.closed is True
    assert len(session.request_calls) == 1
    method, _url, kwargs = session.request_calls[0]
    assert method == "POST"
    assert kwargs["stream"] is True
    assert kwargs["allow_redirects"] is False
    assert kwargs["headers"]["Accept-Encoding"] == "identity"


@pytest.mark.parametrize(
    "failure",
    [
        requests.exceptions.Timeout("ambiguous timeout"),
        requests.exceptions.SSLError("ambiguous tls failure"),
        requests.exceptions.RequestException("ambiguous network failure"),
    ],
)
def test_production_observation_network_failure_has_unknown_delivery(
    monkeypatch, failure
):
    class FailingSession:
        def __init__(self):
            self.trust_env = True
            self.headers = {}
            self.cookies = {}
            self.calls = 0
            self.closed = False

        def mount(self, *_args):
            return None

        def request(self, *_args, **_kwargs):
            self.calls += 1
            raise failure

        def close(self):
            self.closed = True

    session = FailingSession()
    monkeypatch.setattr(transport.requests, "Session", lambda: session)
    target = transport._canonicalize_target(
        transport.CANONICAL_OBSERVATION_ENDPOINT
    )

    with pytest.raises(transport.InspectTransportError) as caught:
        transport._exchange_observation_once(
            target,
            PUBLIC_V4,
            5.0,
            b"{}",
        )

    assert caught.value.stage == "transport"
    assert caught.value.code == "observation_delivery_unknown"
    assert session.calls == 1
    assert session.closed is True


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update({"headers": {"Authorization": "Bearer raw"}}),
        lambda value: value.update({"body": "raw request body"}),
        lambda value: value.update({"credential": "raw credential"}),
        lambda value: value.update({"macaroon": "raw macaroon"}),
        lambda value: value.update({"schema_version": "mcp_observation_report.v2"}),
        lambda value: value["evidence"].update({"payment_performed": True}),
        lambda value: value["evidence"].update({"payment_performed": 0}),
        lambda value: value["evidence"].update({"proof_reference": "raw-proof"}),
        lambda value: value["protocol"].update({"unexpected": "field"}),
        lambda value: value.update({"agentId": "a" * 1025}),
        lambda value: value.update({"agentId": "agent\u0085hidden"}),
    ],
    ids=[
        "raw-headers",
        "raw-body",
        "credential",
        "proof-material-key",
        "schema-version",
        "payment-true",
        "payment-non-bool",
        "raw-proof",
        "nested-unknown",
        "overlong-string",
        "unicode-control",
    ],
)
def test_observation_payload_allowlist_rejects_unknown_secret_and_invalid_shapes(
    monkeypatch, mutation
):
    payload = _safe_observation_payload()
    mutation(payload)
    resolver_calls = _public_resolver(monkeypatch)
    exchange_calls = _fake_exchange(monkeypatch, [])

    result = mcp_inspect.submit_mcp_observation(payload)

    assert set(result) == {
        "status", "status_code", "failure_code", "recommended_action"
    }
    assert result["status"] != "success"
    assert result["status_code"] is None
    assert result["failure_code"] == "observation_payload_rejected"
    assert "raw" not in json.dumps(result).lower()
    assert resolver_calls == []
    assert exchange_calls == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("network", "0x" + ("1" * 64)),
        ("network", "solana:" + ("A" * 64)),
        ("network", "DUMMY_PRIVATE_KEY_SECRET"),
        ("asset", "0x" + ("2" * 64)),
        ("rail", "DUMMY_CREDENTIAL_VALUE"),
        ("payment_intent", "DUMMY_PROOF_VALUE"),
    ],
)
def test_observation_protocol_fields_require_public_semantics_before_network(
    monkeypatch, field, value
):
    payload = _safe_observation_payload()
    payload["protocol"][field] = value
    if field == "rail":
        payload["protocol"]["authorization_scheme"] = value
    resolver_calls = _public_resolver(monkeypatch)
    exchange_calls = _fake_exchange(monkeypatch, [])

    result = mcp_inspect.submit_mcp_observation(payload)

    assert result["failure_code"] == "observation_payload_rejected"
    assert resolver_calls == []
    assert exchange_calls == []


def test_observation_builder_drops_nonsemantic_secret_shaped_fields():
    private_key = "0x" + ("3" * 64)
    source = _safe_observation_input()
    source.update({
        "settlement_rails_detected": ["DUMMY_CREDENTIAL_VALUE"],
        "commerce_intent": "DUMMY_PROOF_VALUE",
        "selected_settlement_option": {
            "network": private_key,
            "asset": private_key,
            "rail": "DUMMY_SECRET_RAIL",
            "scheme": "DUMMY_PRIVATE_KEY_SECRET",
        },
        "settlement_options": [{
            "network": private_key,
            "asset": private_key,
            "rail": "DUMMY_SECRET_RAIL",
            "scheme": "DUMMY_PRIVATE_KEY_SECRET",
            "selected": True,
        }],
    })

    payload = mcp_inspect.build_mcp_observation_payload(
        source,
        agent_id=private_key,
    )
    serialized = json.dumps(payload, sort_keys=True)

    assert private_key not in serialized
    assert "DUMMY_" not in serialized
    assert payload["agentId"] == "optional-agent-id"
    assert mcp_inspect._validate_observation_payload(payload) is None


@pytest.mark.parametrize(
    "credential",
    [
        "AKIA" + "1234567890ABCDEF",
        "ghp_" + "123456789012345678901234567890123456",
        "sk-" + "proj-123456789012345678901234567890",
        "xoxb-" + "1234567890-abcdefghijklmnop",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.abcdefghijklmnopqrstuvwxyz",
    ],
)
def test_known_credential_formats_are_redacted_from_agent_id_and_target_path(
    monkeypatch, credential
):
    raw_url = "https://public.example/session/" + credential
    payload = mcp_inspect.build_mcp_observation_payload(
        _safe_observation_input(url=raw_url),
        agent_id=credential,
    )
    forged_agent = _safe_observation_payload()
    forged_agent["agentId"] = credential
    forged_target = _safe_observation_payload()
    forged_target["targetUrl"] = raw_url
    _public_resolver(monkeypatch)
    _fake_exchange(monkeypatch, [_FakeResponse(200)])

    direct = inspect_url(raw_url)

    assert payload["agentId"] == "optional-agent-id"
    assert payload["targetUrl"] == "https://public.example/"
    assert credential not in json.dumps(payload)
    assert credential not in direct.model_dump_json()
    assert direct.url == "https://public.example/"
    assert (
        mcp_inspect._validate_observation_payload(forged_agent)
        == "observation_secret_material_rejected"
    )
    assert (
        mcp_inspect._validate_observation_payload(forged_target)
        == "observation_secret_material_rejected"
    )


@pytest.mark.parametrize(
    "path",
    [
        "/authorization/Bearer%20opaque_token_123456789",
        "/macaroon/AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA%3D",
        "/payment_signature/AQIDBAUGBwgJCgsMDQ4PEA%3D",
        "/receipt_token/opaque-token-1234567890",
        "/cookie/session-opaque-1234567890",
        "/proof/opaque-proof-1234567890",
        "/payment_signature_opaque-token-1234567890",
        "/receipt_token_opaque-token-1234567890",
        "/cookie_session-opaque-1234567890",
        "/authorization-Bearer-opaque_token_123456789",
    ],
)
def test_semantic_secret_path_segments_are_never_public(
    monkeypatch, path
):
    raw_url = "https://public.example" + path
    _public_resolver(monkeypatch)
    exchange_calls = _fake_exchange(
        monkeypatch,
        [_FakeResponse(200), _FakeResponse(200)],
    )

    direct = inspect_url(raw_url)
    mcp_result = mcp_inspect.inspect_paid_surface(raw_url)
    observation = mcp_inspect.build_mcp_observation_payload(mcp_result)
    serialized = json.dumps({
        "direct": direct.model_dump(),
        "mcp": mcp_result,
        "observation": observation,
    })

    assert exchange_calls[0]["target"].url.endswith(path)
    assert exchange_calls[1]["target"].url.endswith(path)
    assert direct.url == "https://public.example/"
    assert mcp_result["url"] == "https://public.example/"
    assert observation["targetUrl"] == "https://public.example/"
    assert raw_url not in serialized


def test_observation_payload_size_limit_is_enforced_before_network(monkeypatch):
    payload = _safe_observation_payload()
    long_value = "x-" * 64
    summary = {
        "network": long_value,
        "asset": long_value,
        "rail": long_value,
        "scheme": long_value,
        "selected": False,
        "execution_support": long_value,
        "selection_reason": long_value,
        "settlement_model": long_value,
        "authorization_artifact": long_value,
        "finality_model": long_value,
        "deferred_settlement": False,
        "requires_channel_state": False,
    }
    payload["targetUrl"] = "https://public.example/" + ("x" * 8000)
    payload["settlement_options_summary"] = [
        copy.deepcopy(summary) for _ in range(32)
    ]
    for key in (
        "ask_site_for",
        "do_not",
        "required_evidence",
        "missing_information",
    ):
        payload["handoff"][key] = [long_value] * 32
    resolver_calls = _public_resolver(monkeypatch)
    exchange_calls = _fake_exchange(monkeypatch, [])

    assert (
        mcp_inspect._validate_observation_payload(payload)
        == "observation_payload_too_large"
    )
    result = mcp_inspect.submit_mcp_observation(payload)

    assert result["failure_code"] == "observation_payload_rejected"
    assert resolver_calls == []
    assert exchange_calls == []


def test_observation_uses_a_detached_revalidated_snapshot(monkeypatch):
    payload = _safe_observation_payload()
    resolver_calls = _public_resolver(monkeypatch)
    exchange_calls = _fake_exchange(monkeypatch, [])
    production_validator = mcp_inspect._validate_observation_payload
    validation_calls = 0

    def mutate_after_first_validation(candidate):
        nonlocal validation_calls
        validation_calls += 1
        result = production_validator(candidate)
        if validation_calls == 1 and result is None:
            payload["evidence"]["payment_performed"] = True
        return result

    monkeypatch.setattr(
        mcp_inspect,
        "_validate_observation_payload",
        mutate_after_first_validation,
    )

    result = mcp_inspect.submit_mcp_observation(payload)

    assert result["failure_code"] == "observation_payload_rejected"
    assert validation_calls == 2
    assert resolver_calls == []
    assert exchange_calls == []


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/private",
        "http://169.254.169.254/latest/meta-data",
        "http://192.0.0.192/latest/user-data",
        "http://168.63.129.16/machine",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://service.internal/private",
        "http://internal/private",
        "http://intranet/private",
        "http://database/private",
        "http://127.0.0.1.nip.io/private",
        "http://2130706433/private",
        "https://public.example:22/private",
        "https://public.example:/private",
        "https://public.example/%0d%0aHost:internal",
    ],
)
def test_forged_internal_observation_target_is_redacted_and_rejected_pre_network(
    monkeypatch,
    url,
):
    payload = mcp_inspect.build_mcp_observation_payload(
        _safe_observation_input(url=url)
    )
    resolver_calls = _public_resolver(monkeypatch)
    exchange_calls = _fake_exchange(monkeypatch, [])

    assert payload["targetUrl"] == QUERY_REDACTION
    assert url not in json.dumps(payload)
    result = mcp_inspect.submit_mcp_observation(payload)

    assert result["failure_code"] == "observation_payload_rejected"
    assert resolver_calls == []
    assert exchange_calls == []


def test_observation_target_dns_is_revalidated_before_canonical_submission(
    monkeypatch,
):
    resolver_calls = []

    def resolve(host, port):
        resolver_calls.append((host, port))
        if host == "public.example":
            return ("127.0.0.1",)
        return (PUBLIC_V4,)

    monkeypatch.setattr(transport, "_resolve_addresses", resolve)
    exchange_calls = _fake_exchange(monkeypatch, [])

    result = mcp_inspect.submit_mcp_observation(
        _safe_observation_payload()
    )

    assert result == {
        "status": "failure",
        "status_code": None,
        "failure_code": "observation_target_rejected",
        "recommended_action": "stop_safely",
    }
    assert resolver_calls == [("public.example", 443)]
    assert exchange_calls == []


@pytest.mark.parametrize("address", ["192.0.0.192", "168.63.129.16"])
def test_observation_dns_special_address_is_rejected_before_post(
    monkeypatch, address
):
    resolver_calls = []

    def resolve(host, port):
        resolver_calls.append((host, port))
        if host == "public.example":
            return (address,)
        return (PUBLIC_V4,)

    monkeypatch.setattr(transport, "_resolve_addresses", resolve)
    post_calls = _fake_observation_exchange(monkeypatch, [])

    result = mcp_inspect.submit_mcp_observation(_safe_observation_payload())

    assert result["failure_code"] == "observation_target_rejected"
    assert result["recommended_action"] == "stop_safely"
    assert resolver_calls == [("public.example", 443)]
    assert post_calls == []


def test_inspect_does_not_read_private_key_or_initialize_payment_runtime(monkeypatch):
    original_environ = os.environ

    class GuardedEnviron(dict):
        def _guard(self, key):
            if key == "AGENT_PRIVATE_KEY":
                raise AssertionError("Inspect must not read AGENT_PRIVATE_KEY")

        def get(self, key, default=None):
            self._guard(key)
            return super().get(key, default)

        def __getitem__(self, key):
            self._guard(key)
            return super().__getitem__(key)

        def __contains__(self, key):
            self._guard(key)
            return super().__contains__(key)

    monkeypatch.setattr(os, "environ", GuardedEnviron(original_environ))
    _public_resolver(monkeypatch)
    _fake_exchange(monkeypatch, [_FakeResponse(200), _FakeResponse(200)])

    from ln_church_agent.client import Payment402Client

    with patch.object(
        Payment402Client,
        "__init__",
        side_effect=AssertionError("payment client must not initialize"),
    ) as init_payment, patch.object(
        Payment402Client,
        "execute_detailed",
        side_effect=AssertionError("payment runtime must not execute"),
    ) as execute_payment:
        direct = inspect_url("https://public.example/")
        mcp_result = mcp_inspect.inspect_paid_surface("https://public.example/")

    init_payment.assert_not_called()
    execute_payment.assert_not_called()
    assert direct.will_execute_payment is False
    assert mcp_result["will_execute_payment"] is False
    assert mcp_result["safety"] == {
        "inspect_only": True,
        "payment_performed": False,
        "requires_private_key": False,
        "secrets_redacted": True,
    }


def test_transport_module_has_no_payment_wallet_signer_or_rpc_dependency():
    source = inspect.getsource(transport)
    forbidden = (
        "Payment402Client",
        "LnChurchClient",
        "Wallet",
        "Signer",
        "solana.rpc",
        "web3",
        "execute_detailed",
        "paid_retry",
    )
    assert all(token not in source for token in forbidden)


def test_public_inspect_api_exposes_no_resolver_ip_or_proxy_override():
    forbidden_names = {
        "resolver",
        "resolve",
        "addresses",
        "ip_policy",
        "proxy",
        "proxies",
        "trust_env",
        "verify",
        "headers",
    }
    for callable_object in (
        inspect_url,
        mcp_inspect.inspect_paid_surface,
        mcp_inspect.submit_mcp_observation,
    ):
        assert forbidden_names.isdisjoint(inspect.signature(callable_object).parameters)


@pytest.mark.parametrize(
    "header",
    [
        'L402 macaroon="DUMMY_RAW_MACAROON_P0_3", invoice="DUMMY_RAW_INVOICE_P0_3"',
        'MPP invoice="DUMMY_RAW_MPP_INVOICE_P0_3", intent="charge"',
    ],
)
def test_l402_and_mpp_raw_invoice_material_never_reaches_mcp_output(monkeypatch, header):
    _public_resolver(monkeypatch)
    _fake_exchange(
        monkeypatch,
        [
            _FakeResponse(
                402,
                headers={"WWW-Authenticate": header},
                url="https://public.example/",
            )
        ],
    )

    result = mcp_inspect.inspect_paid_surface("https://public.example/")
    serialized = json.dumps(result, sort_keys=True)

    assert "DUMMY_RAW_MACAROON_P0_3" not in serialized
    assert "DUMMY_RAW_INVOICE_P0_3" not in serialized
    assert "DUMMY_RAW_MPP_INVOICE_P0_3" not in serialized
    for option in result["settlement_options"]:
        if option["rail"] in {"L402", "MPP"}:
            assert option["pay_to"] in {None, QUERY_REDACTION}


def test_untrusted_x402_fields_cannot_smuggle_secret_material(monkeypatch):
    raw_invoice = "lnbc1" + ("a" * 60)
    raw_private_material = "-----BEGIN " + "PRIVATE KEY-----DUMMY"
    raw_bearer = "Bearer DUMMY_X402_SECRET_MATERIAL"
    requirement = {
        "scheme": "exact",
        "network": "eip155:1",
        "asset": raw_private_material,
        "amount": raw_bearer,
        "payTo": raw_invoice,
    }
    parsed = SimpleNamespace(
        _inspect_semantically_valid=True,
        scheme="exact",
        network="eip155:1",
        asset=raw_private_material,
        amount=raw_bearer,
        payment_intent=None,
        draft_shape=None,
        source=None,
        parameters={
            "_all_accepted": [requirement],
            "_raw_accepted": requirement,
            "_selection_reason": "first_acceptable",
        },
    )
    _public_resolver(monkeypatch)
    _fake_exchange(monkeypatch, [_FakeResponse(402), _FakeResponse(402)])

    with patch(
        "ln_church_agent.cli.parse_challenge_from_response",
        return_value=parsed,
    ):
        cli_result = inspect_url("https://public.example/")
        mcp_result = mcp_inspect.inspect_paid_surface(
            "https://public.example/"
        )

    serialized = json.dumps(
        {"cli": cli_result.model_dump(), "mcp": mcp_result},
        sort_keys=True,
    )
    assert raw_invoice not in serialized
    assert raw_private_material not in serialized
    assert raw_bearer not in serialized
    assert cli_result.settlement_options[0].asset == QUERY_REDACTION
    assert cli_result.settlement_options[0].amount == QUERY_REDACTION
    assert cli_result.settlement_options[0].pay_to == QUERY_REDACTION
    assert mcp_result["safety"]["secrets_redacted"] is True


@pytest.mark.parametrize(
    "hostile_asset",
    [
        "ResetToken1234567890",
        "0x0123456789abcdef0123456789abcdef01234567",
    ],
)
def test_regex_shaped_public_scalars_do_not_become_exfiltration_channels(
    monkeypatch, hostile_asset
):
    hostile_network = "eip155:12345678901234567890"
    hostile_amount = "9876543210987654321098765432109876543210"
    hostile_pay_to = "0x1111111111111111111111111111111111111111"
    requirement = {
        "scheme": "exact",
        "network": hostile_network,
        "asset": hostile_asset,
        "amount": hostile_amount,
        "payTo": hostile_pay_to,
    }
    parsed = SimpleNamespace(
        _inspect_semantically_valid=True,
        scheme="exact",
        network=hostile_network,
        asset=hostile_asset,
        amount=hostile_amount,
        payment_intent=None,
        draft_shape=None,
        source=None,
        parameters={
            "_all_accepted": [requirement],
            "_raw_accepted": requirement,
            "_selection_reason": "first_acceptable",
        },
    )
    _public_resolver(monkeypatch)
    _fake_exchange(monkeypatch, [_FakeResponse(402), _FakeResponse(402)])

    with patch(
        "ln_church_agent.cli.parse_challenge_from_response",
        return_value=parsed,
    ):
        cli_result = inspect_url("https://public.example/")
        mcp_result = mcp_inspect.inspect_paid_surface(
            "https://public.example/"
        )
    payload = mcp_inspect.build_mcp_observation_payload(mcp_result)
    serialized = json.dumps({
        "cli": cli_result.model_dump(),
        "mcp": mcp_result,
        "payload": payload,
    })

    assert hostile_network not in serialized
    assert hostile_asset not in serialized
    assert hostile_amount not in serialized
    assert hostile_pay_to not in serialized
    assert cli_result.settlement_options[0].network == QUERY_REDACTION
    assert cli_result.settlement_options[0].asset == QUERY_REDACTION
    assert cli_result.settlement_options[0].amount == QUERY_REDACTION
    assert cli_result.settlement_options[0].pay_to == QUERY_REDACTION
    assert (
        cli_result.settlement_options[0].raw_requirement_fingerprint
        == QUERY_REDACTION
    )
    assert payload["protocol"]["network"] == "unknown"
    assert payload["protocol"]["asset"] == "unknown"


def test_mixed_type_and_oversized_accepts_are_bounded_without_exception():
    valid_requirement = {
        "scheme": "exact",
        "network": "eip155:1",
        "asset": "USDC",
        "amount": "1",
        "payTo": "0x1111111111111111111111111111111111111111",
    }
    parsed = SimpleNamespace(
        scheme="exact",
        network="eip155:1",
        asset="USDC",
        amount="1",
        parameters={
            "_all_accepted": (
                [valid_requirement, "attacker", None]
                + [dict(valid_requirement) for _ in range(64)]
            ),
            "_raw_accepted": valid_requirement,
            "_selection_reason": "first_acceptable",
        },
    )

    options, selected = _extract_settlement_options(parsed)

    assert len(options) == 30
    assert selected is not None
    assert selected.selected is True
    assert all(option.source.startswith("accepts[") for option in options)


@pytest.mark.parametrize("source_kind", ["header", "json_key"])
def test_grant_signal_field_names_cannot_expose_private_key_material(
    monkeypatch, source_kind
):
    private_key = "0x" + ("4" * 64)
    hostile_name = "grant_" + private_key
    if source_kind == "header":
        responses = [
            _FakeResponse(200, headers={"X-" + hostile_name: "true"}),
            _FakeResponse(200, headers={"X-" + hostile_name: "true"}),
        ]
    else:
        content = json.dumps({hostile_name: True}).encode("utf-8")
        responses = [
            _FakeResponse(200, content=content),
            _FakeResponse(200, content=content),
        ]
    _public_resolver(monkeypatch)
    _fake_exchange(monkeypatch, responses)

    direct = inspect_url("https://public.example/")
    mcp_result = mcp_inspect.inspect_paid_surface(
        "https://public.example/"
    )
    serialized = json.dumps(
        {"direct": direct.model_dump(), "mcp": mcp_result},
        sort_keys=True,
    )

    assert direct.grant_signal_detected is True
    assert mcp_result["grant_signal_detected"] is True
    assert direct.grant_signals.detected_fields == ["grant"]
    assert mcp_result["grant_signals"]["detected_fields"] == ["grant"]
    assert private_key not in serialized
    assert hostile_name not in serialized
    assert mcp_result["safety"]["secrets_redacted"] is True


def test_x402_recipient_addresses_are_fixed_redacted_scalars():
    evm_address = "0x1111111111111111111111111111111111111111"
    solana_address = "2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4"
    invoice = "lnbc1" + ("a" * 60)

    assert _public_x402_pay_to(evm_address, "eip155:1") == QUERY_REDACTION
    assert _public_x402_pay_to(
        solana_address,
        "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    ) == QUERY_REDACTION
    assert _public_x402_pay_to(invoice, "eip155:1") == QUERY_REDACTION


def test_p0_1_query_and_secret_metadata_redaction_regression():
    raw_url = "https://public.example/path?custom=" + RAW_QUERY_SECRET + "#fragment"
    redacted = redact_inspect_public_url(raw_url)
    metadata = redact_remote_metadata(
        {
            "resource_url": raw_url,
            "nested": {"receipt_token": "DUMMY_RECEIPT_TOKEN_P0_2"},
        }
    )
    serialized = json.dumps(metadata)

    assert RAW_QUERY_SECRET not in redacted
    assert "fragment" not in redacted
    assert redacted == "https://public.example/"
    assert RAW_QUERY_SECRET not in serialized
    assert "DUMMY_RECEIPT_TOKEN_P0_2" not in serialized


def test_p0_2_mcp_receipt_token_remains_hash_only(monkeypatch):
    from ln_church_agent.integrations import mcp as payment_mcp

    raw_token = "DUMMY_P0_2_RECEIPT.header.payload.signature"
    client = MagicMock()
    client.agent_id = "agent-test"
    client.probe_token = "probe-present"
    client.faucet_token = None
    client.execute_detailed.return_value = SimpleNamespace(
        response={
            "result": "entropy",
            "message": "ok",
            "paid": True,
            "receipt": {"verify_token": raw_token},
        },
        settlement_receipt=None,
    )
    monkeypatch.setattr(payment_mcp, "get_client", lambda: client)

    output = payment_mcp.execute_paid_entropy_oracle()

    assert raw_token not in output
    assert sha256_prefixed(raw_token) in output


def test_canonical_svm_exact_still_halts_before_signing_rpc_or_paid_retry():
    from solders.keypair import Keypair

    from ln_church_agent.client import Payment402Client
    from ln_church_agent.exceptions import PaymentExecutionError

    sender = Keypair()
    destination = Keypair()

    class ForbiddenSvmSigner:
        address = str(sender.pubkey())

        def generate_svm_exact_payload(self, **_kwargs):
            raise AssertionError("canonical SVM exact signer must not run")

    requirement = {
        "x402Version": 2,
        "accepts": [
            {
                "scheme": "exact",
                "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
                "asset": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                "amount": "1000000",
                "payTo": str(destination.pubkey()),
                "extra": {"feePayer": str(sender.pubkey())},
            }
        ],
        "resource": {
            "url": "https://buyer.test/start",
            "description": "P0-3 regression",
            "mimeType": "application/json",
        },
    }
    encoded = base64.urlsafe_b64encode(
        json.dumps(requirement, separators=(",", ":")).encode("utf-8")
    ).decode("ascii").rstrip("=")
    response = MagicMock()
    response.status_code = 402
    response.url = "https://buyer.test/start"
    response.headers = {"PAYMENT-REQUIRED": encoded}
    response.content = b""
    response.json.side_effect = ValueError()

    client = Payment402Client()
    client.svm_signer = ForbiddenSvmSigner()
    with patch(
        "ln_church_agent.client.requests.request",
        return_value=response,
    ) as request, patch.object(
        client,
        "_process_payment",
        side_effect=AssertionError("payment must not run"),
    ) as process_payment, patch(
        "solana.rpc.api.Client.get_latest_blockhash",
        side_effect=AssertionError("RPC must not run"),
    ) as rpc:
        with pytest.raises(
            PaymentExecutionError,
            match="canonical SVM exact auto-payment",
        ):
            client.execute_detailed("GET", "https://buyer.test/start")

    assert request.call_count == 1
    process_payment.assert_not_called()
    rpc.assert_not_called()
