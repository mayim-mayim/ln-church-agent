"""Focused regressions for the P0-3 independent re-audit repair.

All DNS and transport interactions are local fakes.  The tests exercise the
public identity and failure contracts without opening a socket.
"""

import base64
import json
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from ln_church_agent import cli as cli_module
from ln_church_agent import inspect_transport as transport
from ln_church_agent.cli import inspect_url
from ln_church_agent.exceptions import PaymentChallengeError
from ln_church_agent.integrations import mcp_inspect


PUBLIC_ADDRESS = "8.8.8.8"
AUTHORITY_MARKER = "b01-reflected-query-marker"
RAW_PARSE_MARKER = "DUMMY_UNEXPECTED_PARSER_DETAIL_P0_3"
RAW_SEMANTIC_MARKER = "DUMMY_SEMANTIC_INVALID_DETAIL_P0_3"

_FORBIDDEN_INSPECT_SIDE_EFFECTS = (
    "ln_church_agent.integrations.mcp_inspect.submit_mcp_observation",
    "ln_church_agent.client.Payment402Client.__init__",
    "ln_church_agent.client.Payment402Client.execute_detailed",
    "ln_church_agent.crypto.evm.sign_standard_x402_evm",
    "ln_church_agent.crypto.solana.sign_standard_x402_solana",
    "ln_church_agent.crypto.lightning.pay_lightning_invoice",
    "ln_church_agent.inspect_transport._submit_observation_request",
)


class _FakeResponse:
    def __init__(self, status_code, *, headers=None, content=b""):
        self.status_code = status_code
        self.headers = dict(headers or {})
        self._content = content
        self.url = "https://public.example/"
        self.closed = False

    @property
    def content(self):
        return self._content

    def close(self):
        self.closed = True


def _install_public_resolver(monkeypatch):
    calls = []

    def resolve(host, port):
        calls.append((host, port))
        return (PUBLIC_ADDRESS,)

    monkeypatch.setattr(transport, "_resolve_addresses", resolve)
    return calls


def _install_get_exchange(monkeypatch, outcomes):
    calls = []
    queue = list(outcomes)

    def exchange(target, address, method, timeout, body=None):
        calls.append((target, address, method, timeout, body))
        if not queue:
            raise AssertionError("unexpected Inspect transport call")
        response = queue.pop(0)
        response.url = target.url
        return response

    monkeypatch.setattr(transport, "_exchange_once", exchange)
    return calls


def _run_cli_and_mcp(
    monkeypatch,
    content,
    *,
    headers=None,
    parser_exceptions=None,
):
    _install_public_resolver(monkeypatch)
    calls = _install_get_exchange(
        monkeypatch,
        [
            _FakeResponse(402, headers=headers, content=content),
            _FakeResponse(402, headers=headers, content=content),
        ],
    )

    with ExitStack() as stack:
        forbidden = [
            stack.enter_context(
                patch(target, side_effect=AssertionError(target))
            )
            for target in _FORBIDDEN_INSPECT_SIDE_EFFECTS
        ]
        if parser_exceptions is not None:
            stack.enter_context(
                patch.object(
                    cli_module,
                    "parse_challenge_from_response",
                    side_effect=parser_exceptions,
                )
            )
        cli_result = inspect_url("https://public.example/challenge")
        mcp_result = mcp_inspect.inspect_paid_surface(
            "https://public.example/challenge"
        )

    assert all(mock.call_count == 0 for mock in forbidden)
    assert len(calls) == 2
    return cli_result, mcp_result


def _assert_parser_contract(
    cli_result,
    mcp_result,
    *,
    failure_class,
    diagnostic_class,
    expected_ok,
    expected_action,
):
    assert cli_result.ok is expected_ok
    assert cli_result.error_stage == "parse"
    assert cli_result.failure_class == failure_class
    assert cli_result.failure_reason == failure_class
    assert cli_result.diagnostic_class == diagnostic_class
    assert cli_result.recommended_action == expected_action
    assert cli_result.will_execute_payment is False

    assert mcp_result["ok"] is expected_ok
    assert mcp_result["error_stage"] == "parse"
    assert mcp_result["failure_class"] == failure_class
    assert mcp_result["failure_reason"] == failure_class
    assert mcp_result["diagnostic_class"] == diagnostic_class
    assert mcp_result["recommended_action"] == expected_action
    assert mcp_result["will_execute_payment"] is False
    assert mcp_result["safety"]["payment_performed"] is False


def _assert_semantic_parse_failure(
    cli_result,
    mcp_result,
    *,
    caplog,
    raw_marker=RAW_SEMANTIC_MARKER,
):
    _assert_parser_contract(
        cli_result,
        mcp_result,
        failure_class="parse_failure",
        diagnostic_class="invalid_payment_auth_request",
        expected_ok=True,
        expected_action="reject_invalid",
    )
    assert cli_result.surfaces_detected == []
    assert cli_result.rails_detected == []
    assert cli_result.settlement_rails_detected == []
    assert cli_result.settlement_options == []
    assert cli_result.selected_settlement_option is None
    assert mcp_result["surfaces_detected"] == []
    assert mcp_result["rails_detected"] == []
    assert mcp_result["settlement_rails_detected"] == []
    assert mcp_result["settlement_options"] == []
    assert mcp_result["selected_settlement_option"] is None

    payload = mcp_inspect.build_mcp_observation_payload(mcp_result)
    assert mcp_inspect._validate_observation_payload(payload) is None
    assert payload["protocol"]["rail"] == "unknown"
    assert payload["protocol"]["network"] == "unknown"
    assert payload["protocol"]["asset"] == "unknown"
    assert payload["protocol"]["payment_intent"] == "unknown"
    assert payload["protocol"]["selected_settlement_option"] is None
    assert payload["settlement_options_summary"] == []
    assert payload["evidence"]["payment_performed"] is False
    assert payload["evidence"]["payment_receipt_present"] is False

    serialized = json.dumps(
        {
            "cli": cli_result.model_dump(),
            "mcp": mcp_result,
            "payload": payload,
        },
        sort_keys=True,
    )
    assert raw_marker not in serialized
    assert raw_marker not in caplog.text


@pytest.mark.parametrize("terminal_status", [200, 500])
def test_initial_origin_survives_cross_origin_redirect_in_every_public_boundary(
    monkeypatch,
    terminal_status,
):
    initial_url = (
        "https://public.example/start?reflected=" + AUTHORITY_MARKER
    )
    redirect_url = (
        "https://" + AUTHORITY_MARKER + ".redirect.example/final"
    )
    expected_public_url = "https://public.example/"

    resolver_calls = _install_public_resolver(monkeypatch)
    get_calls = _install_get_exchange(
        monkeypatch,
        [
            _FakeResponse(302, headers={"Location": redirect_url}),
            _FakeResponse(terminal_status),
            _FakeResponse(302, headers={"Location": redirect_url}),
            _FakeResponse(terminal_status),
        ],
    )

    cli_result = inspect_url(initial_url)
    mcp_result = mcp_inspect.inspect_paid_surface(initial_url)
    payload = mcp_inspect.build_mcp_observation_payload(mcp_result)

    assert cli_result.url == expected_public_url
    assert mcp_result["url"] == expected_public_url
    assert payload["targetUrl"] == expected_public_url
    assert mcp_inspect._validate_observation_payload(payload) is None
    assert cli_result.ok is (terminal_status == 200)
    assert mcp_result["ok"] is (terminal_status == 200)

    wire_bodies = []

    def observation_exchange(target, address, timeout, body):
        del target, address, timeout
        wire_bodies.append(body)
        return 204

    monkeypatch.setattr(
        transport,
        "_exchange_observation_once",
        observation_exchange,
    )
    submission = mcp_inspect.submit_mcp_observation(payload)

    assert submission["status"] == "success"
    assert submission["status_code"] == 204
    assert len(wire_bodies) == 1
    wire_payload = json.loads(wire_bodies[0].decode("utf-8"))
    assert wire_payload["targetUrl"] == expected_public_url

    serialized = json.dumps(
        {
            "cli_json": cli_result.model_dump_json(),
            "mcp": mcp_result,
            "payload": payload,
            "wire": wire_payload,
        },
        sort_keys=True,
    )
    assert AUTHORITY_MARKER not in serialized
    assert len(get_calls) == 4
    assert ("public.example", 443) in resolver_calls
    assert (AUTHORITY_MARKER + ".redirect.example", 443) in resolver_calls


def test_transport_failure_cannot_replace_initial_public_identity(monkeypatch):
    initial_url = "https://public.example/start?reflected=" + AUTHORITY_MARKER
    hostile_public_url = "https://" + AUTHORITY_MARKER + ".redirect.example/"

    def fail_with_transport_state(*_args, **_kwargs):
        raise transport.InspectTransportError(
            "transport",
            "network_error",
            public_url=hostile_public_url,
        )

    monkeypatch.setattr(cli_module, "_inspect_request", fail_with_transport_state)

    cli_result = inspect_url(initial_url)
    mcp_result = mcp_inspect.inspect_paid_surface(initial_url)

    assert cli_result.url == "https://public.example/"
    assert mcp_result["url"] == "https://public.example/"
    assert cli_result.failure_class == "network_error"
    assert mcp_result["failure_class"] == "network_error"

    serialized = json.dumps(
        {"cli": cli_result.model_dump(), "mcp": mcp_result},
        sort_keys=True,
    )
    assert AUTHORITY_MARKER not in serialized


def test_real_malformed_ap2_body_is_typed_semantic_parse_failure(
    monkeypatch,
    caplog,
):
    caplog.set_level("DEBUG")
    body = {
        "protocol": "ap2",
        "intent": "payment_mandate",
        "accepts": [1],
        "debug": RAW_PARSE_MARKER,
    }
    cli_result, mcp_result = _run_cli_and_mcp(
        monkeypatch,
        json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )

    _assert_parser_contract(
        cli_result,
        mcp_result,
        failure_class="parse_failure",
        diagnostic_class="invalid_payment_auth_request",
        expected_ok=True,
        expected_action="reject_invalid",
    )
    payload = mcp_inspect.build_mcp_observation_payload(mcp_result)
    assert mcp_inspect._validate_observation_payload(payload) is None
    serialized = json.dumps(
        {
            "cli_json": cli_result.model_dump_json(),
            "mcp": mcp_result,
            "payload": payload,
        },
        sort_keys=True,
    )
    assert RAW_PARSE_MARKER not in serialized
    assert RAW_PARSE_MARKER not in caplog.text
    assert mcp_result["surfaces_detected"] == []


@pytest.mark.parametrize(
    "body",
    [
        {"accepts": []},
        {"protocol": "ap2", "intent": "payment_mandate", "accepts": []},
        {"protocol": "acp", "intent": "cart", "accepts": []},
        {
            "protocol": "ap2",
            "intent": "payment_mandate",
            "accepted_payments": [],
        },
        {
            "protocol": "acp",
            "intent": "cart",
            "accepted_payments": [{}],
        },
        {"accepts": {}},
        {"accepts": RAW_SEMANTIC_MARKER},
        {"accepts": [1]},
        {"accepts": [None]},
        {"accepts": [{}]},
        {"accepts": [{"network": "eip155:8453"}]},
        {"accepts": [{"scheme": "exact"}]},
        {"accepts": [{"scheme": "", "network": "eip155:8453"}]},
        {"accepts": [{"scheme": "exact", "network": ""}]},
        {"accepts": [{"scheme": "exact", "network": "not-a-network"}]},
        {
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": RAW_SEMANTIC_MARKER,
            }]
        },
        {
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "decimals": -1,
            }]
        },
        {
            "accepts": [{
                "scheme": "x402",
                "network": "eip155:8453",
            }]
        },
        {
            "accepts": [{
                "scheme": "x402",
                "network": "eip155:8453",
                "asset": "USDC",
                "amount": "1",
                "decimals": "6",
                "payTo": "0x1111111111111111111111111111111111111111",
            }]
        },
        {
            "accepts": [{
                "scheme": "x402",
                "network": "eip155:8453",
                "asset": "USDC",
                "symbol": "JPYC",
                "amount": "1",
                "payTo": "0x1111111111111111111111111111111111111111",
            }]
        },
        {
            "accepts": [{
                "scheme": "x402",
                "network": "eip155:8453",
                "asset": "USDC",
                "amount": "1",
                "maxAmountRequired": "2",
                "payTo": "0x1111111111111111111111111111111111111111",
            }]
        },
        {
            "accepts": [
                {
                    "scheme": "x402",
                    "network": "eip155:8453",
                    "asset": "USDC",
                    "amount": "1",
                    "payTo": "0x1111111111111111111111111111111111111111",
                },
                {"scheme": "x402", "network": "eip155:8453"},
            ]
        },
        {
            "accepts": [
                {"scheme": "exact", "network": "eip155:8453"},
                {},
            ]
        },
        {
            "accepts": [
                {"scheme": "exact", "network": "eip155:8453"},
                {"scheme": "x402", "network": "eip155:8453"},
            ]
        },
        {
            "accepts": [
                {"scheme": "x402", "network": "eip155:8453"},
                {"scheme": "exact", "network": "eip155:8453"},
            ]
        },
        {
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "parameters": [],
            }]
        },
        {
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "extra": RAW_SEMANTIC_MARKER,
            }]
        },
        {"challenge": {}},
        {"challenge": []},
        {"challenge": RAW_SEMANTIC_MARKER},
        {"challenge": {"scheme": "L402"}},
        {"challenge": {"scheme": "L402", "amount": 0, "asset": "SATS"}},
        {"challenge": {"scheme": "MPP", "amount": 10, "asset": "SATS"}},
        {
            "challenge": {
                "scheme": "bogus",
                "network": "eip155:8453",
                "amount": 1,
                "asset": "USDC",
            }
        },
        {
            "challenge": {
                "scheme": "batch-settlement",
                "network": "eip155:8453",
                "amount": 0,
                "asset": "USDC",
            }
        },
        {"challenge": {"scheme": "x402", "amount": 0, "asset": "USDC"}},
        {
            "challenge": {
                "scheme": "x402",
                "network": "eip155:8453",
                "amount": "1e-324",
                "asset": "USDC",
                "parameters": {
                    "payTo": "0x1111111111111111111111111111111111111111"
                },
            }
        },
        {
            "challenge": {
                "scheme": "x402",
                "network": "eip155:8453",
                "amount": 1,
                "asset": "USDC",
                "parameters": {
                    "network": "eip155:1",
                    "payTo": "0x1111111111111111111111111111111111111111",
                },
            }
        },
        {
            "challenge": {
                "scheme": "L402",
                "amount": 10,
                "asset": "SATS",
            },
            "accepts": [],
        },
        {
            "challenge": {
                "scheme": "L402",
                "amount": 10,
                "asset": "SATS",
            },
            "resource": [],
        },
        {
            "challenge": {
                "scheme": "Payment",
                "amount": 0,
                "asset": "unknown",
                "parameters": {"invoice": "lnbc-incomplete"},
            },
        },
        {
            "accepts": [{"scheme": "exact", "network": "eip155:8453"}],
            "resource": [],
        },
        {
            "accepts": [{"scheme": "exact", "network": "eip155:8453"}],
            "network": {},
        },
        {
            "accepts": [{"scheme": "exact", "network": "eip155:8453"}],
            "decimals": {},
        },
        {
            "accepts": [{"scheme": "exact", "network": "eip155:8453"}],
            "chainId": {},
        },
        {
            "accepts": [{"scheme": "exact", "network": "eip155:8453"}],
            "x402Version": 999,
        },
        {
            "accepts": [{"scheme": "exact", "network": "eip155:8453"}],
            "scheme": "L402",
        },
        {
            "network": "eip155:1",
            "accepts": [{
                "scheme": "x402",
                "network": "eip155:8453",
                "asset": "USDC",
                "amount": "1",
                "payTo": "0x1111111111111111111111111111111111111111",
            }],
        },
        {
            "chainId": 1,
            "chain_id": 8453,
            "accepts": [{"scheme": "exact", "network": "eip155:8453"}],
        },
        {
            "chainId": 1,
            "accepts": [{"scheme": "exact", "network": "eip155:8453"}],
        },
        {
            "asset": "JPYC",
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "asset": "USDC",
            }],
        },
        {
            "amount": 2,
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "1",
            }],
        },
        {
            "payTo": "0x2222222222222222222222222222222222222222",
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "payTo": "0x1111111111111111111111111111111111111111",
            }],
        },
        {
            "contract": "0x2222222222222222222222222222222222222222",
            "accepts": [{
                "scheme": "x402",
                "network": "eip155:8453",
                "asset": "USDC",
                "amount": "1",
                "payTo": "0x1111111111111111111111111111111111111111",
            }],
        },
        {
            "decimals": 18,
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "decimals": 6,
            }],
        },
        {
            "parameters": {"network": "eip155:1"},
            "accepts": [{"scheme": "exact", "network": "eip155:8453"}],
        },
        {
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "parameters": {"network": "eip155:1"},
            }],
        },
        {
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "payTo": "0x1111111111111111111111111111111111111111",
                "extra": {
                    "payTo": "0x2222222222222222222222222222222222222222"
                },
            }],
        },
        {
            "accepts": [{"scheme": "exact", "network": "eip155:8453"}],
            "challenge": {},
        },
        {
            "accepts": [{"scheme": "exact", "network": "eip155:8453"}],
            "settlement": {},
        },
        {
            "scheme": "x402",
            "accepts": [
                {"scheme": "exact", "network": "eip155:8453"},
                {
                    "scheme": "x402",
                    "network": "eip155:8453",
                    "asset": "USDC",
                    "amount": "1",
                    "payTo": "0x1111111111111111111111111111111111111111",
                },
            ],
        },
        {
            "scheme": {},
            "accepts": [{"scheme": "exact", "network": "eip155:8453"}],
        },
        {
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "asset": "USDC",
                "token": "0x1111111111111111111111111111111111111111",
                "mint": "0x2222222222222222222222222222222222222222",
            }],
        },
        {
            "schema_version": "ln_church.paid_surface_challenge.v1",
            "accepted_payments": [],
            "challenge": {},
        },
        {
            "schema_version": "ln_church.paid_surface_challenge.v1",
            "accepted_payments": [],
            "extensions": [],
        },
        {
            "protocol": "okx-app",
            "intent": "charge",
            "payment": {},
            "challenge": {
                "scheme": "L402",
                "amount": 10,
                "asset": "SATS",
            },
        },
        {
            "protocol": "okx-app",
            "intent": "charge",
            "payment": {
                "method": "eip3009",
                "network": "eip155:196",
                "asset": "USDG",
            },
            "challenge": {
                "scheme": "L402",
                "amount": 10,
                "asset": "SATS",
            },
        },
        {"resource": {}},
        {"x402Version": 2},
        {"paymentRequirements": []},
    ],
)
def test_semantic_invalid_body_markers_fail_closed_before_success(
    monkeypatch,
    caplog,
    body,
):
    caplog.set_level("DEBUG")
    body = {**body, "debug": RAW_SEMANTIC_MARKER}
    cli_result, mcp_result = _run_cli_and_mcp(
        monkeypatch,
        json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )

    _assert_semantic_parse_failure(
        cli_result,
        mcp_result,
        caplog=caplog,
    )


def _encode_payment_header(payload):
    return base64.urlsafe_b64encode(
        json.dumps(payload).encode("utf-8")
    ).decode("ascii").rstrip("=")


def _payment_request_bytes():
    return json.dumps(
        {
            "method": "lightning",
            "intent": "charge",
            "methodDetails": {
                "invoice": "lnbc-public-fixture",
                "currency": "SATS",
                "amount": "1",
            },
        },
        separators=(",", ":"),
    ).encode("utf-8")


def _payment_request_header(encoded_request):
    return (
        'Payment id="public-fixture", method="lightning", '
        f'intent="charge", request="{encoded_request}"'
    )


@pytest.mark.parametrize("unpadded", [False, True])
def test_payment_request_accepts_canonical_padded_and_unpadded_base64url(
    monkeypatch,
    unpadded,
):
    encoded = base64.urlsafe_b64encode(_payment_request_bytes()).decode("ascii")
    assert encoded.endswith("=")
    if unpadded:
        encoded = encoded.rstrip("=")

    cli_result, mcp_result = _run_cli_and_mcp(
        monkeypatch,
        b"",
        headers={"WWW-Authenticate": _payment_request_header(encoded)},
    )

    assert cli_result.ok is True
    assert cli_result.failure_class is None
    assert {"Payment", "MPP"}.issubset(cli_result.rails_detected)
    assert cli_result.recommended_action == "pay_and_verify"
    assert cli_result.will_execute_payment is False
    assert mcp_result["ok"] is True
    assert mcp_result["failure_class"] is None
    assert {"Payment", "MPP"}.issubset(mcp_result["rails_detected"])
    assert mcp_result["safety"]["payment_performed"] is False


@pytest.mark.parametrize(
    "mutation",
    [
        "invalid_alphabet",
        "misplaced_padding",
        "excess_padding",
        "wrong_padding_count",
        "noncanonical_pad_bits",
    ],
)
def test_payment_request_rejects_noncanonical_base64url(
    monkeypatch,
    caplog,
    mutation,
):
    caplog.set_level("DEBUG")
    canonical = base64.urlsafe_b64encode(_payment_request_bytes()).decode("ascii")
    core = canonical.rstrip("=")
    if mutation == "invalid_alphabet":
        encoded = core[:8] + "!" + core[8:]
    elif mutation == "misplaced_padding":
        encoded = core[:8] + "=" + core[8:]
    elif mutation == "excess_padding":
        encoded = core + "==="
    elif mutation == "wrong_padding_count":
        encoded = core + "="
    else:
        assert canonical.endswith("==") and core.endswith("Q")
        encoded = core[:-1] + "R=="

    cli_result, mcp_result = _run_cli_and_mcp(
        monkeypatch,
        json.dumps({
            "protocol": "ap2",
            "intent": "payment_mandate",
            "debug": RAW_SEMANTIC_MARKER,
        }).encode("utf-8"),
        headers={"WWW-Authenticate": _payment_request_header(encoded)},
    )

    _assert_semantic_parse_failure(
        cli_result,
        mcp_result,
        caplog=caplog,
    )


@pytest.mark.parametrize(
    "decoded_request",
    [
        b"\xff\xfe",
        b"[]",
        (
            b'{"method":"lightning","intent":"charge",'
            b'"methodDetails":{"invoice":"one","INVOICE":"two"}}'
        ),
        (
            b'{"method":"lightning","intent":"charge",'
            b'"methodDetails":{"invoice":"lnbc-public-fixture"},'
            b'"amount":NaN}'
        ),
    ],
)
def test_payment_request_rejects_invalid_decoded_json(
    monkeypatch,
    caplog,
    decoded_request,
):
    caplog.set_level("DEBUG")
    encoded = base64.urlsafe_b64encode(decoded_request).decode("ascii").rstrip("=")
    cli_result, mcp_result = _run_cli_and_mcp(
        monkeypatch,
        json.dumps({
            "protocol": "ap2",
            "intent": "payment_mandate",
            "debug": RAW_SEMANTIC_MARKER,
        }).encode("utf-8"),
        headers={"WWW-Authenticate": _payment_request_header(encoded)},
    )

    _assert_semantic_parse_failure(
        cli_result,
        mcp_result,
        caplog=caplog,
    )


def _flat_x402_header(*suffixes):
    fields = [
        'scheme="x402"',
        'network="eip155:8453"',
        'amount="1"',
        'asset="USDC"',
        'destination="0x1111111111111111111111111111111111111111"',
        *suffixes,
    ]
    return ", ".join(fields)


def test_flat_payment_header_accepts_consistent_security_aliases(monkeypatch):
    token = "0x2222222222222222222222222222222222222222"
    destination = "0x1111111111111111111111111111111111111111"
    header = _flat_x402_header(
        'chainId="8453"',
        'chain_id="8453"',
        'maxAmountRequired="1"',
        'symbol="usdc"',
        'decimals="6"',
        f'contract="{token}"',
        f'token_address="{token}"',
        f'token="{token}"',
        f'mint="{token}"',
        f'payTo="{destination}"',
        'extension="public"',
    )

    cli_result, mcp_result = _run_cli_and_mcp(
        monkeypatch,
        b"",
        headers={"PAYMENT-REQUIRED": header},
    )

    assert cli_result.ok is True
    assert cli_result.failure_class is None
    assert cli_result.settlement_rails_detected == ["x402"]
    assert cli_result.will_execute_payment is False
    assert mcp_result["ok"] is True
    assert mcp_result["failure_class"] is None
    assert mcp_result["settlement_rails_detected"] == ["x402"]
    assert mcp_result["safety"]["payment_performed"] is False


@pytest.mark.parametrize(
    "suffix",
    [
        'chainId="1"',
        'maxAmountRequired="2"',
        'decimals="-1"',
        (
            'contract="0x2222222222222222222222222222222222222222", '
            'token_address="0x3333333333333333333333333333333333333333"'
        ),
        'payTo="0x2222222222222222222222222222222222222222"',
        'chainId="8453", chain_id="1"',
        'parameters.network="eip155:1"',
        'extra.chainId="1"',
    ],
)
def test_flat_payment_header_rejects_security_alias_contradictions(
    monkeypatch,
    caplog,
    suffix,
):
    caplog.set_level("DEBUG")
    header = _flat_x402_header(
        suffix,
        f'debug="{RAW_SEMANTIC_MARKER}"',
    )
    cli_result, mcp_result = _run_cli_and_mcp(
        monkeypatch,
        json.dumps({
            "protocol": "ap2",
            "intent": "payment_mandate",
            "debug": RAW_SEMANTIC_MARKER,
        }).encode("utf-8"),
        headers={"PAYMENT-REQUIRED": header},
    )

    _assert_semantic_parse_failure(
        cli_result,
        mcp_result,
        caplog=caplog,
    )


@pytest.mark.parametrize(
    "header",
    [
        (
            'scheme="x402" network="eip155:8453", amount="1", '
            'asset="USDC", '
            'destination="0x1111111111111111111111111111111111111111"'
        ),
        (
            'scheme=x402 network=eip155:8453, amount=1, asset=USDC, '
            'destination=0x1111111111111111111111111111111111111111'
        ),
        _flat_x402_header('extension=publicchainId=1'),
        _flat_x402_header('extension=public;chainId=1'),
    ],
)
def test_flat_payment_header_requires_auth_param_delimiters(
    monkeypatch,
    caplog,
    header,
):
    caplog.set_level("DEBUG")
    cli_result, mcp_result = _run_cli_and_mcp(
        monkeypatch,
        json.dumps({
            "protocol": "ap2",
            "intent": "payment_mandate",
            "debug": RAW_SEMANTIC_MARKER,
        }).encode("utf-8"),
        headers={"PAYMENT-REQUIRED": header},
    )

    _assert_semantic_parse_failure(
        cli_result,
        mcp_result,
        caplog=caplog,
    )


@pytest.mark.parametrize("rail", ["L402", "MPP", "x402", "exact"])
def test_marker_only_canonical_options_fail_closed_in_public_boundaries(
    monkeypatch,
    caplog,
    rail,
):
    caplog.set_level("DEBUG")
    body = {
        "schema_version": "ln_church.paid_surface_challenge.v1",
        "accepted_payments": [{
            "settlement_rail": rail,
            "debug": RAW_SEMANTIC_MARKER,
        }],
    }
    cli_result, mcp_result = _run_cli_and_mcp(
        monkeypatch,
        json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )

    _assert_semantic_parse_failure(
        cli_result,
        mcp_result,
        caplog=caplog,
    )


@pytest.mark.parametrize("validity", ["missing", None, False, 1, "true"])
def test_inspect_rejects_unmarked_or_nonboolean_parser_validity(
    monkeypatch,
    caplog,
    validity,
):
    caplog.set_level("DEBUG")
    attributes = {} if validity == "missing" else {
        "_inspect_semantically_valid": validity
    }
    parsed = SimpleNamespace(**attributes)
    body = json.dumps({
        "protocol": "ap2",
        "intent": "payment_mandate",
        "debug": RAW_SEMANTIC_MARKER,
    }).encode("utf-8")
    cli_result, mcp_result = _run_cli_and_mcp(
        monkeypatch,
        body,
        parser_exceptions=lambda *_args, **_kwargs: parsed,
    )

    _assert_semantic_parse_failure(
        cli_result,
        mcp_result,
        caplog=caplog,
    )


@pytest.mark.parametrize(
    "payment_header",
    [
        "",
        f'foo="{RAW_SEMANTIC_MARKER}"',
        (
            'scheme="x402", network="eip155:8453", '
            f'amount="{RAW_SEMANTIC_MARKER}", asset="USDC", '
            'destination="0x1111111111111111111111111111111111111111"'
        ),
        (
            'scheme="x402", network="eip155:8453", amount="1", '
            'asset="USDC"'
        ),
        _encode_payment_header({"foo": RAW_SEMANTIC_MARKER}),
        _encode_payment_header({
            "scheme": "L402",
            "network": "lightning",
            "amount": 1,
            "asset": "SATS",
        }),
        _encode_payment_header({
            "scheme": "x402",
            "network": "unknown:1",
            "amount": 1,
            "asset": "USDC",
            "destination": "0x1111111111111111111111111111111111111111",
        }),
        (
            'scheme="x402", network="unknown:1", amount="1", '
            'asset="USDC", '
            'destination="0x1111111111111111111111111111111111111111"'
        ),
        _encode_payment_header({
            "scheme": "MPP",
            "network": "lightning",
            "amount": 1,
            "asset": "SATS",
        }),
        _encode_payment_header({
            "scheme": "bogus",
            "network": "eip155:8453",
            "amount": 1,
            "asset": "USDC",
            "destination": "0x1111111111111111111111111111111111111111",
        }),
        _encode_payment_header({
            "scheme": "exact",
            "network": "not-a-network",
            "amount": 1,
            "asset": "USDC",
            "destination": "0x1111111111111111111111111111111111111111",
        }),
        _encode_payment_header({
            "scheme": "x402",
            "network": "eip155:8453",
            "amount": 1,
            "asset": "USDC",
            "destination": "0x1111111111111111111111111111111111111111",
            "payTo": "0x2222222222222222222222222222222222222222",
        }),
        _encode_payment_header({
            "scheme": "x402",
            "network": "eip155:8453",
            "chainId": 1,
            "amount": 1,
            "asset": "USDC",
            "destination": "0x1111111111111111111111111111111111111111",
        }),
        _encode_payment_header({
            "scheme": "x402",
            "network": "eip155:8453",
            "amount": 1,
            "asset": "USDC",
            "destination": "0x1111111111111111111111111111111111111111",
            "contract": "0x1111111111111111111111111111111111111111",
            "token_address": "0x2222222222222222222222222222222222222222",
        }),
        _encode_payment_header({
            "scheme": "x402",
            "network": "eip155:8453",
            "amount": 1,
            "asset": "USDC",
            "destination": "0x1111111111111111111111111111111111111111",
            "decimals": {},
        }),
        _encode_payment_header({
            "scheme": "x402",
            "network": "eip155:8453",
            "amount": 1,
            "asset": "USDC",
            "destination": "0x1111111111111111111111111111111111111111",
            "parameters": {"network": "eip155:1"},
        }),
        _encode_payment_header({
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
            }]
        }) + "!!!!",
        base64.urlsafe_b64encode(
            (
                '{"accepts":[],"accepts":[{"scheme":"exact",'
                '"network":"eip155:8453"}]}'
            ).encode("utf-8")
        ).decode("ascii").rstrip("="),
    ],
)
def test_semantic_invalid_payment_headers_cannot_borrow_ap2_success(
    monkeypatch,
    caplog,
    payment_header,
):
    caplog.set_level("DEBUG")
    body = {
        "protocol": "ap2",
        "intent": "payment_mandate",
        "debug": RAW_SEMANTIC_MARKER,
    }
    cli_result, mcp_result = _run_cli_and_mcp(
        monkeypatch,
        json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "PAYMENT-REQUIRED": payment_header,
        },
    )

    _assert_semantic_parse_failure(
        cli_result,
        mcp_result,
        caplog=caplog,
    )


@pytest.mark.parametrize(
    "body",
    [
        {
            "protocol": "ap2",
            "intent": "payment_mandate",
            "accepts": [],
        },
        {
            "protocol": "ap2",
            "intent": "payment_mandate",
            "accepted_payments": [],
        },
        {
            "protocol": "okx-app",
            "intent": "charge",
            "payment": {},
        },
    ],
)
def test_valid_header_cannot_mask_malformed_body_settlement_marker(
    monkeypatch,
    caplog,
    body,
):
    caplog.set_level("DEBUG")
    body = {**body, "debug": RAW_SEMANTIC_MARKER}
    payment_header = _encode_payment_header({
        "accepts": [{
            "scheme": "exact",
            "network": "eip155:8453",
        }]
    })
    cli_result, mcp_result = _run_cli_and_mcp(
        monkeypatch,
        json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "PAYMENT-REQUIRED": payment_header,
        },
    )

    _assert_semantic_parse_failure(
        cli_result,
        mcp_result,
        caplog=caplog,
    )


def test_conflicting_valid_header_and_body_contracts_fail_closed(
    monkeypatch,
    caplog,
):
    caplog.set_level("DEBUG")
    body = {
        "accepts": [{
            "scheme": "exact",
            "network": "eip155:1",
            "asset": "USDC",
            "amount": "1",
            "payTo": "0x1111111111111111111111111111111111111111",
        }],
        "debug": RAW_SEMANTIC_MARKER,
    }
    payment_header = _encode_payment_header({
        "accepts": [{
            "scheme": "exact",
            "network": "eip155:8453",
            "asset": "USDC",
            "amount": "1",
            "payTo": "0x1111111111111111111111111111111111111111",
        }]
    })
    cli_result, mcp_result = _run_cli_and_mcp(
        monkeypatch,
        json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "PAYMENT-REQUIRED": payment_header,
        },
    )

    _assert_semantic_parse_failure(
        cli_result,
        mcp_result,
        caplog=caplog,
    )


@pytest.mark.parametrize(
    "headers",
    [
        {"x-402-payment-required": f'foo="{RAW_SEMANTIC_MARKER}"'},
        {"WWW-Authenticate": f'L402 foo="{RAW_SEMANTIC_MARKER}"'},
        {"WWW-Authenticate": f'MPP intent="{RAW_SEMANTIC_MARKER}"'},
        {
            "WWW-Authenticate": (
                'MPP invoice="lnbc-public-fixture", '
                f'intent="{RAW_SEMANTIC_MARKER}"'
            )
        },
        {
            "WWW-Authenticate": (
                'MPP invoice="lnbc-public-fixture", amount="1", '
                'currency="USD", intent="charge"'
            )
        },
        {
            "WWW-Authenticate": (
                'MPP invoice="lnbc-public-fixture", amount="1e2", '
                'currency="SATS", intent="charge"'
            )
        },
        {
            "WWW-Authenticate": (
                'Payment id="public-fixture", method="lightning", '
                'intent="charge", '
                f'request="not-valid-base64-{RAW_SEMANTIC_MARKER}"'
            )
        },
        {
            "WWW-Authenticate": (
                'Payment id="public-fixture", method="eip3009", '
                'intent="charge", request="'
                + _encode_payment_header({
                    "method": "eip3009",
                    "intent": "charge",
                })
                + '"'
            )
        },
        {
            "WWW-Authenticate": (
                'Payment id="public-fixture", method="lightning", '
                'intent="charge", request="'
                + _encode_payment_header({
                    "method": "lightning",
                    "intent": "charge",
                    "invoice": "lnbc-public-fixture",
                    "currency": "USD",
                })
                + '"'
            )
        },
        {"WWW-Authenticate": f'x402 foo="{RAW_SEMANTIC_MARKER}"'},
        {
            "PAYMENT-REQUIRED": _encode_payment_header({
                "accepts": [{
                    "scheme": "exact",
                    "network": "eip155:8453",
                }]
            }),
            "X-PAYMENT-REQUIRED": f'foo="{RAW_SEMANTIC_MARKER}"',
        },
    ],
)
def test_all_payment_header_aliases_require_one_supported_contract(
    monkeypatch,
    caplog,
    headers,
):
    caplog.set_level("DEBUG")
    body = {
        "protocol": "ap2",
        "intent": "payment_mandate",
        "debug": RAW_SEMANTIC_MARKER,
    }
    cli_result, mcp_result = _run_cli_and_mcp(
        monkeypatch,
        json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
    )

    _assert_semantic_parse_failure(
        cli_result,
        mcp_result,
        caplog=caplog,
    )


@pytest.mark.parametrize(
    "headers",
    [
        {
            "WWW-Authenticate": (
                'MPP invoice="lnbc-public-fixture", intent="charge"'
            ),
            "PAYMENT-REQUIRED": f'foo="{RAW_SEMANTIC_MARKER}"',
        },
        {
            "WWW-Authenticate": (
                'Payment id="public-fixture", method="eip3009", '
                'intent="charge", request="'
                + _encode_payment_header({
                    "method": "eip3009",
                    "intent": "charge",
                    "amount": 10,
                })
                + '"'
            ),
            "PAYMENT-REQUIRED": f'foo="{RAW_SEMANTIC_MARKER}"',
        },
        {
            "WWW-Authenticate": (
                'Basic realm="public", L402 invoice="bad"'
            ),
            "PAYMENT-REQUIRED": _encode_payment_header({
                "accepts": [{
                    "scheme": "exact",
                    "network": "eip155:8453",
                }]
            }),
        },
    ],
)
def test_malformed_secondary_challenge_cannot_be_hidden_by_precedence(
    monkeypatch,
    caplog,
    headers,
):
    caplog.set_level("DEBUG")
    body = {
        "protocol": "ap2",
        "intent": "payment_mandate",
        "debug": RAW_SEMANTIC_MARKER,
    }
    cli_result, mcp_result = _run_cli_and_mcp(
        monkeypatch,
        json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
    )

    _assert_semantic_parse_failure(
        cli_result,
        mcp_result,
        caplog=caplog,
    )


def test_canonical_paid_surface_rejects_unrecognized_sibling_alias(
    monkeypatch,
    caplog,
):
    caplog.set_level("DEBUG")
    body = {
        "schema_version": "ln_church.paid_surface_challenge.v1",
        "accepted_payments": [],
        "debug": RAW_SEMANTIC_MARKER,
    }
    cli_result, mcp_result = _run_cli_and_mcp(
        monkeypatch,
        json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-PAYMENT-REQUIRED": f'foo="{RAW_SEMANTIC_MARKER}"',
        },
    )

    _assert_semantic_parse_failure(
        cli_result,
        mcp_result,
        caplog=caplog,
    )


@pytest.mark.parametrize(
    "case,expected_rail,expected_action",
    [
        ("l402", "L402", "pay_and_verify"),
        ("mpp", "MPP", "pay_and_verify"),
        ("body_challenge", "L402", "pay_and_verify"),
        ("flat_x402", "x402", "pay_and_verify"),
        ("accepts", "x402", "observe_only"),
        ("x402_accepts", "x402", "pay_and_verify"),
        ("body_accepts", "x402", "observe_only"),
    ],
)
def test_valid_payment_contracts_remain_recognized(
    monkeypatch,
    case,
    expected_rail,
    expected_action,
):
    headers = {}
    body = {}
    if case == "l402":
        headers["WWW-Authenticate"] = (
            'L402 macaroon="public-fixture", invoice="lnbc-public-fixture"'
        )
    elif case == "mpp":
        headers["WWW-Authenticate"] = (
            'MPP invoice="lnbc-public-fixture", intent="charge"'
        )
    elif case == "body_challenge":
        headers["Content-Type"] = "application/json"
        body = {
            "challenge": {"scheme": "L402", "amount": 10, "asset": "SATS"}
        }
    elif case == "flat_x402":
        headers["PAYMENT-REQUIRED"] = (
            'scheme="x402", network="eip155:8453", amount="1.5", '
            'asset="USDC", '
            'destination="0x1111111111111111111111111111111111111111"'
        )
    elif case in {"accepts", "body_accepts"}:
        payment_payload = {
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "asset": "USDC",
                "amount": "1",
                "payTo": "0x1111111111111111111111111111111111111111",
            }]
        }
        if case == "body_accepts":
            headers["Content-Type"] = "application/json"
            body = payment_payload
        else:
            headers["PAYMENT-REQUIRED"] = _encode_payment_header(
                payment_payload
            )
    else:
        headers["PAYMENT-REQUIRED"] = _encode_payment_header({
            "accepts": [{
                "scheme": "x402",
                "network": "eip155:8453",
                "asset": "USDC",
                "amount": "1",
                "decimals": 6,
                "payTo": "0x1111111111111111111111111111111111111111",
            }]
        })

    cli_result, mcp_result = _run_cli_and_mcp(
        monkeypatch,
        json.dumps(body).encode("utf-8"),
        headers=headers,
    )

    assert cli_result.ok is True
    assert cli_result.failure_class is None
    assert cli_result.settlement_rails_detected == [expected_rail]
    assert cli_result.recommended_action == expected_action
    assert cli_result.will_execute_payment is False
    assert mcp_result["ok"] is True
    assert mcp_result["failure_class"] is None
    assert mcp_result["settlement_rails_detected"] == [expected_rail]
    assert mcp_result["recommended_action"] == expected_action
    assert mcp_result["will_execute_payment"] is False
    assert mcp_result["safety"]["payment_performed"] is False


@pytest.mark.parametrize(
    "protocol,intent,expected_surface",
    [
        ("ap2", "payment_mandate", "AP2"),
        ("acp", "agentic_checkout", "ACP"),
    ],
)
def test_valid_commerce_and_x402_coexistence_remains_observe_only(
    monkeypatch,
    protocol,
    intent,
    expected_surface,
):
    body = {"protocol": protocol, "intent": intent}
    payment_header = _encode_payment_header({
        "accepts": [{
            "scheme": "exact",
            "network": "eip155:8453",
            "asset": "USDC",
            "amount": "1",
            "payTo": "0x1111111111111111111111111111111111111111",
        }]
    })
    cli_result, mcp_result = _run_cli_and_mcp(
        monkeypatch,
        json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "PAYMENT-REQUIRED": payment_header,
        },
    )

    assert cli_result.ok is True
    assert cli_result.surfaces_detected == [expected_surface]
    assert cli_result.settlement_rails_detected == ["x402"]
    assert cli_result.recommended_action == "observe_only"
    assert cli_result.will_execute_payment is False
    assert mcp_result["surfaces_detected"] == [expected_surface]
    assert mcp_result["settlement_rails_detected"] == ["x402"]
    assert mcp_result["recommended_action"] == "observe_only"
    assert mcp_result["safety"]["payment_performed"] is False


@pytest.mark.parametrize(
    "exception,failure_class,diagnostic_class,expected_ok,expected_action",
    [
        (
            RuntimeError(RAW_PARSE_MARKER),
            "unexpected_error",
            "x402_parse_error",
            False,
            "stop_safely",
        ),
        (
            PaymentChallengeError(RAW_PARSE_MARKER),
            "parse_failure",
            "invalid_payment_auth_request",
            True,
            "reject_invalid",
        ),
    ],
)
def test_typed_parser_outcomes_preempt_valid_ap2_commerce(
    monkeypatch,
    caplog,
    exception,
    failure_class,
    diagnostic_class,
    expected_ok,
    expected_action,
):
    caplog.set_level("DEBUG")
    body = {
        "protocol": "ap2",
        "intent": "payment_mandate",
        "mandate_id": "public-fixture",
    }
    cli_result, mcp_result = _run_cli_and_mcp(
        monkeypatch,
        json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        parser_exceptions=[exception, exception],
    )

    _assert_parser_contract(
        cli_result,
        mcp_result,
        failure_class=failure_class,
        diagnostic_class=diagnostic_class,
        expected_ok=expected_ok,
        expected_action=expected_action,
    )
    payload = mcp_inspect.build_mcp_observation_payload(mcp_result)
    assert mcp_inspect._validate_observation_payload(payload) is None
    serialized = json.dumps(
        {"cli": cli_result.model_dump(), "mcp": mcp_result, "payload": payload},
        sort_keys=True,
    )
    assert RAW_PARSE_MARKER not in serialized
    assert RAW_PARSE_MARKER not in caplog.text
    assert mcp_result["surfaces_detected"] == []


def test_real_no_commerce_absence_retains_no_valid_challenge_contract(
    monkeypatch,
):
    cli_result, mcp_result = _run_cli_and_mcp(
        monkeypatch,
        b"{}",
        headers={"Content-Type": "application/json"},
    )

    _assert_parser_contract(
        cli_result,
        mcp_result,
        failure_class="no_valid_challenge",
        diagnostic_class="unsupported_challenge_shape",
        expected_ok=True,
        expected_action="reject_invalid",
    )


def test_payment_auth_after_basic_cannot_borrow_ap2_success(monkeypatch):
    body = {"protocol": "ap2", "intent": "payment_mandate"}
    cli_result, mcp_result = _run_cli_and_mcp(
        monkeypatch,
        json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "WWW-Authenticate": (
                'Basic realm="public, L402 quoted text", '
                'L402 invoice="bad"'
            ),
        },
    )

    _assert_parser_contract(
        cli_result,
        mcp_result,
        failure_class="parse_failure",
        diagnostic_class="invalid_payment_auth_request",
        expected_ok=True,
        expected_action="reject_invalid",
    )


@pytest.mark.parametrize(
    "marker_field,marker",
    [
        ("payment", None),
        ("payment", []),
        ("payment", {}),
        ("payment", {"method": ""}),
        (
            "settlement",
            {"method": "eip3009", "network": "", "asset": "USDG"},
        ),
        (
            "payment",
            {
                "method": "eip3009",
                "network": "eip155:196",
                "asset": "USDG",
                "amount": "NaN",
            },
        ),
    ],
)
def test_malformed_okx_marker_cannot_borrow_commerce_success(
    monkeypatch,
    marker_field,
    marker,
):
    body = {
        "protocol": "okx-app",
        "intent": "charge",
        marker_field: marker,
    }
    cli_result, mcp_result = _run_cli_and_mcp(
        monkeypatch,
        json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )

    _assert_parser_contract(
        cli_result,
        mcp_result,
        failure_class="parse_failure",
        diagnostic_class="invalid_payment_auth_request",
        expected_ok=True,
        expected_action="reject_invalid",
    )


@pytest.mark.parametrize(
    "body,expected_surface",
    [
        (
            {"protocol": "ap2", "intent": "payment_mandate"},
            "AP2",
        ),
        (
            {"protocol": "acp", "intent": "agentic_checkout"},
            "ACP",
        ),
        (
            {
                "protocol": "okx-app",
                "intent": "charge",
                "broker": {"required": True},
                "payment": {
                    "method": "eip3009",
                    "network": "eip155:196",
                    "asset": "USDG",
                },
            },
            "OKX_APP",
        ),
    ],
)
def test_valid_commerce_only_absence_retains_observe_only(
    monkeypatch,
    body,
    expected_surface,
):
    cli_result, mcp_result = _run_cli_and_mcp(
        monkeypatch,
        json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )

    assert cli_result.ok is True
    assert cli_result.recommended_action == "observe_only"
    assert cli_result.surfaces_detected == [expected_surface]
    assert cli_result.will_execute_payment is False
    assert mcp_result["ok"] is True
    assert mcp_result["recommended_action"] == "observe_only"
    assert mcp_result["surfaces_detected"] == [expected_surface]
    assert mcp_result["will_execute_payment"] is False
    assert mcp_result["safety"]["payment_performed"] is False
