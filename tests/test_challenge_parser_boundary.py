import pytest
import base64
import json
import httpx
from pathlib import Path
from unittest.mock import patch

from ln_church_agent.client import Payment402Client
from ln_church_agent.models import ChallengeSource, PaymentPolicy
from ln_church_agent.exceptions import (
    NoValidPaymentChallengeError,
    PaymentChallengeError,
    PaymentExecutionError,
)

# Test 1: direct parser import
from ln_church_agent.challenges import (
    parse_challenge_from_response,
    parse_www_authenticate,
)


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(402, json={"accepts": []}),
        httpx.Response(402, json={"accepts": [{}]}),
        httpx.Response(402, json={"challenge": {}}),
        httpx.Response(402, headers={"PAYMENT-REQUIRED": 'foo="bar"'}),
        httpx.Response(402, headers={"PAYMENT-REQUIRED": ""}),
    ],
)
def test_semantic_malformed_markers_raise_typed_parser_error(response):
    with pytest.raises(PaymentChallengeError) as caught:
        parse_challenge_from_response(response)

    assert type(caught.value) is PaymentChallengeError
    assert str(caught.value) == "Malformed payment challenge."


def test_genuine_marker_absence_remains_distinct_parser_outcome():
    with pytest.raises(NoValidPaymentChallengeError):
        parse_challenge_from_response(httpx.Response(402, json={}))


def test_canonical_paid_surface_rejects_empty_legacy_header_view():
    fixture_path = (
        Path(__file__).parent
        / "fixtures"
        / "agent-server-l402-contract-v1.json"
    )
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    request = fixture["request"]
    response = fixture["response"]
    headers = dict(response["headers"])
    headers["PAYMENT-REQUIRED"] = ""
    httpx_response = httpx.Response(
        response["status"],
        headers=headers,
        json=response["body"],
        request=httpx.Request(
            request["method"],
            request["url"],
            headers=request["headers"],
        ),
    )

    with pytest.raises(PaymentChallengeError):
        parse_challenge_from_response(
            httpx_response,
            now=fixture["clock_unix_seconds"],
        )


def test_disallowed_exact_option_cannot_be_promoted_to_signer_requirement():
    payload = {
        "accepts": [{
            "scheme": "exact",
            "network": "eip155:8453",
            "asset": "USDC",
            "amount": "1000000",
            "payTo": "0x1111111111111111111111111111111111111111",
        }]
    }
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload).encode("utf-8")
    ).decode("ascii").rstrip("=")
    client = Payment402Client(
        policy=PaymentPolicy(
            allowed_networks=["eip155:1"],
            allowed_assets=["USDC"],
        )
    )

    parsed = client._parse_challenge(
        httpx.Response(402, headers={"PAYMENT-REQUIRED": encoded}),
        request_url="https://public.example/resource",
        method="GET",
        idempotency_key="public-idempotency-fixture",
    )

    assert parsed.parameters["_selection_reason"] == "no_allowed_network_match"
    assert parsed.parameters.get("_raw_accepted") is None
    assert not hasattr(parsed._canonical_requirement, "token_address_or_mint")
    assert not hasattr(parsed._canonical_requirement, "pay_to")
    with pytest.raises(PaymentExecutionError, match="not in allowed_networks"):
        client._enforce_policy(parsed, "https://public.example/resource")

def test_direct_parser_import():
    header = 'MPP invoice="lnbc123", intent="charge"'
    parsed = parse_www_authenticate(header)
    assert parsed.scheme == "MPP"
    assert parsed.draft_shape == "legacy-mpp-flat"

# Test 2: client wrapper compatibility
def test_client_wrapper_compatibility():
    client = Payment402Client()
    header = 'MPP invoice="lnbc123", intent="charge"'
    parsed = client._parse_www_authenticate(header, ChallengeSource.STANDARD_WWW)
    assert parsed.scheme == "MPP"

# Test 3: parser result equivalence
def test_parser_result_equivalence():
    client = Payment402Client()
    req_json = {"amount": "1000", "currency": "sats", "methodDetails": {"invoice": "lnbc123"}}
    b64_req = base64.urlsafe_b64encode(json.dumps(req_json).encode()).decode().rstrip('=')
    header = f'Payment id="ch_123", method="lightning", intent="charge", request="{b64_req}"'

    parsed1 = parse_www_authenticate(header, ChallengeSource.STANDARD_WWW)
    parsed2 = client._parse_www_authenticate(header, ChallengeSource.STANDARD_WWW)

    fields = [
        "scheme", "amount", "asset", "draft_shape", "payment_method", 
        "payment_intent", "request_b64_present", "decoded_request_valid"
    ]
    for field in fields:
        assert getattr(parsed1, field) == getattr(parsed2, field)
    
    assert parsed1.parameters.get("invoice") == parsed2.parameters.get("invoice")

# Test 4: no execution behavior change
@patch("ln_church_agent.client.LightningProvider")
def test_no_execution_behavior_change(MockLNProvider):
    mock_ln_adapter = MockLNProvider()
    client = Payment402Client(ln_adapter=mock_ln_adapter, allow_legacy_payment_auth_fallback=False)
    
    req_json = {"amount": "1000", "currency": "sats", "methodDetails": {"invoice": "lnbc123"}}
    b64_req = base64.urlsafe_b64encode(json.dumps(req_json).encode()).decode().rstrip('=')
    header = f'Payment id="ch_123", method="lightning", intent="charge", request="{b64_req}"'
    
    parsed = client._parse_www_authenticate(header, ChallengeSource.STANDARD_WWW)
    
    with pytest.raises(PaymentExecutionError, match="unsupported-payment-auth-json"):
        client._process_payment(parsed, {}, {}, method="GET", url="http://mock")
