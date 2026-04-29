import pytest
import base64
import json
from unittest.mock import patch

from ln_church_agent.client import Payment402Client
from ln_church_agent.models import ChallengeSource
from ln_church_agent.exceptions import PaymentExecutionError

# Test 1: direct parser import
from ln_church_agent.challenges import parse_www_authenticate

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