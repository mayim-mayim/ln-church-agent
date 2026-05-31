import pytest
import json
import base64
from unittest.mock import patch, MagicMock

from ln_church_agent.cli import inspect_url
from ln_church_agent.client import Payment402Client
from ln_church_agent.models import ParsedChallenge, ChallengeSource, PaymentPolicy
from ln_church_agent.exceptions import PaymentExecutionError
from ln_church_agent.capabilities import get_capability_matrix

def _mock_402_response(accepts_array: list) -> MagicMock:
    mock_res = MagicMock()
    mock_res.status_code = 402
    mock_res.content = b""
    mock_res.url = "http://test.local"
    
    payload = {"accepts": accepts_array}
    b64_str = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    mock_res.headers = {"PAYMENT-REQUIRED": b64_str}
    
    return mock_res

@patch("ln_church_agent.cli.requests.request")
def test_auth_capture_inspect_classification(mock_req):
    """Ensure auth-capture is correctly classified as an x402 observe-only settlement option."""
    mock_req.return_value = _mock_402_response([{
        "scheme": "auth-capture",
        "network": "eip155:8453",
        "asset": "USDC",
        "amount": "100",
        "payTo": "0xabc"
    }])

    res = inspect_url("http://test.local")

    assert res.ok is True
    assert res.recommended_action == "observe_only"
    assert res.diagnostic_class == "deferred_auth_capture_observed"
    assert res.will_execute_payment is False
    assert "x402" in res.settlement_rails_detected
    
    assert "authorization signature is not final settlement proof" in res.reason.lower()
    assert "inspect-only mode will not sign, capture, void, refund, or reclaim" in res.reason.lower()

    assert res.selected_settlement_option is not None
    sel = res.selected_settlement_option
    assert sel.scheme == "auth-capture"
    assert sel.rail == "x402"
    assert sel.execution_support == "observe_only"
    assert sel.settlement_model == "auth_capture_deferred_refundable"
    assert sel.authorization_artifact == "authorization_signature"
    assert sel.deferred_settlement is True

def test_auth_capture_execution_guard():
    """Ensure execution is strictly halted even if the policy overrides allow it."""
    parsed = ParsedChallenge(
        scheme="auth-capture",
        network="eip155:137",
        amount=1.0,
        asset="USDC",
        parameters={},
        source=ChallengeSource.STANDARD_X402
    )
    
    policy_overridden = PaymentPolicy(allowed_schemes=["auth-capture"])
    client = Payment402Client(policy=policy_overridden)
    
    with pytest.raises(PaymentExecutionError, match="auth_capture_execution_not_supported"):
        client._process_payment(parsed, {}, {})

def test_capability_matrix_contains_auth_capture():
    """Ensure the static matrix accurately maps auth-capture constraints."""
    matrix = get_capability_matrix()
    auth_cap = next((row for row in matrix if row["id"] == "x402_auth_capture"), None)
    
    assert auth_cap is not None
    assert auth_cap["layer"] == "settlement_rail"
    assert auth_cap["current_sdk_support"] == "observe_only"
    assert auth_cap["execution_behavior"] == "halt"
    assert auth_cap["proof_semantics"] == "authorization_signature_not_settlement_proof"
    assert auth_cap["default_recommended_action"] == "observe_only"