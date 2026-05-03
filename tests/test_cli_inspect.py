import pytest
from unittest.mock import patch, MagicMock
from ln_church_agent.cli import inspect_url
import requests
import base64
import json

@patch("ln_church_agent.cli.requests.request")
def test_inspect_l402_pay_and_verify(mock_req):
    mock_res = MagicMock()
    mock_res.status_code = 402
    mock_res.headers = {"WWW-Authenticate": 'L402 macaroon="mac", invoice="inv"'}
    mock_res.content = b""
    mock_res.url = "http://test.local"
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    assert res.ok is True
    assert res.recommended_action == "pay_and_verify"
    assert "L402" in res.rails_detected
    assert res.will_execute_payment is False

@patch("ln_church_agent.cli.requests.request")
def test_inspect_mpp_charge_pay_and_verify(mock_req):
    mock_res = MagicMock()
    mock_res.status_code = 402
    mock_res.headers = {"WWW-Authenticate": 'MPP invoice="inv", intent="charge"'}
    mock_res.content = b""
    mock_res.url = "http://test.local"
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    assert res.ok is True
    assert res.recommended_action == "pay_and_verify"
    assert res.payment_intent == "charge"
    assert "MPP" in res.rails_detected

@patch("ln_church_agent.cli.requests.request")
def test_inspect_mpp_session_stop_safely(mock_req):
    mock_res = MagicMock()
    mock_res.status_code = 402
    mock_res.headers = {"WWW-Authenticate": 'MPP invoice="inv", intent="session"'}
    mock_res.content = b""
    mock_res.url = "http://test.local"
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    assert res.ok is True
    assert res.recommended_action == "stop_safely"
    assert res.payment_intent == "session"

@patch("ln_church_agent.cli.requests.request")
def test_inspect_200_no_payment_required(mock_req):
    mock_res = MagicMock()
    mock_res.status_code = 200
    mock_res.content = b""
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    assert res.ok is True
    assert res.recommended_action == "no_payment_required"
    assert res.will_execute_payment is False

@patch("ln_church_agent.cli.requests.request")
def test_inspect_network_exception(mock_req):
    mock_req.side_effect = requests.exceptions.ConnectionError("Failed to connect")

    res = inspect_url("http://test.local")
    assert res.ok is False
    assert res.recommended_action == "stop_safely"
    assert res.error_stage == "fetch"
    assert "Failed to connect" in res.failure_reason

@patch("ln_church_agent.cli.requests.request")
def test_inspect_invalid_challenge_reject_invalid(mock_req):
    mock_res = MagicMock()
    mock_res.status_code = 402
    mock_res.headers = {"WWW-Authenticate": 'UnknownScheme invalid="data"'}
    mock_res.content = b""
    mock_res.url = "http://test.local"
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    assert res.ok is True
    assert res.recommended_action == "reject_invalid"
    assert "Failed to parse challenge" in res.reason

@patch("ln_church_agent.cli.requests.request")
def test_inspect_x402_exact_post_settlement_observe_only(mock_req):
    """
    x402 exact チャレンジを検知した際、CLI が post-settlement validator であることを理解し、
    pay_and_verify ではなく observe_only を推奨することを確認
    """
    mock_res = MagicMock()
    mock_res.status_code = 402
    
    # x402 V2 Exact のペイロードをモック
    payload = {
        "accepts": [{"scheme": "exact", "network": "solana:1234"}]
    }
    b64_str = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    
    mock_res.headers = {"PAYMENT-REQUIRED": b64_str}
    mock_res.content = b""
    mock_res.url = "http://test.local"
    mock_req.return_value = mock_res
    
    res = inspect_url("http://test.local")
    
    assert res.ok is True
    # 支払いを推奨せず、監視のみを推奨する
    assert res.recommended_action == "observe_only"
    assert res.diagnostic_class == "post_settlement_proof_required"
    assert res.will_execute_payment is False
    assert "post-settlement evidence" in res.reason