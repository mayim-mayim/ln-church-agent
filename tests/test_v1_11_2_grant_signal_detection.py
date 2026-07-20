import pytest
import json
import base64
from unittest.mock import patch, MagicMock

from ln_church_agent.cli import inspect_url
from ln_church_agent.integrations.mcp_inspect import inspect_paid_surface, build_mcp_observation_payload
from ln_church_agent.capabilities import get_capability_matrix

@patch("ln_church_agent.inspect_transport._exchange_once")
def test_1_structured_grant_metadata_on_200_ok(mock_req):
    mock_res = MagicMock(status_code=200, url="http://public.example")
    payload = {
        "grant": {
            "available": True,
            "type": "trial_credit",
            "redemption_endpoint": "/.well-known/grants",
            "eligibility": {"agent": True},
            "scope": ["read_api"],
            "expires_at": "2026-12-31T23:59:59Z"
        }
    }
    mock_res.json.return_value = payload
    mock_res.content = json.dumps(payload).encode()
    mock_res.headers = {"Content-Type": "application/json"}
    mock_req.return_value = mock_res

    res = inspect_url("http://public.example")

    assert res.ok is True
    assert res.recommended_action == "no_payment_required"
    assert res.grant_signal_detected is True
    assert res.grant_signals.detected is True
    assert res.grant_signals.machine_readable is True
    assert res.grant_signals.redeemability_verified is False
    assert res.grant_signals.availability_verified is False
    assert "trial_credit" in res.grant_signals.signal_types
    assert res.will_execute_payment is False

@patch("ln_church_agent.inspect_transport._exchange_once")
def test_2_x402_exact_and_grant_signal_coexist(mock_req):
    mock_res = MagicMock(status_code=402, url="http://public.example")
    payload = {
        "grant_available": True,
        "accepts": [{"scheme": "exact", "network": "eip155:137", "payTo": "0xABC"}]
    }
    b64_str = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    mock_res.headers = {"PAYMENT-REQUIRED": b64_str, "Content-Type": "application/json"}
    mock_res.content = json.dumps(payload).encode()
    mock_res.json.return_value = payload
    mock_req.return_value = mock_res

    res = inspect_url("http://public.example")

    assert res.recommended_action == "observe_only"
    assert res.diagnostic_class == "post_settlement_proof_required"
    assert res.grant_signal_detected is True
    assert len(res.settlement_options) > 0
    assert res.will_execute_payment is False

@patch("ln_church_agent.inspect_transport._exchange_once")
def test_3_l402_and_grant_signal_coexist(mock_req):
    mock_res = MagicMock(status_code=402, url="http://public.example")
    mock_res.headers = {"WWW-Authenticate": 'L402 macaroon="mac", invoice="inv"'}
    payload = {"promotional_credit": "100"}
    mock_res.content = json.dumps(payload).encode()
    mock_res.json.return_value = payload
    mock_req.return_value = mock_res

    res = inspect_url("http://public.example")

    assert res.recommended_action == "pay_and_verify"
    assert "L402" in res.rails_detected
    assert res.grant_signal_detected is True
    assert res.will_execute_payment is False

@patch("ln_church_agent.inspect_transport._exchange_once")
def test_4_oauth_grant_type_false_positive_guard(mock_req):
    mock_res = MagicMock(status_code=200, url="http://public.example")
    payload = {
        "grant_type": "client_credentials",
        "token_type": "Bearer",
        "access_token": "DO_NOT_LEAK"
    }
    mock_res.json.return_value = payload
    mock_res.content = json.dumps(payload).encode()
    mock_req.return_value = mock_res

    res = inspect_url("http://public.example")

    assert res.grant_signal_detected is False
    assert "DO_NOT_LEAK" not in res.model_dump_json()

@patch("ln_church_agent.inspect_transport._exchange_once")
def test_5_weak_text_no_false_positive(mock_req):
    mock_res = MagicMock(status_code=200, url="http://public.example")
    payload = {
        "message": "This report contains 120 data points and a reward model discussion."
    }
    mock_res.json.return_value = payload
    mock_res.content = json.dumps(payload).encode()
    mock_req.return_value = mock_res

    res = inspect_url("http://public.example")

    assert res.grant_signal_detected is False

@patch("ln_church_agent.inspect_transport._exchange_once")
def test_6_raw_grant_token_must_not_leak(mock_req):
    mock_res = MagicMock(status_code=200, url="http://public.example")
    payload = {
        "grant": {"available": True},
        "grant_token": "SECRET_GRANT_TOKEN_SHOULD_NOT_LEAK"
    }
    mock_res.json.return_value = payload
    mock_res.content = json.dumps(payload).encode()
    mock_req.return_value = mock_res

    res = inspect_url("http://public.example")

    assert res.grant_signal_detected is True
    assert "SECRET_GRANT_TOKEN_SHOULD_NOT_LEAK" not in res.model_dump_json()

@patch("ln_church_agent.inspect_transport._exchange_once")
def test_7_mcp_inspect_includes_local_grant_sidecar(mock_req):
    mock_res = MagicMock(status_code=200, url="http://public.example")
    payload = {"faucet": "available"}
    mock_res.json.return_value = payload
    mock_res.content = json.dumps(payload).encode()
    mock_req.return_value = mock_res

    res = inspect_paid_surface("http://public.example")

    assert res["grant_signal_detected"] is True
    assert res["grant_signals"] is not None
    assert res["grant_signals"]["detected"] is True

@patch("ln_church_agent.inspect_transport._exchange_once")
def test_8_mcp_observation_payload_excludes_grant_signals(mock_req):
    mock_res = MagicMock(status_code=200, url="http://public.example")
    payload = {"faucet": "available"}
    mock_res.json.return_value = payload
    mock_res.content = json.dumps(payload).encode()
    mock_req.return_value = mock_res

    inspect_res = inspect_paid_surface("http://public.example")
    obs_payload = build_mcp_observation_payload(inspect_res)

    # observation payload には含まれていないことを確認
    assert "grant_signals" not in obs_payload
    assert "grant_signal_detected" not in obs_payload

def test_9_capability_matrix_contains_grant_like_signal_detection():
    matrix = get_capability_matrix()
    grant_sig = next((row for row in matrix if row["id"] == "grant_like_signal_detection"), None)

    assert grant_sig is not None
    assert grant_sig["layer"] == "incentive_signal"
    assert grant_sig["current_sdk_support"] == "observe_only"
    assert grant_sig["execution_behavior"] == "none"
    assert grant_sig["proof_semantics"] == "unverified_signal_not_grant_proof"
    assert grant_sig["watchlist_status"] == "experimental"
