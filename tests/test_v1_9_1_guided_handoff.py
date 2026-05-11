import pytest
import json
import base64
from unittest.mock import patch, MagicMock
from ln_church_agent.cli import inspect_url

@patch("ln_church_agent.cli.requests.request")
def test_ap2_payment_mandate_returns_guided_handoff(mock_req):
    mock_res = MagicMock(status_code=402)
    mock_res.url = "http://test.local"
    mock_res.headers = {"Content-Type": "application/json"}
    
    payload = {
        "protocol": "ap2",
        "intent": "payment_mandate",
        "mandate_id": "m_123"
    }
    mock_res.json.return_value = payload
    mock_res.content = json.dumps(payload).encode()
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    
    assert "AP2" in res.surfaces_detected
    assert "AP2" not in res.rails_detected
    assert res.recommended_action == "observe_only"
    assert res.handoff_mode == "guided_handoff"
    assert res.approval_required is True
    assert "mandate_scope" in res.ask_site_for
    assert "treat_mandate_as_settlement_proof" in res.do_not
    assert "explicit_price" in res.required_evidence

@patch("ln_church_agent.cli.requests.request")
def test_ap2_with_x402_coexist_still_observe_only(mock_req):
    mock_res = MagicMock(status_code=402)
    mock_res.url = "http://test.local"
    
    ap2_payload = {"protocol": "ap2", "intent": "checkout_mandate"}
    x402_payload = {"accepts": [{"scheme": "exact", "network": "eip155:1", "payTo": "0xABC"}]}
    b64_x402 = base64.urlsafe_b64encode(json.dumps(x402_payload).encode()).decode().rstrip('=')
    
    mock_res.headers = {
        "Content-Type": "application/json",
        "PAYMENT-REQUIRED": b64_x402
    }
    mock_res.json.return_value = ap2_payload
    mock_res.content = json.dumps(ap2_payload).encode()
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    
    assert "AP2" in res.surfaces_detected
    assert "x402" in res.settlement_rails_detected
    assert "x402" in res.rails_detected
    assert res.recommended_action == "observe_only"
    assert res.handoff_mode == "guided_handoff"
    assert res.approval_required is True
    assert res.operator_approval_reason == "commerce_surface_with_settlement_rail"
    assert "settlement_rail_options" in res.ask_site_for

@patch("ln_church_agent.cli.requests.request")
def test_acp_shared_payment_token_does_not_expose_raw_token(mock_req):
    mock_res = MagicMock(status_code=402, url="http://test.local")
    payload = {
        "protocol": "acp",
        "intent": "agentic_checkout",
        "shared_payment_token": "SECRET_TOKEN_SHOULD_NOT_LEAK"
    }
    mock_res.json.return_value = payload
    mock_res.content = json.dumps(payload).encode()
    mock_res.headers = {"Content-Type": "application/json"}
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    
    assert "ACP" in res.surfaces_detected
    assert "ACP" not in res.rails_detected
    assert res.authorization_artifact == "shared_payment_token"
    assert res.handoff_mode == "guided_handoff"
    assert "treat_shared_payment_token_as_settlement_proof" in res.do_not

    # Secret is not leaked in serialized InspectResult
    serialized = res.model_dump_json() if hasattr(res, "model_dump_json") else res.json()
    assert "SECRET_TOKEN_SHOULD_NOT_LEAK" not in serialized

@patch("ln_church_agent.cli.requests.request")
def test_acp_cart_returns_cart_guidance(mock_req):
    mock_res = MagicMock(status_code=402, url="http://test.local")
    payload = {
        "protocol": "acp",
        "intent": "cart"
    }
    mock_res.json.return_value = payload
    mock_res.content = json.dumps(payload).encode()
    mock_res.headers = {"Content-Type": "application/json"}
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    
    assert "ACP" in res.surfaces_detected
    assert res.surface_type in ["checkout", "commerce", "catalog"]
    assert res.handoff_mode == "guided_handoff"
    assert "cart_details" in res.ask_site_for
    assert "price_breakdown" in res.ask_site_for
    assert "cart_total" in res.required_evidence

@patch("ln_church_agent.cli.requests.request")
def test_app_okx_app_returns_broker_escrow_guidance(mock_req):
    mock_res = MagicMock(status_code=402, url="http://test.local")
    payload = {
        "protocol": "okx-app",
        "intent": "escrow",
        "broker": {"required": True}
    }
    mock_res.json.return_value = payload
    mock_res.content = json.dumps(payload).encode()
    mock_res.headers = {"Content-Type": "application/json"}
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    
    assert res.handoff_mode == "guided_handoff"
    assert res.approval_required is True
    assert "broker_identity" in res.ask_site_for
    assert "treat_broker_hint_as_settlement_proof" in res.do_not
    assert "escrow_or_dispute_terms" in res.required_evidence

@patch("ln_church_agent.cli.requests.request")
def test_normal_l402_regression_has_no_guided_handoff(mock_req):
    mock_res = MagicMock(status_code=402, url="http://test.local")
    mock_res.headers = {"WWW-Authenticate": 'L402 macaroon="mac", invoice="inv"'}
    mock_res.content = b""
    mock_res.json.side_effect = ValueError()
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    
    assert "L402" in res.settlement_rails_detected
    assert res.surfaces_detected == []
    assert res.recommended_action == "pay_and_verify"
    assert res.handoff_mode is None
    assert res.approval_required is None
    assert res.ask_site_for == []
    assert res.do_not == []
    assert res.required_evidence == []
    assert res.missing_information == []

@patch("ln_church_agent.cli.requests.request")
def test_malformed_overlap_returns_stop_safely_with_guidance(mock_req):
    mock_res = MagicMock(status_code=402, url="http://test.local")
    acp_payload = {"protocol": "acp", "intent": "cart"}
    mock_res.headers = {
        "Content-Type": "application/json",
        "WWW-Authenticate": "UnknownScheme fake_data=123"
    }
    mock_res.json.return_value = acp_payload
    mock_res.content = json.dumps(acp_payload).encode()
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    
    assert "ACP" in res.surfaces_detected
    assert res.recommended_action == "stop_safely"
    assert res.handoff_mode == "guided_handoff"
    assert res.approval_required is True
    assert res.operator_approval_reason == "malformed_or_unsupported_settlement_hint"
    assert res.unsupported_reason is not None