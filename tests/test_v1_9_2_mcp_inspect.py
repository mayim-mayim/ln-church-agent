import pytest
import json
import base64
from unittest.mock import patch, MagicMock

# Import directly to ensure it loads without any AGENT_PRIVATE_KEY setup
from ln_church_agent.integrations.mcp_inspect import (
    inspect_paid_surface,
    explain_recommended_action,
    build_mcp_observation_payload,
    submit_mcp_observation,
    _contains_secret_keys
)

@patch("ln_church_agent.cli.requests.request")
def test_mcp_inspect_paid_surface_never_executes_payment(mock_req):
    """Ensure the inspect tool returns will_execute_payment=False and requires no keys."""
    mock_res = MagicMock(status_code=402, url="http://test.local")
    mock_res.headers = {"WWW-Authenticate": 'L402 macaroon="mac", invoice="inv"'}
    mock_res.content = b""
    mock_res.json.side_effect = ValueError()
    mock_req.return_value = mock_res

    res = inspect_paid_surface("http://test.local")
    
    assert res["status_code"] == 402
    assert "L402" in res["settlement_rails_detected"]
    assert res["recommended_action"] == "pay_and_verify"
    assert res["will_execute_payment"] is False
    assert res["safety"]["inspect_only"] is True
    assert res["safety"]["payment_performed"] is False
    assert res["safety"]["requires_private_key"] is False

@patch("ln_church_agent.cli.requests.request")
def test_mcp_ap2_acp_remain_observe_only(mock_req):
    """AP2/ACP surfaces should be classified as observe_only without hitting execution paths."""
    mock_res = MagicMock(status_code=402, url="http://test.local")
    payload = {"protocol": "ap2", "intent": "payment_mandate"}
    mock_res.headers = {"Content-Type": "application/json"}
    mock_res.content = json.dumps(payload).encode()
    mock_res.json.return_value = payload
    mock_req.return_value = mock_res

    res = inspect_paid_surface("http://test.local")
    
    assert "AP2" in res["surfaces_detected"]
    assert "AP2" not in res["settlement_rails_detected"]
    assert res["recommended_action"] == "observe_only"
    assert res["will_execute_payment"] is False

def test_mcp_explain_action():
    """Ensure the explanation clearly states payment execution is disabled."""
    fake_res = {"recommended_action": "pay_and_verify"}
    explanation = explain_recommended_action(fake_res)
    
    assert explanation["recommended_action"] == "pay_and_verify"
    assert "THIS inspect-only MCP server does NOT execute payments" in explanation["safe_next_step"]
    assert explanation["payment_execution_available_in_this_mcp"] is False

def test_mcp_build_observation_redacts_secrets():
    """Observation payload must explicitly hardcode false for payment status."""
    fake_res = {
        "url": "http://test.local",
        "method": "GET",
        "status_code": 402,
        "settlement_rails_detected": ["x402"]
    }
    
    payload = build_mcp_observation_payload(fake_res)
    
    assert payload["source_channel"] == "mcp"
    assert payload["source_scope"] == "external_agent_report"
    assert payload["evidence"]["payment_performed"] is False
    assert payload["evidence"]["payment_receipt_present"] is False
    assert payload["evidence"]["proof_reference"] == "none"

# --- 4-1. AP2 guided handoff fields are exposed through MCP ---
@patch("ln_church_agent.cli.requests.request")
def test_mcp_exposes_guided_handoff_fields(mock_req):
    mock_res = MagicMock(status_code=402, url="http://test.local")
    payload = {"protocol": "ap2", "intent": "payment_mandate"}
    mock_res.headers = {"Content-Type": "application/json"}
    mock_res.content = json.dumps(payload).encode()
    mock_res.json.return_value = payload
    mock_req.return_value = mock_res

    res = inspect_paid_surface("http://test.local")

    assert res["recommended_action"] == "observe_only"
    assert res["handoff_mode"] == "guided_handoff"
    assert res["approval_required"] is True
    assert res["operator_approval_reason"] is not None
    assert "mandate_scope" in res["ask_site_for"]
    assert "treat_mandate_as_settlement_proof" in res["do_not"]
    assert "explicit_price" in res["required_evidence"]
    assert res["will_execute_payment"] is False
    assert res["safety"]["payment_performed"] is False

# --- 4-2. Normal L402 has no guided handoff but remains non-executing in MCP ---
@patch("ln_church_agent.cli.requests.request")
def test_mcp_l402_has_no_guided_handoff_but_never_executes(mock_req):
    mock_res = MagicMock(status_code=402, url="http://test.local")
    mock_res.headers = {"WWW-Authenticate": 'L402 macaroon="mac", invoice="inv"'}
    mock_res.content = b""
    mock_res.json.side_effect = ValueError()
    mock_req.return_value = mock_res

    res = inspect_paid_surface("http://test.local")

    assert "L402" in res["settlement_rails_detected"]
    assert res["recommended_action"] == "pay_and_verify"
    assert res["handoff_mode"] is None
    assert res["approval_required"] is None
    assert res["ask_site_for"] == []
    assert res["do_not"] == []
    assert res["required_evidence"] == []
    assert res["missing_information"] == []
    assert res["will_execute_payment"] is False

# --- 4-3. observation payload includes handoff summary and remains non-payment ---
def test_mcp_observation_payload_includes_handoff_summary():
    fake_res = {
        "url": "http://test.local",
        "method": "GET",
        "status_code": 402,
        "settlement_rails_detected": [],
        "commerce_intent": "payment_mandate",
        "handoff_mode": "guided_handoff",
        "approval_required": True,
        "operator_approval_reason": "commerce_surface_detected",
        "ask_site_for": ["mandate_scope"],
        "do_not": ["treat_mandate_as_settlement_proof"],
        "required_evidence": ["explicit_price"],
        "missing_information": ["merchant_identity"],
    }

    payload = build_mcp_observation_payload(fake_res)

    assert payload["evidence"]["payment_performed"] is False
    assert payload["handoff"]["handoff_mode"] == "guided_handoff"
    assert payload["handoff"]["approval_required"] is True
    assert "mandate_scope" in payload["handoff"]["ask_site_for"]
    assert "treat_mandate_as_settlement_proof" in payload["handoff"]["do_not"]

# --- 4-4. explanation includes guided handoff context ---
def test_mcp_explain_guided_handoff_context():
    fake_res = {
        "recommended_action": "observe_only",
        "handoff_mode": "guided_handoff",
        "approval_required": True,
        "operator_approval_reason": "commerce_surface_detected",
        "ask_site_for": ["mandate_scope"],
        "do_not": ["treat_mandate_as_settlement_proof"],
        "required_evidence": ["explicit_price"],
        "missing_information": ["merchant_identity"],
    }

    explanation = explain_recommended_action(fake_res)

    assert explanation["payment_execution_available_in_this_mcp"] is False
    assert explanation["handoff_mode"] == "guided_handoff"
    assert explanation["approval_required"] is True
    assert "operator approval" in explanation["safe_next_step"].lower()

# ==========================================
# 🛡️ New Secret Redaction Tests 
# ==========================================
@patch("requests.post")
def test_mcp_submit_safety_guardrails(mock_post):
    mock_post.return_value = MagicMock(status_code=200, text='{"status":"ok"}')
    
    # 1. Reject payment_performed = True
    bad_payload_1 = {"evidence": {"payment_performed": True}}
    res1 = submit_mcp_observation(bad_payload_1)
    assert "Safety violation" in res1["error"]
    
    # 2. Accept valid payload directly from build_mcp_observation_payload (authorization_scheme should be allowed)
    fake_res = {
        "url": "http://test.local",
        "method": "GET",
        "status_code": 402,
        "settlement_rails_detected": ["L402"]
    }
    built_payload = build_mcp_observation_payload(fake_res)
    # 念のため authorization_scheme が入っていることを確認
    assert built_payload["protocol"]["authorization_scheme"] == "L402"
    
    res_built = submit_mcp_observation(built_payload)
    assert res_built.get("status") == "success", f"Should accept perfectly valid built payload: {res_built}"
    
    # 3. Reject raw headers.Authorization
    bad_payload_2 = {
        "evidence": {"payment_performed": False, "proof_reference": "none"},
        "headers": {"Authorization": "Bearer secret123"}
    }
    res2 = submit_mcp_observation(bad_payload_2)
    assert "Safety violation: potential secret leaked" in res2["error"]

    # 4. Reject grant_token key
    bad_payload_3 = {
        "evidence": {"payment_performed": False, "proof_reference": "none"},
        "grant_token": "jws.token.here"
    }
    res3 = submit_mcp_observation(bad_payload_3)
    assert "Safety violation: potential secret leaked" in res3["error"]

def test_contains_secret_keys_recursive():
    """再帰的なキー名チェックが正しく機能するか単体テスト"""
    
    # OKケース
    safe_obj = {
        "protocol": {
            "authorization_scheme": "L402",
            "payment_intent": "charge"
        },
        "evidence": {
            "payment_performed": False
        },
        "source_channel": "mcp",
        "schema_version": "v1"
    }
    assert _contains_secret_keys(safe_obj) is False

    # NGケース (ネストされたリストの中の辞書にキーがある)
    unsafe_obj = {
        "metadata": [
            {"safe_key": 123},
            {"macaroon": "secret_string"} # ここで検知されるべき
        ]
    }
    assert _contains_secret_keys(unsafe_obj) is True

@patch("ln_church_agent.client.Payment402Client.execute_detailed")
@patch("ln_church_agent.cli.requests.request")
def test_mcp_inspect_never_calls_execute_detailed(mock_req, mock_execute_detailed):
    """
    Ensure the inspect_paid_surface tool purely relies on request/parsing
    and NEVER accidentally triggers the full runtime Payment402Client.execute_detailed loop.
    """
    mock_res = MagicMock(status_code=402, url="http://test.local")
    mock_res.headers = {"WWW-Authenticate": 'L402 macaroon="mac", invoice="inv"'}
    mock_res.content = b""
    mock_res.json.side_effect = ValueError()
    mock_req.return_value = mock_res

    res = inspect_paid_surface("http://test.local")
    
    # 決済実行メソッドが一度も呼ばれていないことを担保する
    mock_execute_detailed.assert_not_called()
    assert res["will_execute_payment"] is False
    assert res["safety"]["requires_private_key"] is False