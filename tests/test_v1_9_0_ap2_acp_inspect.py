import pytest
import json
import base64
from unittest.mock import patch, MagicMock
from ln_church_agent.cli import inspect_url

@patch("ln_church_agent.cli.requests.request")
def test_ap2_payment_mandate_detection(mock_req):
    """AP2 payment mandate detection: AP2のみの場合は observe_only となること"""
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
    assert res.surface_type == "authorization"
    assert res.commerce_intent == "payment_mandate"
    assert len(res.settlement_rails_detected) == 0
    assert res.recommended_action == "observe_only"

@patch("ln_church_agent.cli.requests.request")
def test_acp_checkout_detection(mock_req):
    """ACP checkout detection: ACPのみの場合は observe_only となること"""
    mock_res = MagicMock(status_code=402)
    mock_res.url = "http://test.local"
    mock_res.headers = {"Content-Type": "application/json"}
    
    payload = {
        "protocol": "acp",
        "intent": "agentic_checkout",
        "shared_payment_token": "tok_abc"
    }
    mock_res.json.return_value = payload
    mock_res.content = json.dumps(payload).encode()
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    
    assert "ACP" in res.surfaces_detected
    # 💡 任意追加: ACP が決済レールとして誤認されていないことを明示
    assert "ACP" not in res.rails_detected 
    assert res.surface_type == "checkout"
    assert res.commerce_intent == "agentic_checkout"
    assert len(res.settlement_rails_detected) == 0
    assert res.recommended_action == "observe_only"

@patch("ln_church_agent.cli.requests.request")
def test_ap2_with_x402_challenge_coexistence(mock_req):
    """AP2 + x402-like challenge: 両方検知するが、アクションは observe_only にとどめる"""
    mock_res = MagicMock(status_code=402)
    mock_res.url = "http://test.local"
    
    # Body: AP2 Metadata
    ap2_payload = {"protocol": "ap2", "intent": "checkout_mandate"}
    # Header: x402
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
    assert "AP2" not in res.rails_detected
    assert "x402" in res.settlement_rails_detected
    assert "x402" in res.rails_detected
    # 決済レールが共存していても pay_and_verify には昇格させない
    assert res.recommended_action == "observe_only"

@patch("ln_church_agent.cli.requests.request")
def test_acp_with_malformed_settlement_hint(mock_req):
    """ACP + malformed settlement hint: 安全のため stop_safely になること"""
    mock_res = MagicMock(status_code=402)
    mock_res.url = "http://test.local"
    
    acp_payload = {"protocol": "acp", "intent": "cart"}
    mock_res.headers = {
        "Content-Type": "application/json",
        "WWW-Authenticate": "UnknownScheme fake_data=123" # 存在しない/不正な決済スキーム
    }
    mock_res.json.return_value = acp_payload
    mock_res.content = json.dumps(acp_payload).encode()
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    
    assert "ACP" in res.surfaces_detected
    assert "ACP" not in res.rails_detected
    assert len(res.settlement_rails_detected) == 0
    assert res.recommended_action == "stop_safely"
    assert res.unsupported_reason is not None

@patch("ln_church_agent.cli.requests.request")
def test_ap2_checkout_mandate_artifact(mock_req):
    """AP2 checkout_mandate の artifact 分類確認"""
    mock_res = MagicMock(status_code=402, url="http://test.local")
    payload = {"protocol": "ap2", "intent": "checkout_mandate"}
    mock_res.json.return_value = payload
    mock_res.content = json.dumps(payload).encode()
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    assert "AP2" in res.surfaces_detected
    assert "AP2" not in res.rails_detected
    assert res.authorization_artifact == "checkout_mandate"

@patch("ln_church_agent.cli.requests.request")
def test_acp_catalog_artifact_none(mock_req):
    """ACP catalog の artifact が none になること"""
    mock_res = MagicMock(status_code=402, url="http://test.local")
    payload = {"protocol": "acp", "intent": "catalog"}
    mock_res.json.return_value = payload
    mock_res.content = json.dumps(payload).encode()
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    assert "ACP" in res.surfaces_detected
    assert "ACP" not in res.rails_detected
    assert res.authorization_artifact == "none"

@patch("ln_church_agent.cli.requests.request")
def test_acp_shared_token_artifact(mock_req):
    """ACP shared_payment_token の artifact 分類確認"""
    mock_res = MagicMock(status_code=402, url="http://test.local")
    payload = {"protocol": "acp", "shared_payment_token": "abc"}
    mock_res.json.return_value = payload
    mock_res.content = json.dumps(payload).encode()
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    assert "ACP" in res.surfaces_detected
    assert "ACP" not in res.rails_detected
    assert res.authorization_artifact == "shared_payment_token"

@patch("ln_church_agent.cli.requests.request")
def test_regression_normal_l402_inspect(mock_req):
    """通常 L402 inspect が AP2/ACP 拡張の影響を受けず正常動作するかの回帰テスト"""
    mock_res = MagicMock(status_code=402, url="http://test.local")
    mock_res.headers = {"WWW-Authenticate": 'L402 macaroon="mac", invoice="inv"'}
    mock_res.content = b""
    mock_res.json.side_effect = ValueError() # JSONペイロードではないことをシミュレート
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    
    assert "L402" in res.rails_detected
    assert "L402" in res.settlement_rails_detected
    assert res.surfaces_detected == []
    assert res.recommended_action == "pay_and_verify"
    assert res.will_execute_payment is False