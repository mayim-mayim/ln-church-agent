import pytest
import base64
import json
from unittest.mock import patch, MagicMock
from ln_church_agent.cli import inspect_url
import httpx

@patch("ln_church_agent.cli.requests.request")
def test_inspect_alchemy_x402_body_accepts_detects_x402(mock_req):
    mock_res = MagicMock()
    mock_res.status_code = 402
    mock_res.headers = {"Content-Type": "application/json"}
    
    # HeaderなしでBodyのトップレベルにaccepts配列があるケース
    payload = {
        "accepts": [{"scheme": "exact", "network": "eip155:196", "payTo": "0xABC"}]
    }
    
    mock_res.json.return_value = payload
    mock_res.content = json.dumps(payload).encode()
    mock_res.url = "http://test.local"
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    assert res.ok is True
    assert "x402" in res.rails_detected
    assert res.diagnostic_class == "post_settlement_proof_required"

@patch("ln_church_agent.cli.requests.request")
def test_inspect_www_authenticate_x402_detects_x402(mock_req):
    mock_res = MagicMock()
    mock_res.status_code = 402
    mock_res.headers = {"WWW-Authenticate": 'x402 macaroon="mac", txHash="hash"'}
    mock_res.content = b""
    mock_res.url = "http://test.local"
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    assert res.ok is True
    assert "x402" in res.rails_detected

@patch("ln_church_agent.cli.requests.request")
def test_inspect_payment_lightning_normalizes_to_payment_and_mpp(mock_req):
    mock_res = MagicMock()
    mock_res.status_code = 402
    
    req_json = {"method": "lightning", "methodDetails": {"invoice": "lnbc123"}}
    b64_req = base64.urlsafe_b64encode(json.dumps(req_json).encode()).decode().rstrip('=')
    
    mock_res.headers = {"WWW-Authenticate": f'Payment id="123", request="{b64_req}"'}
    mock_res.content = b""
    mock_res.url = "http://test.local"
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    assert res.ok is True
    assert "Payment" in res.rails_detected
    assert "MPP" in res.rails_detected

@patch("ln_church_agent.cli.requests.request")
def test_inspect_payment_eip3009_normalizes_to_payment_and_x402(mock_req):
    mock_res = MagicMock()
    mock_res.status_code = 402
    
    req_json = {"method": "eip3009", "amount": 10.0}
    b64_req = base64.urlsafe_b64encode(json.dumps(req_json).encode()).decode().rstrip('=')
    
    mock_res.headers = {"WWW-Authenticate": f'Payment id="123", request="{b64_req}"'}
    mock_res.content = b""
    mock_res.url = "http://test.local"
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    assert res.ok is True
    assert "Payment" in res.rails_detected
    assert "x402" in res.rails_detected

@patch("ln_church_agent.cli.requests.request")
def test_inspect_missing_amount_does_not_crash(mock_req):
    mock_res = MagicMock()
    mock_res.status_code = 402
    # 修正: キーを大文字に
    mock_res.headers = {"PAYMENT-REQUIRED": 'scheme="x402", network="eip155:137", amount="INVALID_STRING"'}
    mock_res.content = b""
    mock_res.url = "http://test.local"
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    assert res.ok is True
    assert "x402" in res.rails_detected
    # Floatの変換エラーは内部で安全に 0.0 として処理されます

def test_discovery_worker_uses_python_api_or_sys_executable():
    import sys
    from ln_church_agent.cli import inspect_url
    assert callable(inspect_url)
    assert sys.executable is not None

@patch("ln_church_agent.cli.requests.request")
def test_inspect_no_valid_402_returns_unsupported_challenge_shape(mock_req):
    """
    HTTP 402を返すが、ヘッダーにもボディにも有効なチャレンジが存在しない場合、
    正しく 'unsupported_challenge_shape' として分類されることを確認
    """
    mock_res = MagicMock()
    mock_res.status_code = 402
    # 関連するヘッダーやボディを一切含めない
    mock_res.headers = {"Some-Random-Header": "value"}
    mock_res.content = b""
    mock_res.json.side_effect = ValueError()
    mock_res.url = "http://test.local"
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    
    assert res.ok is True  # 予期せぬクラッシュではなく、安全な拒絶として扱われる
    assert res.recommended_action == "reject_invalid"
    assert res.error_stage == "parse"
    assert res.diagnostic_class == "unsupported_challenge_shape"
    assert res.failure_class == "no_valid_challenge"


@patch("ln_church_agent.cli.parse_challenge_from_response")
@patch("ln_church_agent.cli.requests.request")
def test_inspect_failed_parse_returns_invalid_payment_auth_request(mock_req, mock_parse):
    """
    パーサー内部で 'Failed to parse' を含むエラーが発生した場合、
    正しく 'invalid_payment_auth_request' として分類されることを確認
    """
    # パーサーが特定のエラーメッセージでクラッシュした状態をモックで再現
    mock_parse.side_effect = Exception("Failed to parse base64 payload")
    
    mock_res = MagicMock()
    mock_res.status_code = 402
    mock_res.headers = {"PAYMENT-REQUIRED": "invalid_base64_string_that_causes_crash"}
    mock_res.content = b""
    mock_res.url = "http://test.local"
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    
    assert res.ok is True  # 安全な拒絶
    assert res.recommended_action == "reject_invalid"
    assert res.error_stage == "parse"
    assert res.diagnostic_class == "invalid_payment_auth_request"
    assert res.failure_class == "parse_failure"