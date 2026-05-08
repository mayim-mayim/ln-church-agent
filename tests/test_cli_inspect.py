import pytest
from unittest.mock import patch, MagicMock
from ln_church_agent.cli import inspect_url
import requests
import base64
import json
import subprocess

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
    mock_res.url = "http://test.local"
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


# ==========================================
# 🆕 v1.8.0: OKX APP / Agent Commerce / APP Detection Tests
# ==========================================
@patch("ln_church_agent.cli.requests.request")
def test_inspect_app_402_json_body(mock_req):
    """1. 402 + APP JSON body: OKX APP メタデータが正しく検出され、observe_only になること"""
    mock_res = MagicMock()
    mock_res.status_code = 402
    mock_res.headers = {"Content-Type": "application/json"}
    
    app_payload = {
        "protocol": "okx-app",
        "intent": "charge",
        "broker": {"required": True},
        "payment": {
            "method": "eip3009",
            "network": "eip155:196",
            "asset": "USDG"
        }
    }
    
    mock_res.json.return_value = app_payload
    mock_res.content = json.dumps(app_payload).encode()
    mock_res.url = "http://test.local/app/payment"
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local/app/payment")
    
    assert res.ok is True
    assert "APP" in res.rails_detected
    assert res.app_protocol == "okx_app"
    assert res.app_intent == "charge"
    assert res.settlement_method == "evm_eip3009"
    assert res.network == "eip155:196"
    assert res.broker_required is True
    assert res.recommended_action == "observe_only"
    assert res.will_execute_payment is False
    assert "Agent Commerce surface detected" in res.reason

@patch("ln_church_agent.cli.requests.request")
def test_inspect_app_200_ok_metadata(mock_req):
    """2. 200 OK + APP metadata: 200応答であってもAPPメタデータが強ければAPPと検知し observe_only となること"""
    mock_res = MagicMock()
    mock_res.status_code = 200
    mock_res.headers = {"Content-Type": "application/json"}
    
    app_payload = {
        "agentPaymentsProtocol": "okx-app",
        "intent": "batch",
        "paymentMethods": [{"method": "eip3009"}],
        "broker": {"required": False}
    }
    
    mock_res.json.return_value = app_payload
    mock_res.content = json.dumps(app_payload).encode()
    mock_res.url = "http://test.local/app/info"
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local/app/info")
    
    assert "APP" in res.rails_detected
    assert res.recommended_action == "observe_only"
    assert res.will_execute_payment is False

@patch("ln_church_agent.cli.requests.request")
def test_inspect_x402_exact_not_falsely_detected(mock_req):
    """3. x402 exact単体: APP固有のシグナルがない場合、既存のx402として処理され誤検知しないこと"""
    mock_res = MagicMock()
    mock_res.status_code = 402
    
    payload = {
        "accepts": [{"scheme": "exact", "network": "solana:1234"}]
    }
    b64_str = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    
    mock_res.headers = {"PAYMENT-REQUIRED": b64_str}
    mock_res.content = b""
    mock_res.json.side_effect = ValueError()
    mock_res.url = "http://test.local"
    mock_req.return_value = mock_res
    
    res = inspect_url("http://test.local")
    
    # x402 exact の既存挙動が維持されていること
    assert res.ok is True
    assert res.recommended_action == "observe_only"
    assert res.diagnostic_class == "post_settlement_proof_required"
    assert getattr(res, "app_protocol", None) is None  # APPとしては検知されていない
    assert "APP" not in res.rails_detected

@patch("ln_church_agent.cli.requests.request")
def test_inspect_app_session_escrow_stop_safely(mock_req):
    """4. session / escrow: 高度なインテントの場合はより安全側に倒し stop_safely になること"""
    mock_res = MagicMock()
    mock_res.status_code = 402
    mock_res.headers = {"Content-Type": "application/json"}
    
    app_payload = {
        "protocol": "okx-app",
        "intent": "escrow",
        "broker": {"required": True}
    }
    
    mock_res.json.return_value = app_payload
    mock_res.content = json.dumps(app_payload).encode()
    mock_res.url = "http://test.local/app/escrow"
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local/app/escrow")
    
    assert res.recommended_action == "stop_safely"
    assert res.will_execute_payment is False
    assert "escrow" in res.reason

@patch("ln_church_agent.cli.requests.request")
def test_inspect_app_weak_string_no_false_positive(mock_req):
    """5. 弱いAPP文字列: 通常のWebページの文言などではAPPとして誤検知しないこと"""
    mock_res = MagicMock()
    mock_res.status_code = 200
    mock_res.headers = {"Content-Type": "application/json"}
    
    # 単なるメッセージ内に app という単語があるだけ
    normal_payload = {
        "message": "Please download the OKX app for a better experience.",
        "status": "success"
    }
    
    mock_res.json.return_value = normal_payload
    mock_res.content = json.dumps(normal_payload).encode()
    mock_res.url = "http://test.local/general"
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local/general")
    
    # 200 OK なので、通常通り支払不要として扱われること
    assert res.recommended_action == "no_payment_required"
    assert getattr(res, "app_protocol", None) is None
    assert "APP" not in res.rails_detected

@patch("ln_church_agent.cli.requests.request")
def test_inspect_okx_app_charge_observe_only(mock_req):
    mock_res = MagicMock()
    mock_res.status_code = 402
    mock_res.headers = {"Content-Type": "application/json"}
    app_payload = {
        "protocol": "okx-app",
        "intent": "charge",
        "broker": {"required": True},
        "payment": {"method": "eip3009", "network": "eip155:196", "asset": "USDG"}
    }
    mock_res.json.return_value = app_payload
    mock_res.content = json.dumps(app_payload).encode()
    mock_res.url = "http://test.local"
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    
    assert res.ok is True
    assert "APP" in res.rails_detected
    assert res.commerce_protocol == "okx_app"
    assert res.commerce_intent == "charge"
    assert res.broker_required is True
    assert res.recommended_action == "observe_only"
    assert res.will_execute_payment is False

@patch("ln_church_agent.cli.requests.request")
def test_inspect_okx_app_session_stop_safely(mock_req):
    mock_res = MagicMock()
    mock_res.status_code = 402
    mock_res.headers = {"Content-Type": "application/json"}
    app_payload = {"protocol": "okx-app", "intent": "session"}
    mock_res.json.return_value = app_payload
    mock_res.content = json.dumps(app_payload).encode()
    mock_res.url = "http://test.local"
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    
    assert res.commerce_intent == "session"
    assert res.recommended_action == "stop_safely"
    assert res.will_execute_payment is False

@patch("ln_church_agent.cli.requests.request")
def test_inspect_okx_app_escrow_stop_safely(mock_req):
    mock_res = MagicMock()
    mock_res.status_code = 402
    mock_res.headers = {"Content-Type": "application/json"}
    app_payload = {"protocol": "okx-app", "intent": "escrow"}
    mock_res.json.return_value = app_payload
    mock_res.content = json.dumps(app_payload).encode()
    mock_res.url = "http://test.local"
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    
    assert res.commerce_intent == "escrow"
    assert res.recommended_action == "stop_safely"
    assert res.will_execute_payment is False

@patch("ln_church_agent.cli.requests.request")
def test_inspect_plain_x402_exact_not_misclassified_as_app(mock_req):
    mock_res = MagicMock()
    mock_res.status_code = 402
    payload = {"accepts": [{"scheme": "exact", "network": "eip155:196", "payTo": "0x..."}]}
    b64_str = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    mock_res.headers = {"PAYMENT-REQUIRED": b64_str}
    mock_res.content = b""
    mock_res.json.side_effect = ValueError()
    mock_res.url = "http://test.local"
    mock_req.return_value = mock_res
    
    res = inspect_url("http://test.local")
    
    # x402 exactとして処理され、APPとは誤認されない（eip155:196だけではAPPにならない）
    assert res.recommended_action == "observe_only"
    assert res.diagnostic_class == "post_settlement_proof_required"
    assert res.commerce_protocol is None
    assert "APP" not in res.rails_detected

@patch("ln_church_agent.cli.requests.request")
def test_inspect_plain_okx_text_not_misclassified_as_app(mock_req):
    mock_res = MagicMock()
    mock_res.status_code = 200
    mock_res.headers = {"Content-Type": "application/json"}
    normal_payload = {"message": "Download the OKX app!"}
    mock_res.json.return_value = normal_payload
    mock_res.content = json.dumps(normal_payload).encode()
    mock_res.url = "http://test.local"
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    
    assert res.recommended_action == "no_payment_required"
    assert "APP" not in res.rails_detected

@patch("ln_church_agent.cli.requests.request")
def test_inspect_app_metadata_200_observe_only(mock_req):
    mock_res = MagicMock()
    mock_res.status_code = 200
    mock_res.headers = {"Content-Type": "application/json"}
    app_payload = {"agentPaymentsProtocol": "okx-app", "intent": "batch", "broker": {"required": False}}
    mock_res.json.return_value = app_payload
    mock_res.content = json.dumps(app_payload).encode()
    mock_res.url = "http://test.local"
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    
    assert "APP" in res.rails_detected
    assert res.commerce_intent == "batch"
    assert res.broker_required is False
    assert res.recommended_action == "observe_only"
    assert res.will_execute_payment is False

@patch("ln_church_agent.cli.requests.request")
def test_inspect_app_x402_coexistence(mock_req):
    """APPメタデータと x402 exact チャレンジが共存する場合の検知と正規化テスト"""
    mock_res = MagicMock()
    mock_res.status_code = 402
    
    # Body: APPシグナル
    app_payload = {
        "protocol": "okx-app",
        "intent": "charge",
        "broker": {"required": True}
    }
    
    # Header: x402 exact チャレンジ
    x402_payload = {
        "accepts": [{"scheme": "exact", "network": "eip155:196", "asset": "USDG", "amount": "1000", "payTo": "0xABC"}]
    }
    b64_x402 = base64.urlsafe_b64encode(json.dumps(x402_payload).encode()).decode().rstrip('=')
    
    mock_res.headers = {
        "Content-Type": "application/json",
        "PAYMENT-REQUIRED": b64_x402
    }
    mock_res.json.return_value = app_payload
    mock_res.content = json.dumps(app_payload).encode()
    mock_res.url = "http://test.local"
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    
    # APP と x402 (exactからの正規化) が両方検出されること
    assert "APP" in res.rails_detected
    assert "x402" in res.rails_detected
    assert res.commerce_protocol == "okx_app"
    assert res.settlement_rail == "x402"
    assert res.recommended_action == "observe_only"
    assert res.will_execute_payment is False
    assert res.error_stage is None

def test_cli_grant_inspect_does_not_print_raw_token():
    """grant inspectコマンドがトークン自体をログに漏洩させないことを確認"""
    import base64
    import json
    
    claims = {
        "jti": "grant_secret_123", "asset": "GRANT_CREDIT", "iss": "issuer", 
        "sub": "agent1", "aud": "domain.com", "exp": 9999999999, 
        "scope": {"routes": ["/r"], "methods": ["POST"]}
    }
    header = base64.urlsafe_b64encode(b'{"alg":"EdDSA"}').decode().rstrip('=')
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
    secret_token = f"{header}.{payload}.DO_NOT_PRINT_ME_SIGNATURE"
    
    # サブプロセスとしてCLIを直接叩く
    result = subprocess.run(
        ["python", "-m", "ln_church_agent.cli", "grant", "inspect", "--token", secret_token, "--agent-id", "agent1"],
        capture_output=True, text=True
    )
    
    output = result.stdout
    assert "DO_NOT_PRINT_ME_SIGNATURE" not in output
    assert "usable" in output
    assert "grant_secret_123" not in output  # JTIでさえCLIのデフォルト出力には乗らないように設計されている（res辞書構造参照）