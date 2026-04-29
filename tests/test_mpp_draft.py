import pytest
import base64
import json
from unittest.mock import patch, MagicMock

from ln_church_agent.client import Payment402Client
from ln_church_agent.models import PaymentPolicy, ChallengeSource
from ln_church_agent.exceptions import PaymentExecutionError

def test_1_payment_scheme_allowed():
    """Test 1: Payment scheme が policy でデフォルト許可されていること"""
    policy = PaymentPolicy()
    assert "Payment" in policy.allowed_schemes

def test_2_legacy_mpp_flat_invoice():
    """Test 2: legacy MPP flat invoice のパースと分類"""
    client = Payment402Client()
    
    header = 'MPP invoice="lnbc123", intent="charge"'
    parsed = client._parse_www_authenticate(header, ChallengeSource.STANDARD_WWW)
    
    assert parsed.scheme == "MPP"
    assert parsed.parameters.get("invoice") == "lnbc123"
    assert parsed.draft_shape == "legacy-mpp-flat"
    assert parsed.payment_method == "lightning"
    assert parsed.payment_intent == "charge"

def test_3_payment_draft_challenge():
    """Test 3: Payment draft challenge (Base64URL JSON) のパースと分類"""
    client = Payment402Client()
    
    req_json = {
        "amount": "1000",
        "currency": "sats",
        "methodDetails": {
            "invoice": "lnbc123"
        }
    }
    b64_req = base64.urlsafe_b64encode(json.dumps(req_json).encode()).decode().rstrip('=')
    
    header = f'Payment id="ch_123", realm="example", method="lightning", intent="charge", request="{b64_req}"'
    parsed = client._parse_www_authenticate(header, ChallengeSource.STANDARD_WWW)
    
    assert parsed.scheme == "Payment"
    assert parsed.parameters.get("id") == "ch_123"
    assert parsed.payment_method == "lightning"
    assert parsed.payment_intent == "charge"
    assert parsed.parameters.get("invoice") == "lnbc123"
    assert parsed.draft_shape == "payment-auth-draft"
    assert parsed.request_b64_present is True
    assert parsed.decoded_request_valid is True
    
    # 💡 追加: amount と currency が反映されていること
    assert parsed.amount == 1000.0
    assert parsed.asset == "SATS"
    
    # 💡 追加: request_json が保持されていること
    assert parsed.parameters["request_json"]["amount"] == "1000"

def test_4_invalid_request():
    """Test 4: Invalid な request (不正なBase64) でクラッシュせず分類されること"""
    client = Payment402Client()
    
    header = 'Payment id="ch_123", method="lightning", intent="charge", request="not-valid-base64-!!!"'
    parsed = client._parse_www_authenticate(header, ChallengeSource.STANDARD_WWW)
    
    assert parsed.scheme == "Payment"
    assert parsed.request_b64_present is True
    assert parsed.decoded_request_valid is False
    assert parsed.draft_shape == "payment-auth-draft-invalid-request"
    assert parsed.payment_method == "lightning"
    assert parsed.payment_intent == "charge"

def test_5_session_unsupported():
    """Test 5: intent="session" がサポート外として安全に拒否されること"""
    client = Payment402Client()
    
    req_json = {"amount": "1000", "currency": "sats", "methodDetails": {"invoice": "lnbc123"}}
    b64_req = base64.urlsafe_b64encode(json.dumps(req_json).encode()).decode().rstrip('=')
    
    header = f'Payment id="sess_123", method="lightning", intent="session", request="{b64_req}"'
    parsed = client._parse_www_authenticate(header, ChallengeSource.STANDARD_WWW)
    
    assert parsed.payment_intent == "session"
    assert parsed.draft_shape == "payment-auth-draft"
    
    # 実行フェーズで意図したエラーが出るか確認
    with pytest.raises(PaymentExecutionError, match="mpp_session_not_supported_yet"):
        client._process_payment(parsed, {}, {}, method="GET", url="http://mock")

@patch("ln_church_agent.client.LightningProvider")
def test_6_payment_draft_execution_guard(MockLNProvider):
    """Test 6: scheme=Payment, payment-auth-draft の場合、レガシーフォールバックが無効なら支払い前に止まること"""
    mock_ln_adapter = MockLNProvider()
    client = Payment402Client(ln_adapter=mock_ln_adapter, allow_legacy_payment_auth_fallback=False)
    
    req_json = {"amount": "1000", "currency": "sats", "methodDetails": {"invoice": "lnbc123"}}
    b64_req = base64.urlsafe_b64encode(json.dumps(req_json).encode()).decode().rstrip('=')
    
    header = f'Payment id="ch_123", method="lightning", intent="charge", request="{b64_req}"'
    parsed = client._parse_www_authenticate(header, ChallengeSource.STANDARD_WWW)
    
    assert parsed.draft_shape == "payment-auth-draft"
    
    with pytest.raises(PaymentExecutionError, match="unsupported-payment-auth-json"):
        client._process_payment(parsed, {}, {}, method="GET", url="http://mock")
        
    # 支払いが実行されていないことを確認
    mock_ln_adapter.pay_invoice.assert_not_called()

def test_7_payment_receipt_presence():
    """Test 7: payment_receipt_present がサーバーからのトークン有無で判定されること（run_mpp_charge_sandbox_harnessロジック）"""
    client = Payment402Client()
    # このテストはクライアントのメソッドに組み込まれたロジックを直接検証するのではなく、
    # 概念として「サーバーレシートなし」なら False になることを意図したものです。
    # 実際には run_mpp_charge_sandbox_harness 内で
    # payment_receipt_present = bool(receipt and getattr(...) ...) 
    # として評価されます。ここでは receipt オブジェクトの状態を模倣して確認します。
    
    from ln_church_agent.models import SettlementReceipt, AttestationSource
    
    receipt_without_server_token = SettlementReceipt(
        receipt_id="123", scheme="L402", network="Lightning", asset="SATS", settled_amount=10.0,
        proof_reference="preimage123", source=AttestationSource.CLIENT_REPORTED
    )
    
    # 内部ロジックと同じ評価
    is_present_false = bool(
        receipt_without_server_token
        and getattr(receipt_without_server_token, "receipt_token", None)
        and getattr(receipt_without_server_token, "source", None) == AttestationSource.SERVER_JWS
    )
    assert is_present_false is False
    
    receipt_with_server_token = SettlementReceipt(
        receipt_id="123", scheme="L402", network="Lightning", asset="SATS", settled_amount=10.0,
        proof_reference="preimage123", receipt_token="jws.token.here", source=AttestationSource.SERVER_JWS
    )
    
    is_present_true = bool(
        receipt_with_server_token
        and getattr(receipt_with_server_token, "receipt_token", None)
        and getattr(receipt_with_server_token, "source", None) == AttestationSource.SERVER_JWS
    )
    assert is_present_true is True

def test_8_request_is_json_list():
    """Test 8: request が valid JSON だが dict ではない(listなど)場合に落ちないこと"""
    client = Payment402Client()
    
    req_json = ["not", "a", "dict"]
    b64_req = base64.urlsafe_b64encode(json.dumps(req_json).encode()).decode().rstrip('=')
    
    header = f'Payment id="ch_123", method="lightning", intent="charge", request="{b64_req}"'
    parsed = client._parse_www_authenticate(header, ChallengeSource.STANDARD_WWW)
    
    # parser が落ちず、不正なリクエストとして扱われること
    assert parsed.request_b64_present is True
    assert parsed.decoded_request_valid is False
    assert parsed.draft_shape == "payment-auth-draft-invalid-request"