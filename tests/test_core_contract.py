import pytest
import warnings
import httpx
import asyncio

from unittest.mock import MagicMock, patch
from eth_account import Account

from ln_church_agent.client import Payment402Client, _normalize_scheme
from ln_church_agent.models import (
    SchemeType, ChallengeSource, ParsedChallenge, PaymentPolicy, ExecutionContext
)
from ln_church_agent.exceptions import PaymentExecutionError

# ==========================================
# 1. 旧仕様互換のポリシーテスト (修正版)
# ==========================================
def test_payment_policy_enforcement():
    """1.3.0仕様: ParsedChallenge を使用した1回あたりの上限チェック"""
    policy = PaymentPolicy(max_spend_per_tx_usd=5.0)
    client = Payment402Client(policy=policy)
    
    # 正常な範囲 (2.0 USD)
    valid_challenge = ParsedChallenge(
        scheme="x402", network="eip155:137", amount=2.0, asset="USDC",
        parameters={}, source=ChallengeSource.STANDARD_X402, raw_header=""
    )
    client._enforce_policy(valid_challenge, "https://api.example.com") # 正常に通過
    
    # 上限突破 (6.0 USD) -> エラーを期待
    invalid_challenge = ParsedChallenge(
        scheme="x402", network="eip155:137", amount=6.0, asset="USDC",
        parameters={}, source=ChallengeSource.STANDARD_X402, raw_header=""
    )
    with pytest.raises(PaymentExecutionError, match="exceeds max_spend_per_tx_usd"):
        client._enforce_policy(invalid_challenge, "https://api.example.com")

def test_session_spend_limit_enforcement():
    """セッション上限(累積)のブロック機能テスト"""
    policy = PaymentPolicy(max_spend_per_tx_usd=5.0, max_spend_per_session_usd=7.0)
    client = Payment402Client(policy=policy)
    
    # 1回目: 4.0 USD (OK)
    challenge = ParsedChallenge(
        scheme="x402", network="eip155:137", amount=4.0, asset="USDC",
        parameters={}, source=ChallengeSource.STANDARD_X402, raw_header=""
    )
    client._enforce_policy(challenge, "https://api.example.com")
    client._record_session_spend(challenge) # 決済成功として計上
    assert client.policy._session_spent_usd == 4.0
    
    # 2回目: 4.0 USD (累積が8.0となり上限7.0を超えるため、ブロックされる)
    with pytest.raises(PaymentExecutionError, match="would exceed limit"):
        client._enforce_policy(challenge, "https://api.example.com")

def test_execute_paid_action_compatibility():
    """廃止予定メソッドが正しくラッパーとして機能しているか確認"""
    client = Payment402Client(base_url="https://kari.mayim-mayim.com")
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        try:
            client.execute_paid_action("/api/agent/omikuji", {"asset": "SATS"})
        except Exception:
            pass 
        assert len(w) >= 1
        assert issubclass(w[-1].category, DeprecationWarning)
        assert "execute_paid_action" in str(w[-1].message)

# ==========================================
# 2. Async Lifecycle テスト (プラグイン不要版)
# ==========================================
def test_async_client_lifecycle():
    """AsyncClientの初期化、再利用、および aclose の挙動を確認"""
    async def run_test():
        client = Payment402Client(base_url="https://dummy.local")
        assert client._async_client is None
        
        async with client as c:
            assert c._async_client is not None
            assert not c._async_client.is_closed
        
        assert client._async_client is None
    
    # pytest-asyncioプラグインなしで実行するため、標準のasyncio.runを使用
    asyncio.run(run_test())

# ==========================================
# 3. 1.5.3 標準化機能のテスト
# ==========================================
def test_normalize_scheme():
    """レガシーなエイリアスがFoundation標準の命名に正しく変換されるか確認"""
    assert _normalize_scheme("x402-direct") == SchemeType.lnc_evm_transfer.value
    assert _normalize_scheme("x402-solana") == SchemeType.lnc_solana_transfer.value
    assert _normalize_scheme("x402-relay") == SchemeType.lnc_evm_relay.value
    assert _normalize_scheme("x402") == SchemeType.x402.value

def test_parse_standard_x402_challenge():
    """PAYMENT-REQUIREDヘッダーが正しくパースされ、networkとsourceが設定されるか確認"""
    client = Payment402Client()
    mock_response = httpx.Response(
        402,
        headers={
            "PAYMENT-REQUIRED": 'scheme="x402", network="eip155:137", amount="1.5", asset="USDC", destination="0xABC"'
        }
    )
    parsed = client._parse_challenge(mock_response, expected_asset="USDC")
    
    assert parsed.scheme == "x402"
    assert parsed.network == "eip155:137"
    assert parsed.amount == 1.5
    assert parsed.asset == "USDC"
    assert parsed.source == ChallengeSource.STANDARD_X402

@patch("ln_church_agent.client.requests.request")
@patch("ln_church_agent.crypto.evm.sign_standard_x402_evm")
def test_full_x402_execution_roundtrip(mock_sign_evm, mock_request):
    """402を受け取り、標準x402署名し、再リクエストしてレシートを受け取る一連のフロー"""
    
    # 標準のEVM署名関数の戻り値をモック
    mock_sign_evm.return_value = "0xDummySignature"
    
    client = Payment402Client(
        private_key="0x0000000000000000000000000000000000000000000000000000000000000001",
    )
    
    # 1回目のリクエスト（402 Payment Required）
    response_402 = MagicMock()
    response_402.status_code = 402
    response_402.headers = {
        "PAYMENT-REQUIRED": 'scheme="x402", network="eip155:137", amount="1.0", asset="USDC", payTo="0xABC"'
    }
    
    # 2回目のリクエスト（200 OK と Payment-Receipt）
    response_200 = MagicMock()
    response_200.status_code = 200
    response_200.headers = {
        "PAYMENT-RESPONSE": "ey...JWS_TOKEN..."
    }
    response_200.json.return_value = {"data": "success"}
    response_200.content = b'{"data": "success"}'
    
    # requests.request が呼ばれる順番で戻り値を設定
    mock_request.side_effect = [response_402, response_200]
    
    # 実行
    context = ExecutionContext()
    result = client.execute_detailed("POST", "https://api.example.com/data", context=context)
    
    # 検証
    assert mock_request.call_count == 2
    assert mock_sign_evm.call_count == 1
    
    # 結果の検証
    assert result.response == {"data": "success"}
    assert result.used_scheme == "x402"
    
    # レシート（決済証跡）の検証
    assert result.settlement_receipt is not None
    assert result.settlement_receipt.settled_amount == 1.0
    assert result.settlement_receipt.receipt_token == "ey...JWS_TOKEN..."
    assert result.settlement_receipt.verification_status == "verified"

# ==========================================
# 4. 1.5.6 Wire-Level Protocol Purity & Parser テスト
# ==========================================
import base64
import json

def test_parse_mpp_www_authenticate():
    """v1.5.6: WWW-Authenticate ヘッダーから MPP のチャレンジを正しく最優先でパースできるか確認"""
    client = Payment402Client()
    mock_response = httpx.Response(
        402,
        headers={"WWW-Authenticate": 'MPP invoice="lnbc123", charge="charge456"'}
    )
    parsed = client._parse_challenge(mock_response)
    
    assert parsed.scheme == "MPP"
    assert parsed.parameters["invoice"] == "lnbc123"
    assert parsed.parameters["charge"] == "charge456"
    assert parsed.source == ChallengeSource.STANDARD_WWW

def test_parse_payment_required_respects_scheme():
    """v1.5.6: Base64 JSON パース時に "x402" をハードコードせず、サーバー指定の scheme を尊重するか確認"""
    client = Payment402Client()
    
    # カスタムスキームを含むBase64 JSONを構築
    payload = {"scheme": "CustomL2Scheme", "amount": 10, "asset": "USDC", "network": "eip155:1"}
    b64_str = base64.urlsafe_b64encode(json.dumps(payload).encode('utf-8')).decode('utf-8').rstrip('=')
    
    mock_response = httpx.Response(
        402,
        headers={"PAYMENT-REQUIRED": b64_str}
    )
    parsed = client._parse_challenge(mock_response)
    
    # ハードコードされた "x402" ではなく、サーバーが指定したスキームになること
    assert parsed.scheme == "CustomL2Scheme"

@patch("ln_church_agent.client.LightningProvider")
def test_protocol_purity_mpp_headers(MockLNProvider):
    """v1.5.6: MPP 決済時にボディを汚染せず、Authorization ヘッダーのみを使用するか確認"""
    mock_ln_adapter = MockLNProvider()
    mock_ln_adapter.pay_invoice.return_value = "preimage789"
    
    client = Payment402Client(ln_adapter=mock_ln_adapter)
    
    parsed = ParsedChallenge(
        scheme="MPP", network="Lightning", amount=0, asset="SATS",
        parameters={"invoice": "lnbc123", "charge": "charge456"},
        source=ChallengeSource.STANDARD_WWW
    )
    
    original_headers = {}
    original_payload = {"business_data": "important_value"}
    
    proof_ref, network_name, _ = client._process_payment(parsed, original_headers, original_payload)
    
    # 1. Authorization ヘッダーが正しく設定されていること
    assert "Authorization" in original_headers
    assert original_headers["Authorization"] == "MPP charge456:preimage789"
    
    # 2. x402用の PAYMENT-SIGNATURE ヘッダーが「存在しない」こと（プロトコルの分離）
    assert "PAYMENT-SIGNATURE" not in original_headers
    
    # 3. リクエストボディが汚染（paymentAuthの注入）されていないこと
    assert "paymentAuth" not in original_payload
    assert original_payload == {"business_data": "important_value"}

@patch("ln_church_agent.crypto.evm.sign_standard_x402_evm")
def test_protocol_purity_x402_headers(mock_sign_evm):
    """v1.5.6: x402 決済時には正しく PAYMENT-SIGNATURE ヘッダーが生成されるか確認"""
    mock_sign_evm.return_value = "0xSignature123"
    client = Payment402Client(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")
    
    parsed = ParsedChallenge(
        scheme="x402", network="eip155:137", amount=1, asset="USDC",
        parameters={"destination": "0xabc", "challenge": "macaroon123"},
        source=ChallengeSource.STANDARD_X402
    )
    
    original_headers = {}
    original_payload = {"business_data": "important_value"}
    
    proof_ref, network_name, _ = client._process_payment(parsed, original_headers, original_payload)

    # x402 では PAYMENT-SIGNATURE がBase64で付与されること
    assert "PAYMENT-SIGNATURE" in original_headers
    
    # （後方互換性のため、x402の場合はボディへのインジェクトが許容されていることを確認）
    # x402仕様に準拠し、リクエストボディ（payload）が paymentAuth で汚染されないことを確認する
    assert "paymentAuth" not in original_payload
    assert original_payload == {"business_data": "important_value"}