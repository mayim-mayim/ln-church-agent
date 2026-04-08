import pytest
from unittest.mock import Mock, patch
from ln_church_agent.client import Payment402Client
from ln_church_agent.models import PaymentPolicy
from ln_church_agent.adapters.nwc import NWCAdapter
from ln_church_agent.exceptions import PaymentExecutionError

# ==========================================
# 1. NWCAdapter の初期化テスト (Bridge前提)
# ==========================================
def test_nwc_adapter_initialization():
    """NWCAdapterがHTTP Bridge URLと共に正常に初期化されることを確認"""
    uri = "nostr+walletconnect://mypubkey?relay=wss://relay.example.com&secret=mock"
    bridge = "https://bridge.example.com/api/nwc"
    
    adapter = NWCAdapter(nwc_uri=uri, bridge_url=bridge)
    
    assert adapter.wallet_pubkey == "mypubkey"
    assert adapter.bridge_url == bridge
    assert adapter.get_balance() == 0.0  # スタブがクラッシュせずに返るか

# ==========================================
# 2. PaymentPolicy の実効性テスト
# ==========================================
def test_payment_policy_enforcement():
    """PolicyがScheme, Asset, USD上限に基づいて正確にブロックすることを確認"""
    policy = PaymentPolicy(
        allowed_schemes=["L402"],
        allowed_assets=["SATS", "USDC"],
        max_spend_per_tx_usd=1.0  # 上限1ドル
    )
    client = Payment402Client(policy=policy)
    
    # [A] 許可されていないSchemeによるブロック
    with pytest.raises(PaymentExecutionError, match="Scheme 'x402' is restricted"):
        client._enforce_policy(scheme="x402", asset="USDC", amount=0.5)
        
    # [B] 許可されていないAssetによるブロック
    with pytest.raises(PaymentExecutionError, match="Asset 'JPYC' is restricted"):
        client._enforce_policy(scheme="L402", asset="JPYC", amount=100)
        
    # [C] USD換算の限度額超過によるブロック (2 USDC = 2 USD > 1 USD)
    with pytest.raises(PaymentExecutionError, match="exceeds max_spend_per_tx_usd"):
        client._enforce_policy(scheme="L402", asset="USDC", amount=2.0)

    # [D] 正常系 (0.5 USDC = 0.5 USD) -> エラーが起きずに通過すること
    try:
        client._enforce_policy(scheme="L402", asset="USDC", amount=0.5)
    except Exception as e:
        pytest.fail(f"Valid policy check raised an exception: {e}")

# ==========================================
# 3. SettlementReceipt の生成テスト
# ==========================================
def test_settlement_receipt_generation():
    """402チャレンジ処理後に、正確な内容のReceiptが生成されることを確認"""
    
    # NWCAdapterのモック (決済成功とPreimage返却をシミュレート)
    mock_adapter = Mock(spec=NWCAdapter)
    mock_adapter.pay_invoice.return_value = "fake_preimage_123"
    
    client = Payment402Client(ln_adapter=mock_adapter)
    
    # 402 HTTPレスポンスのモック
    mock_res = Mock()
    mock_res.json.return_value = {
        "challenge": {
            "scheme": "L402",
            "amount": 500,
            "asset": "SATS",
            "parameters": {"invoice": "lnbc500mock..."}
        }
    }
    mock_res.headers = {"WWW-Authenticate": 'L402 macaroon="mock_macaroon", invoice="lnbc500mock..."'}
    
    # 再帰的な execute_request 呼び出しをパッチして止める
    with patch.object(client, 'execute_request') as mock_exec:
        mock_exec.return_value = {"status": "success"}
        
        # _handle_402_challenge を直接実行
        client._handle_402_challenge(
            response=mock_res, 
            payload={"asset": "SATS"}, 
            headers={}, 
            url="http://fake-api", 
            method="POST", 
            _current_hop=0, 
            _payment_retry_count=0
        )
        
        # 生成された Receipt の検証
        receipt = client.last_receipt
        assert receipt is not None, "SettlementReceipt was not generated."
        assert receipt.receipt_id.startswith("rec_")
        assert receipt.scheme == "L402"
        assert receipt.network == "Lightning"
        assert receipt.asset == "SATS"
        assert receipt.settled_amount == 500.0
        assert receipt.proof_reference == "fake_preimage_123"
        assert receipt.verification_status == "verified"