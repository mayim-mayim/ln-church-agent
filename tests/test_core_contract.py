import pytest
import warnings
from ln_church_agent.models import PaymentPolicy, ParsedChallenge
from ln_church_agent.client import Payment402Client
from ln_church_agent.exceptions import PaymentExecutionError

def test_payment_policy_enforcement():
    """1.3.0仕様: ParsedChallenge を使用した1回あたりの上限チェック"""
    # 1回の上限を 5.0 USD に設定
    policy = PaymentPolicy(max_spend_per_tx_usd=5.0)
    client = Payment402Client(policy=policy)
    
    # 正常な範囲 (2.0 USD)
    valid_challenge = ParsedChallenge(scheme="x402", amount=2.0, asset="USDC")
    client._enforce_policy(valid_challenge, "https://api.example.com") # 正常に通過
    
    # 上限突破 (6.0 USD) -> エラーを期待
    invalid_challenge = ParsedChallenge(scheme="x402", amount=6.0, asset="USDC")
    with pytest.raises(PaymentExecutionError, match="exceeds max_spend_per_tx_usd"):
        client._enforce_policy(invalid_challenge, "https://api.example.com")

def test_session_spend_limit_enforcement():
    """セッション上限(累積)のブロック機能テスト"""
    # 1回 5.0 / セッション合計 7.0 USD に設定
    policy = PaymentPolicy(max_spend_per_tx_usd=5.0, max_spend_per_session_usd=7.0)
    client = Payment402Client(policy=policy)
    
    # 1回目: 4.0 USD (OK)
    challenge = ParsedChallenge(scheme="x402", amount=4.0, asset="USDC")
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
            # 真の旧シグネチャ互換テスト: execute_paid_action(path, payload) ※methodなし
            client.execute_paid_action("/api/agent/omikuji", {"asset": "SATS"})
        except Exception:
            pass # 通信自体の成否ではなく、シグネチャによる例外が出ないことを検証

        assert len(w) >= 1
        assert issubclass(w[-1].category, DeprecationWarning)
        assert "execute_paid_action" in str(w[-1].message)

import pytest
from ln_church_agent import Payment402Client, LnChurchClient

# --- v1.3.1 挙動担保テスト ---

def test_invalid_private_key_raises_value_error():
    """不正な秘密鍵を渡した際、Silent Fallbackせずに明示的なエラーが出ることを確認"""
    with pytest.raises(ValueError, match="Invalid private_key format"):
        # 明らかにEVMでもSolanaでもない文字列
        LnChurchClient(private_key="this_is_a_completely_invalid_key_string")

@pytest.mark.asyncio
async def test_async_client_lifecycle():
    """AsyncClientの初期化、再利用、および aclose の挙動を確認"""
    client = Payment402Client(base_url="https://dummy.local")
    
    # 最初はNone
    assert client._async_client is None
    
    # コンテキストマネージャーに入ると初期化される
    async with client as c:
        assert c._async_client is not None
        assert not c._async_client.is_closed
    
    # コンテキストマネージャーを抜けると自動で閉じられ、Noneに戻る
    assert client._async_client is None