import pytest
import asyncio
from unittest.mock import patch
from ln_church_agent import LnChurchClient, AssetType
from ln_church_agent.crypto.evm import LocalKeyAdapter

# ==========================================
# 1. EVM Relay Payload の完全性テスト
# ==========================================
@patch("ln_church_agent.crypto.evm.requests.post")
def test_evm_relay_payload_completeness_and_padding(mock_post):
    """
    1.6.1 の修正が正しく機能しているかを確認：
    - 'to' フィールドが存在するか
    - 'chainId' フィールドが存在するか
    - 'r' と 's' が 64桁（32バイト）で固定されているか
    """
    dummy_key = "0x0000000000000000000000000000000000000000000000000000000000000001"
    dummy_treasury = "0x0000000000000000000000000000000000000002"
    dummy_token = "0x0000000000000000000000000000000000000003"
    
    adapter = LocalKeyAdapter(dummy_key)
    
    mock_post.return_value.ok = True
    mock_post.return_value.json.return_value = {"txHash": "0xabc123"}
    
    adapter.execute_lnc_evm_relay_settlement(
        asset="USDC",
        human_amount=0.01,
        relayer_url="http://mock-relayer",
        treasury_address=dummy_treasury,
        chain_id=8453,
        token_address=dummy_token
    )
    
    args, kwargs = mock_post.call_args
    payload = kwargs["json"]
    
    # A. 必須フィールドの確認
    assert payload["to"] == dummy_treasury, "payload に 'to' が含まれていません"
    assert payload["chainId"] == 8453, "payload に 'chainId' が含まれていません"
    
    # B. 署名パディングの確認
    r_hex = payload["r"].replace("0x", "")
    s_hex = payload["s"].replace("0x", "")
    assert len(r_hex) == 64, f"r の長さが正しくありません: {len(r_hex)}"
    assert len(s_hex) == 64, f"s の長さが正しくありません: {len(s_hex)}"
    
    # C. v の型確認
    assert isinstance(payload["v"], int), "v は整数型である必要があります"

# ==========================================
# 2. Convenience Method の **kwargs 注入テスト (Sync)
# ==========================================
@patch("ln_church_agent.client.LnChurchClient.execute_request")
def test_convenience_method_kwargs_injection(mock_execute):
    """
    draw_omikuji 等のメソッドが **kwargs を受け取り、
    正しくペイロードに追加パラメータをマージすることを確認する
    """
    client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")
    
    try:
        client.draw_omikuji(asset=AssetType.USDC, chainId="8453")
    except Exception:
        pass
    
    args, kwargs = mock_execute.call_args
    sent_payload = args[2] 
    assert sent_payload["chainId"] == "8453", "draw_omikuji で注入した chainId が payload に含まれていません"

    try:
        client.submit_confession(raw_message="fail", custom_tag="debug_mode")
    except Exception:
        pass
        
    args, kwargs = mock_execute.call_args
    sent_payload = args[2]
    assert sent_payload["custom_tag"] == "debug_mode", "submit_confession で注入した任意引数が含まれていません"

# ==========================================
# 3. Core Field Override の意図的な許容テスト
# ==========================================
@patch("ln_church_agent.client.LnChurchClient.execute_request")
def test_convenience_method_allows_core_field_override_currently(mock_execute):
    """
    現行仕様として、agentId などのコアフィールドも **kwargs で上書き可能であることを固定する。
    将来的に保護すべきフィールドが出てきた場合は、このテストを見直すこと。
    """
    client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")
    
    try:
        client.draw_omikuji(agentId="FORCE_OVERWRITE_ID")
    except Exception:
        pass
        
    args, kwargs = mock_execute.call_args
    sent_payload = args[2]
    assert sent_payload["agentId"] == "FORCE_OVERWRITE_ID", "kwargs による内部フィールドの上書きが機能していません"

# ==========================================
# 4. Convenience Method の **kwargs 注入テスト (Async)
# ==========================================
def test_convenience_method_async_kwargs_injection():
    """
    非同期(async)版の convenience method でも **kwargs 注入が機能するか確認する
    """
    async def run_test():
        with patch("ln_church_agent.client.LnChurchClient.execute_request_async") as mock_execute_async:
            client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")
            
            # ★ 警告を消すための修正：非同期モックが返すダミーの辞書をセットする
            mock_execute_async.return_value = {
                "status": "success", "result": "吉", "message": "OK", "tx_ref": "tx", "paid": "0.01",
                "receipt": {"txHash": "x", "ritual": "R", "timestamp": 1, "paid": "x", "verify_token": "jws"}
            }
            
            try:
                await client.draw_omikuji_async(asset=AssetType.USDC, chainId="8453")
            except Exception:
                pass
            
            args, kwargs = mock_execute_async.call_args
            sent_payload = args[2]
            assert sent_payload["chainId"] == "8453", "draw_omikuji_async で注入した chainId が payload に含まれていません"
            
    asyncio.run(run_test())