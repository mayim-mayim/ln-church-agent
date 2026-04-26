import pytest
import httpx
import base64
import json
from unittest.mock import patch, MagicMock

from ln_church_agent.client import Payment402Client, _b64url_decode
from ln_church_agent.models import PaymentPolicy
from ln_church_agent.exceptions import PaymentExecutionError

# ==========================================
# 1. Accepts 配列からの動的ネットワーク選択テスト
# ==========================================
def test_v2_accepts_array_chain_selection():
    """accepts 配列から要求した chainId (8453: Base) のオプションが正しく選択されるか確認"""
    client = Payment402Client()
    
    payload = {
        "accepts": [
            {"network": "eip155:137", "scheme": "exact", "asset": "USDC", "amount": "1000000", "payTo": "0xPolygonAddress"},
            {"network": "eip155:8453", "scheme": "exact", "asset": "USDC", "amount": "1000000", "payTo": "0xBaseAddress"}
        ]
    }
    b64_str = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    mock_res = httpx.Response(402, headers={"PAYMENT-REQUIRED": b64_str})
    
    # 8453 (Base) を期待してパース
    parsed = client._parse_challenge(mock_res, expected_chain_id="8453")
    
    assert parsed.network == "eip155:8453"
    assert parsed.parameters["payTo"] == "0xBaseAddress"
    assert parsed.parameters["destination"] == "0xBaseAddress"

# ==========================================
# 2. Heuristic Raw-to-Human Unit Conversion と Policy テスト
# ==========================================
def test_v2_raw_to_human_amount_normalization():
    """"10000" が USDC で 0.01 に正規化され、Policyの巨大額ブロックに引っかからないか確認"""
    policy = PaymentPolicy(max_spend_per_tx_usd=5.0) # 上限 5 USD
    client = Payment402Client(policy=policy)
    
    payload = {
        "accepts": [
            {"network": "eip155:137", "scheme": "exact", "asset": "USDC", "amount": "10000", "payTo": "0xABC"} 
        ]
    }
    b64_str = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    mock_res = httpx.Response(402, headers={"PAYMENT-REQUIRED": b64_str})
    
    parsed = client._parse_challenge(mock_res, expected_asset="USDC")
    
    # 10000 Wei(最小単位) -> 0.01 USDC へのヒューリスティック変換が機能しているか
    assert parsed.amount == 0.01
    
    # 10000 USDとして扱われた場合、ここで PaymentExecutionError が発生する
    try:
        client._enforce_policy(parsed, "https://api.example.com")
    except PaymentExecutionError:
        pytest.fail("Policy enforcement failed; raw amount was not correctly normalized to human units.")

# ==========================================
# 3. Exact V2 Envelope 構造のデコードテスト
# ==========================================
@patch("ln_church_agent.client.requests.request")
@patch("ln_church_agent.crypto.evm.LocalKeyAdapter.generate_eip3009_payload")
def test_v2_exact_envelope_construction_and_extension_echo(mock_gen_payload, mock_request):
    """exact スキーム時、x402Versionやextensionsを含む正しいV2エンベロープが構築・送信されるか確認"""
    # 署名生成のモック
    mock_gen_payload.return_value = {"signature": "0xDummySignature", "authorization": {}}
    
    # 402 レスポンス (Extensions付き)
    payload = {
        "accepts": [{"network": "eip155:137", "scheme": "exact", "asset": "USDC", "amount": "1000000", "payTo": "0xABC"}],
        "resource": {"url": "http://api.test", "method": "POST"},
        "extensions": {"agentic_market": {"discovery_id": "999-XYZ"}}
    }
    b64_str = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    res_402 = MagicMock()
    res_402.status_code = 402
    res_402.headers = {"PAYMENT-REQUIRED": b64_str}
    
    # 200 レスポンス
    res_200 = MagicMock()
    res_200.status_code = 200
    res_200.headers = {}
    res_200.json.return_value = {"status": "ok"}
    res_200.content = b'{"status": "ok"}'
    
    mock_request.side_effect = [res_402, res_200]
    
    client = Payment402Client(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")
    client.execute_detailed("POST", "http://api.test")
    
    # リトライ時(インデックス1)の送信リクエスト引数を検証
    args, kwargs = mock_request.call_args_list[1]
    headers = kwargs.get("headers", {})
    
    assert "PAYMENT-SIGNATURE" in headers
    encoded_sig = headers["PAYMENT-SIGNATURE"]
    decoded_env = _b64url_decode(encoded_sig)
    
    # V2 Envelopeの必須キーが存在するか
    assert decoded_env.get("x402Version") == 2
    assert "accepted" in decoded_env
    assert "resource" in decoded_env
    assert "payload" in decoded_env
    
    # Extensions が正しくエコーバックされているか
    assert "extensions" in decoded_env
    assert decoded_env["extensions"]["agentic_market"]["discovery_id"] == "999-XYZ"

# ==========================================
# 4. コントラクトアドレス (0x...) から論理シンボルへのフォールバックテスト
# ==========================================
def test_v2_contract_address_fallback_to_logical_symbol():
    """assetが0xで始まるコントラクトアドレスだった場合、token_addressに退避し、論理シンボルにフォールバックするか確認"""
    client = Payment402Client()
    
    # assetフィールドにUSDCのコントラクトアドレスが直接入ってくるケース
    payload = {
        "accepts": [
            {
                "network": "eip155:137", 
                "scheme": "exact", 
                "asset": "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174", 
                "amount": "1000000", 
                "payTo": "0xTreasury"
            }
        ]
    }
    b64_str = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    mock_res = httpx.Response(402, headers={"PAYMENT-REQUIRED": b64_str})
    
    parsed = client._parse_challenge(mock_res, expected_asset="USDC")
    
    # 0xアドレスが論理シンボル(USDC)に置き換わっていること
    assert parsed.asset == "USDC"
    # 元の0xアドレスはtoken_addressに保持されていること
    assert parsed.parameters["token_address"] == "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174"

# ==========================================
# 5. eth_gasPrice RPC Fix と On-Chain Transfer テスト
# ==========================================
@patch("ln_church_agent.crypto.evm.requests.post")
def test_v1_6_2_eth_gas_price_rpc_call(mock_post):
    """直接送金(lnc-evm-transfer)時に、無効なeth_priceではなくeth_gasPriceが呼ばれることを確認"""
    from ln_church_agent.crypto.evm import LocalKeyAdapter
    
    # RPCコールのモック (eth_getTransactionCount -> eth_gasPrice -> eth_sendRawTransaction)
    mock_res_nonce = MagicMock()
    mock_res_nonce.ok = True
    mock_res_nonce.json.return_value = {"result": "0x1"}
    
    mock_res_gas = MagicMock()
    mock_res_gas.ok = True
    mock_res_gas.json.return_value = {"result": "0x3B9ACA00"} # Gas Price
    
    mock_res_tx = MagicMock()
    mock_res_tx.ok = True
    mock_res_tx.json.return_value = {"result": "0xTxHashSuccess"}
    
    mock_post.side_effect = [mock_res_nonce, mock_res_gas, mock_res_tx]
    
    adapter = LocalKeyAdapter("0x0000000000000000000000000000000000000000000000000000000000000001")
    
    tx_hash = adapter.execute_lnc_evm_transfer_settlement(
        asset="USDC", 
        human_amount=0.01, 
        treasury_address="0x0000000000000000000000000000000000000002", 
        chain_id=137
    )
    
    assert tx_hash == "0xTxHashSuccess"
    
    # 呼び出し履歴をチェックして eth_gasPrice が含まれているか確認
    rpc_methods_called = []
    for call_args in mock_post.call_args_list:
        kwargs = call_args[1]
        if "json" in kwargs and "method" in kwargs["json"]:
            rpc_methods_called.append(kwargs["json"]["method"])
            
    assert "eth_gasPrice" in rpc_methods_called
    assert "eth_price" not in rpc_methods_called  # 旧バグのメソッドが呼ばれていないこと