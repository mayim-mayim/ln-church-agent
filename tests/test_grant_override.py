import pytest
import time
import base64
import json
from unittest.mock import patch
from ln_church_agent import LnChurchClient, AssetType

def create_mock_grant(claims: dict) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"EdDSA"}').decode().rstrip('=')
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
    signature = "dummy_signature"
    return f"{header}.{payload}.{signature}"

def test_grant_evaluation_and_priority():
    client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001", base_url="https://mock.shrine")
    
    valid_claims = {
        "iss": "https://trusted-issuer",
        "sub": client.agent_id,
        "aud": "https://mock.shrine",
        "exp": time.time() + 3600,
        "scope": {"routes": ["/api/agent/omikuji"], "methods": ["POST"]}
    }

    # テストを通過させるためのダミーレスポンス
    dummy_response = {
        "status": "success", 
        "result": "大吉", 
        "message": "OK", 
        "tx_ref": "tx", 
        "paid": "1 GRANT_CREDIT", 
        "receipt": {"txHash": "x", "ritual": "OMIKUJI", "timestamp": 123, "paid": "1 GRANT_CREDIT", "verify_token": "jws"}
    }

    # 1. Valid Grant -> Omikuji Success (Override Injected)
    client.set_grant_token(create_mock_grant(valid_claims))
    with patch.object(client, 'execute_request') as mock_exec:
        mock_exec.return_value = dummy_response
        
        client.draw_omikuji()
        called_payload = mock_exec.call_args[0][2]
        
        assert "paymentOverride" in called_payload
        assert called_payload["paymentOverride"]["type"] == "grant"
        assert called_payload["paymentOverride"]["asset"] == "GRANT_CREDIT"

    # 2. Expired Grant -> Normal Settlement Fallback (No Override Injected)
    expired_claims = {**valid_claims, "exp": time.time() - 100}
    client.set_grant_token(create_mock_grant(expired_claims))
    with patch.object(client, 'execute_request') as mock_exec:
        mock_exec.return_value = dummy_response # ←★ココを追加
        
        client.draw_omikuji()
        called_payload = mock_exec.call_args[0][2]
        assert "paymentOverride" not in called_payload # Falls back to normal 402

    # 3. Wrong Route / Wrong Audience -> Fallback
    wrong_route_claims = {**valid_claims, "scope": {"routes": ["/api/agent/other"], "methods": ["POST"]}}
    client.set_grant_token(create_mock_grant(wrong_route_claims))
    assert client.has_valid_scoped_grant("/api/agent/omikuji", "POST") is False

    # 4. Legacy Faucet Path Still Works (If Grant is invalid but Faucet exists)
    client.faucet_token = "legacy_faucet_token_123"
    with patch.object(client, 'execute_request') as mock_exec:
        mock_exec.return_value = dummy_response # ←★ココも追加
        
        client.draw_omikuji()
        called_payload = mock_exec.call_args[0][2]
        assert called_payload["paymentOverride"]["type"] == "faucet"