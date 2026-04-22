import pytest
import time
import base64
import json
from unittest.mock import patch
from ln_church_agent import LnChurchClient, AssetType
from ln_church_agent.models import _ExecutionUnlock, _FundingPolicy, _EntitlementKind

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

def test_internal_access_selection_priority():
    """v1.6 internal: Selector が正しい優先順位で Plan を生成・選択することを確認"""
    client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001", base_url="https://mock.shrine")
    
    valid_claims = {
        "iss": "https://trusted-issuer",
        "sub": client.agent_id,
        "aud": "https://mock.shrine",
        "exp": time.time() + 3600,
        "scope": {"routes": ["/api/agent/omikuji"], "methods": ["POST"]}
    }

    # 1. 両方持っている場合 (Grant 優先)
    client.set_grant_token(create_mock_grant(valid_claims))
    client.faucet_token = "faucet_dummy"
    
    candidates = client._collect_execution_access_candidates("/api/agent/omikuji", "POST", "SATS", "L402")
    assert len(candidates) == 3 # Grant, Faucet, Direct
    
    plan = client._select_execution_access_plan(candidates)
    assert plan.entitlement_kind == _EntitlementKind.GRANT
    assert plan.funding_policy == _FundingPolicy.FULLY_SPONSORED
    
    # 2. Grant が無効な場合 (Faucet にフォールバック)
    invalid_claims = {**valid_claims, "exp": time.time() - 3600}
    client.set_grant_token(create_mock_grant(invalid_claims))
    
    candidates2 = client._collect_execution_access_candidates("/api/agent/omikuji", "POST", "SATS", "L402")
    assert len(candidates2) == 2 # Faucet, Direct
    
    plan2 = client._select_execution_access_plan(candidates2)
    assert plan2.entitlement_kind == _EntitlementKind.FAUCET
    
    # 3. どちらも無い場合 (Direct Settlement)
    client.faucet_token = None
    
    candidates3 = client._collect_execution_access_candidates("/api/agent/omikuji", "POST", "SATS", "L402")
    assert len(candidates3) == 1 # Direct
    
    plan3 = client._select_execution_access_plan(candidates3)
    assert plan3.unlock == _ExecutionUnlock.SETTLEMENT_PROOF
    assert plan3.entitlement_kind is None