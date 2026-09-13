# tests/test_grant_override.py
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
        "jti": "mock_jti_123",              # <- 追加
        "asset": "GRANT_CREDIT",            # <- 追加
        "iss": "https://trusted-issuer",
        "sub": client.agent_id,
        "aud": "https://mock.shrine",
        "exp": int(time.time()) + 3600,
        "scope": {"routes": ["/api/agent/omikuji"], "methods": ["POST"]}
    }

    dummy_response = {
        "status": "success", "result": "大吉", "message": "OK", "tx_ref": "tx", "paid": "1 GRANT_CREDIT", 
        "receipt": {"txHash": "x", "ritual": "OMIKUJI", "timestamp": 123, "paid": "1 GRANT_CREDIT", "verify_token": "jws"}
    }

    # 1. Valid Grant -> Omikuji Success
    client.set_grant_token(create_mock_grant(valid_claims))
    with patch.object(client, 'execute_request') as mock_exec:
        mock_exec.return_value = dummy_response
        client.draw_omikuji()
        called_payload = mock_exec.call_args[0][2]
        
        assert "paymentOverride" in called_payload
        assert called_payload["paymentOverride"]["type"] == "grant"

    # 2. Expired Grant -> Graceful Fallback to Standard 402
    expired_claims = {**valid_claims, "exp": int(time.time()) - 100}
    client.set_grant_token(create_mock_grant(expired_claims))
    with patch.object(client, 'execute_request') as mock_exec:
        mock_exec.return_value = dummy_response
        client.draw_omikuji()
        called_payload = mock_exec.call_args[0][2]
        
        assert "paymentOverride" not in called_payload

    # 3. Wrong Route -> Fallback
    wrong_route_claims = {**valid_claims, "scope": {"routes": ["/api/agent/other"], "methods": ["POST"]}}
    client.set_grant_token(create_mock_grant(wrong_route_claims))
    assert client.has_valid_scoped_grant("/api/agent/omikuji", "POST") is False

    # 4. Legacy Faucet Fallback
    client.faucet_token = "legacy_faucet_token_123"
    with patch.object(client, 'execute_request') as mock_exec:
        mock_exec.return_value = dummy_response
        client.draw_omikuji()
        called_payload = mock_exec.call_args[0][2]
        assert called_payload["paymentOverride"]["type"] == "faucet"

@pytest.mark.parametrize("async_mode", [False, True])
@pytest.mark.parametrize("valid, faucet, expected", [
    (True, True, "grant"), (True, False, "grant"),
    (False, True, "faucet"), (False, False, None),
])
def test_public_access_priority_and_diagnostic(async_mode, valid, faucet, expected):
    import asyncio
    from unittest.mock import AsyncMock
    client = LnChurchClient(agent_id="grant-test", base_url="https://mock.shrine")
    client.set_grant_token(create_mock_grant({
        "jti": "mock_jti_123", "asset": "GRANT_CREDIT", "iss": "https://issuer.test",
        "sub": client.agent_id, "aud": client.base_url, "exp": int(time.time()) + 3600,
        "scope": {"routes": ["/api/agent/omikuji" if valid else "/other"], "methods": ["POST"]},
    }))
    client.faucet_token = "fixture-faucet" if faucet else None
    client.probe_token = "fixture-probe"
    response = {"status": "success", "result": "ok", "message": "ok", "tx_ref": "tx", "paid": "1",
                "receipt": {"txHash": "x", "ritual": "OMIKUJI", "timestamp": 123, "paid": "1", "verify_token": "jws"}}
    method = "execute_request_async" if async_mode else "execute_request"
    with patch.object(client, method, **({"new_callable": AsyncMock} if async_mode else {})) as send:
        send.return_value = response
        call = client.draw_omikuji_async if async_mode else client.draw_omikuji
        result = call(scheme="L402", clientType="caller")
        if async_mode:
            asyncio.run(result)
        payload, headers = send.call_args.args[2:4]
        assert send.call_count == 1
        assert payload.get("paymentOverride", {}).get("type") == expected
        assert payload["scheme"] == "L402" and payload["asset"] == "SATS"
        assert payload["clientType"] == "caller"
        assert headers == {"x-probe-token": "fixture-probe"}
        assert client._last_grant_diagnostics.usable is valid


def test_graceful_fallback_no_exceptions():
    client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001", base_url="https://mock.shrine")
    invalid_claims = {
        "jti": "mock_jti_123", "asset": "GRANT_CREDIT", "iss": "https://trusted-issuer", 
        "sub": "wrong_agent", "aud": "https://mock.shrine", "exp": int(time.time()) + 3600, 
        "scope": {"routes": ["/api/agent/omikuji"], "methods": ["POST"]}
    }
    client.set_grant_token(create_mock_grant(invalid_claims))
    
    # has_valid_scoped_grant はエラーを投げずに False を返す
    assert client.has_valid_scoped_grant("/api/agent/omikuji", "POST") is False
    assert client._last_grant_diagnostics.usable is False
    assert client._last_grant_diagnostics.failure_class == "subject_mismatch"