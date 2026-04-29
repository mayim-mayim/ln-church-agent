import pytest
import json
import hashlib
import asyncio
from unittest.mock import patch, AsyncMock
from ln_church_agent.client import LnChurchClient
from ln_church_agent.models import ExecutionResult, SettlementReceipt, AttestationSource

@patch("ln_church_agent.client.LnChurchClient.execute_detailed")
def test_mpp_sandbox_harness_dynamic_telemetry(mock_execute):
    """
    MPP Harness がハードコードされた Authorization Scheme を使わず、
    動的に Receipt から抽出した値を送信し、拡張テレメトリを含めることを確認する。
    """
    client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")
    
    # 💡 修正: 新しい厳密な判定を通過させるため、receipt_token と source=SERVER_JWS を追加
    mock_receipt = SettlementReceipt(
        receipt_id="r_123", scheme="MPP_Draft_v2", network="Lightning", 
        asset="SATS", settled_amount=10, proof_reference="preimage123",
        receipt_token="dummy.jws.token.here", source=AttestationSource.SERVER_JWS
    )
    
    deterministic_payload = {
        "message": "MPP success", "scenario": "mpp-charge-basic-v1", 
        "contract": "stable", "verifiable": True
    }
    json_str = json.dumps(deterministic_payload, separators=(',', ':'))
    expected_hash = hashlib.sha256(json_str.encode('utf-8')).hexdigest()

    get_result = ExecutionResult(
        response={
            **deterministic_payload,
            "meta": {
                "run_id": "run_123", "scenario_id": "mpp-charge-basic-v1",
                "canonical_hash_expected": expected_hash, "interop_token": "token:1:2:3:4"
            }
        },
        final_url="http://mock/sandbox/mpp",
        settlement_receipt=mock_receipt,
        used_scheme="MPP_Draft_v2"
    )
    
    post_result = ExecutionResult(response={"status": "success"}, final_url="http://mock/report")
    mock_execute.side_effect = [get_result, post_result]
    
    res = client.run_mpp_charge_sandbox_harness()
    
    assert res.ok is True
    
    args, kwargs = mock_execute.call_args_list[1]
    assert args[0] == "POST"
    
    payload = kwargs["payload"]
    assert payload["rail"] == "MPP"
    assert payload["payment_intent"] == "charge"
    assert payload["authorization_scheme"] == "MPP_Draft_v2"
    assert payload["payment_receipt_present"] is True


@patch("ln_church_agent.client.LnChurchClient.execute_detailed_async")
def test_mpp_sandbox_harness_async_dynamic_telemetry(mock_execute_async):
    """
    MPP Harness の非同期 (async) 版でも動的抽出と拡張テレメトリが正常に機能するかを確認する。
    """
    async def run_test():
        client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")
        
        # 💡 修正: 新しい厳密な判定を通過させるため、receipt_token と source=SERVER_JWS を追加
        mock_receipt = SettlementReceipt(
            receipt_id="r_123", scheme="MPP_Async_Test", network="Lightning", 
            asset="SATS", settled_amount=10, proof_reference="preimage123",
            receipt_token="dummy.jws.token.here", source=AttestationSource.SERVER_JWS
        )

        deterministic_payload = {
            "message": "MPP async success", "scenario": "mpp-charge-basic-v1", 
            "contract": "stable", "verifiable": True
        }
        json_str = json.dumps(deterministic_payload, separators=(',', ':'))
        expected_hash = hashlib.sha256(json_str.encode('utf-8')).hexdigest()

        get_result = ExecutionResult(
            response={
                **deterministic_payload,
                "meta": {
                    "run_id": "run_async_123", "scenario_id": "mpp-charge-basic-v1",
                    "canonical_hash_expected": expected_hash, "interop_token": "token:1:2:3:4"
                }
            },
            final_url="http://mock/sandbox/mpp",
            settlement_receipt=mock_receipt,
            used_scheme="MPP_Async_Test"
        )
        
        post_result = ExecutionResult(response={"status": "success"}, final_url="http://mock/report")
        mock_execute_async.side_effect = [get_result, post_result]
        
        res = await client.run_mpp_charge_sandbox_harness_async()
        
        assert res.ok is True
        
        args, kwargs = mock_execute_async.call_args_list[1]
        assert args[0] == "POST"
        payload = kwargs["payload"]
        
        assert payload["rail"] == "MPP"
        assert payload["payment_intent"] == "charge"
        assert payload["authorization_scheme"] == "MPP_Async_Test"
        assert payload["payment_receipt_present"] is True

    asyncio.run(run_test())


# 💡 復活: 欠落してしまっていたL402のテストケース
@patch("ln_church_agent.client.LnChurchClient.execute_detailed")
def test_l402_sandbox_harness_extended_telemetry(mock_execute):
    """
    L402 Harness でも MPP と同様に拡張テレメトリ (rail, payment_intent 等) が
    送信されるよう修正されたことを確認する。
    """
    client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")
    
    # 💡 修正: こちらのモックにも追加しておく
    mock_receipt = SettlementReceipt(
        receipt_id="r_123", scheme="L402", network="Lightning", 
        asset="SATS", settled_amount=10, proof_reference="preimage123",
        receipt_token="dummy.jws.token.here", source=AttestationSource.SERVER_JWS
    )

    deterministic_payload = {
        "message": "L402 success", "scenario": "l402-basic-v1", 
        "contract": "stable", "verifiable": True
    }
    json_str = json.dumps(deterministic_payload, separators=(',', ':'))
    expected_hash = hashlib.sha256(json_str.encode('utf-8')).hexdigest()

    get_result = ExecutionResult(
        response={
            **deterministic_payload,
            "meta": {
                "run_id": "run_123", "scenario_id": "l402-basic-v1",
                "canonical_hash_expected": expected_hash, "interop_token": "token:1:2:3:4"
            }
        },
        final_url="http://mock/sandbox/l402",
        settlement_receipt=mock_receipt,
        used_scheme="L402"
    )
    
    post_result = ExecutionResult(response={"status": "success"}, final_url="http://mock/report")
    mock_execute.side_effect = [get_result, post_result]
    
    res = client.run_l402_sandbox_harness()
    
    assert res.ok is True
    
    args, kwargs = mock_execute.call_args_list[1]
    payload = kwargs["payload"]
    
    assert payload["rail"] == "L402"
    assert payload["payment_intent"] == "charge"
    assert payload["authorization_scheme"] == "L402"
    assert payload["payment_receipt_present"] is True