import pytest
import asyncio
from unittest.mock import patch, MagicMock
from ln_church_agent.client import LnChurchClient, SURFACE_PREFLIGHT_SCHEMA_VERSION
from ln_church_agent.models import (
    build_observation_provenance,
    build_protocol_role_observation,
    build_verification_cost_vector,
    OBSERVATION_PROVENANCE_SCHEMA_VERSION,
    PROTOCOL_ROLES_SCHEMA_VERSION
)

def test_build_observation_provenance_normalization():
    """P1-1: 常に4つのキーが正規化されて含まれ、別々のdictオブジェクトであること"""
    mix = {"self_reported": 1}
    prov = build_observation_provenance(mix)
    
    assert prov["not_a_trust_score"] is True
    
    # 正規化の確認
    mix_res = prov["reporter_verification_mix"]
    assert mix_res["self_reported"] == 1
    assert mix_res["key_control_verified"] == 0
    assert mix_res["expired"] == 0
    assert mix_res["unknown"] == 0
    
    # 参照が独立していることの確認
    att_res = prov["attempt_count_by_reporter_verification_status"]
    assert mix_res is not att_res

def test_build_protocol_role_observation_normalization():
    """P1-2 & P1-3: Capability flagがデフォルト値で正規化され、schema_versionが含まれること"""
    obs = build_protocol_role_observation(
        role="payment_settlement",
        protocol="x402",
        capability_observations={"challenge_observed": True}
    )
    
    assert obs["schema_version"] == PROTOCOL_ROLES_SCHEMA_VERSION
    assert obs["role"] == "payment_settlement"
    
    flags = obs["capability_observations"]
    assert flags["challenge_observed"] is True
    assert flags["payment_authorized"] is False  # default
    assert flags["receipt_observed"] is False    # default
    assert len(flags) == 13

@patch("ln_church_agent.client.LnChurchClient.execute_request")
def test_submit_external_observation_with_v13_fields(mock_exec):
    """P0-1 & P1-5: submit_external_observation() に protocol_roles / cost_vector が入ること"""
    client = LnChurchClient(private_key="0x" + "1" * 64)
    mock_exec.return_value = {"status": "accepted"}

    roles = [build_protocol_role_observation("agent_interop", "MCP", {"detected": True})]
    cost = build_verification_cost_vector(label="low")
    
    # Add secrets to verify recursive stripping
    roles[0]["proof_id"] = "SECRET_PROOF_ID"
    cost["signature"] = "SECRET_SIGNATURE"

    client.submit_external_observation(
        target_url="https://api.example.com",
        protocol_roles=roles,
        verification_cost_vector=cost
    )

    payload = mock_exec.call_args.kwargs["payload"]
    assert "protocol_roles" in payload
    assert "verification_cost_vector" in payload
    
    assert payload["protocol_roles"][0]["protocol"] == "MCP"
    # Secret stripping 
    assert "proof_id" not in payload["protocol_roles"][0]
    assert "signature" not in payload["verification_cost_vector"]

@patch("ln_church_agent.client.LnChurchClient.execute_request_async")
def test_async_submissions_with_v13_fields(mock_exec_async):
    """P0-1 & P1-5: Asyncメソッドにもv13_fieldsが入り、後方互換性も維持されること"""
    client = LnChurchClient(private_key="0x" + "1" * 64)
    mock_exec_async.return_value = {"status": "accepted"}

    async def run():
        # A. Optional fieldsを指定した場合
        await client.submit_external_observation_async(
            target_url="https://api.example.com",
            verification_cost_vector=build_verification_cost_vector()
        )
        payload_a = mock_exec_async.call_args.kwargs["payload"]
        assert "verification_cost_vector" in payload_a
        assert "protocol_roles" not in payload_a
        
        # B. 指定しない場合（後方互換性）
        await client.submit_goal_attempt_observation_async(
            goal={"goal_text": "test"},
            attempt={"attempt_mode": "free"}
        )
        payload_b = mock_exec_async.call_args.kwargs["payload"]
        assert "verification_cost_vector" not in payload_b
        assert "protocol_roles" not in payload_b

    asyncio.run(run())

def test_secret_stripping_removes_proof_id_and_nonce():
    """P0-2 & P1-5: proof_id, nonce, signature 等が正確に削除されること"""
    client = LnChurchClient(private_key="0x" + "1" * 64)
    
    dirty_data = {
        "proof_reference": "safe_hash_ref_123", # これは残るべき
        "proof_id": "secret1",
        "ReporterProofId": "secret2",
        "nonce": "secret3",
        "challenge_id": "secret4",
        "signature": "secret5",
        "raw_signature": "secret6",
        "nested": {
            "proof_id": "secret_nested"
        }
    }
    
    clean_data = client._strip_secrets_from_evidence(dirty_data)
    
    assert "proof_reference" in clean_data
    assert "proof_id" not in clean_data
    assert "ReporterProofId" not in clean_data
    assert "nonce" not in clean_data
    assert "challenge_id" not in clean_data
    assert "signature" not in clean_data
    assert "raw_signature" not in clean_data
    assert "proof_id" not in clean_data.get("nested", {})

@patch("ln_church_agent.client.LnChurchClient.ensure_reporter_verification")
@patch("ln_church_agent.client.LnChurchClient.execute_request")
def test_no_auto_identity_verification_hooks(mock_exec, mock_verify):
    """P2: v1.12.0制約の維持 (hook回避)"""
    client = LnChurchClient(private_key="0x" + "1" * 64)
    mock_exec.return_value = {"status": "accepted"}

    client.submit_goal_attempt_observation(goal={"goal_text": "Test"}, attempt={"attempt_mode": "free"})
    
    mock_exec.assert_called_once()
    mock_verify.assert_not_called()

@patch("requests.get")
def test_surface_preflight_accepts_v13_additive_fields(mock_get):
    """P2: v1.12.0制約の維持 (Surface Preflight 後方互換とRead-Only制約)"""
    client = LnChurchClient(private_key="0x" + "1"*64)
    mock_res = MagicMock()
    mock_res.status_code = 200
    
    mock_res.json.return_value = {
        "schema_version": SURFACE_PREFLIGHT_SCHEMA_VERSION,
        "not_a_recommendation": True,
        "not_a_verdict": True,
        "surface": {"known": True},
        "guardrails": {
            "final_authority": "local_runtime",
            "this_read_model_does_not_execute_payments": True,  
            "this_read_model_does_not_prove_settlement": True   
        },
        "observation_provenance": build_observation_provenance({"self_reported": 1})
    }
    mock_get.return_value = mock_res

    res = client.get_surface_preflight(surface_key="surface_0123456789abcdef01234567")
    
    assert res["surface"]["known"] is True
    assert "observation_provenance" in res