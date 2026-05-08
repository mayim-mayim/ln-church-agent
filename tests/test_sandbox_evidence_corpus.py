import pytest
from unittest.mock import patch
from ln_church_agent.models import SandboxEvidence
from ln_church_agent.evidence import build_sandbox_corpus_candidate
from ln_church_agent.client import LnChurchClient

def test_corpus_candidate_l402_verified():
    ev = SandboxEvidence(
        evidence_scope="sandbox_internal",
        run_id="r1",
        scenario_id="s1",
        rail="L402",
        verification_status="verified",
        canonical_hash_matched=True
    )
    cand = build_sandbox_corpus_candidate(ev)
    assert cand.corpus_eligible is True
    assert cand.exclusion_reason is None
    assert cand.rail == "L402"
    
def test_corpus_candidate_mpp_verified():
    ev = SandboxEvidence(
        evidence_scope="sandbox_internal",
        run_id="r1",
        scenario_id="s1",
        rail="MPP",
        payment_intent="charge",
        verification_status="verified",
        canonical_hash_matched=True
    )
    cand = build_sandbox_corpus_candidate(ev)
    assert cand.corpus_eligible is True
    assert cand.rail == "MPP"

def test_corpus_candidate_x402_evm_verified():
    ev = SandboxEvidence(
        evidence_scope="sandbox_internal",
        run_id="r1",
        scenario_id="s1",
        rail="x402",
        network="eip155:137",
        asset="USDC", # 追加
        verification_status="verified",
        canonical_hash_matched=True
    )
    cand = build_sandbox_corpus_candidate(ev)
    assert cand.corpus_eligible is True
    assert cand.rail == "x402"
    assert cand.network == "eip155:137" 
    assert cand.asset == "USDC"         

def test_corpus_candidate_x402_svm_verified():
    ev = SandboxEvidence(
        evidence_scope="sandbox_internal",
        run_id="r1",
        scenario_id="s1",
        rail="x402",
        network="solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
        asset="USDC", # 追加
        verification_status="verified",
        canonical_hash_matched=True
    )
    cand = build_sandbox_corpus_candidate(ev)
    assert cand.corpus_eligible is True
    assert cand.rail == "x402"
    assert cand.network.startswith("solana:") 
    assert cand.asset == "USDC"

def test_corpus_candidate_mismatch():
    ev = SandboxEvidence(
        evidence_scope="sandbox_internal",
        verification_status="mismatch",
        canonical_hash_matched=False
    )
    cand = build_sandbox_corpus_candidate(ev)
    assert cand.corpus_eligible is False
    assert cand.exclusion_reason == "canonical_mismatch"

def test_corpus_candidate_server_observed():
    ev = SandboxEvidence(
        evidence_scope="sandbox_internal",
        verification_status="server_observed",
        canonical_hash_matched=True
    )
    cand = build_sandbox_corpus_candidate(ev)
    assert cand.corpus_eligible is None
    assert cand.exclusion_reason == "candidate_pending_client_confirmation"

def test_corpus_candidate_non_sandbox_scope():
    ev = SandboxEvidence(
        evidence_scope="external_production",
        verification_status="verified",
        canonical_hash_matched=True
    )
    cand = build_sandbox_corpus_candidate(ev)
    assert cand.corpus_eligible is False
    assert cand.exclusion_reason == "non_sandbox_scope"

def test_raw_token_not_in_candidate_json():
    ev = SandboxEvidence(
        evidence_scope="sandbox_internal",
        run_id="r1",
        interop_token_hash="fake_hash_123"
    )
    cand = build_sandbox_corpus_candidate(ev)
    json_str = cand.model_dump_json()
    assert "fake_hash_123" not in json_str
    assert "RAW_SECRET" not in json_str

def test_no_external_observe_call_for_corpus():
    client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")
    client._last_sandbox_evidence = SandboxEvidence(
        evidence_scope="sandbox_internal",
        verification_status="verified",
        canonical_hash_matched=True
    )
    
    with patch.object(client, 'execute_request') as mock_req:
        cand1 = client.get_last_sandbox_corpus_candidate()
        cand2 = client.build_sandbox_corpus_candidate_from_last_evidence()
        
        assert cand1 is not None
        assert cand2 is not None
        assert cand1.corpus_eligible is True
        
        # 確実に /api/agent/external/observe 等に外部通信していないこと
        mock_req.assert_not_called()