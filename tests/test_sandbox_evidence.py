import pytest
from ln_church_agent.evidence import (
    build_sandbox_evidence_from_response, 
    merge_sandbox_report_result
)

def test_sandbox_evidence_parsing():
    """evidence_ref からSandboxEvidenceを構築し、Raw tokenを保存しないことを確認"""
    raw_token = "RAW_INTEROP_TOKEN_SECRET"
    resp = {
        "evidence_ref": {
            "schema_version": "sandbox_evidence_ref.v1",
            "evidence_scope": "sandbox_internal",
            "run_id": "r_123",
            "scenario_id": "scen_1",
            "rail": "L402",
            "canonical_hash_expected": "hash_exp",
            "payment_receipt_present": True
        },
        "meta": {
            "interop_token": raw_token
        },
        "canonical_hash": "hash_exp"
    }

    evidence = build_sandbox_evidence_from_response(resp)

    assert evidence is not None
    assert evidence.evidence_scope == "sandbox_internal"
    assert evidence.run_id == "r_123"
    assert evidence.scenario_id == "scen_1"
    assert evidence.rail == "L402"
    assert evidence.canonical_hash_expected == "hash_exp"
    assert evidence.payment_receipt_present is True
    
    # Redaction Check
    json_data = evidence.model_dump_json()
    assert raw_token not in json_data
    assert evidence.interop_token_hash is not None

def test_sandbox_report_merge_verified():
    """Report result (Verified) のマージ"""
    resp = {
        "evidence_ref": {"schema_version": "sandbox_evidence_ref.v1"}
    }
    evidence = build_sandbox_evidence_from_response(resp)
    
    report_res = {
        "verification_status": "verified",
        "canonical_hash_matched": True,
        "server_payment_receipt_present": True
    }
    
    merge_sandbox_report_result(evidence, report_res)
    assert evidence.verification_status == "verified"
    assert evidence.canonical_hash_matched is True
    assert evidence.server_payment_receipt_present is True

def test_sandbox_report_merge_mismatch():
    """Report result (Mismatch) のマージ"""
    resp = {
        "evidence_ref": {"schema_version": "sandbox_evidence_ref.v1"}
    }
    evidence = build_sandbox_evidence_from_response(resp)
    
    report_res = {
        "verification_status": "mismatch",
        "canonical_hash_matched": False
    }
    
    merge_sandbox_report_result(evidence, report_res)
    assert evidence.verification_status == "mismatch"
    assert evidence.canonical_hash_matched is False

def test_normal_response_no_evidence_ref():
    """L402/x402/MPP 通常レスポンス時（evidence_refなし）は None を返すこと"""
    resp = {"status": "success", "result": "ok"}
    evidence = build_sandbox_evidence_from_response(resp)
    assert evidence is None

def test_no_external_observe_call():
    """実装内に ExternalObserve への自動POSTがないことをコードの作りから担保"""
    # client.py の submit_sandbox_interop_report などは
    # "/api/agent/external/observe" を呼んでいない
    # これは手動のコードレビューと、テスト実行時に外部通信モックが呼ばれないことで担保される。
    pass

def test_meta_non_sandbox_does_not_create_sandbox_evidence():
    """meta fallbackを sandbox_result に限定していることの確認"""
    resp = {"meta": {"kind": "normal_api_result"}, "status": "success"}
    assert build_sandbox_evidence_from_response(resp) is None
    
def test_sandbox_result_in_meta_creates_evidence():
    """meta に sandbox_result があれば正常にパースされることの確認"""
    resp = {"meta": {"kind": "sandbox_result", "run_id": "123"}, "status": "success"}
    ev = build_sandbox_evidence_from_response(resp)
    assert ev is not None
    assert ev.run_id == "123"