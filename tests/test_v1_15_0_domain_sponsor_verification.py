import pytest
import os
import io
import sys
import json
from unittest.mock import patch, MagicMock

from ln_church_agent.client import LnChurchClient
from ln_church_agent.models import (
    DomainSponsorVerification,
    DomainSponsorChallengeResponse,
    DomainSponsorVerifyResponse,
    DomainSponsorVerificationSummary,
    DomainObservationRequestStatus,
    DomainObservationDomainReadModel
)

# ==========================================
# 1. Model Tests
# ==========================================
def test_models_default_safety_flags():
    """安全線（not_a_verdict等）がデフォルトで保持されていること"""
    ch = DomainSponsorChallengeResponse(request_id="obsreq_1", domain="test.com", challenge_id="c1", challenge_url="url")
    assert ch.not_a_verdict is True
    assert ch.not_a_security_scan is True
    
    vr = DomainSponsorVerifyResponse(request_id="obsreq_1", domain="test.com")
    assert vr.not_legal_ownership_proof is True
    assert vr.verification_scope == "domain_control_not_legal_ownership"
    
    su = DomainSponsorVerificationSummary()
    assert su.not_legal_ownership_proof is True
    assert su.not_a_recommendation is True

def test_observation_models_parse_sponsor_fields():
    """既存の Read Model モデルが新規オブジェクトを適切にパースできること"""
    req_status = DomainObservationRequestStatus(
        request_id="obsreq_1",
        domain="test.com",
        status="active",
        sponsor_verification={"sponsor_verification_status": "verified"}
    )
    assert req_status.sponsor_verification is not None
    assert req_status.sponsor_verification.sponsor_verification_status == "verified"
    
    domain_rm = DomainObservationDomainReadModel(
        domain="test.com",
        sponsor_verification_summary={"has_verified_domain_sponsor": True}
    )
    assert domain_rm.sponsor_verification_summary is not None
    assert domain_rm.sponsor_verification_summary.has_verified_domain_sponsor is True

# ==========================================
# 2. Client Tests
# ==========================================
@patch("ln_church_agent.client.LnChurchClient.execute_request")
def test_create_challenge_path_and_headers(mock_exec):
    client = LnChurchClient(private_key="0x" + "0"*64)
    mock_exec.return_value = {
        "request_id": "obsreq_abc", "domain": "test.com", 
        "challenge_id": "c1", "challenge_url": "url", "challenge_document": {"challenge_token": "secret123"}
    }
    
    res = client.create_domain_sponsor_challenge("obsreq_abc", result_handle="RH", request_hash="RHSH")
    
    args, kwargs = mock_exec.call_args
    assert args[0] == "POST"
    assert args[1] == "/api/agent/external/observatory/domain-observation-requests/obsreq_abc/sponsor-challenge"
    assert kwargs["headers"]["X-LN-Result-Handle"] == "RH"
    assert kwargs["headers"]["X-LN-Request-Hash"] == "RHSH"
    assert "X-Internal-Secret" not in kwargs["headers"]
    
    assert res.challenge_document["challenge_token"] == "secret123"

@patch("ln_church_agent.client.LnChurchClient.execute_request")
def test_verify_path_and_internal_secret(mock_exec):
    client = LnChurchClient(private_key="0x" + "0"*64)
    mock_exec.return_value = {"request_id": "obsreq_123", "domain": "test.com", "domain_control_verified": True}
    
    res = client.verify_domain_sponsor("obsreq_123", internal_secret="INT_SEC")
    
    args, kwargs = mock_exec.call_args
    assert args[0] == "POST"
    assert args[1] == "/api/agent/external/observatory/domain-observation-requests/obsreq_123/verify-sponsor"
    assert kwargs["headers"]["X-Internal-Secret"] == "INT_SEC"
    assert "X-LN-Result-Handle" not in kwargs["headers"]
    
    assert res.domain_control_verified is True

def test_missing_credentials_raises_error():
    client = LnChurchClient(private_key="0x" + "0"*64)
    with pytest.raises(ValueError, match="must be provided"):
        client.create_domain_sponsor_challenge("obsreq_123")

def test_invalid_request_id_raises_error():
    client = LnChurchClient(private_key="0x" + "0"*64)
    with pytest.raises(ValueError, match="Invalid request_id format"):
        client.verify_domain_sponsor("invalid/path/traversal", internal_secret="sec")

# ==========================================
# 3. Save Helper Tests
# ==========================================
def test_save_challenge_document_creates_file(tmp_path):
    client = LnChurchClient(private_key="0x" + "0"*64)
    chal = DomainSponsorChallengeResponse(
        request_id="obsreq_1", domain="test.com", challenge_id="c1", challenge_url="url",
        challenge_document={"challenge_token": "safe_token", "not_a_verdict": True}
    )
    
    file_path = tmp_path / ".well-known" / "ln-church-domain-sponsor.json"
    client.save_domain_sponsor_challenge_document(chal, str(file_path))
    
    assert file_path.exists()
    with open(file_path, "r") as f:
        data = json.load(f)
    
    assert data["challenge_token"] == "safe_token"
    # ファイルにレスポンスメタデータやシークレットが混入しないこと
    assert "request_id" not in data 

# ==========================================
# 4. CLI Tests (Safety and Formats)
# ==========================================
@patch("sys.stdout", new_callable=io.StringIO)
@patch("ln_church_agent.client.LnChurchClient.create_domain_sponsor_challenge")
def test_cli_challenge_does_not_leak_secrets(mock_create, mock_stdout):
    """Challengeトークンや引数のシークレットがstdoutに漏れないこと"""
    mock_res = MagicMock()
    mock_res.request_id = "obsreq_1"
    mock_res.domain = "test.com"
    mock_res.challenge_url = "https://test.com/.well-known"
    mock_res.challenge_document = {"challenge_token": "SUPER_SECRET_TOKEN_DO_NOT_PRINT"}
    mock_create.return_value = mock_res
    
    from ln_church_agent.cli import main
    test_args = [
        "ln-church-agent", "observe-domain", "sponsor", "challenge", "obsreq_1",
        "--internal-secret", "CLI_SECRET_123", "--result-handle", "CLI_HANDLE_456"
    ]
    with patch.object(sys, 'argv', test_args):
        main()
        
    output = mock_stdout.getvalue()
    assert "Domain sponsor challenge issued" in output
    assert "SUPER_SECRET_TOKEN_DO_NOT_PRINT" not in output
    assert "CLI_SECRET_123" not in output
    assert "CLI_HANDLE_456" not in output

@patch("sys.stdout", new_callable=io.StringIO)
@patch("ln_church_agent.client.LnChurchClient.verify_domain_sponsor")
def test_cli_verify_legal_ownership_proof_is_false(mock_verify, mock_stdout):
    """人間が誤解しないようLegal Ownership Proof: False と印字されること"""
    mock_res = MagicMock()
    mock_res.request_id = "obsreq_1"
    mock_res.domain = "test.com"
    mock_res.domain_control_verified = True
    mock_res.sponsor_verified = True
    mock_res.verification_scope = "domain_control_not_legal_ownership"
    mock_res.not_legal_ownership_proof = True
    mock_res.public_read_model_url = "url"
    mock_verify.return_value = mock_res
    
    from ln_church_agent.cli import main
    with patch.object(sys, 'argv', ["ln-church-agent", "observe-domain", "sponsor", "verify", "obsreq_1", "--internal-secret", "sec"]):
        main()
        
    output = mock_stdout.getvalue()
    assert "Legal Ownership Proof   : False" in output