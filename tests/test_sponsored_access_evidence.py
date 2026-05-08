import pytest
import json
from ln_church_agent.evidence import build_sponsored_access_evidence
from ln_church_agent.models import GrantDiagnostics

def test_sponsored_access_evidence_success():
    """Grant成功レスポンスからEvidenceを構築し、Raw tokenが含まれないことを確認"""
    diag = GrantDiagnostics(
        ok=True, usable=True, grant_jti="jti_123", issuer="trusted", sponsor_id="sp_1"
    )
    resp = {
        "access_path": "sponsored_grant",
        "authorization_artifact": "scoped_grant",
        "settlement_rail": "none",
        "grant": {
            "jti": "jti_123",
            "consumed": True,
            "scope": {"routes": ["/a"], "methods": ["POST"]}
        },
        "receipt": {"verify_token": "jws.token.abc"}
    }
    raw_token = "RAW_SECRET_GRANT_TOKEN_DO_NOT_STORE"

    evidence = build_sponsored_access_evidence(
        grant_diagnostics=diag, response_body=resp, grant_token=raw_token
    )

    # Values
    assert evidence.access_path == "sponsored_grant"
    assert evidence.settlement_rail == "none"
    assert evidence.grant_jti == "jti_123"
    assert evidence.server_consumed is True
    assert evidence.receipt_present is True
    assert evidence.verify_token_present is True
    
    # Redaction
    json_data = evidence.model_dump_json()
    assert "RAW_SECRET_GRANT_TOKEN_DO_NOT_STORE" not in json_data
    assert evidence.token_hash is not None

def test_local_diagnostic_failure_evidence():
    """Expired grant の診断結果が Evidence に反映されること"""
    diag = GrantDiagnostics(
        ok=False, usable=False, failure_class="expired", reason="Time passed"
    )
    
    evidence = build_sponsored_access_evidence(grant_diagnostics=diag)
    
    assert evidence.local_diagnostic_ok is False
    assert evidence.local_diagnostic_failure_class == "expired"
    assert evidence.settlement_rail == "none"