import pytest
import time
import base64
import json
from ln_church_agent.grants import diagnose_grant_token

def create_mock_grant(claims: dict) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"EdDSA"}').decode().rstrip('=')
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
    signature = "dummy_signature"
    return f"{header}.{payload}.{signature}"

@pytest.fixture
def valid_claims():
    return {
        "jti": "grant_123",
        "iss": "https://trusted-issuer",
        "sub": "agent_abc",
        "aud": "https://mock.shrine",
        "exp": int(time.time()) + 3600,
        "nbf": int(time.time()) - 100,
        "asset": "GRANT_CREDIT",
        "scope": {"routes": ["/api/agent/omikuji"], "methods": ["POST"]}
    }

def test_diagnose_valid_grant(valid_claims):
    token = create_mock_grant(valid_claims)
    diag = diagnose_grant_token(token, agent_id="agent_abc", base_url="https://mock.shrine", route="/api/agent/omikuji", method="POST")
    assert diag.usable is True
    assert diag.recommended_action == "use_grant"
    assert diag.failure_class is None

def test_diagnose_missing_token(valid_claims):
    diag = diagnose_grant_token(None, agent_id="agent_abc", base_url="https://mock.shrine", route="/api/agent/omikuji", method="POST")
    assert diag.usable is False
    assert diag.failure_class == "missing_grant_token"
    assert diag.fallback_action == "standard_settlement"

def test_diagnose_malformed_token():
    diag = diagnose_grant_token("invalid.token", agent_id="a", base_url="b", route="c")
    assert diag.usable is False
    assert diag.failure_class == "malformed_token"

def test_diagnose_missing_exp(valid_claims):
    del valid_claims["exp"]
    diag = diagnose_grant_token(create_mock_grant(valid_claims), agent_id="agent_abc", base_url="https://mock.shrine", route="/api/agent/omikuji", method="POST")
    assert diag.usable is False
    assert diag.failure_class == "missing_exp"

def test_diagnose_expired(valid_claims):
    valid_claims["exp"] = int(time.time()) - 3600
    diag = diagnose_grant_token(create_mock_grant(valid_claims), agent_id="agent_abc", base_url="https://mock.shrine", route="/api/agent/omikuji", method="POST")
    assert diag.usable is False
    assert diag.failure_class == "expired"

def test_diagnose_not_yet_valid(valid_claims):
    valid_claims["nbf"] = int(time.time()) + 3600
    diag = diagnose_grant_token(create_mock_grant(valid_claims), agent_id="agent_abc", base_url="https://mock.shrine", route="/api/agent/omikuji", method="POST")
    assert diag.usable is False
    assert diag.failure_class == "not_yet_valid"

def test_diagnose_subject_mismatch(valid_claims):
    diag = diagnose_grant_token(create_mock_grant(valid_claims), agent_id="wrong_agent", base_url="https://mock.shrine", route="/api/agent/omikuji", method="POST")
    assert diag.usable is False
    assert diag.failure_class == "subject_mismatch"

def test_diagnose_audience_mismatch(valid_claims):
    diag = diagnose_grant_token(create_mock_grant(valid_claims), agent_id="agent_abc", base_url="https://other.shrine", route="/api/agent/omikuji", method="POST")
    assert diag.usable is False
    assert diag.failure_class == "audience_mismatch"

def test_diagnose_route_out_of_scope(valid_claims):
    diag = diagnose_grant_token(create_mock_grant(valid_claims), agent_id="agent_abc", base_url="https://mock.shrine", route="/api/agent/forbidden", method="POST")
    assert diag.usable is False
    assert diag.failure_class == "route_out_of_scope"

def test_diagnose_method_out_of_scope(valid_claims):
    diag = diagnose_grant_token(create_mock_grant(valid_claims), agent_id="agent_abc", base_url="https://mock.shrine", route="/api/agent/omikuji", method="GET")
    assert diag.usable is False
    assert diag.failure_class == "method_out_of_scope"

def test_diagnose_asset_mismatch(valid_claims):
    valid_claims["asset"] = "SATS"
    diag = diagnose_grant_token(create_mock_grant(valid_claims), agent_id="agent_abc", base_url="https://mock.shrine", route="/api/agent/omikuji", method="POST")
    assert diag.usable is False
    assert diag.failure_class == "asset_mismatch"

def test_diagnose_missing_jti(valid_claims):
    del valid_claims["jti"]
    diag = diagnose_grant_token(create_mock_grant(valid_claims), agent_id="agent_abc", base_url="https://mock.shrine", route="/api/agent/omikuji", method="POST")
    assert diag.usable is False
    assert diag.failure_class == "missing_jti"

def test_settlement_rail_is_none(valid_claims):
    diag = diagnose_grant_token(create_mock_grant(valid_claims), agent_id="agent_abc", base_url="https://mock.shrine", route="/api/agent/omikuji", method="POST")
    assert diag.settlement_rail == "none"
    assert diag.access_path == "sponsored_grant"

def test_diagnose_missing_asset(valid_claims):
    del valid_claims["asset"]
    diag = diagnose_grant_token(create_mock_grant(valid_claims), agent_id="agent_abc", base_url="https://mock.shrine", route="/api/agent/omikuji", method="POST")
    assert diag.usable is False
    assert diag.failure_class == "missing_asset"

def test_audience_domain_without_scheme_matches_backend(valid_claims):
    # トークンの aud が単なるドメイン名 (kari.mayim-mayim.com) の場合
    valid_claims["aud"] = "kari.mayim-mayim.com"
    diag = diagnose_grant_token(create_mock_grant(valid_claims), agent_id="agent_abc", base_url="https://kari.mayim-mayim.com", route="/api/agent/omikuji", method="POST")
    assert diag.usable is True
    assert diag.failure_class is None

def test_evm_subject_case_insensitive(valid_claims):
    # トークンの sub が大文字混じりで、agent_id が小文字の場合
    valid_claims["sub"] = "0xAbCdEf123"
    diag = diagnose_grant_token(create_mock_grant(valid_claims), agent_id="0xabcdef123", base_url="https://mock.shrine", route="/api/agent/omikuji", method="POST")
    assert diag.usable is True
    assert diag.failure_class is None