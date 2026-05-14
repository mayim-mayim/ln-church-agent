import pytest
from ln_church_agent.failures import (
    build_payment_failure_record, 
    build_payment_failure_observation_payload,
    fingerprint_public_challenge_summary
)

def test_payload_schema_public_safe():
    rec = build_payment_failure_record(endpoint="https://test.com")
    payload = build_payment_failure_observation_payload(rec)
    
    assert payload["schema_version"] == "payment_failure_observation_report.v1"
    assert payload["observation_type"] == "payment_failure"
    assert payload["not_a_verdict"] is True
    assert payload["evidence"]["payment_performed"] is False
    assert payload["evidence"]["settlement_confirmed"] is False

def test_authorization_scheme_is_allowed():
    # authorization_scheme 自体はシークレットキーとして除外されない
    challenge = {"authorization_scheme": "L402", "macaroon": "secret"}
    fp = fingerprint_public_challenge_summary(challenge)
    
    challenge_variant = {"authorization_scheme": "L402", "macaroon": "changed_secret"}
    fp_variant = fingerprint_public_challenge_summary(challenge_variant)
    
    assert fp == fp_variant  # Secret has been ignored
    
    # 別のスキーマなら指紋は変わるべき
    challenge_other = {"authorization_scheme": "x402", "macaroon": "secret"}
    fp_other = fingerprint_public_challenge_summary(challenge_other)
    assert fp != fp_other

def test_nested_accepts_fee_payer_changed():
    rec = build_payment_failure_record(
        endpoint="https://test.com",
        challenge_before={"accepts": [{"feePayer": "A", "amount": 10}]},
        challenge_after={"accepts": [{"feePayer": "B", "amount": 10}]}
    )
    assert rec.challenge_fingerprint_changed is True
    assert "accepts[0].feePayer" in rec.changed_fields

def test_no_matching_payment_requirements_is_subclass():
    rec = build_payment_failure_record(
        endpoint="https://test.com",
        failure_class="unknown",
        failure_subclass="no_matching_payment_requirements"
    )
    assert rec.failure_class == "retry_mismatch"
    assert rec.failure_subclass == "no_matching_payment_requirements"

def test_secondary_client_sets_dual_client_medium():
    rec = build_payment_failure_record(
        endpoint="https://test.com",
        secondary_client_used="x402-official"
    )
    assert rec.reproducibility == "dual_client_reproduced"
    assert rec.evidence_strength == "medium"

def test_operator_verified_high():
    rec = build_payment_failure_record(
        endpoint="https://test.com",
        operator_verified=True
    )
    assert rec.reproducibility == "operator_verified"
    assert rec.evidence_strength == "high"
    assert rec.confidence == "high"

def test_scheme_default_unknown():
    rec = build_payment_failure_record(endpoint="https://test.com")
    payload = build_payment_failure_observation_payload(rec)
    
    assert payload["protocol"]["scheme"] == "unknown"
    assert payload["protocol"]["authorization_scheme"] == "unknown"

def test_message_redaction():
    rec = build_payment_failure_record(
        endpoint="https://test.com",
        server_message="Your macaroon is invalid and preimage is empty."
    )
    assert "macaroon" not in rec.server_message_excerpt.lower()
    assert "[REDACTED]" in rec.server_message_excerpt

def test_message_redaction_advanced():
    # 1. macaroon=... 形式 (値ごと消えること)
    rec1 = build_payment_failure_record(
        endpoint="https://test.com",
        server_message="Failed because macaroon=abcdef123456 is expired."
    )
    assert "abcdef123456" not in rec1.server_message_excerpt
    assert "Failed because [REDACTED] is expired." in rec1.server_message_excerpt

    # 2. Authorization: Bearer xxx 形式 (Bearerも含めて消えること)
    rec2 = build_payment_failure_record(
        endpoint="https://test.com",
        client_error="Header rejected: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    )
    assert "Bearer" not in rec2.client_error_excerpt
    assert "eyJhbGci" not in rec2.client_error_excerpt
    assert "Header rejected: [REDACTED]" in rec2.client_error_excerpt

    # 3. authorization_scheme は対象外として維持されること
    rec3 = build_payment_failure_record(
        endpoint="https://test.com",
        server_message="Invalid authorization_scheme=L402"
    )
    assert "authorization_scheme=L402" in rec3.server_message_excerpt

    # 4. key value 形式 (スペース区切り)
    rec4 = build_payment_failure_record(
        endpoint="https://test.com",
        server_message="Missing private_key 0x123abc456def in payload."
    )
    assert "0x123abc456def" not in rec4.server_message_excerpt
    assert "Missing [REDACTED] in payload." in rec4.server_message_excerpt