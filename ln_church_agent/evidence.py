# ln_church_agent/evidence.py
import hashlib
from typing import Optional
from .models import SponsoredAccessEvidence, SandboxEvidence, GrantDiagnostics,SandboxCorpusCandidate

def sha256_redacted(value: Optional[str]) -> Optional[str]:
    """生トークンや Proof を安全にハッシュ化する"""
    if not value:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

def build_sponsored_access_evidence(
    *,
    grant_diagnostics: Optional[GrantDiagnostics] = None,
    response_body: Optional[dict] = None,
    grant_token: Optional[str] = None,
) -> SponsoredAccessEvidence:
    """Grant成功時のレスポンスから SponsoredAccessEvidence を構築する"""
    resp = response_body or {}
    evidence = SponsoredAccessEvidence(
        token_hash=sha256_redacted(grant_token)
    )

    if grant_diagnostics:
        evidence.local_diagnostic_ok = grant_diagnostics.usable
        evidence.local_diagnostic_failure_class = grant_diagnostics.failure_class
        evidence.local_diagnostic_reason = grant_diagnostics.reason
        evidence.grant_jti = grant_diagnostics.grant_jti
        evidence.issuer = grant_diagnostics.issuer
        evidence.sponsor_id = grant_diagnostics.sponsor_id
        evidence.entitlement = grant_diagnostics.entitlement
        evidence.scope_routes = grant_diagnostics.scope_routes
        evidence.scope_methods = grant_diagnostics.scope_methods

    grant_data = resp.get("grant", {})
    if grant_data:
        evidence.grant_jti = grant_data.get("jti", evidence.grant_jti)
        evidence.sponsor_id = grant_data.get("sponsor_id", evidence.sponsor_id)
        evidence.issuer = grant_data.get("issuer", evidence.issuer)
        evidence.server_consumed = grant_data.get("consumed")

        scope = grant_data.get("scope", {})
        if "routes" in scope:
            evidence.scope_routes = scope["routes"]
        if "methods" in scope:
            evidence.scope_methods = scope["methods"]

    receipt = resp.get("receipt", {})
    if receipt:
        evidence.receipt_present = True
        if receipt.get("verify_token"):
            evidence.verify_token_present = True

    return evidence

def build_sandbox_evidence_from_response(
    response_body: dict,
    *,
    interop_token: Optional[str] = None,
    canonical_hash_actual: Optional[str] = None
) -> Optional[SandboxEvidence]:
    """Sandbox の Basic エンドポイントからの応答を SandboxEvidence に変換する"""
    evidence_ref = response_body.get("evidence_ref")
    meta = response_body.get("meta") or {}

    # 1. 判定の厳格化: meta fallback を sandbox_result に限定
    if not evidence_ref:
        if meta.get("kind") != "sandbox_result":
            return None
    else:
        if evidence_ref.get("schema_version") != "sandbox_evidence_ref.v1":
            return None

    src = evidence_ref if evidence_ref else meta
    
    expected_hash = src.get("canonical_hash_expected")
    actual_hash = canonical_hash_actual or response_body.get("canonical_hash")
    matched = (expected_hash == actual_hash) if expected_hash and actual_hash else None

    raw_token = interop_token or meta.get("interop_token")
    token_hash = sha256_redacted(raw_token)

    return SandboxEvidence(
        evidence_scope="sandbox_internal",
        run_id=src.get("run_id"),
        scenario_id=src.get("scenario_id"),
        rail=src.get("rail"),
        payment_intent=src.get("payment_intent"),
        canonical_hash_expected=expected_hash,
        canonical_hash_actual=actual_hash,
        canonical_hash_matched=matched,
        payment_receipt_present=src.get("payment_receipt_present"),
        report_interop_url=src.get("report_interop_url"),
        logs_url=src.get("logs_url") or f"/api/agent/sandbox/interop/logs?run_id={src.get('run_id')}",
        interop_token_hash=token_hash
    )

def merge_sandbox_report_result(
    evidence: SandboxEvidence,
    report_response: dict,
) -> SandboxEvidence:
    """Interop Report 送信後の結果を元の SandboxEvidence にマージする"""
    if not report_response:
        return evidence

    evidence.canonical_hash_matched = report_response.get("canonical_hash_matched", evidence.canonical_hash_matched)
    evidence.verification_status = report_response.get("verification_status")
    
    if "payment_receipt_present" in report_response:
        evidence.payment_receipt_present = report_response["payment_receipt_present"]
    if "server_payment_receipt_present" in report_response:
        evidence.server_payment_receipt_present = report_response["server_payment_receipt_present"]
    if "client_reported_payment_receipt_present" in report_response:
        evidence.client_reported_payment_receipt_present = report_response["client_reported_payment_receipt_present"]

    return evidence

def build_sandbox_interop_report_payload(
    *,
    sandbox_evidence: SandboxEvidence,
    canonical_hash_actual: str,
    sdk_version: str,
    interop_token: str,
    executor_mode: str = "sdk",
    comparison_class: str = "production_like",
    test_mode: str = "normal",
    payment_receipt_id: Optional[str] = None
) -> dict:
    """Interop Report 用のペイロードを生成する（自動POSTはしない）"""
    return {
        "run_id": sandbox_evidence.run_id,
        "scenario_id": sandbox_evidence.scenario_id,
        "canonical_hash_expected": sandbox_evidence.canonical_hash_expected,
        "canonical_hash_observed": canonical_hash_actual,
        "interop_token": interop_token,
        "sdk_version": sdk_version,
        "executor_mode": executor_mode,
        "comparison_class": comparison_class,
        "test_mode": test_mode,
        "payment_receipt_present": sandbox_evidence.payment_receipt_present,
        "payment_receipt_id": payment_receipt_id or sandbox_evidence.payment_receipt_id,
        "rail": sandbox_evidence.rail,
        "payment_intent": sandbox_evidence.payment_intent
    }

def build_sandbox_corpus_candidate(sandbox_evidence: SandboxEvidence) -> SandboxCorpusCandidate:
    """SandboxEvidence を評価し、ローカルの SandboxCorpusCandidate を構築する"""
    eligible = False
    reason = None

    if sandbox_evidence.evidence_scope != "sandbox_internal":
        eligible = False
        reason = "non_sandbox_scope"
    elif sandbox_evidence.verification_status == "verified" and sandbox_evidence.canonical_hash_matched is True:
        eligible = True
    elif sandbox_evidence.verification_status == "mismatch":
        eligible = False
        reason = "canonical_mismatch"
    elif sandbox_evidence.verification_status == "server_observed":
        eligible = None  # candidate_pending_client_confirmation として保留扱い
        reason = "candidate_pending_client_confirmation"
    else:
        eligible = False
        reason = "unverified_or_incomplete"

    return SandboxCorpusCandidate(
        evidence_scope=sandbox_evidence.evidence_scope,
        run_id=sandbox_evidence.run_id,
        scenario_id=sandbox_evidence.scenario_id,
        rail=sandbox_evidence.rail,
        payment_intent=sandbox_evidence.payment_intent,
        
        network=sandbox_evidence.network,
        asset=sandbox_evidence.asset,
        payment_method=sandbox_evidence.payment_method,
        authorization_scheme=sandbox_evidence.authorization_scheme,
        draft_shape=sandbox_evidence.draft_shape,
  
        verification_status=sandbox_evidence.verification_status,
        canonical_hash_matched=sandbox_evidence.canonical_hash_matched,
        payment_receipt_present=sandbox_evidence.payment_receipt_present,
        server_payment_receipt_present=sandbox_evidence.server_payment_receipt_present,
        client_reported_payment_receipt_present=sandbox_evidence.client_reported_payment_receipt_present,
        corpus_eligible=eligible,
        exclusion_reason=reason
    )