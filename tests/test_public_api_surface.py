import pytest
# 1. 完全に Public Stable な概念のみトップレベルからインポート
from ln_church_agent import (
    Payment402Client,
    LnChurchClient,
    ParsedChallenge,
    ExecutionResult,
    ExecutionContext,
    TrustDecision,
    OutcomeSummary,
    TrustEvidence
)
# 2. Experimental な概念は .models から明示的にインポート
from ln_church_agent.models import PaymentEvidenceRecord, EvidenceRepository

def test_public_api_imports_and_instantiation():
    """トップレベルからインポートした Stable なモデルがスキーマエラーなく生成できるか確認"""
    
    # 1. ParsedChallenge
    pc = ParsedChallenge(scheme="L402", amount=10.0, asset="SATS")
    assert pc.scheme == "L402"
    assert pc.amount == 10.0

    # 2. ExecutionContext
    ctx = ExecutionContext(intent_label="test_intent", hints={"key": "value"})
    assert ctx.intent_label == "test_intent"
    assert ctx.session_id is not None
    assert ctx.hints["key"] == "value"

    # 3. TrustDecision
    td = TrustDecision(is_trusted=True, reason="ok")
    assert td.is_trusted is True

    # 4. TrustEvidence (ParsedChallengeをネスト)
    te = TrustEvidence(url="http://test.local", challenge=pc, agent_hints=ctx.hints)
    assert te.url == "http://test.local"
    assert te.challenge.scheme == "L402"
    assert te.agent_hints["key"] == "value"

    # 5. OutcomeSummary
    os_summary = OutcomeSummary(is_success=True, observed_state="done")
    assert os_summary.is_success is True

    # 6. ExecutionResult (OutcomeSummaryをネスト)
    er = ExecutionResult(
        response={"ok": True},
        final_url="http://test.local",
        outcome=os_summary
    )
    assert er.outcome is not None
    assert er.outcome.is_success is True

def test_experimental_evidence_models_instantiation():
    """v1.5.1 の Experimental 概念が依存関係エラーなく .models 経由で生成できるか確認"""
    
    # EvidenceRepository (抽象クラスのデフォルト挙動)
    repo = EvidenceRepository()
    assert repo.import_evidence("http://dummy", ExecutionContext()) == []

    # PaymentEvidenceRecord
    record = PaymentEvidenceRecord(
        session_id="sess_123",
        correlation_id="corr_123",
        target_url="http://dummy",
        method="POST"
    )
    assert record.session_id == "sess_123"
    assert record.timestamp > 0
    assert record.trust_decision is None