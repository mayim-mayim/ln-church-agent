import pytest
import asyncio
import requests
from unittest.mock import AsyncMock, patch, MagicMock

from ln_church_agent.client import Payment402Client
from ln_church_agent.models import (
    ExecutionContext, PaymentPolicy, PaymentEvidenceRecord, EvidenceRepository
)
from ln_church_agent.exceptions import PaymentExecutionError
from _p0_2_fixture import (
    configure_contract_clock,
    contract_response,
    load_contract_fixture,
    success_response,
)

# ==========================================
# テスト用の Mock Repository
# ==========================================
class MockSessionRepo(EvidenceRepository):
    def __init__(self, mock_records: list[PaymentEvidenceRecord]):
        self.mock_records = mock_records
        self.sync_call_count = 0
        self.async_call_count = 0

    def import_session_evidence(self, context: ExecutionContext) -> list[PaymentEvidenceRecord]:
        self.sync_call_count += 1
        return self.mock_records

    async def import_session_evidence_async(self, context: ExecutionContext) -> list[PaymentEvidenceRecord]:
        self.async_call_count += 1
        return self.mock_records

# ==========================================
# ヘルパー関数
# ==========================================
def _create_402_mock(fixture):
    """Production-shaped canonical 402 response."""
    return contract_response(fixture)

# ==========================================
# テストケース (A〜F: 基本要件)
# ==========================================
def test_sync_budget_restore():
    """A. Sync Restore: 過去のEvidenceからセッション予算が復元され、上限ブロックが機能することを確認"""
    past_record = PaymentEvidenceRecord(
        session_id="test_session", correlation_id="c1", target_url="http://mock",
        method="POST", session_spend_delta_usd=4.0
    )
    repo = MockSessionRepo([past_record])
    fixture = load_contract_fixture()
    policy = PaymentPolicy(max_spend_per_session_usd=4.005)
    
    client = configure_contract_clock(
        Payment402Client(policy=policy, evidence_repo=repo), fixture
    )
    ctx = ExecutionContext(session_id="test_session")

    with patch("requests.request") as mock_req:
        mock_req.return_value = _create_402_mock(fixture)
        
        with pytest.raises(PaymentExecutionError, match="would exceed limit"):
            client.execute_detailed(
                fixture["request"]["method"],
                fixture["request"]["url"],
                headers=fixture["request"]["headers"],
                context=ctx,
            )
        
        assert repo.sync_call_count == 1
        assert client.policy._session_spent_usd == 4.0

def test_async_budget_restore():
    """B. Async Restore: 非同期環境でもセッション予算が復元され、ブロックが機能することを確認"""
    past_record = PaymentEvidenceRecord(
        session_id="test_session", correlation_id="c1", target_url="http://mock",
        method="POST", session_spend_delta_usd=4.0
    )
    repo = MockSessionRepo([past_record])
    fixture = load_contract_fixture()
    policy = PaymentPolicy(max_spend_per_session_usd=4.005)
    
    client = configure_contract_clock(
        Payment402Client(policy=policy, evidence_repo=repo), fixture
    )
    ctx = ExecutionContext(session_id="test_session")

    async def run_test():
        client._async_client = MagicMock()
        client._async_client.request = AsyncMock(
            return_value=_create_402_mock(fixture)
        )

        with pytest.raises(PaymentExecutionError, match="would exceed limit"):
            await client.execute_detailed_async(
                fixture["request"]["method"],
                fixture["request"]["url"],
                headers=fixture["request"]["headers"],
                context=ctx,
            )

        assert repo.async_call_count == 1
        assert client.policy._session_spent_usd == 4.0

    asyncio.run(run_test())

def test_no_repo_fallback():
    """C. No Repo Fallback: EvidenceRepositoryがない場合でも、インメモリで正常に動作・消費されるか"""
    policy = PaymentPolicy(max_spend_per_session_usd=5.0)
    fixture = load_contract_fixture()
    client = configure_contract_clock(
        Payment402Client(policy=policy, evidence_repo=None), fixture
    )
    ctx = ExecutionContext()

    with patch("requests.request") as mock_req:
        mock_req.side_effect = [
            _create_402_mock(fixture),
            success_response(fixture, {}),
        ]
        
        with patch.object(client, "_process_payment", return_value=("dummy_proof", "Lightning", None)):
            client.execute_detailed(
                fixture["request"]["method"],
                fixture["request"]["url"],
                headers=fixture["request"]["headers"],
                context=ctx,
            )
            
        assert client.policy._session_spent_usd == pytest.approx(0.0065)

def test_non_budget_evidence_ignored():
    """D. Non-budget Evidence is Ignored: 失敗やナビゲーションの履歴が合算されないことを確認"""
    records = [
        PaymentEvidenceRecord(session_id="s1", correlation_id="c1", target_url="t1", method="GET", error_message="Failed"),
        PaymentEvidenceRecord(session_id="s1", correlation_id="c2", target_url="t2", method="GET", navigation_source="link_header"), 
        PaymentEvidenceRecord(session_id="s1", correlation_id="c3", target_url="t3", method="POST", session_spend_delta_usd=1.0) 
    ]
    repo = MockSessionRepo(records)
    client = Payment402Client(policy=PaymentPolicy(), evidence_repo=repo)
    ctx = ExecutionContext(session_id="s1")

    client._restore_session_spend_from_evidence(ctx)
    assert client.policy._session_spent_usd == 1.0 

def test_one_shot_restore():
    """E. One-shot Restore: 1つのExecutionContextにつき1回しかリポジトリが呼ばれないことを確認"""
    repo = MockSessionRepo([])
    client = Payment402Client(policy=PaymentPolicy(), evidence_repo=repo)
    ctx = ExecutionContext(session_id="s1")

    client._restore_session_spend_from_evidence(ctx)
    client._restore_session_spend_from_evidence(ctx)
    client._restore_session_spend_from_evidence(ctx)

    assert repo.sync_call_count == 1 

def test_duplicate_receipt_event_safety():
    """F. Duplicate Receipt Event Safety: 同一receipt_idのレコードが重複計上されないことを確認"""
    records = [
        PaymentEvidenceRecord(
            session_id="s1", correlation_id="c1", target_url="t1", method="POST",
            session_spend_delta_usd=3.0, receipt_summary={"receipt_id": "duplicate_id_123"}
        ),
        PaymentEvidenceRecord(
            session_id="s1", correlation_id="c2", target_url="t1", method="GET", 
            session_spend_delta_usd=3.0, receipt_summary={"receipt_id": "duplicate_id_123"}
        )
    ]
    repo = MockSessionRepo(records)
    client = Payment402Client(policy=PaymentPolicy(), evidence_repo=repo)
    ctx = ExecutionContext(session_id="s1")

    client._restore_session_spend_from_evidence(ctx)
    assert client.policy._session_spent_usd == 3.0

# ==========================================
# テストケース (G〜H: GPT先生指摘のクリティカルエッジケース)
# ==========================================
def test_session_leakage_prevention():
    """G. Session Leakage Prevention: 同じClientを別セッションで使い回した際、履歴がなければ予算が0にリセットされること"""
    repo = MockSessionRepo([]) # 履歴なしの空配列を返す
    policy = PaymentPolicy(max_spend_per_session_usd=5.0)
    client = Payment402Client(policy=policy, evidence_repo=repo)
    
    # 前のセッションで意図的に予算を消費させておく
    client.policy._session_spent_usd = 4.0
    
    # 新しいセッションでリストアを実行
    ctx = ExecutionContext(session_id="new_session")
    client._restore_session_spend_from_evidence(ctx)
    
    # 履歴が空だったため、前セッションの4.0がリセットされて0.0になること
    assert client.policy._session_spent_usd == 0.0

def test_budget_event_on_downstream_failure():
    """H. Downstream Failure Logging: 決済成立後、その後の通信が失敗しても、Budget Eventが記録されること"""
    exported_records = []
    class ExportCatchingRepo(EvidenceRepository):
        def export_evidence(self, record: PaymentEvidenceRecord, context: ExecutionContext) -> None:
            exported_records.append(record)

    repo = ExportCatchingRepo()
    fixture = load_contract_fixture()
    client = configure_contract_clock(
        Payment402Client(policy=PaymentPolicy(), evidence_repo=repo), fixture
    )
    ctx = ExecutionContext(session_id="s1")

    with patch("requests.request") as mock_req:
        mock_req.side_effect = [
            _create_402_mock(fixture),
            requests.exceptions.ConnectionError("Downstream failed")
        ]
        
        with patch.object(client, "_process_payment", return_value=("dummy_proof", "Lightning", None)):
            # P0-D要件に基づき、例外はambiguous_payment_resultとして安全にラップされる
            with pytest.raises(PaymentExecutionError, match="ambiguous_payment_result"):
                client.execute_detailed(
                    fixture["request"]["method"],
                    fixture["request"]["url"],
                    headers=fixture["request"]["headers"],
                    context=ctx,
                )
                
    assert len(exported_records) == 1
    record = exported_records[0]
    
    assert "ambiguous_payment_result" in record.error_message
    assert record.session_spend_delta_usd == pytest.approx(0.0065)
    assert record.receipt_summary is not None
