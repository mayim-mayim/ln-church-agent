import pytest
import asyncio
import requests
from unittest.mock import AsyncMock, patch, MagicMock
from dataclasses import asdict
import copy

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
# テストケース (A〜F: 基本要件)
# ==========================================
@pytest.mark.parametrize("async_mode", [False, True], ids=["sync", "async"])
def test_budget_restore_blocks_next_payment(async_mode):
    record = PaymentEvidenceRecord(
        session_id="test_session", correlation_id="c1", target_url="http://mock",
        method="POST", session_spend_delta_usd=4.0,
    )
    repo = MockSessionRepo([record])
    fixture = load_contract_fixture()
    client = configure_contract_clock(
        Payment402Client(
            policy=PaymentPolicy(max_spend_per_session_usd=4.005), evidence_repo=repo,
        ), fixture,
    )
    context = ExecutionContext(session_id="test_session")
    args = (fixture["request"]["method"], fixture["request"]["url"])
    kwargs = {"headers": fixture["request"]["headers"], "context": context}
    response = contract_response(fixture)

    if async_mode:
        async def run():
            client._async_client = MagicMock()
            client._async_client.request = AsyncMock(return_value=response)
            with pytest.raises(PaymentExecutionError, match="would exceed limit"):
                await client.execute_detailed_async(*args, **kwargs)
            assert client._async_client.request.call_count == 1
        asyncio.run(run())
    else:
        with patch("requests.request", return_value=response) as transport:
            with pytest.raises(PaymentExecutionError, match="would exceed limit"):
                client.execute_detailed(*args, **kwargs)
        assert transport.call_count == 1

    assert (repo.sync_call_count, repo.async_call_count) == ((0, 1) if async_mode else (1, 0))
    assert client.policy._session_spent_usd == 4.0
    assert context.session_budget_restored is True


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
            contract_response(fixture),
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


def test_policy_constructor_and_serialization_project_confirmed_spend():
    policy = PaymentPolicy(_session_spent_usd=2.0)
    client = Payment402Client(policy=policy)
    context = ExecutionContext(session_budget_restored=True)
    client._reserve_session_budget(context, "new-purchase", "3")
    assert asdict(policy)["_session_spent_usd"] == 2.0
    client._confirm_session_budget(context, "new-purchase")
    assert asdict(policy)["_session_spent_usd"] == 5.0
    cloned = copy.deepcopy(policy)
    assert asdict(cloned) == asdict(policy)
    cloned._session_spent_usd = 7.0
    assert policy._session_spent_usd == 5.0
    assert context.model_dump()["session_budget_restored"] is True


def test_shared_context_keeps_different_policy_budgets_independent():
    first = Payment402Client(policy=PaymentPolicy(
        _session_spent_usd=0.25, max_spend_per_session_usd=1.5,
    ))
    second = Payment402Client(policy=PaymentPolicy(max_spend_per_session_usd=2.0))
    context = ExecutionContext(session_id="two-policy-session")
    first._reserve_session_budget(context, "first-purchase", "1")
    second._reserve_session_budget(context, "second-purchase", "2")
    assert first.policy._session_reserved_usd == 1.0
    assert second.policy._session_reserved_usd == 2.0
    first._confirm_session_budget(context, "first-purchase")
    assert asdict(first.policy)["_session_spent_usd"] == 1.25
    assert first.policy._session_reserved_usd == 0.0
    assert asdict(second.policy)["_session_spent_usd"] == 0.0
    assert second.policy._session_reserved_usd == 2.0
    second._confirm_session_budget(context, "second-purchase")
    assert second.policy._session_spent_usd == 2.0
    assert first.policy._session_spent_usd == 1.25


@pytest.mark.parametrize("async_mode", [False, True], ids=["sync", "async"])
def test_restore_preserves_preexisting_live_reservation_owner(async_mode):
    policy = PaymentPolicy(max_spend_per_session_usd=1.5)
    payer = Payment402Client(policy=policy)
    owner = ExecutionContext(session_id="live-import-session")
    payer._check_and_set_payment_state(owner, "live-purchase")
    payer._reserve_session_budget(owner, "live-purchase", "1")
    repository = MockSessionRepo([PaymentEvidenceRecord(
        session_id=owner.session_id, correlation_id="prior-export", target_url="urn:test",
        method="GET", session_budget_event="reserved",
        session_budget_operation_id="live-purchase", session_budget_amount_usd=1.0,
    )])
    importer = Payment402Client(policy=policy, evidence_repo=repository)
    restored = ExecutionContext(session_id=owner.session_id)
    if async_mode:
        asyncio.run(importer._restore_session_spend_from_evidence_async(restored))
    else:
        importer._restore_session_spend_from_evidence(restored)
    assert owner.get_payment_state("live-purchase") == "in_progress"
    assert importer._release_session_budget(restored, "live-purchase") == 0
    assert policy._session_reserved_usd == 1.0
    assert payer._confirm_session_budget(owner, "live-purchase") == 1
    assert policy._session_spent_usd == 1.0
    assert policy._session_reserved_usd == 0.0

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
            contract_response(fixture),
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
