import pytest
from unittest.mock import patch, MagicMock
from ln_church_agent.models import ExecutionContext, TrustDecision, PaymentEvidenceRecord, EvidenceRepository
from ln_church_agent.client import Payment402Client
from ln_church_agent.exceptions import CounterpartyTrustError

class MockMemoryRepo(EvidenceRepository):
    def __init__(self):
        self.exported_records = []
        self.mock_past_evidence = []
        
    def export_evidence(self, record: PaymentEvidenceRecord, context: ExecutionContext) -> None:
        self.exported_records.append(record)

    def import_evidence(self, target_url: str, context: ExecutionContext) -> list[PaymentEvidenceRecord]:
        return self.mock_past_evidence

def test_evidence_export_on_trust_block():
    """Trust Evaluator が拒否した場合でも、その履歴が export されることを確認"""
    repo = MockMemoryRepo()
    
    def block_evaluator(evidence, context):
        return TrustDecision(is_trusted=False, reason="Too suspicious")
        
    client = Payment402Client(base_url="http://mock", trust_evaluators=[block_evaluator], evidence_repo=repo)
    
    with patch("requests.request") as mock_req:
        resp_402 = MagicMock()
        resp_402.status_code = 402
        resp_402.headers = {"WWW-Authenticate": 'L402 macaroon="m", invoice="i"'}
        resp_402.json.return_value = {"challenge": {"scheme": "L402", "amount": 10, "asset": "SATS"}, "instruction_for_agents": {}}
        mock_req.return_value = resp_402

        with pytest.raises(CounterpartyTrustError):
            client.execute_detailed("POST", "/test")
            
        # Error が起きても Export されているか
        assert len(repo.exported_records) == 1
        record = repo.exported_records[0]
        assert record.target_url == "http://mock/test"
        assert record.trust_decision.is_trusted is False
        assert record.error_message is not None
        assert "Too suspicious" in record.error_message

def test_evidence_import_assists_trust():
    """Import された過去の Evidence が past_evidence に格納され、型安全に評価に使えることを確認"""
    repo = MockMemoryRepo()
    repo.mock_past_evidence = [PaymentEvidenceRecord(session_id="old", correlation_id="old", target_url="old", method="GET")]
    
    def assist_evaluator(evidence, context):
        # 修正: context.hints.get ではなく、専用の型安全なフィールドへアクセス
        past = context.past_evidence or []
        if len(past) > 0:
            return TrustDecision(is_trusted=True)
        return TrustDecision(is_trusted=False, reason="No history")

    client = Payment402Client(base_url="http://mock", trust_evaluators=[assist_evaluator], evidence_repo=repo)
    
    with patch("requests.request") as mock_req:
        resp_402 = MagicMock()
        resp_402.status_code = 402
        resp_402.headers = {"WWW-Authenticate": 'L402 macaroon="m", invoice="i"'}
        resp_402.json.return_value = {"challenge": {"scheme": "L402", "amount": 10, "asset": "SATS"}, "instruction_for_agents": {}}
        
        resp_200 = MagicMock()
        resp_200.status_code = 200
        resp_200.content = b'{}'
        resp_200.json.return_value = {}
        
        mock_req.side_effect = [resp_402, resp_200]

        with patch.object(client, "_process_payment", return_value=("proof", "Lightning")):
            result = client.execute_detailed("POST", "/test")
            # 評価を通過して200まで到達していればOK
            assert result.response == {}
            # 成功時も Export されているか
            assert len(repo.exported_records) == 1
            assert repo.exported_records[0].error_message is None