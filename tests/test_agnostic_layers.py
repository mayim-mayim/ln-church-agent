import pytest
from unittest.mock import patch, MagicMock
from ln_church_agent.models import ExecutionContext, TrustDecision, OutcomeSummary, TrustEvidence, SettlementReceipt
from ln_church_agent.client import Payment402Client
from ln_church_agent.exceptions import CounterpartyTrustError

def test_v1_5_trust_evidence_from_hints():
    """v1.5: Context の hints を利用した Source-Agnostic な Trust 評価"""
    def hint_evaluator(evidence: TrustEvidence, context: ExecutionContext):
        allowed_hosts = evidence.agent_hints.get("allowed_hosts", [])
        if "mock" not in allowed_hosts:
            return TrustDecision(is_trusted=False, reason="Host not in agent hints")
        return TrustDecision(is_trusted=True)
        
    client = Payment402Client(base_url="http://mock", trust_evaluators=[hint_evaluator])
    ctx = ExecutionContext(hints={"allowed_hosts": ["safe-domain.com"]}) # mock が含まれていない
    
    with patch("requests.request") as mock_req:
        mock_resp = MagicMock()
        mock_resp.status_code = 402
        mock_resp.headers = {"WWW-Authenticate": 'L402 macaroon="mac", invoice="inv"'}
        mock_resp.json.return_value = {"challenge": {"scheme": "L402", "amount": 10, "asset": "SATS"}, "instruction_for_agents": {}}
        mock_req.return_value = mock_resp

        with pytest.raises(CounterpartyTrustError, match="Host not in agent hints"):
            client.execute_detailed("POST", "/test", context=ctx)

def test_v1_5_outcome_with_receipt():
    """v1.5: Receipt の情報を活用した Provider-Agnostic な Outcome 評価"""
    def receipt_matcher(response: dict, receipt: SettlementReceipt, context: ExecutionContext):
        # 決済で使われたProof（ダミー）とレスポンスをクロスチェックするイメージ
        is_success = receipt is not None and receipt.proof_reference == "dummy_proof"
        return OutcomeSummary(is_success=is_success, observed_state="Cross-Verified")

    client = Payment402Client(base_url="http://mock")
    
    with patch("requests.request") as mock_req:
        # 1回目(402) -> 2回目(200) の一連の流れをモックする
        resp_402 = MagicMock()
        resp_402.status_code = 402
        resp_402.headers = {"WWW-Authenticate": 'L402 macaroon="m", invoice="inv"'}
        resp_402.json.return_value = {"challenge": {"scheme": "L402", "amount": 10, "asset": "SATS"}, "instruction_for_agents": {}}

        resp_200 = MagicMock()
        resp_200.status_code = 200
        resp_200.content = b'{"status": "ok"}'
        resp_200.json.return_value = {"status": "ok"}
        
        mock_req.side_effect = [resp_402, resp_200]

        # 決済ロジックをモックして "dummy_proof" を返させる
        with patch.object(client, "_process_payment", return_value=("dummy_proof", "Lightning", None)):
            result = client.execute_detailed("POST", "/test", outcome_matcher=receipt_matcher)
            
            assert result.outcome is not None
            assert result.outcome.is_success is True
            assert result.outcome.observed_state == "Cross-Verified"

def test_v1_4_backward_compatibility():
    """v1.4 時代の古いシグネチャの Evaluator / Matcher がクラッシュせずに動くか"""
    def legacy_evaluator(url, challenge, context):
        return TrustDecision(is_trusted=True)
    def legacy_matcher(response, context):
        return OutcomeSummary(is_success=True)

    client = Payment402Client(base_url="http://mock", trust_evaluators=[legacy_evaluator])
    with patch("requests.request") as mock_req:
        resp_200 = MagicMock()
        resp_200.status_code = 200
        resp_200.content = b'{}'
        resp_200.json.return_value = {}
        mock_req.return_value = resp_200

        # クラッシュせずに結果が返ればOK
        result = client.execute_detailed("POST", "/test", outcome_matcher=legacy_matcher)
        assert result.outcome.is_success is True