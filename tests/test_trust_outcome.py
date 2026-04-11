import pytest
from unittest.mock import patch, MagicMock
from ln_church_agent.models import ExecutionContext, TrustDecision, OutcomeSummary
from ln_church_agent.client import Payment402Client
from ln_church_agent.exceptions import CounterpartyTrustError

def test_trust_evaluator_blocks_payment():
    """Trust Evaluator が 402 チャレンジ受信後、支払い処理の前に正しくブロックすることを確認"""
    def strict_evaluator(url, challenge, context):
        return TrustDecision(is_trusted=False, reason="Unverified Host")
        
    client = Payment402Client(base_url="http://mock", trust_evaluators=[strict_evaluator])
    
    with patch("requests.request") as mock_req:
        # 402レスポンスの偽装
        mock_resp = MagicMock()
        mock_resp.status_code = 402
        # 🚨 修正: headers を追加して re.search などで落ちないようにする
        mock_resp.headers = {"WWW-Authenticate": 'L402 macaroon="mac", invoice="inv"'}
        mock_resp.json.return_value = {
            "challenge": {"scheme": "L402", "amount": 10, "asset": "SATS"},
            "instruction_for_agents": {}
        }
        mock_req.return_value = mock_resp

        with pytest.raises(CounterpartyTrustError, match="Unverified Host"):
            client.execute_detailed("POST", "/test")

def test_outcome_matcher_attaches_summary():
    """Outcome Matcher が 200 OK のレスポンスを評価し、ExecutionResult に OutcomeSummary を付与することを確認"""
    def data_matcher(response, context):
        is_success = "premium_data" in response
        return OutcomeSummary(is_success=is_success, observed_state="Data Extracted")

    client = Payment402Client(base_url="http://mock")
    
    with patch("requests.request") as mock_req:
        # 200レスポンスの偽装
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        # 🚨 修正: headers を追加
        mock_resp.headers = {}
        mock_resp.content = b'{"premium_data": "top_secret"}'
        mock_resp.json.return_value = {"premium_data": "top_secret"}
        mock_req.return_value = mock_resp

        result = client.execute_detailed("POST", "/test", outcome_matcher=data_matcher)
        
        assert result.outcome is not None
        assert result.outcome.is_success is True
        assert result.outcome.observed_state == "Data Extracted"

def test_execution_context_propagation():
    """ExecutionContext が再帰呼び出しなどを経て Matcher まで正しく引き継がれるか確認"""
    def context_matcher(response, context):
        return OutcomeSummary(is_success=True, observed_state=context.intent_label)

    client = Payment402Client(base_url="http://mock")
    ctx = ExecutionContext(intent_label="test_intent_123")
    
    with patch("requests.request") as mock_req:
        # 200レスポンスの偽装
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        # 🚨 修正: headers を追加
        mock_resp.headers = {}
        mock_resp.content = b'{"status": "ok"}'
        mock_resp.json.return_value = {"status": "ok"}
        mock_req.return_value = mock_resp

        result = client.execute_detailed("POST", "/test", context=ctx, outcome_matcher=context_matcher)
        
        assert result.outcome.observed_state == "test_intent_123"