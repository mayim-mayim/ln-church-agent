import pytest
import requests
from unittest.mock import patch, MagicMock

from ln_church_agent.models import (
    ExecutionContext, TrustDecision, OutcomeSummary, TrustEvidence,
    ParsedChallenge, ChallengeSource, SettlementReceipt
)
from ln_church_agent.client import Payment402Client
from ln_church_agent.exceptions import CounterpartyTrustError
from ln_church_agent.evaluators import RemoteTrustEvaluator, RemoteOutcomeMatcher

# ==========================================
# 1. 旧版: SDK Core Engine (フック機構) のテスト
# ==========================================

def test_trust_evaluator_blocks_payment():
    """Trust Evaluator が 402 チャレンジ受信後、支払い処理の前に正しくブロックすることを確認"""
    def strict_evaluator(url, challenge, context):
        return TrustDecision(is_trusted=False, reason="Unverified Host")
        
    client = Payment402Client(base_url="http://mock", trust_evaluators=[strict_evaluator])
    
    with patch("requests.request") as mock_req:
        mock_resp = MagicMock()
        mock_resp.status_code = 402
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
        mock_resp = MagicMock()
        mock_resp.status_code = 200
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
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.content = b'{"status": "ok"}'
        mock_resp.json.return_value = {"status": "ok"}
        mock_req.return_value = mock_resp

        result = client.execute_detailed("POST", "/test", context=ctx, outcome_matcher=context_matcher)
        
        assert result.outcome.observed_state == "test_intent_123"

# ==========================================
# 2. 新版: Remote Advisor (合成・フォールバック機構) のテスト
# ==========================================

def _get_dummy_trust_evidence(url="https://api.example.com/data", hints=None):
    parsed = ParsedChallenge(
        scheme="L402", network="Lightning", amount=10.0, asset="SATS",
        parameters={"invoice": "lnbc123"}, source=ChallengeSource.STANDARD_WWW
    )
    return TrustEvidence(url=url, challenge=parsed, agent_hints=hints or {})

def _get_dummy_receipt():
    return SettlementReceipt(
        receipt_id="rcpt_123", scheme="L402", network="Lightning",
        asset="SATS", settled_amount=10.0, proof_reference="preimage123",
        verification_status="verified"
    )

@patch("requests.post")
def test_trust_local_override_over_remote_deny(mock_post):
    """[Trust] リモート(本殿)が Deny を推奨しても、ローカルの allowed_hosts にあれば Allow で上書きする"""
    mock_resp = MagicMock()
    mock_resp.ok = True
    mock_resp.json.return_value = {
        "recommendation": "deny", 
        "reason": "Past personal mismatch detected.",
        "evidence_bundle": {"personal_mismatch_count": 3}
    }
    mock_post.return_value = mock_resp

    ctx = ExecutionContext(hints={"allowed_hosts": ["api.example.com"]})
    evidence = _get_dummy_trust_evidence(url="https://api.example.com/data", hints=ctx.hints)
    
    evaluator = RemoteTrustEvaluator(endpoint_url="http://mock")
    decision = evaluator(evidence, context=ctx)

    assert decision.is_trusted is True
    assert "[Local Override]" in decision.reason
    assert "Ignored remote advice: deny" in decision.reason
    assert ctx.hints["remote_trust_advice"]["evidence_bundle"]["personal_mismatch_count"] == 3

@patch("requests.post")
def test_trust_remote_failure_strict_fallback(mock_post):
    """[Trust] リモート(本殿)が通信エラーの際、fallback_mode="strict" なら確実に Deny する"""
    mock_post.side_effect = requests.exceptions.Timeout("Connection timed out")

    ctx = ExecutionContext()
    evidence = _get_dummy_trust_evidence()
    
    evaluator = RemoteTrustEvaluator(endpoint_url="http://mock", fallback_mode="strict")
    decision = evaluator(evidence, context=ctx)

    assert decision.is_trusted is False
    assert "[Local Fallback: Strict]" in decision.reason

@patch("requests.post")
def test_trust_remote_failure_allow_on_error_fallback(mock_post):
    """[Trust] リモート(本殿)が通信エラーの際、fallback_mode="allow_on_error" なら Allow する"""
    mock_post.side_effect = requests.exceptions.Timeout("Connection timed out")

    ctx = ExecutionContext()
    evidence = _get_dummy_trust_evidence()
    
    evaluator = RemoteTrustEvaluator(endpoint_url="http://mock", fallback_mode="allow_on_error")
    decision = evaluator(evidence, context=ctx)

    assert decision.is_trusted is True
    assert "[Local Fallback: Allow On Error]" in decision.reason

@patch("requests.post")
def test_trust_backward_compatibility_old_server(mock_post):
    """[Trust] サーバーが古いバージョン(recommendationを返さない)でもクラッシュせず動作する"""
    mock_resp = MagicMock()
    mock_resp.ok = True
    mock_resp.json.return_value = {
        "is_trusted": True,
        "decision": "allow",
        "reason": "Sanctified"
    }
    mock_post.return_value = mock_resp

    ctx = ExecutionContext()
    evidence = _get_dummy_trust_evidence()
    
    evaluator = RemoteTrustEvaluator(endpoint_url="http://mock")
    decision = evaluator(evidence, context=ctx)

    assert decision.is_trusted is True
    assert "allow" in ctx.hints["remote_trust_advice"]["recommendation"]

@patch("requests.post")
def test_outcome_local_fallback_overrides_remote_failure(mock_post):
    """[Outcome] リモート(本殿)が Success=False と判定しても、カスタム関数が True なら最終的に Success とする"""
    mock_resp = MagicMock()
    mock_resp.ok = True
    mock_resp.json.return_value = {
        "recommended_success": False,
        "observed_state": "Shape Mismatch",
        "evidence_bundle": {"target_domain": "api.example.com"}
    }
    mock_post.return_value = mock_resp

    def custom_fallback(resp, receipt, ctx):
        return OutcomeSummary(is_success=True, observed_state="Local Verified", message="Looks good to me")

    matcher = RemoteOutcomeMatcher(endpoint_url="http://mock", local_fallback_matcher=custom_fallback)
    ctx = ExecutionContext()
    
    outcome = matcher(response={"data": "something"}, receipt=_get_dummy_receipt(), context=ctx)

    assert outcome.is_success is True
    assert "Looks good to me" in outcome.message
    assert outcome.external_evidence["evidence_bundle"]["target_domain"] == "api.example.com"

@patch("requests.post")
def test_outcome_remote_failure_generic_fallback(mock_post):
    """[Outcome] リモート(本殿)が通信エラーの際、汎用構造チェック(Generic Fallback)が作動する"""
    mock_post.side_effect = requests.exceptions.Timeout("Connection timed out")

    matcher = RemoteOutcomeMatcher(endpoint_url="http://mock")
    ctx = ExecutionContext()
    
    good_response = {"data": "some value", "status": "ok"}
    outcome_good = matcher(response=good_response, receipt=_get_dummy_receipt(), context=ctx)
    
    assert outcome_good.is_success is True
    assert "unverified_local_fallback" in outcome_good.observed_state
    assert outcome_good.external_evidence["remote_failed"] is True

    bad_response = {"error": "Internal Server Error"}
    outcome_bad = matcher(response=bad_response, receipt=_get_dummy_receipt(), context=ctx)
    
    assert outcome_bad.is_success is False

@patch("requests.post")
def test_outcome_backward_compatibility_old_server(mock_post):
    """[Outcome] サーバーが古いバージョン(recommended_success等を返さない)でもクラッシュせず動作する"""
    mock_resp = MagicMock()
    mock_resp.ok = True
    # v1.4時代の古いレスポンス（is_success のみ）
    mock_resp.json.return_value = {
        "is_success": True,
        "observed_state": "Legacy Verification",
        "verification_id": "vrf_legacy_123",
        "reason": "Verified via old logic"
    }
    mock_post.return_value = mock_resp

    matcher = RemoteOutcomeMatcher(endpoint_url="http://mock")
    ctx = ExecutionContext()
    
    # 実行
    outcome = matcher(response={"data": "ok"}, receipt=_get_dummy_receipt(), context=ctx)

    # クラッシュせずに、古い 'is_success' を正しく拾って OutcomeSummary を作れていること
    assert outcome.is_success is True
    assert outcome.observed_state == "Legacy Verification"
    assert "[Remote Advisor]" in outcome.message
    # evidence_bundle 等の新しいキーが無くても、空辞書として安全に処理されていること
    assert outcome.external_evidence["evidence_bundle"] == {}