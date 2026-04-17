import pytest
from unittest.mock import MagicMock
from ln_church_agent.client import Payment402Client
from ln_church_agent.models import (
    ParsedChallenge, ChallengeSource, SchemeType, 
    L402ExecutionReport, PaymentPolicy, ExecutionContext
)
from ln_church_agent.crypto.protocols import L402Executor

class MockDelegateExecutor(L402Executor):
    def execute_l402(self, url, method, parsed, headers, payload):
        return L402ExecutionReport(
            delegate_source="lightninglabs_mock",
            authorization_value="L402 dummy_mac:dummy_preimage",
            cached_token_used=True,      # キャッシュを使った想定
            payment_performed=False      # 実決済は行われなかった想定
        )

def test_l402_mode_selection_fallback_to_native():
    """POSTメソッドや未許可ホストの場合はNativeにフォールバックすることを確認"""
    mock_delegate = MockDelegateExecutor()
    mock_ln_adapter = MagicMock()
    mock_ln_adapter.pay_invoice.return_value = "native_preimage"

    client = Payment402Client(
        ln_adapter=mock_ln_adapter,
        l402_executor=mock_delegate,
        prefer_lightninglabs_l402=True,
        l402_delegate_allowed_hosts=["allowed.com"]
    )

    parsed = ParsedChallenge(
        scheme="L402", network="Lightning", amount=10.0, asset="SATS",
        parameters={"invoice": "lnbc1", "macaroon": "mac1"}, source=ChallengeSource.STANDARD_WWW
    )

    # 1. Hostが許可されていない場合 -> Native
    _, _, report1 = client._process_payment(parsed, {}, {}, method="GET", url="https://unknown.com/data")
    assert report1.delegate_source == "native"
    assert mock_ln_adapter.pay_invoice.call_count == 1

    # 2. MethodがPOSTの場合 -> Native
    _, _, report2 = client._process_payment(parsed, {}, {"data": "val"}, method="POST", url="https://allowed.com/data")
    assert report2.delegate_source == "native"
    assert mock_ln_adapter.pay_invoice.call_count == 2

    # 3. 条件クリア (GET, 空ペイロード, 許可ホスト) -> Delegate
    _, _, report3 = client._process_payment(parsed, {}, {}, method="GET", url="https://allowed.com/data")
    assert report3.delegate_source == "lightninglabs_mock"
    assert mock_ln_adapter.pay_invoice.call_count == 2 # Nativeは呼ばれない

def test_l402_cached_token_budget_protection():
    """キャッシュ利用(payment_performed=False)の場合はセッション予算が消費されないことを確認"""
    policy = PaymentPolicy(max_spend_per_session_usd=10.0)
    client = Payment402Client(policy=policy)
    
    parsed = ParsedChallenge(
        scheme="L402", network="Lightning", amount=1000.0, asset="SATS",  # 約 $0.65
        parameters={}, source=ChallengeSource.STANDARD_WWW
    )

    # 実決済が行われたケース
    native_report = L402ExecutionReport(authorization_value="auth", payment_performed=True)
    client._record_session_spend(parsed, native_report)
    assert client.policy._session_spent_usd > 0.0

    # キャッシュが使われたケース
    current_spend = client.policy._session_spent_usd
    cached_report = L402ExecutionReport(authorization_value="auth", payment_performed=False, cached_token_used=True)
    client._record_session_spend(parsed, cached_report)
    
    # 予算が変動していないこと
    assert client.policy._session_spent_usd == current_spend