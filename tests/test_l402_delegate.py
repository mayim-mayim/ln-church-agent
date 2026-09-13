from unittest.mock import MagicMock
from bolt11 import Bolt11, MilliSatoshi, Tag, TagChar, Tags, encode
from ln_church_agent.client import Payment402Client
from ln_church_agent.models import (
    ParsedChallenge, ChallengeSource, L402ExecutionReport
)
from ln_church_agent.crypto.protocols import L402Executor


def _signed_10_sat_invoice():
    invoice = Bolt11(
        currency="bc",
        date=1700000000,
        amount_msat=MilliSatoshi(10000),
        tags=Tags([
            Tag(TagChar.payment_hash, "11" * 32),
            Tag(TagChar.payment_secret, "22" * 32),
            Tag(TagChar.description, "ln-church-agent test invoice"),
        ]),
    )
    return encode(invoice, private_key="01".zfill(64))

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
        parameters={"invoice": _signed_10_sat_invoice(), "macaroon": "mac1234567890"}, source=ChallengeSource.STANDARD_WWW
    )
    parsed._invoice_msats = 10000
    parsed._atomic_amount = "10000"

    _, _, report1 = client._process_payment(parsed, {}, {}, method="GET", url="https://unknown.com/data")
    assert report1.delegate_source == "native"
    assert mock_ln_adapter.pay_invoice.call_count == 1

    _, _, report2 = client._process_payment(parsed, {}, {"data": "val"}, method="POST", url="https://allowed.com/data")
    assert report2.delegate_source == "native"
    assert mock_ln_adapter.pay_invoice.call_count == 2

    _, _, report3 = client._process_payment(parsed, {}, {}, method="GET", url="https://allowed.com/data")
    assert report3.delegate_source == "lightninglabs_mock"
    assert mock_ln_adapter.pay_invoice.call_count == 2
