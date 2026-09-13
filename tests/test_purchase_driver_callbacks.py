"""Public callback order across the two purchase transports."""
import asyncio
import threading
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ln_church_agent.client import Payment402Client
from ln_church_agent.models import EvidenceRepository, ExecutionContext, OutcomeSummary, TrustDecision
from _p0_2_fixture import configure_contract_clock, contract_response, load_contract_fixture, success_response


@pytest.mark.parametrize('async_mode', [False, True])
@pytest.mark.parametrize('trust_arity', [2, 3])
@pytest.mark.parametrize('outcome_arity', [2, 3])
def test_purchase_callback_order_arity_and_execution_thread(async_mode, trust_arity, outcome_arity):
    fixture = load_contract_fixture()
    events = []
    driver_thread = threading.get_ident()
    context = ExecutionContext()

    class Repo(EvidenceRepository):
        def import_evidence(self, url, ctx):
            events.append('import')
            return []
        async def import_evidence_async(self, url, ctx):
            return self.import_evidence(url, ctx)
        def export_evidence(self, record, ctx):
            events.append('export')
        async def export_evidence_async(self, record, ctx):
            self.export_evidence(record, ctx)

    def trust_check(ctx):
        assert ctx is context
        assert (threading.get_ident() != driver_thread) == async_mode
        events.append('trust')
        return TrustDecision(is_trusted=True, reason='local approval')
    def trust_new(evidence, ctx):
        return trust_check(ctx)
    def trust_old(url, parsed, ctx):
        return trust_check(ctx)
    def outcome_check(ctx):
        assert ctx is context and threading.get_ident() == driver_thread
        events.append('outcome')
        return OutcomeSummary(is_success=True, observed_state='complete')
    def outcome_new(response, receipt, ctx):
        assert receipt.payment_performed is True
        return outcome_check(ctx)
    def outcome_old(response, ctx):
        return outcome_check(ctx)
    wallet = MagicMock()
    wallet.pay_invoice.side_effect = lambda invoice: events.append('wallet') or fixture['payment']['mock_preimage']
    client = configure_contract_clock(Payment402Client(
        ln_adapter=wallet, evidence_repo=Repo(), trust_evaluators=[trust_new if trust_arity == 2 else trust_old],
    ), fixture)
    responses = iter([contract_response(fixture), success_response(fixture)])
    def request(*args, **kwargs):
        response = next(responses)
        events.append('402' if response.status_code == 402 else '200')
        return response
    args = (fixture['request']['method'], fixture['request']['url'])
    kwargs = dict(headers=fixture['request']['headers'], context=context,
                  outcome_matcher=outcome_new if outcome_arity == 3 else outcome_old)
    if async_mode:
        client._async_client = MagicMock(request=AsyncMock(side_effect=request))
        result = asyncio.run(client.execute_detailed_async(*args, **kwargs))
    else:
        with patch('requests.request', side_effect=request):
            result = client.execute_detailed(*args, **kwargs)
    assert events == ['402', 'import', 'trust', 'wallet', '200', 'outcome', 'export']
    assert result.outcome.is_success and result.settlement_receipt.payment_performed


def test_async_transport_cancellation_stays_cancellation():
    client = Payment402Client(base_url='https://api.test')
    client._async_client = MagicMock(request=AsyncMock(side_effect=asyncio.CancelledError))
    with patch.object(client, '_process_payment', side_effect=AssertionError('payment')) as pay:
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(client.execute_detailed_async('GET', '/resource'))
    pay.assert_not_called()
