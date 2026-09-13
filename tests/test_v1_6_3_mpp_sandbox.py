import asyncio
import hashlib
import json
from unittest.mock import patch

import pytest
from ln_church_agent.client import LnChurchClient
from ln_church_agent.models import ExecutionResult, SettlementReceipt, AttestationSource


@pytest.mark.parametrize('async_mode', [False, True])
@pytest.mark.parametrize('rail', ['l402', 'mpp_charge'])
def test_sandbox_dynamic_telemetry_and_result(async_mode, rail):
    client = LnChurchClient(base_url='https://api.test')
    scheme = 'L402' if rail == 'l402' else 'MPP_Draft_v2'
    receipt = SettlementReceipt(
        receipt_id='r_123', scheme=scheme, network='Lightning', asset='SATS',
        settled_amount=10, proof_reference='preimage123', receipt_token_hash='sha256:' + 'a' * 64,
        present=True, source=AttestationSource.SERVER_JWS,
    )
    body = dict(message='success', scenario=rail, contract='stable', verifiable=True)
    digest = hashlib.sha256(json.dumps(body, separators=(',', ':')).encode()).hexdigest()
    fetched = ExecutionResult(response=dict(body, meta={
        'run_id': 'run_123', 'scenario_id': rail, 'canonical_hash_expected': digest, 'interop_token': 'token',
    }), final_url='https://api.test/basic', settlement_receipt=receipt, used_scheme=scheme)
    reported = ExecutionResult(response={'status': 'success'}, final_url='https://api.test/report')
    suffix = '_async' if async_mode else ''
    with patch.object(client, 'execute_detailed' + suffix, side_effect=[fetched, reported]) as execute:
        method = getattr(client, 'run_' + rail + '_sandbox_harness' + suffix)
        result = asyncio.run(method()) if async_mode else method()
    assert result.ok and result.canonical_hash_matched and result.report_accepted
    assert result.receipt_id == 'r_123' and result.report_status_code == 200
    assert [call.args[0] for call in execute.call_args_list] == ['GET', 'POST']
    payload = execute.call_args_list[1].kwargs['payload']
    assert payload['rail'] == ('L402' if rail == 'l402' else 'MPP')
    assert payload['payment_intent'] == 'charge' and payload['authorization_scheme'] == scheme
    assert payload['payment_receipt_present'] is True
    assert payload['canonical_hash_observed'] == digest


@pytest.mark.parametrize('async_mode', [False, True])
@pytest.mark.parametrize('message, failure', [
    ('mpp_session_not_supported_yet', 'mpp_session_not_supported_yet'),
    ('network failed', 'payment_failed'),
])
def test_mpp_fetch_failure_still_reports_without_claiming_payment(async_mode, message, failure):
    client = LnChurchClient(base_url='https://api.test')
    report = ExecutionResult(response={'status': 'success'}, final_url='https://api.test/report')
    suffix = '_async' if async_mode else ''
    with patch.object(client, 'execute_detailed' + suffix, side_effect=[RuntimeError(message), report]) as execute:
        method = getattr(client, 'run_mpp_charge_sandbox_harness' + suffix)
        result = asyncio.run(method()) if async_mode else method()
    assert not result.ok and not result.payment_performed and not result.canonical_hash_matched
    assert execute.call_args_list[1].kwargs['payload']['failure_reason'] == failure


@pytest.mark.parametrize('async_mode', [False, True])
@pytest.mark.parametrize('rail', ['l402', 'mpp_charge'])
def test_report_failure_retains_http_status(async_mode, rail):
    client = LnChurchClient(base_url='https://api.test')
    fetched = ExecutionResult(response={}, final_url='https://api.test/basic')
    suffix = '_async' if async_mode else ''
    with patch.object(client, 'execute_detailed' + suffix, side_effect=[fetched, RuntimeError('API Error 429: limited')]):
        method = getattr(client, 'run_' + rail + '_sandbox_harness' + suffix)
        result = asyncio.run(method()) if async_mode else method()
    assert result.report_status_code == 429 and not result.report_accepted and not result.ok
