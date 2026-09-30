"""Isolated SDK adapters only; synthetic responses are not a normative pack."""
import json
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

from ln_church_agent.access_quota import AccessQuotaPolicy, AccessQuotaError, ORIGIN
from ln_church_agent.endpoint_choice_reason_client import AgentEndpointChoiceReasonClient
from ln_church_agent.endpoint_choice_reason_transport import EndpointChoiceTransport, EndpointChoiceAPIError
from ln_church_agent.endpoint_choice_reason_transport import EndpointChoiceError
from ln_church_agent.endpoint_choice_reason_requester import EndpointChoiceRequesterClient
from ln_church_agent import endpoint_choice_reason_requester as requester
from ln_church_agent.immediate_visit_transport import ImmediateVisitRawResponse
from test_access_quota import NOW, Signer, challenge as quota_challenge, success, status as quota_status
from test_endpoint_choice_reason_prepack import (
    synthetic_pack, journal, claim, task, raw, error, setup_answer, TASK, TOKEN,
    SUB, EXEC, ADDRESS, Exchange, client, receipt, status, challenge, registration,
)


class QuotaExchange:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def __call__(self, method, path, query, headers, body, timeout, **kwargs):
        self.calls.append((method, path, query, dict(headers), body))
        if not any(k in headers for k in ('PAYMENT-SIGNATURE', 'X-LN-Access-Recovery')):
            return ImmediateVisitRawResponse(*quota_challenge(
                method, ORIGIN + path + ('?' + query if query else ''), headers, body))
        return ImmediateVisitRawResponse(*next(self.responses))


def quota_client(exchange, policy):
    return AgentEndpointChoiceReasonClient(transport=EndpointChoiceTransport(
        exchange=exchange, access_quota=policy))


def test_explicit_access_purchase_continues_same_claim_after_default_stop(tmp_path, synthetic_pack):
    policy = AccessQuotaPolicy(signer=Signer(), budget_atomic=10000, wall_time=lambda: NOW)
    exchange = QuotaExchange([success(claim())])
    client = quota_client(exchange, policy)
    saved = journal(tmp_path)
    with pytest.raises(AccessQuotaError) as caught:
        client.claim_task(journal=saved)
    assert caught.value.code == 'ACCESS_REQUIRED' and policy.signer.calls == 0
    # An explicit caller decision changes only the live policy; no new Claim key.
    policy.allow = True
    result = client.claim_task(journal=saved)
    assert result.task_id == TASK and policy.signer.calls == 1
    assert len(exchange.calls) == 2
    assert exchange.calls[0][4] == exchange.calls[1][4]
    assert exchange.calls[0][3]['Idempotency-Key'] == exchange.calls[1][3]['Idempotency-Key']


def test_pending_access_keeps_original_proof_on_normal_reentry(tmp_path, synthetic_pack):
    policy = AccessQuotaPolicy(allow=True, signer=Signer(), budget_atomic=10000, wall_time=lambda: NOW)
    exchange = QuotaExchange([quota_status(), success(claim())])
    client = quota_client(exchange, policy)
    saved = journal(tmp_path)
    with pytest.raises(AccessQuotaError) as caught:
        client.claim_task(journal=saved)
    assert caught.value.code == 'ACCESS_PENDING'
    client.claim_task(journal=saved)
    assert policy.signer.calls == 1
    paid = [r for r in exchange.calls if 'PAYMENT-SIGNATURE' in r[3]]
    assert len(paid) == 2 and paid[0][3]['PAYMENT-SIGNATURE'] == paid[1][3]['PAYMENT-SIGNATURE']


def test_restart_without_live_access_state_uses_only_claim_recovery(tmp_path, synthetic_pack):
    first = journal(tmp_path)
    first.begin_claim()
    calls = []
    policy = AccessQuotaPolicy(allow=True, signer=Signer(), budget_atomic=10000, wall_time=lambda: NOW)
    def exchange(*args):
        calls.append(args)
        return error('not_found', 404)
    with pytest.raises(EndpointChoiceAPIError):
        quota_client(exchange, policy).claim_task(journal=journal(tmp_path))
    assert calls[0][3]['X-LN-Claim-Recovery'] == '1'
    assert policy.signer.calls == 0
    assert 'PAYMENT-SIGNATURE' not in calls[0][3]


def test_private_answer_not_in_default_report_serialization(tmp_path, synthetic_pack):
    saved, report = setup_answer(tmp_path)
    assert 'answer_reason' not in report.report.model_dump()
    assert 'answer_reason' not in report.report.model_dump_json()
    assert json.loads(report.canonical_bytes)['answer_reason'] == '  My reason\r\nそのまま  '
    assert saved.load_report().canonical_bytes == report.canonical_bytes


@pytest.mark.parametrize('operation', ['list', 'detail'])
def test_discovery_and_detail_use_explicit_shared_access_policy(operation, synthetic_pack):
    policy = AccessQuotaPolicy(allow=True, signer=Signer(), budget_atomic=10000, wall_time=lambda: NOW)
    payload = task() if operation == 'detail' else {
        'schema_version': 'ln_church.agent_task_page.endpoint_choice_reason.v1',
        'tasks': [task()], 'next_cursor': None}
    exchange = QuotaExchange([success(payload)])
    sdk = quota_client(exchange, policy)
    result = sdk.get_task(TASK) if operation == 'detail' else sdk.list_tasks()
    assert (result.task_id if operation == 'detail' else result.tasks[0].task_id) == TASK
    assert policy.spent_atomic == 10000 and policy.signer.calls == 1


@pytest.mark.parametrize('operation', ['completion', 'status', 'abandon', 'public', 'owner_challenge', 'owner_read', 'recover_claim'])
def test_results_completion_and_recovery_never_buy_access(operation):
    policy = AccessQuotaPolicy(allow=True, signer=Signer(), budget_atomic=10000, wall_time=lambda: NOW)
    exchange = QuotaExchange([])
    transport = EndpointChoiceTransport(exchange=exchange, access_quota=policy)
    operations = {
        'completion': lambda: transport.post_completion_bytes(TASK, TOKEN, SUB, b'{}'),
        'status': lambda: transport.get_submission_status(TASK, SUB, TOKEN),
        'abandon': lambda: transport.abandon_claim(TASK, TOKEN, b'{}', idempotency_key='abandon-key'),
        'public': lambda: transport.public_results(TASK),
        'owner_challenge': lambda: transport.results_challenge(TASK, ADDRESS),
        'owner_read': lambda: transport.results_read(b'{}'),
        'recover_claim': lambda: transport.recover_claim(TASK, b'{}', idempotency_key='same-key'),
    }
    # Even an unexpected edge 402 on an exempt route cannot turn it into a
    # purchase. This tests real transport/policy dispatch, not backend success.
    with pytest.raises((EndpointChoiceError, AccessQuotaError)):
        operations[operation]()
    assert policy.signer.calls == policy.spent_atomic == policy.reserved_atomic == 0
    assert len(exchange.calls) == 1
    assert 'PAYMENT-SIGNATURE' not in exchange.calls[0][3]
    if operation == 'recover_claim':
        assert exchange.calls[0][3]['X-LN-Claim-Recovery'] == '1'


def example(name):
    path = Path(__file__).parents[1] / 'examples' / (name + '.py')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_worker_example_calls_real_client_and_preserves_reason(tmp_path, synthetic_pack):
    worker = example('endpoint_choice_reason_worker')
    tmp_path.chmod(0o700)
    saved = worker.open_claim_journal(tmp_path, task_id=TASK, agent_id='test',
                                     reward_address=ADDRESS, claim_key='same-claim-key')
    sdk = client(Exchange([raw(claim())]))
    worker.claim(sdk, saved)
    def accept(*args):
        report = saved.load_report()
        value = receipt(report)
        value['submission_id'] = report.report.submission_id
        value['status_url'] = '/api/agent/tasks/' + TASK + '/submissions/' + value['submission_id'] + '/status'
        return raw(value, 202)
    assert worker.prepare_and_submit(client(accept), saved, selected_candidate_id='c1',
                                     answer_reason='  Exact\r\nreason  ').state == 'accepted'
    assert saved.load_report().report.answer_reason == '  Exact\r\nreason  '
    with pytest.raises(ValueError):
        worker.prepare_and_submit(sdk, saved, selected_candidate_id='c1', answer_reason='replacement')


def test_worker_example_restart_status_only_snapshot(tmp_path, synthetic_pack):
    worker = example('endpoint_choice_reason_worker')
    saved, report = setup_answer(tmp_path)
    ex = Exchange([raw(status(report)), raw(status(report))])
    sdk = client(ex)
    assert worker.resume_answer(sdk, journal(tmp_path)).state == 'accepted'
    snapshot = worker.evaluation_snapshot(sdk, saved)
    assert snapshot['evaluation']['q'] is None
    assert 'answer_reason' not in snapshot and [r[0] for r in ex.calls] == ['GET', 'GET']


def owner_page(cursor=None, deleted=False):
    original = registration()
    original['candidates'][0]['description_state'] = 'DELETED' if deleted else 'RETAINED'
    if deleted:
        original['candidates'][0]['evaluator_description'] = None
    original.update(description_retention_state='DELETED' if deleted else 'RETAINED',
                    description_delete_at='2026-10-30T00:00:00Z' if deleted else None)
    return dict(schema_version='ln_church.offer_results_read_response.v1', task_id=TASK,
                registration=original, items=[], next_cursor=cursor,
                intake_closed_at=None, projected_at='2026-09-28T00:00:00Z')


def test_requester_example_reuses_proof_and_explicit_refresh_keeps_cursor(monkeypatch):
    module = example('endpoint_choice_reason_requester')
    monkeypatch.setattr(requester, 'time', SimpleNamespace(time=lambda: 1001))
    exchange = Exchange([raw(challenge()), raw(owner_page('page2')), raw(owner_page()),
                         raw(challenge()), raw(owner_page(deleted=True))])
    sdk = EndpointChoiceRequesterClient(transport=EndpointChoiceTransport(exchange=exchange), wall_time=lambda: 1001)
    signed = []
    signer = lambda typed: signed.append(typed) or '0x1234'
    proof, page = module.begin_results(sdk, task_id=TASK, payer=ADDRESS, signer=signer)
    assert page.next_cursor == 'page2' and len(signed) == 1
    module.read_next_page(sdk, proof, cursor='page2')
    assert len(signed) == 1
    _, refreshed = module.refresh_results_explicitly(sdk, task_id=TASK, payer=ADDRESS,
                                                    signer=signer, cursor='page2')
    assert len(signed) == 2
    assert refreshed.registration.description_retention_state == 'DELETED'
    assert refreshed.registration.candidates[0].evaluator_description is None
    assert 'registration' not in refreshed.model_dump()
    assert json.loads(exchange.calls[-1][4])['cursor'] == 'page2'
    assert all('PAYMENT-SIGNATURE' not in r[3] for r in exchange.calls)
