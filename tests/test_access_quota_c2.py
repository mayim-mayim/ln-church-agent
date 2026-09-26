"""External c2 outcomes: Charter 563300b0 R4-R6/W3-W6, synthetic HTTP only."""
import json
import pytest
from test_access_quota import FAMILIES, PID, Harness, approved, challenge, status, success, b64
from test_v1_18_5_paid_service_trial_http_v2_contract import wire_v2
from ln_church_agent.access_quota import AccessQuotaError
from ln_church_agent.task_client import AgentTaskClient
from ln_church_agent.task_v2_client import AgentTaskV2Client
from ln_church_agent.immediate_visit_client import AgentImmediateVisitClient
from ln_church_agent.paid_service_trial_client import PaidServiceTrialTaskClient
from ln_church_agent.paid_service_trial_transport import PaidServiceTrialTransportError
from ln_church_agent.task_journal import JournalError


@pytest.mark.parametrize('family', FAMILIES)
@pytest.mark.parametrize('code', ['result_expired', 'result_unavailable'])
def test_public_get_terminal_then_explicit_normal_get(family, code, tmp_path):
    p = approved()
    h = Harness(family, p)
    schemas = {'v17': 'ln_church.agent_task_page.v1',
               'scheduled': 'ln_church.agent_task_page.v1',
               'immediate': 'ln_church.agent_task_page.immediate_visit.v1',
               'paid': 'ln_church.agent_task_page.paid_service_trial.v2'}
    page = dict(schema_version=schemas[family], tasks=[], next_cursor=None)
    normal_remaining = []
    def serve(method, url, headers, body, remaining):
        h.requests.append((method, url, dict(headers), body, remaining))
        if len(h.requests) == 1: return challenge(method, url, headers, body)
        if len(h.requests) == 2:
            assert 'PAYMENT-SIGNATURE' in headers
            raw = status(code, 'PAID', 410)
            return raw[0], success()[1], raw[2]
        assert not {'PAYMENT-SIGNATURE', 'X-LN-Access-Challenge', 'X-LN-Access-Recovery'} & headers.keys()
        # Normal admission consumes an existing credit, not a purchase replay.
        normal_remaining.append(98 - len(normal_remaining))
        return 200, {'X-LN-Access-Quota': b64(dict(version=1, freeRemaining=0,
            paidRemaining=normal_remaining[-1], resetAt='2026-09-26T01:00:00Z'))}, json.dumps(page).encode()
    h.serve = serve
    if family == 'v17': client = AgentTaskClient(_transport=h.transport)
    elif family == 'scheduled': client = AgentTaskV2Client(transport=h.transport)
    elif family == 'immediate': client = AgentImmediateVisitClient(transport=h.transport)
    else: client = PaidServiceTrialTaskClient(transport=h.transport, claim_directory=tmp_path)
    with pytest.raises(AccessQuotaError) as error: client.list_tasks()
    assert error.value.code == 'ACCESS_' + code.upper() and not error.value.origin_not_sent
    assert len(h.requests) == 2  # no hidden latest GET after terminal error
    snapshot = p.snapshot(PID)
    assert snapshot['receipt']['success'] is True and snapshot['quota']['paidRemaining'] == 99
    with pytest.raises(AccessQuotaError): p.finish_failed(PID)
    assert not client.list_tasks().tasks  # explicit new call, same policy and URL
    assert not client.list_tasks().tasks
    assert normal_remaining == [98, 97]
    assert all(r[:2] == h.requests[0][:2] for r in h.requests)
    assert p.spent_atomic == 10000 and p.reserved_atomic == 0
    assert p.signer.calls == 1 and p.snapshot(PID) == snapshot
    count = len(h.requests)
    with pytest.raises(AccessQuotaError):
        with p.read_only(PID): client.list_tasks()
    assert len(h.requests) == count


def test_paid_public_failed_final_explicit_new_purchase_same_request(wire_v2, tmp_path):
    p = approved()
    h = Harness('paid', p)
    new_pid = 'aq_' + '2' * 32
    data = wire_v2.claim
    def serve(method, url, headers, body, remaining):
        h.requests.append((method, url, dict(headers), body, remaining))
        n = len(h.requests)
        assert 'X-LN-Claim-Recovery' not in headers
        if n in (1, 3):
            assert 'PAYMENT-SIGNATURE' not in headers
            return challenge(method, url, headers, body, pid=PID if n == 1 else new_pid)
        if n == 2: return status('failed_final', 'FAILED_FINAL', 409)
        assert n == 4
        result = success(data)
        result[1]['X-LN-Access-Quota'] = b64(dict(version=1, purchaseId=new_pid,
                                               freeRemaining=0, paidRemaining=99))
        return result
    h.serve = serve
    client = PaidServiceTrialTaskClient(transport=h.transport, claim_directory=tmp_path)
    def invoke(agent='synthetic'):
        return client.claim_task(data['task_id'], agent, data['reward_address'], idempotency_key='original-key')
    with pytest.raises(AccessQuotaError) as error: invoke()
    assert error.value.code == 'ACCESS_FAILED_FINAL' and error.value.origin_not_sent
    assert p.spent_atomic == p.reserved_atomic == 0 and p.signer.calls == 1
    with pytest.raises(AccessQuotaError) as error: invoke()
    assert error.value.code == 'ACCESS_FAILED_FINAL' and len(h.requests) == 2
    p.finish_failed(PID)  # explicit selection; no request or signature yet
    assert len(h.requests) == 2 and p.signer.calls == 1
    with pytest.raises(JournalError): invoke('changed-agent')
    assert len(h.requests) == 2
    claim = invoke()
    assert claim.task_id == data['task_id'] and claim.execution_id == data['execution_id']
    assert len(h.requests) == 4 and p.signer.calls == 2
    assert p.spent_atomic == 10000 and p.reserved_atomic == 0
    for r in h.requests:
        assert r[:2] == h.requests[0][:2] and r[3] == h.requests[0][3]
        assert r[2]['Idempotency-Key'] == 'original-key' and r[2]['Content-Type'] == 'application/json'
    assert h.requests[1][2]['PAYMENT-SIGNATURE'] != h.requests[3][2]['PAYMENT-SIGNATURE']
    assert p.snapshot(new_pid)['quota']['paidRemaining'] == 99
    assert invoke().execution_id == claim.execution_id and len(h.requests) == 4
    restored = PaidServiceTrialTaskClient(transport=h.transport, claim_directory=tmp_path)
    assert restored.recover_claim(data['task_id'], idempotency_key='original-key').execution_id == claim.execution_id
    assert len(h.requests) == 4


@pytest.mark.parametrize('paid', [False, True])
def test_paid_public_unresolved_or_paid_cannot_select_replacement(paid, wire_v2, tmp_path):
    p = approved(20000)
    response = status('result_unavailable', 'PAID', 410) if paid else status()
    h = Harness('paid', p, [response, status('failed_final', 'FAILED_FINAL', 409) if paid else status()])
    client = PaidServiceTrialTaskClient(transport=h.transport, claim_directory=tmp_path)
    data = wire_v2.claim
    def invoke():
        return client.claim_task(data['task_id'], 'synthetic', data['reward_address'], idempotency_key='original-key')
    with pytest.raises(AccessQuotaError) as error: invoke()
    assert not error.value.origin_not_sent
    with pytest.raises(AccessQuotaError): p.finish_failed(PID)
    with pytest.raises(AccessQuotaError) as error: invoke()
    assert error.value.code == 'ACCESS_PENDING' and not error.value.origin_not_sent
    with pytest.raises(AccessQuotaError): p.finish_failed(PID)
    assert p.signer.calls == 1 and len(h.requests) == 3
    assert h.requests[1][2]['PAYMENT-SIGNATURE'] == h.requests[2][2]['PAYMENT-SIGNATURE']
    assert (p.spent_atomic, p.reserved_atomic) == ((10000, 0) if paid else (0, 10000))


def test_paid_public_unknown_readonly_miss_never_creates_purchase(wire_v2, tmp_path):
    p = approved()
    h = Harness('paid', p)
    def serve(method, url, headers, body, remaining):
        h.requests.append((method, url, dict(headers), body, remaining))
        if len(h.requests) == 1: raise OSError('synthetic response loss')
        assert headers.get('X-LN-Claim-Recovery') == '1'
        return challenge(method, url, headers, body)  # readonly miss cannot buy
    h.serve = serve
    client = PaidServiceTrialTaskClient(transport=h.transport, claim_directory=tmp_path)
    data = wire_v2.claim
    def invoke():
        return client.claim_task(data['task_id'], 'synthetic', data['reward_address'], idempotency_key='original-key')
    with pytest.raises(PaidServiceTrialTransportError): invoke()
    for _ in range(2):
        with pytest.raises(AccessQuotaError) as error: invoke()
        assert error.value.code == 'ACCESS_PENDING' and not error.value.origin_not_sent
    with pytest.raises(AccessQuotaError): p.finish_failed(PID)
    assert p.signer.calls == p.spent_atomic == p.reserved_atomic == 0 and len(h.requests) == 3
