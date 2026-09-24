"""I21-A: API spec §3 same Claim identity + SDK private persistence boundary."""
import copy
import json
import multiprocessing
import hashlib
from types import SimpleNamespace

import pytest
from test_v1_18_5_paid_service_trial_contract import wire
from test_v1_18_5_paid_service_trial_http_v2_contract import wire_v2
from ln_church_agent import paid_service_trial_contract as c
from ln_church_agent.paid_service_trial_client import PaidServiceTrialTaskClient
from ln_church_agent.paid_service_trial_journal import PaidServiceTrialJournal, _ClaimRequest
from ln_church_agent.paid_service_trial_transport import PaidServiceTrialTransport, PaidServiceTrialRawResponse, PaidServiceTrialTransportError, PaidServiceTrialAPIError
from ln_church_agent.task_journal import JournalError, JournalPersistenceError


class Server:
    def __init__(self,w):
        self.w=w;self.calls=[];self.allocations=0;self.original=None;self.mode='success'
    def exchange(self,method,path,query,headers,body,timeout):
        request=(path,headers['Idempotency-Key'],body)
        self.calls.append(request)
        if self.mode=='not_sent':
            raise PaidServiceTrialTransportError('TIMEOUT',request_bytes_sent=False)
        if self.mode=='reject':
            raise PaidServiceTrialAPIError('capacity_unavailable',status_code=409)
        if self.original is None:self.original=request;self.allocations+=1
        assert request==self.original,'Recovery changed the original request/key'
        if self.mode=='lost':raise PaidServiceTrialTransportError('TIMEOUT',request_bytes_sent=True)
        if self.mode=='uncertain':raise PaidServiceTrialTransportError('TIMEOUT')
        payload=copy.deepcopy(self.w.claim)
        if self.mode=='invalid':payload['unexpected']='SYNTHETIC-PRIVATE'
        return PaidServiceTrialRawResponse(200,{},json.dumps(payload).encode())


@pytest.fixture(params=['v1','v2'])
def claim_case(request,tmp_path,record_property):
    w=request.getfixturevalue('wire' if request.param=='v1' else 'wire_v2')
    server=Server(w);version=request.param
    def client():return PaidServiceTrialTaskClient(version=version,claim_directory=tmp_path,
        transport=PaidServiceTrialTransport(version=version,exchange=server.exchange))
    case=SimpleNamespace(w=w,server=server,client=client,directory=tmp_path,version=version,
        record=_ClaimRequest(tmp_path,version,w.claim['task_id'],'original-key'))
    yield case
    record_property('claim_evidence',json.dumps(dict(version=version,
        api_calls=len(server.calls),new_claims=server.allocations,
        same_request=all(x==server.calls[0] for x in server.calls),
        request_sha256=[hashlib.sha256(x[2]).hexdigest() for x in server.calls],
        state=case.record.read()['state'] if case.record.path.exists() else 'NOT_CREATED',
        live_claims=0,live_payments=0)))


def start(case):
    return case.client().claim_task(case.w.claim['task_id'],'synthetic-agent',case.w.claim['reward_address'],idempotency_key='original-key')


def recover(case):return case.client().recover_claim(case.w.claim['task_id'],idempotency_key='original-key')


def assert_original(case,claim):
    assert claim._private_payload()==case.w.claim
    assert case.record.read()['state']=='READY'
    loaded=PaidServiceTrialJournal.load_claim(case.directory,claim.task_id,claim.execution_id)
    assert loaded._private_payload()==claim._private_payload()
    assert 'claim_token' not in claim.model_dump() and claim._claim_token_value() not in repr(claim)
    journal=PaidServiceTrialJournal(case.directory,claim)
    assert claim._claim_token_value() not in journal.path.read_text()
    assert case.record.path.stat().st_mode & 0o777==0o600
    return journal


def test_success_is_durable_before_return_and_cached_recovery(claim_case):
    case=claim_case;claim=start(case);journal=assert_original(case,claim)
    before=journal.snapshot();assert_original(case,recover(case))
    assert len(case.server.calls)==1 and case.server.allocations==1
    assert journal.snapshot()==before


@pytest.mark.parametrize('mode',['lost','uncertain','invalid'])
def test_unknown_then_same_request_recovers_original(claim_case,mode):
    case=claim_case;case.server.mode=mode
    with pytest.raises(PaidServiceTrialTransportError) as error:start(case)
    assert error.value.code=='CLAIM_OUTCOME_UNKNOWN'
    assert error.value.__context__ is None
    assert case.record.read()['state']=='UNKNOWN' and case.record.read()['claim'] is None
    case.server.mode='success';assert_original(case,recover(case))
    assert len(case.server.calls)==2 and case.server.allocations==1
    assert case.server.calls[0]==case.server.calls[1]


def test_not_sent_then_success_and_unknown_then_not_sent(claim_case):
    case=claim_case;case.server.mode='not_sent'
    with pytest.raises(PaidServiceTrialTransportError) as error:start(case)
    assert error.value.code=='TIMEOUT' and error.value.request_bytes_sent is False
    assert case.record.read()['state']=='NOT_SENT' and case.server.allocations==0
    case.server.mode='lost'
    with pytest.raises(PaidServiceTrialTransportError):recover(case)
    case.server.mode='not_sent'
    with pytest.raises(PaidServiceTrialTransportError) as error:recover(case)
    assert error.value.code=='CLAIM_OUTCOME_UNKNOWN' and case.record.read()['state']=='UNKNOWN'
    case.server.mode='success';assert_original(case,recover(case));assert case.server.allocations==1


def test_definite_rejection_stays_rejected_without_auto_claim(claim_case):
    case=claim_case;case.server.mode='reject'
    for _ in range(2):
        with pytest.raises(PaidServiceTrialAPIError) as error:start(case)
        assert error.value.public_error_code=='capacity_unavailable'
    assert len(case.server.calls)==1 and case.server.allocations==0
    assert case.record.read()['state']=='REJECTED'


@pytest.mark.parametrize('stage',['request','response','credential','ready'])
def test_persistence_failure_never_returns_usable_claim_and_can_resume(claim_case,monkeypatch,stage):
    case=claim_case
    from ln_church_agent import paid_service_trial_journal as j
    original=j._write;failed=[False]
    def write(path,data):
        hit=(stage=='request' and data.get('state')=='NOT_SENT'
             or stage=='response' and data.get('state')=='RECEIVED'
             or stage=='credential' and 'claim_token' in data
             or stage=='ready' and data.get('state')=='READY')
        if hit and not failed[0]:failed[0]=True;raise JournalPersistenceError()
        return original(path,data)
    monkeypatch.setattr(j,'_write',write)
    with pytest.raises(JournalPersistenceError):start(case)
    assert failed[0]
    assert len(case.server.calls)==(0 if stage=='request' else 1)
    monkeypatch.setattr(j,'_write',original)
    claim=start(case) if stage=='request' else recover(case)
    assert_original(case,claim)
    assert case.server.allocations==1
    assert len(case.server.calls)==(2 if stage=='response' else 1)


def test_changed_request_or_missing_state_never_sends(claim_case):
    case=claim_case
    with pytest.raises(JournalError):recover(case)
    assert not case.server.calls
    case.server.mode='lost'
    with pytest.raises(PaidServiceTrialTransportError):start(case)
    with pytest.raises(JournalError):
        case.client().claim_task(case.w.claim['task_id'],'different-agent',case.w.claim['reward_address'],idempotency_key='original-key')
    assert len(case.server.calls)==1


def test_real_process_exit_after_acceptance_keeps_request(claim_case):
    case=claim_case;ctx=multiprocessing.get_context('fork');queue=ctx.Queue()
    def child():
        case.server.mode='lost'
        try:start(case)
        except PaidServiceTrialTransportError as error:queue.put((error.code,case.server.original))
    process=ctx.Process(target=child);process.start();process.join(10)
    assert process.exitcode==0
    code,original=queue.get(timeout=2);assert code=='CLAIM_OUTCOME_UNKNOWN'
    case.server.original=original;case.server.allocations=1
    claim=recover(case);assert_original(case,claim)
    assert case.server.calls==[original] and case.server.allocations==1


def test_ready_history_loss_does_not_recreate_purchase_journal(claim_case):
    case=claim_case;claim=start(case)
    journal=PaidServiceTrialJournal(case.directory,claim);journal.path.unlink()
    with pytest.raises(JournalError):recover(case)
    assert len(case.server.calls)==1 and not journal.path.exists()


from test_v1_18_5_paid_service_trial_accepted_address import address_lane, run_and_check


@pytest.mark.parametrize('expired',[False,True])
def test_unknown_claim_cannot_purchase_then_normal_executor(address_lane,expired):
    lane=address_lane;server=Server(lane.w);server.mode='lost'
    client=PaidServiceTrialTaskClient(version=lane.version,claim_directory=lane.tmp_path,
        transport=PaidServiceTrialTransport(version=lane.version,exchange=server.exchange))
    with pytest.raises(PaidServiceTrialTransportError):
        client.claim_task(lane.w.claim['task_id'],'synthetic-agent',lane.signer.address,idempotency_key='same')
    assert lane.http.paid==0 and lane.http.unpaid==0 and not lane.signer.calls
    server.mode='success'
    claim=client.recover_claim(lane.w.claim['task_id'],idempotency_key='same')
    assert claim._private_payload()==lane.w.claim
    assert server.allocations==1 and len(server.calls)==2
    if expired:
        lane.executor._wall_time=lambda:lane.w.now+601
        result=lane.executor.execute(claim,journal=PaidServiceTrialJournal(lane.tmp_path,claim))
        assert result.state=='NO_DISPATCH' and result.reason=='report_deadline'
        assert lane.http.unpaid==lane.http.paid==0 and not lane.signer.calls
    else:
        run_and_check(lane,'claim-recovered')
