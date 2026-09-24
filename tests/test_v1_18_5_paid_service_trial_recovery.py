import json
import multiprocessing
import os
import time

import pytest

from test_v1_18_5_paid_service_trial_contract import wire, FakeTaskTransport, report_for, status_for
from test_v1_18_5_paid_service_trial_purchase import lane
from ln_church_agent.paid_service_trial_journal import PaidServiceTrialJournal
from ln_church_agent.paid_service_trial_client import PaidServiceTrialTaskClient
from ln_church_agent.paid_service_trial_transport import PaidServiceTrialTransportError, PaidServiceTrialAPIError
from ln_church_agent.task_journal import JournalError


class Crash(BaseException):pass


def test_crash_after_reservation_recovers_saved_purchase_without_resend(wire,lane,tmp_path,monkeypatch):
    def crash(*a,**k):raise Crash()
    monkeypatch.setattr(lane.http,'fetch',lambda *a,**k:crash() if k.get('payment_signature') else __import__('test_v1_18_5_paid_service_trial_purchase').FakeHTTP.fetch(lane.http,*a,**k))
    with pytest.raises(Crash):lane.executor.execute(wire.credential,journal=lane.journal)
    before=lane.journal.load_report()
    assert lane.journal.snapshot()['paid_dispatch_reserved']
    loaded=PaidServiceTrialJournal.load_claim(tmp_path,wire.claim['task_id'],wire.claim['execution_id'])
    reopened=PaidServiceTrialJournal(tmp_path,loaded)
    monkeypatch.setattr(lane.http,'fetch',crash)
    lane.executor._signer=None
    result=lane.executor.execute(loaded,journal=reopened)
    assert result.report.report_sha256==before.report_sha256
    assert result.report.submission_id==before.submission_id
    assert len(lane.transport.posts)==1


def test_response_loss_status_first_even_after_report_deadline(wire,lane):
    lane.transport.lose_response=True
    result=lane.executor.execute(wire.credential,journal=lane.journal)
    assert lane.transport.events==['POST','GET']
    lane.executor._wall_time=lambda:wire.now+7200
    lane.client.recover_completion(wire.credential,result.report,journal=lane.journal)
    assert lane.transport.events==['POST','GET','GET'] and lane.http.paid==1


def test_three_automatic_attempts_durable_and_explicit_one(wire,lane,tmp_path):
    lane.transport.fail_posts=True
    with pytest.raises(PaidServiceTrialTransportError):lane.executor.execute(wire.credential,journal=lane.journal)
    assert lane.transport.events==['POST','GET','POST','GET','POST','GET']
    assert lane.journal.snapshot()['completion_attempts']==3
    reopened=PaidServiceTrialJournal(tmp_path,wire.credential)
    with pytest.raises(PaidServiceTrialTransportError):lane.executor.execute(wire.credential,journal=reopened)
    assert len(lane.transport.posts)==3
    with pytest.raises(PaidServiceTrialTransportError):lane.client.recover_completion(wire.credential,reopened.load_report(),journal=reopened)
    assert len(lane.transport.posts)==4 and reopened.snapshot()['completion_attempts']==3
    assert lane.http.paid==1


def test_transaction_supplement_same_identity_and_receipt(wire,lane):
    result=lane.executor.execute(wire.credential,journal=lane.journal)
    before=lane.journal.snapshot()
    reply=lane.client.supplement_transaction(wire.credential,result.report,'0x'+'ef'*32,journal=lane.journal)
    assert lane.transport.events==['POST','GET','POST']
    body=json.loads(lane.transport.posts[-1][0])
    assert body['transaction_hash']=='0x'+'ef'*32
    assert body['submission_id']==result.report.submission_id
    assert reply.report_sha256==before['report_sha256']
    assert reply.received_at==before['result']['received_at']
    assert reply.verification_deadline==before['result']['verification_deadline']
    assert lane.http.paid==1


def test_conflict_preserves_first_report_and_locator(wire,lane):
    result=lane.executor.execute(wire.credential,journal=lane.journal)
    before=lane.journal.snapshot();lane.transport.conflict=True
    with pytest.raises(PaidServiceTrialAPIError):
        lane.client.supplement_transaction(wire.credential,result.report,'0x'+'fe'*32,journal=lane.journal)
    after=lane.journal.snapshot()
    assert after['report']==before['report'] and after['transaction_hash']==before['transaction_hash']
    assert after['rejection']=='report_conflict' and lane.http.paid==1


def test_changed_report_does_not_create_new_submission(wire,lane):
    result=lane.executor.execute(wire.credential,journal=lane.journal)
    from ln_church_agent.paid_service_trial_models import FrozenPaidServiceTrialReport
    bad=json.loads(result.report.to_bytes());bad['submission_id']='sub_'+'b'*32
    with pytest.raises(JournalError):lane.client.complete_task(wire.credential,FrozenPaidServiceTrialReport.from_dict(bad),journal=lane.journal)
    assert len(lane.transport.posts)==1


@pytest.mark.parametrize('state',['MISMATCH','PAYMENT_ALREADY_USED','INCONCLUSIVE'])
def test_final_evaluation_cannot_revive_or_repurchase(wire,lane,state):
    from ln_church_agent.paid_service_trial_models import PaidServiceTrialSubmissionStatus
    result=lane.executor.execute(wire.credential,journal=lane.journal)
    final=status_for(result.report)
    final['purchase_verification']['state']=state
    final['purchase_verification']['reason']=None
    final['evaluation'].update(state=state,approved_amount_atomic='0',evaluated_at='2026-09-21T00:00:06.000Z')
    lane.journal.save_result(PaidServiceTrialSubmissionStatus.model_validate(final),result.report)
    with pytest.raises(JournalError):
        lane.journal.save_result(PaidServiceTrialSubmissionStatus.model_validate(status_for(result.report)),result.report)
    replay=lane.executor.execute(wire.credential,journal=lane.journal)
    assert replay.completion.evaluation.state==state and lane.http.paid==1
    assert lane.journal.snapshot()['state']=='FINAL'


@pytest.mark.parametrize('damage',['journal_missing','credential_missing','corrupt','credential_changed'])
def test_missing_corrupt_or_mismatched_history_fails_before_network(wire,lane,tmp_path,damage):
    result=lane.executor.execute(wire.credential,journal=lane.journal)
    if damage=='journal_missing':lane.journal.path.unlink()
    elif damage=='credential_missing':lane.journal.credential_path.unlink()
    elif damage=='corrupt':lane.journal.path.write_text('{}')
    else:
        from ln_church_agent.immediate_visit_journal import _read,_write
        data=_read(lane.journal.credential_path);data['claim_token']='A'*43;_write(lane.journal.credential_path,data)
    with pytest.raises(JournalError):PaidServiceTrialJournal(tmp_path,wire.credential)
    assert lane.http.paid==1


def test_tokens_headers_and_signatures_never_in_ordinary_journal(wire,lane):
    lane.executor.execute(wire.credential,journal=lane.journal)
    text=lane.journal.path.read_text()
    for forbidden in ('claim_token',wire.claim['claim_token'],'signature','PAYMENT-SIGNATURE','product is private'):
        assert forbidden not in text
    assert lane.journal.path.stat().st_mode & 0o777==0o600
    assert lane.journal.credential_path.stat().st_mode & 0o777==0o600


@pytest.mark.skipif(os.name=='nt',reason='Linux Tier 1 cross-process lane')
def test_concurrent_process_one_paid_dispatch(wire,lane,tmp_path):
    ctx=multiprocessing.get_context('fork');entered=ctx.Event();release=ctx.Event();paid=ctx.Value('i',0)
    original=lane.http.fetch
    def fetch(*args,**kwargs):
        if kwargs.get('payment_signature'):
            with paid.get_lock():paid.value+=1
            entered.set();assert release.wait(10)
        return original(*args,**kwargs)
    lane.http.fetch=fetch
    def work():
        try:lane.executor.execute(wire.credential,journal=PaidServiceTrialJournal(tmp_path,wire.credential))
        except JournalError:pass
    first=ctx.Process(target=work);first.start()
    assert entered.wait(10)
    second=ctx.Process(target=work);second.start();second.join(10)
    release.set();first.join(10)
    assert first.exitcode==0 and second.exitcode==0 and paid.value==1


@pytest.mark.skipif(os.name=='nt',reason='Linux Tier 1 abrupt-exit lane')
def test_abrupt_exit_after_fence_cannot_repurchase(wire,lane,tmp_path):
    ctx=multiprocessing.get_context('fork')
    original=lane.http.fetch
    def fetch(*a,**k):
        if k.get('payment_signature'):os._exit(77)
        return original(*a,**k)
    lane.http.fetch=fetch
    child=ctx.Process(target=lambda:lane.executor.execute(wire.credential,journal=lane.journal))
    child.start();child.join(10);assert child.exitcode==77
    lane.http.fetch=lambda *a,**k:pytest.fail('Recovery cannot fetch again')
    lane.executor._signer=None
    result=lane.executor.execute(wire.credential,journal=PaidServiceTrialJournal(tmp_path,wire.credential))
    assert result.state=='REPORTED' and result.http_outcome=='UNKNOWN'


def _post_h_server_status(report, outcome):
    """API §4 / SDK recovery outcomes; not a Backend persistence simulation."""
    saved = status_for(report)
    saved['updated_at'] = '2026-09-21T01:00:06.000Z'
    if outcome == 'APPROVED':
        saved['purchase_verification'].update(state='VERIFIED', reason=None,
                                              verified_at='2026-09-21T01:00:04.999Z')
        saved['evaluation'].update(state='APPROVED', approved_amount_atomic='20000',
                                   evaluated_at='2026-09-21T01:00:06.000Z')
        saved['payout']['state'] = 'pending'
    elif outcome == 'INCONCLUSIVE':
        saved['purchase_verification'].update(state='INCONCLUSIVE', reason='verification_deadline')
        saved['evaluation'].update(state='INCONCLUSIVE', approved_amount_atomic='0',
                                   evaluated_at='2026-09-21T01:00:06.000Z')
    return saved


@pytest.mark.parametrize('scenario,outcome', [
    ('a_before_h_persistence_wins_late_finalize', 'APPROVED'),
    ('V20_saved_witness_ack_loss_backend_crash', 'APPROVED'),
    ('V19_expiry_wins_late_write_rejected', 'INCONCLUSIVE'),
    ('V09_a_equals_h', 'INCONCLUSIVE'),
    ('V09_a_after_h', 'INCONCLUSIVE'),
    ('V22_required_async_prerequisite_reaches_h', 'INCONCLUSIVE'),
    ('V21_crash_loses_unsaved_decision', 'INCONCLUSIVE'),
    ('V23_unknown_write_not_yet_resolved', 'PENDING'),
])
def test_post_h_recovery_consumes_server_result_without_new_purchase(wire,lane,tmp_path,monkeypatch,scenario,outcome):
    import copy
    initial = lane.executor.execute(wire.credential, journal=lane.journal)
    before = lane.journal.snapshot()
    expected = _post_h_server_status(initial.report, outcome)
    calls = []
    def read(task_id, submission_id, token, **kwargs):
        calls.append((task_id, submission_id, token))
        return copy.deepcopy(expected)
    monkeypatch.setattr(lane.transport, 'get_submission_status', read)
    monkeypatch.setattr(lane.http, 'fetch', lambda *a, **k: pytest.fail('Recovery must not fetch or pay'))
    monkeypatch.setattr(lane.guard, 'ready', lambda *a: pytest.fail('Recovery must not read chain RPC'))
    lane.executor._signer = None
    lane.executor._wall_time = lambda: wire.now + 7200
    claim = PaidServiceTrialJournal.load_claim(tmp_path, wire.claim['task_id'], wire.claim['execution_id'])
    reopened = PaidServiceTrialJournal(tmp_path, claim)
    result = lane.client.recover_completion(claim, reopened.load_report(), journal=reopened)
    assert result.model_dump(mode='json') == expected, scenario
    assert calls == [(claim.task_id, initial.report.submission_id, claim._claim_token_value())]
    after = reopened.snapshot()
    for key in ('operation_id','report','report_sha256','payload_digest','completion_attempts','paid_dispatch_reserved','transaction_hash'):
        assert after[key] == before[key]
    assert result.received_at == before['result']['received_at']
    assert result.verification_deadline == before['result']['verification_deadline']
    assert len(lane.transport.posts) == 1 and lane.http.paid == 1
    sent = json.loads(lane.transport.posts[0][0])
    assert set(sent) == {'schema_version','task_id','task_type','task_definition_version',
                         'task_definition_digest','terms_digest','execution_id','submission_id','purchase'}
    replay = lane.executor.execute(claim, journal=reopened)
    assert replay.completion.model_dump(mode='json') == expected
    assert len(calls) == 1
    if outcome == 'APPROVED':
        assert result.purchase_verification.verified_at == '2026-09-21T01:00:04.999Z'
        assert result.evaluation.evaluated_at == '2026-09-21T01:00:06.000Z'
        assert result.payout.confirmed_paid_amount_atomic == '0'
        assert result.payout.paid_confirmed_at is None
    elif outcome == 'INCONCLUSIVE':
        monkeypatch.setattr(lane.transport, 'get_submission_status', lambda *a, **k: _post_h_server_status(initial.report, 'APPROVED'))
        with pytest.raises(JournalError):
            lane.client.recover_completion(claim, reopened.load_report(), journal=reopened)
        assert reopened.snapshot() == after


@pytest.mark.parametrize('eventual', ['APPROVED', 'INCONCLUSIVE'])
def test_unknown_status_after_h_keeps_saved_state_until_server_recovers(wire,lane,tmp_path,monkeypatch,eventual):
    initial = lane.executor.execute(wire.credential, journal=lane.journal)
    before = lane.journal.snapshot()
    lane.executor._wall_time = lambda: wire.now + 7200
    def unavailable(*a, **k):
        raise PaidServiceTrialTransportError('TIMEOUT')
    monkeypatch.setattr(lane.transport, 'get_submission_status', unavailable)
    with pytest.raises(PaidServiceTrialTransportError, match='COMPLETION_OUTCOME_UNKNOWN'):
        lane.client.recover_completion(wire.credential, initial.report, journal=lane.journal)
    assert lane.journal.snapshot() == before
    reopened = PaidServiceTrialJournal(tmp_path, wire.credential)
    monkeypatch.setattr(lane.transport, 'get_submission_status', lambda *a, **k: _post_h_server_status(initial.report, eventual))
    recovered = lane.client.recover_completion(wire.credential, reopened.load_report(), journal=reopened)
    assert recovered.evaluation.state == eventual
    assert recovered.verification_deadline == before['result']['verification_deadline']
    assert reopened.load_report().to_bytes() == initial.report.to_bytes()
    assert reopened.snapshot()['completion_attempts'] == before['completion_attempts']
    assert len(lane.transport.posts) == 1 and lane.http.paid == 1
