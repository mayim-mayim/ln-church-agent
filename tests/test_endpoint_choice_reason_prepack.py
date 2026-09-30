"""Pre-pack isolated source checks. Synthetic inputs are NOT a normative Hondo pack."""
import base64
import copy
import json
import pickle
import pytest

from ln_church_agent import endpoint_choice_reason_contract as c
from ln_church_agent.endpoint_choice_reason_client import AgentEndpointChoiceReasonClient
from ln_church_agent.endpoint_choice_reason_journal import EndpointChoiceJournal
from ln_church_agent.endpoint_choice_reason_models import EndpointChoiceEvaluation, EndpointChoiceTask, EndpointChoicePublicResults
from ln_church_agent.endpoint_choice_reason_transport import EndpointChoiceTransport, EndpointChoiceError
from ln_church_agent.endpoint_choice_reason_requester import (
    prepare_registration, registration_operation_ref, OfferResultsChallenge, _DOMAIN, _TYPES,
)
from ln_church_agent.immediate_visit_transport import ImmediateVisitRawResponse
from ln_church_agent.task_journal import JournalError

TASK='task_'+'1'*32
EXEC='exec_'+'2'*32
SUB='sub_'+'3'*32
ADDRESS='0x'+'ab'*20
TOKEN='A'*43
DEF='a'*64
REWARD=dict(network='eip155:8453', asset='USDC', asset_address=c.ASSET, correct_amount_atomic='100000',
            incorrect_amount_atomic='10000', full_reward_threshold='0.7', rounding='FLOOR_ATOMIC')

@pytest.fixture
def synthetic_pack(monkeypatch):
    # Solely adapter/model tests: final pack bytes/digest must come from DC.
    monkeypatch.setattr(c,'load_contract_pack',lambda:dict(manifest={'task_definition_digest':DEF}))


def task():
    t=dict(schema_version=c.TASK_SCHEMA_VERSION, task_id=TASK, task_type=c.TASK_TYPE,
           task_definition_version='1.0.0', task_definition_digest=DEF, question='Which one?',
           candidates=[dict(candidate_id='c1',url='https://example.com/a')],reveal_correct_set_after_answer=False,
           evaluation_profile_id=c.PROFILE_ID,reward=REWARD,plan_id='C5',registration_amount_atomic='1000000',
           capacity_total=5,capacity_reserved=0,capacity_consumed=0,capacity_available=5,
           successful_claims_lifetime=None,rewards_paid_confirmed=0,pending_result_count=None,status='OPEN',
           published_at='2026-09-28T00:00:00Z',listing_ends_at='2026-09-30T00:00:00Z',answer_acceptance_closed_at=None,
           definition_url=c.PUBLIC_API_ORIGIN+'/agent-task-specs/endpoint_choice_reason.v1/1.0.0/manifest.json',
           summary_url=c.PUBLIC_API_ORIGIN+'/api/agent/task-offers/'+TASK+'/summary',
           results_url=c.PUBLIC_API_ORIGIN+'/api/agent/tasks/'+TASK+'/results')
    t['terms_digest']=c.digest({k:t[k] for k in c.TERMS_FIELDS})
    return t


def claim():
    t=task()
    fields=['task_id','task_type','task_definition_version','task_definition_digest','terms_digest',
            'question','candidates','reveal_correct_set_after_answer','evaluation_profile_id','reward']
    return dict({k:t[k] for k in fields},schema_version=c.schema('agent_task_claim_response'),execution_id=EXEC,
                claim_token=TOKEN,reward_address=ADDRESS,reward_address_control_verified=False,
                claim_accepted_at='2026-09-28T00:00:00Z',report_deadline='2026-09-28T00:10:00Z')


def receipt(report):
    return dict(schema_version=c.schema('task_completion_receipt'),task_id=TASK,execution_id=EXEC,
                submission_id=SUB,terms_digest=task()['terms_digest'],report_sha256=report.report_sha256,
                receipt_state='accepted',received_at='2026-09-28T00:00:01Z',evaluation_deadline='2026-09-28T00:30:01Z',
                status_url='/api/agent/tasks/'+TASK+'/submissions/'+SUB+'/status')


def status(report):
    r=receipt(report);r.pop('receipt_state');r.pop('status_url');r['schema_version']=c.schema('task_submission_status')
    r.update(selected_candidate_id='c1',answer_reason=report.report.answer_reason,
             evaluation=dict(state='PENDING',is_correct=None,q=None,applied_coefficient=None,reward_basis=None,
                             base_amount_atomic=None,approved_amount_atomic=None,evaluated_at=None),
             payout=dict(state='not_applicable',transaction_hash=None,transaction_url=None,confirmed_paid_amount_atomic=None,paid_confirmed_at=None),
             correct_candidate_ids=None,updated_at='2026-09-28T00:00:02Z')
    return r


def raw(value, code=200):
    return ImmediateVisitRawResponse(code,{'Content-Type':'application/json'},json.dumps(value).encode())


def error(code, status=400):
    return raw(dict(schema_version=c.schema('task_error'),code=code,message='private-body-must-not-leak',request_id='r'),status)


def journal(tmp_path):
    tmp_path.chmod(0o700)
    return EndpointChoiceJournal(tmp_path,task_id=TASK,agent_id='test',reward_address=ADDRESS.upper().replace('0X','0x'),idempotency_key='same-claim-key')


class Exchange:
    def __init__(self,responses):self.responses=iter(responses);self.calls=[]
    def __call__(self,*args,**kwargs):
        self.calls.append(args)
        result=next(self.responses)
        if isinstance(result,Exception):raise result
        return result


def client(ex):return AgentEndpointChoiceReasonClient(transport=EndpointChoiceTransport(exchange=ex))


def setup_answer(tmp_path):
    j=journal(tmp_path);j.save_claim(claim())
    cli=client(Exchange([]))
    report=cli.prepare_answer(journal=j,selected_candidate_id='c1',answer_reason='  My reason\r\nそのまま  ',submission_id=SUB)
    return j,report


def test_missing_fixed_pack_stops_before_claim_network(tmp_path, monkeypatch):
    monkeypatch.setattr(c, "PACK_SHA256", {})
    ex=Exchange([]);j=journal(tmp_path)
    with pytest.raises(ValueError):client(ex).claim_task(journal=j)
    assert ex.calls==[] and j.claim_request()[3] is False


def test_discovery_detail_terms_null_stats(synthetic_pack):
    ex=Exchange([raw(dict(schema_version=c.schema('agent_task_page'),tasks=[task()],next_cursor='opaque/+=')),raw(task())])
    cli=client(ex);page=cli.list_tasks(limit=1);value=cli.get_task(TASK)
    assert value.successful_claims_lifetime is None and value.rewards_paid_confirmed==0
    assert 'task_type=endpoint_choice_reason.v1' in ex.calls[0][2]
    assert len(page.tasks)==1
    bad=task();bad['question']='substituted'
    with pytest.raises(ValueError):EndpointChoiceTask.model_validate(bad)


def test_durable_claim_before_dispatch_and_restart_recovery(tmp_path,synthetic_pack):
    j=journal(tmp_path)
    def lost(*args):
        assert j.claim_request()[3] is True
        raise EndpointChoiceError('TIMEOUT',request_bytes_sent=True)
    with pytest.raises(EndpointChoiceError,match='CLAIM_OUTCOME_UNKNOWN'):
        client(lost).claim_task(journal=j)
    reopened=journal(tmp_path);ex=Exchange([raw(claim())])
    saved=client(ex).claim_task(journal=reopened)
    assert ex.calls[0][3]['X-LN-Claim-Recovery']=='1'
    assert ex.calls[0][3]['Idempotency-Key']=='same-claim-key'
    assert TOKEN not in repr(saved) and TOKEN not in json.dumps(saved.model_dump())
    assert reopened.load_claim().execution_id==EXEC
    with pytest.raises(TypeError):pickle.dumps(saved)


def test_changed_claim_body_same_key_rejected_before_network(tmp_path,synthetic_pack):
    journal(tmp_path)
    with pytest.raises(JournalError):
        EndpointChoiceJournal(tmp_path,task_id=TASK,agent_id='other',reward_address=ADDRESS,idempotency_key='same-claim-key')


def test_answer_saved_exactly_before_post_and_receipt_not_reward(tmp_path,synthetic_pack):
    j,r=setup_answer(tmp_path)
    def exchange(*args):
        assert j.completion_started() and j.load_report().canonical_bytes==args[4]
        return raw(receipt(r),202)
    result=client(exchange).complete_task(journal=j)
    assert result.state=='accepted' and result.status is None
    assert r.report.answer_reason=='  My reason\r\nそのまま  '


def test_unknown_then_restart_is_status_first_and_preserves_body(tmp_path,synthetic_pack):
    j,r=setup_answer(tmp_path)
    ex=Exchange([EndpointChoiceError('TIMEOUT',request_bytes_sent=True),error('not_found',404)])
    result=client(ex).complete_task(journal=j,max_post_requests=1)
    assert result.state=='unknown' and [x[0] for x in ex.calls]==['POST','GET']
    with pytest.raises(JournalError):client(Exchange([])).prepare_answer(journal=j,selected_candidate_id='c1',answer_reason='changed',correction=True)
    reopened=journal(tmp_path)
    ex2=Exchange([error('not_found',404),raw(receipt(r))])
    result=client(ex2).recover_completion(journal=reopened)
    assert result.state=='accepted' and [x[0] for x in ex2.calls]==['GET','POST']
    assert ex.calls[0][4]==ex2.calls[1][4]
    assert ex.calls[0][3]['Idempotency-Key']==ex2.calls[1][3]['Idempotency-Key']==SUB


def test_definite_first_form_rejection_allows_explicit_correction(tmp_path,synthetic_pack):
    j,r=setup_answer(tmp_path)
    result=client(Exchange([error('invalid_request')])).complete_task(journal=j)
    assert result.state=='rejected'
    new=client(Exchange([])).prepare_answer(journal=j,selected_candidate_id='c1',answer_reason='Revised',correction=True)
    assert new.report.answer_reason=='Revised'


def test_later_rejection_never_clears_unknown(tmp_path,synthetic_pack):
    j,r=setup_answer(tmp_path)
    ex=Exchange([EndpointChoiceError('TIMEOUT',request_bytes_sent=True),error('not_found',404),error('invalid_request')])
    result=client(ex).complete_task(journal=j)
    assert result.state=='unknown'
    with pytest.raises(JournalError):client(Exchange([])).prepare_answer(journal=j,selected_candidate_id='c1',answer_reason='new',correction=True)


def test_private_status_after_deadline_no_purchase_or_answer_leak(tmp_path,synthetic_pack):
    j,r=setup_answer(tmp_path);ex=Exchange([raw(status(r))])
    value=client(ex).get_submission_status(journal=j)
    assert value.evaluation.q is None and value.answer_reason==r.report.answer_reason
    assert 'answer_reason' not in value.model_dump()
    assert ex.calls[0][0]=='GET' and ex.calls[0][3]['X-LN-Task-Claim-Token']==TOKEN
    assert TOKEN not in ex.calls[0][1] and 'Payment-Signature' not in ex.calls[0][3]


@pytest.mark.parametrize('q,coef,basis,amount',[('0','0','SCORE_PROPORTIONAL','0'),('0.69','0.69','SCORE_PROPORTIONAL','69000'),
    ('0.69999999999999999','0.69999999999999999','SCORE_PROPORTIONAL','69999'),('0.7','1','FULL_REWARD_LINE','100000')])
def test_lossless_score_and_server_amount(q,coef,basis,amount):
    value=EndpointChoiceEvaluation(state='GRADED',is_correct=True,q=q,applied_coefficient=coef,
        reward_basis=basis,base_amount_atomic='100000',approved_amount_atomic=amount,evaluated_at='2026-09-28T00:01:00Z')
    assert value.q==q and value.approved_amount_atomic==amount


@pytest.mark.parametrize('q',[0,False,'NaN','0.70','1e-1','1.1',None])
def test_invalid_score_is_not_zero(q):
    with pytest.raises(ValueError):EndpointChoiceEvaluation(state='GRADED',is_correct=True,q=q,applied_coefficient='1',reward_basis='FULL_REWARD_LINE',base_amount_atomic='100000',approved_amount_atomic='100000',evaluated_at='2026-09-28T00:01:00Z')


def registration():
    return dict(task_type=c.TASK_TYPE,plan_id='C5',question='Choose',candidates=[dict(candidate_id='x',url='https://example.com/a',evaluator_description='Private context')],correct_candidate_ids=['x'],reveal_correct_set_after_answer=False)


def test_registration_private_input_and_single_all_correct():
    value=prepare_registration(registration())
    assert value._private_payload()['correct_candidate_ids']==['x']
    assert 'Private context' not in repr(value)
    with pytest.raises(TypeError):pickle.dumps(value)


@pytest.mark.parametrize('change',[{'correct_candidate_ids':[]},{'correct_candidate_ids':['unknown']},{'repeat_policy':'allow'},{'question':' '}, {'reveal_correct_set_after_answer':1}])
def test_registration_invalid_before_fee(change):
    with pytest.raises(ValueError):prepare_registration(dict(registration(),**change))


def test_duplicate_keys_and_invalid_unicode():
    with pytest.raises(ValueError):prepare_registration(b'{"task_type":"x","task_type":"y"}')
    with pytest.raises(ValueError):prepare_registration(dict(registration(),question='\ud800'))


def challenge():
    return dict(schema_version='ln_church.offer_results_challenge.v1',challenge_token='opaque-server-token',typed_data=dict(
        domain=copy.deepcopy(_DOMAIN),types=copy.deepcopy(_TYPES),primaryType='OfferResultsRead',message=dict(
        audience=c.PUBLIC_API_ORIGIN+'/api/agent/task-offer-results/read',action='read_offer_results',taskId=TASK,
        payer=ADDRESS,nonce='0x'+'1'*64,issuedAt='1000',expiresAt='1300')))


def test_explicit_proof_memory_only_and_page_reuse():
    value=OfferResultsChallenge(challenge(),task_id=TASK,payer=ADDRESS,now=1001)
    signed=[]
    proof=value.sign(lambda data:signed.append(data) or '0x1234',now=1002)
    one=json.loads(proof._read_body(20,None,1003));two=json.loads(proof._read_body(20,'page2',1004))
    assert one['typed_data']==two['typed_data'] and len(signed)==1
    assert '0x1234' not in repr(proof) and 'opaque-server-token' not in repr(value)
    with pytest.raises(TypeError):pickle.dumps(proof)
    with pytest.raises(ValueError):proof._read_body(20,None,1300)


@pytest.mark.parametrize('key,value',[('action','read_registration_result'),('taskId','other'),('payer','0x'+'c'*40),('expiresAt','1301')])
def test_wrong_proof_scope_rejected_before_signing(key,value):
    payload=challenge();payload['typed_data']['message'][key]=value
    with pytest.raises(ValueError):OfferResultsChallenge(payload,task_id=TASK,payer=ADDRESS,now=1001)


def test_registration_reference_from_original_nonce_is_stable():
    p=dict(x402Version=2,accepted=dict(network='eip155:8453',asset=c.ASSET),payload=dict(authorization=dict(from_=ADDRESS,nonce='0x'+'A'*64)))
    p['payload']['authorization']['from']=p['payload']['authorization'].pop('from_')
    header=base64.b64encode(json.dumps(p).encode()).decode()
    a=registration_operation_ref(header)
    p['payload']['authorization']['nonce']='0x'+'a'*64
    assert registration_operation_ref(base64.b64encode(json.dumps(p).encode()).decode())==a
    assert len(a)==36 and a[14]=='4' and a[19]=='8'
def test_url_normalization_preserves_immediate_query_rules():
    from ln_church_agent.endpoint_choice_reason_contract import prepare_url
    assert prepare_url('https://EXAMPLE.com:443') == 'https://example.com/'
    assert prepare_url('https://example.com/?token=public-label') == 'https://example.com/?token=public-label'
