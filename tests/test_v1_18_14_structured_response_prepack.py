"""Fixed c2 SDK observations using controlled API responses, not a Backend pack.

Oracle: ui-sdk-csv sections 3-4 / api-data section 4 / acceptance SDK01,
AC05/07/10, PC03, CT03. INT01 Backend/mirror remains unverified.
"""
import copy
import hashlib
import json
import os
import pickle
import traceback
from pathlib import Path

import pytest

from ln_church_agent import structured_response_contract as c
from ln_church_agent.structured_response_client import StructuredResponseClient
from ln_church_agent.structured_response_journal import StructuredResponseJournal
from ln_church_agent.structured_response_models import StructuredResponseTask
from ln_church_agent.structured_response_transport import StructuredResponseTransport,StructuredResponseError
from ln_church_agent.immediate_visit_transport import ImmediateVisitRawResponse
from ln_church_agent.task_journal import JournalError

TASK='task_sdk_prepack'
EXEC='exec_'+'a'*32
ADDRESS='0x'+'1'*40
TOKEN='A'*43
DEF='d'*64
TERMS='e'*64
ASSUMPTIONS={'must':'','volume':'','outcome':''}


def item(key='answer_1',kind='text',required=True,**extra):
    bank=json.loads((Path(c.__file__).parent/'contracts'/c.PACK_DIRECTORY/'question-bank.json').read_text())
    fixed=next((x for x in bank['items'] if x['item_id']==key),None)
    if fixed is not None and ('axis' in extra or key in {'category','competitors'}): return copy.deepcopy(fixed)
    for ch in extra.get('choices',[]): ch.setdefault('description','')
    return dict(item_id=key,kind=kind,required=required,allowed_statuses=['answered','unknown','not_disclosed','not_performed'],
        question={'en':'Describe your actual experience.'},quality_condition='Explain the requested judgment.',content_conditions=[],**extra)


def task(items=None):
    terms=dict(task_type=c.TASK_TYPE,task_definition_version='3.0.0',task_definition_digest=DEF,
        title='Controlled SDK question',description='',context_id='ctx_fixed',items=items or [item()],
        participation={'mode':'ANY'},plan_id='C5',capacity_total=5,registration_amount_atomic='1000000',
        reward=dict(normal_amount_atomic='150000',quality_cutoff='0.30',full_reward_boundary='0.70',
            boundary_behavior='REDUCED_AT_EQUAL',compensation_amount_atomic='150000'),
        capacity_profile_id='structured-response-rpah.v1',evaluation_profile_id='structured-response-custom.v1',
        visibility_profile_id='research-after-close.v1')
    return dict(terms,schema_version=c.TASK_SCHEMA_VERSION,task_id=TASK,terms_digest=c.digest(terms),
        capacity_reserved=0,capacity_quality_pending=0,capacity_consumed=0,capacity_compensated=0,
        capacity_available=5,status='OPEN',published_at='2026-10-13T10:00:00.000Z',
        listing_ends_at='2026-10-20T10:00:00.000Z',answer_acceptance_closed_at=None,
        successful_claims_lifetime=0,rewards_paid_confirmed=0,pending_result_count=0,
        manifest_url=c.PUBLIC_API_ORIGIN+'/agent-task-specs/structured_response.v3/3.0.0/manifest.json',
        definition_url=c.PUBLIC_API_ORIGIN+'/agent-task-specs/structured_response.v3/3.0.0/SKILL.md')


def claim(t=None):
    t=t or task()
    return dict(schema_version=c.schema('agent_task_claim_response'),task_id=TASK,task_type=c.TASK_TYPE,
        task_definition_version='3.0.0',task_definition_digest=DEF,terms_digest=t['terms_digest'],
        execution_id=EXEC,reward_address=ADDRESS,claim_token=TOKEN,reward_address_control_verified=False,
        claim_accepted_at='2026-10-13T10:00:00.000Z',report_deadline='2026-10-13T10:10:00.000Z',
        context_id=t['context_id'])


def receipt(report):
    return dict(schema_version=c.schema('task_completion_receipt'),task_id=TASK,execution_id=EXEC,
        submission_id=report['submission_id'],report_sha256=hashlib.sha256(c.canonical_bytes(report)).hexdigest(),
        received_at='2026-10-13T10:01:00.000Z',evaluation_deadline='2026-10-13T10:31:00.000Z',state='accepted')


def status(report):
    accepted=receipt(report);accepted.pop('state')
    return dict(accepted,schema_version=c.schema('task_submission_status'),report=report,context_id=report['context_id'],
        quality={'state':'PENDING','required_values':None,'Q':None},content={'state':'PENDING','items':None},
        analysis_eligible=False,analysis_exclusion_reason='evaluation_pending',
        entitlement={'state':'PENDING','kind':None,'amount_atomic':None},
        payout={'state':'NOT_STARTED','transaction_hash':None,'paid_confirmed_at':None})


def raw(payload,status_code=200,headers=None):
    return ImmediateVisitRawResponse(status_code,headers or {},json.dumps(payload).encode())


def error(code,status_code,**extra):
    return raw(dict(schema_version=c.schema('task_error'),code=code,message='private-message-'+TOKEN,request_id='test',**extra),status_code)


class Venue:
    """In-process controlled exchange; no actual Backend/provider call."""
    def __init__(self,t=None):
        self.task=t or task();self.calls=[];self.report=None;self.fail_posts=0;self.accept_before_loss=False
        self.structural_rejection=False;self.temporary=False

    def __call__(self,method,path,query,headers,body,timeout):
        self.calls.append((method,path,query,dict(headers),body,timeout))
        if path=='/api/agent/tasks':
            return raw(dict(schema_version=c.schema('agent_task_page'),tasks=[self.task],next_cursor=None))
        if path.endswith('/claim'):
            return raw(claim(self.task))
        if path.endswith('/context'):
            return raw(dict(schema_version=c.schema('task_context'),task_id=TASK,execution_id=EXEC,
                context_id='ctx_fixed',context=None,prior=None))
        if path.endswith('/status'):
            return raw(status(self.report)) if self.report else error('not_found',404)
        if path.endswith('/completion'):
            p=json.loads(body)
            if self.structural_rejection:
                return error('invalid_structure',422,field_errors=[{'path':'items.answer_1','code':'invalid_structure'}])
            if self.temporary:
                return error('temporarily_unavailable',503,retry_after_ms=95000)
            if self.fail_posts:
                self.fail_posts-=1
                if self.accept_before_loss:
                    self.report=p
                raise StructuredResponseError('TRANSPORT_ERROR',request_bytes_sent=True)
            self.report=p
            return raw(receipt(p),202)
        if path.endswith('/abandon'):
            return raw(dict(schema_version=c.schema('agent_task_abandon_response'),task_id=TASK,execution_id=EXEC,state='abandoned',abandoned_at='2026-10-13T10:01:00.000Z'))
        return raw(self.task)


@pytest.fixture
def fixture_pack(monkeypatch):
    # Test-only adapter. No contract files/pins are produced by this fixture.
    pack=c.load_contract_pack()
    monkeypatch.setattr(c,'load_contract_pack',lambda:dict(pack,manifest=dict(pack['manifest'],task_definition_digest=DEF)))


def connected(tmp_path,fixture_pack,t=None):
    v=Venue(t);transport=StructuredResponseTransport(exchange=v)
    cli=StructuredResponseClient(transport=transport)
    operation=cli.claim(TASK,'sdk-test',ADDRESS,'claim-key-fixed',journal_directory=tmp_path)
    return cli,operation.journal,v


def answer(key='answer_1',status='answered',value='It meets my stated need.',reason='Relevant evidence.'):
    return dict(item_id=key,status=status,value=value,reason=reason)


def test_discovery_claim_context_prepare_submit_status(tmp_path,fixture_pack):
    v=Venue();cli=StructuredResponseClient(transport=StructuredResponseTransport(exchange=v))
    assert cli.list_tasks().tasks[0].supported
    assert cli.get_task(TASK).items[0]['kind']=='text'
    op=cli.claim(TASK,'sdk-test',ADDRESS,'claim-key-fixed',journal_directory=tmp_path)
    assert cli.get_context(journal=op.journal).context_id=='ctx_fixed'
    count=len(v.calls)
    frozen=cli.prepare_answer(journal=op.journal,shared_assumptions=ASSUMPTIONS,items=[answer()])
    assert len(v.calls)==count
    assert frozen.report['context_id']=='ctx_fixed'
    result=cli.submit(journal=op.journal)
    assert result.state=='accepted'
    s=cli.get_submission_status(journal=op.journal)
    assert s.state=='accepted' and s.quality['state']=='PENDING'
    assert s.entitlement['amount_atomic'] is None and s.payout['state']=='NOT_STARTED'
    assert v.calls[-2][4]==frozen.canonical_bytes
    assert v.calls[-2][3]['Idempotency-Key']==frozen.report['submission_id']


@pytest.mark.parametrize('accepted_before_loss',[False,True])
def test_response_loss_recovery_same_bytes_and_id(tmp_path,fixture_pack,accepted_before_loss):
    cli,j,v=connected(tmp_path,fixture_pack)
    r=cli.prepare_answer(journal=j,shared_assumptions=ASSUMPTIONS,items=[answer()])
    v.fail_posts=1;v.accept_before_loss=accepted_before_loss
    result=cli.submit(journal=j)
    assert result.state=='accepted'
    posts=[call for call in v.calls if call[1].endswith('/completion')]
    assert len(posts)==(1 if accepted_before_loss else 2)
    assert all(x[4]==r.canonical_bytes and x[3]['Idempotency-Key']==r.report['submission_id'] for x in posts)
    old=StructuredResponseJournal.open(tmp_path,j.handle)
    count=len(posts);assert cli.recover_completion(journal=old).state=='accepted'
    assert len([x for x in v.calls if x[1].endswith('/completion')])==count


def test_unknown_recovery_survives_restart_and_never_correction(tmp_path,fixture_pack):
    cli,j,v=connected(tmp_path,fixture_pack)
    r=cli.prepare_answer(journal=j,shared_assumptions=ASSUMPTIONS,items=[answer()])
    v.fail_posts=5
    result=cli.submit(journal=j,max_post_requests=1)
    assert result.state=='unknown'
    loaded=StructuredResponseJournal.open(tmp_path,j.handle)
    with pytest.raises(JournalError):
        cli.prepare_answer(journal=loaded,shared_assumptions=ASSUMPTIONS,items=[answer(value='changed')],correction=True)
    v.fail_posts=0
    before=len(v.calls);assert cli.recover_completion(journal=loaded).state=='accepted'
    assert v.calls[before][1].endswith('/status')
    assert v.calls[before+1][4]==r.canonical_bytes


def test_definite_structural_rejection_permits_explicit_new_id(tmp_path,fixture_pack):
    cli,j,v=connected(tmp_path,fixture_pack)
    first=cli.prepare_answer(journal=j,shared_assumptions=ASSUMPTIONS,items=[answer()])
    v.structural_rejection=True
    assert cli.submit(journal=j).state=='rejected'
    with pytest.raises(JournalError):
        cli.prepare_answer(journal=j,shared_assumptions=ASSUMPTIONS,items=[answer(value='corrected')])
    corrected=cli.prepare_answer(journal=j,shared_assumptions=ASSUMPTIONS,items=[answer(value='corrected')],correction=True)
    assert first.report['submission_id']!=corrected.report['submission_id']
    v.structural_rejection=False;assert cli.submit(journal=j).state=='accepted'
    with pytest.raises(JournalError):
        cli.prepare_answer(journal=j,shared_assumptions=ASSUMPTIONS,items=[answer(value='replacement')],correction=True)


@pytest.mark.parametrize('status_value',['unknown','not_disclosed','not_performed'])
def test_profile_four_required_optional_model_omission(tmp_path,fixture_pack,status_value):
    definitions=[item('profile_'+key,required=key!='model') for key in ('role','activity','tools','authority','model')]
    cli,j,v=connected(tmp_path,fixture_pack,task(definitions))
    answers=[answer(d['item_id'],status_value,None,'Cannot disclose or determine this.') for d in definitions[:4]]
    r=cli.prepare_answer(journal=j,shared_assumptions=ASSUMPTIONS,items=answers)
    assert [i['status'] for i in r.report['items']]==[status_value]*4
    assert len(r.report['items'])==4
    assert cli.submit(journal=j).state=='accepted'


def test_model_unknown_and_omitted_are_different(tmp_path,fixture_pack):
    definitions=[item('profile_role'),item('profile_model',required=False)]
    cli,j,_=connected(tmp_path,fixture_pack,task(definitions))
    r=cli.prepare_answer(journal=j,shared_assumptions=ASSUMPTIONS,items=[answer('profile_role'),answer('profile_model','unknown',None,'Model not provided.')])
    assert r.report['items'][-1]['value'] is None and r.report['items'][-1]['status']=='unknown'


@pytest.mark.parametrize('change',[
    {'status':'unknown','value':'not-null'}, {'status':'not_disclosed','reason':''},
    {'value':1}, {'score':5}, {'q':'1'}, {'p':'1'}, {'status':'unsupported'},
    {'item_id':'unregistered'}, {'reason':'x'*8193}, {'evidence_mode':'executed'},
])
def test_invalid_item_is_local_and_not_accepted(tmp_path,fixture_pack,change):
    cli,j,v=connected(tmp_path,fixture_pack);count=len(v.calls)
    a=answer();a.update(change)
    with pytest.raises((ValueError,StructuredResponseError)):
        cli.prepare_answer(journal=j,shared_assumptions=ASSUMPTIONS,items=[a])
    assert len(v.calls)==count and j.load_report() is None


@pytest.mark.parametrize('entries',[[],[answer(),answer()]])
def test_missing_or_duplicate_item(tmp_path,fixture_pack,entries):
    cli,j,v=connected(tmp_path,fixture_pack)
    with pytest.raises((ValueError,StructuredResponseError)):
        cli.prepare_answer(journal=j,shared_assumptions=ASSUMPTIONS,items=entries)


@pytest.mark.parametrize('patch',[{'task_definition_version':'99.0.0'},{'task_definition_digest':'f'*64},{'task_type':'future_task.v4'},{'schema_version':'ln_church.agent_task.future.v4'}])
def test_unknown_tuple_is_read_only_never_claim(tmp_path,fixture_pack,patch):
    t=task();t.update(patch);v=Venue(t);cli=StructuredResponseClient(transport=StructuredResponseTransport(exchange=v))
    read=cli.get_task(TASK)
    assert read.update_required and not read.supported
    with pytest.raises(StructuredResponseError,match='UNSUPPORTED_TUPLE'):
        cli.claim(TASK,'sdk-test',ADDRESS,'claim-key-fixed',journal_directory=tmp_path)
    assert all(x[0]=='GET' for x in v.calls)


def test_fixed_pack_absent_prevents_mutation(tmp_path,monkeypatch):
    monkeypatch.setattr(c,'PACK_SHA256',{})
    monkeypatch.setattr(c,'PACK_SOURCE',None)
    assert not c.PACK_SHA256 and c.PACK_SOURCE is None
    v=Venue();cli=StructuredResponseClient(transport=StructuredResponseTransport(exchange=v))
    assert not cli.get_task(TASK).supported
    with pytest.raises(StructuredResponseError):
        cli.claim(TASK,'sdk-test',ADDRESS,'same',journal_directory=tmp_path)
    assert all(call[0]=='GET' for call in v.calls)


def test_read_after_expiry_and_token_not_serialized(tmp_path,fixture_pack):
    cli,j,v=connected(tmp_path,fixture_pack)
    cli.prepare_answer(journal=j,shared_assumptions=ASSUMPTIONS,items=[answer()]);cli.submit(journal=j)
    # Read has no client wall-clock Claim deadline gate; server receipt binding persists.
    cli._clock=lambda:99999999999
    s=cli.get_submission_status(journal=StructuredResponseJournal.open(tmp_path,j.handle))
    cred=j.load_claim()
    assert TOKEN not in repr(cred)+cred.model_dump_json()+repr(j)+s.model_dump_json()
    with pytest.raises(TypeError):pickle.dumps(cred)
    if os.name!='nt':assert j.path.stat().st_mode&0o777==0o600


def test_retry_after_beyond_budget_returns_unknown_without_wait(tmp_path,fixture_pack):
    cli,j,v=connected(tmp_path,fixture_pack)
    cli.prepare_answer(journal=j,shared_assumptions=ASSUMPTIONS,items=[answer()])
    v.temporary=True;cli._sleep=lambda delay:pytest.fail('Exceeded finite recovery budget.')
    result=cli.submit(journal=j)
    assert result.state=='unknown' and result.post_requests==1


def test_recovery_bounds(tmp_path,fixture_pack):
    cli,j,v=connected(tmp_path,fixture_pack)
    with pytest.raises(ValueError):cli.submit(journal=j,max_post_requests=4)
    with pytest.raises(ValueError):cli.recover_completion(journal=j,timeout_seconds=91)


def test_same_prepare_preserves_id_and_assumptions(tmp_path,fixture_pack):
    cli,j,v=connected(tmp_path,fixture_pack)
    assumptions=dict(must='Owner allows read-only access',volume='',outcome='')
    a=cli.prepare_answer(journal=j,shared_assumptions=assumptions,items=[answer()])
    b=cli.prepare_answer(journal=j,shared_assumptions=assumptions,items=[answer()])
    assert a.canonical_bytes==b.canonical_bytes and a.report['shared_assumptions']==assumptions


def test_aps_empty_search_vs_not_performed_and_axis5(tmp_path,fixture_pack):
    definitions=[item('a1_3',kind='report',axis=1),item('a5_1',axis=5)]
    cli,j,v=connected(tmp_path,fixture_pack,task(definitions))
    r=cli.prepare_answer(journal=j,shared_assumptions=ASSUMPTIONS,items=[
        dict(answer('a5_1',value='Cannot pay from this environment.'),evidence_mode='specification_review'),
        answer('a1_3',value={'candidates':[],'method':'Searched available sources.'})])
    assert [a['item_id'] for a in r.report['items']]==['a1_3','a5_1']
    assert r.report['items'][0]['status']=='answered'


def test_abandon_is_explicit_and_not_accepted(tmp_path,fixture_pack):
    cli,j,v=connected(tmp_path,fixture_pack)
    assert cli.abandon(journal=j,idempotency_key='abandon-key')['state']=='abandoned'
    with pytest.raises(JournalError):cli.prepare_answer(journal=j,shared_assumptions=ASSUMPTIONS,items=[answer()])


def test_exception_graph_has_no_private_payload(tmp_path,fixture_pack):
    cli,j,v=connected(tmp_path,fixture_pack)
    def poison(*args,**kwargs):raise RuntimeError('private-'+TOKEN)
    cli._transport._exchange=poison
    try:
        cli.get_context(journal=j)
    except Exception as e:
        text=''.join(traceback.format_exception(type(e),e,e.__traceback__))
        assert TOKEN not in text
        assert e.__context__ is None and e.__cause__ is None


def test_mcp_names_and_outputs_no_token():
    from ln_church_agent.integrations.mcp_structured_response import register_tools
    class Registry:
        tools={}
        def tool(self):
            def save(f):self.tools[f.__name__]=f;return f
            return save
    reg=Registry();register_tools(reg)
    assert len(reg.tools)==10
    assert set(reg.tools)=={'structured_response_'+name for name in ('list_tasks','get_task','claim','recover_claim','get_context','prepare_answer','submit','get_submission_status','recover_completion','abandon')}


def test_v21_namespace_is_distinct_and_legacy_packs_remain():
    from ln_church_agent import endpoint_choice_reason_contract as ec
    assert ec.schema('agent_task','v2_1')=='ln_church.agent_task.endpoint_choice_reason.v2_1'
    assert ec.version_of(dict(task_type='endpoint_choice_reason.v2',task_definition_version='2.1.0'))=='v2_1'
    assert ec.load_contract_pack('v1')['manifest']['task_definition_version']=='1.0.0'
    assert ec.load_contract_pack('v2')['manifest']['task_definition_version']=='2.0.0'
    assert ec.load_contract_pack('v2_1')['manifest']['task_definition_digest']=='4d7cb9d024ae41f60898146e4dbcd7ea3be63a33a9e8c0d01696192abe8f1b56'


def test_claim_loss_returns_handle_and_recovers_read_only(tmp_path,fixture_pack):
    v=Venue();original=v.__call__;lost=[False]
    def exchange(method,path,query,headers,body,timeout):
        if path.endswith('/claim') and not lost[0]:
            lost[0]=True
            v.calls.append((method,path,query,dict(headers),body,timeout))
            raise StructuredResponseError('TRANSPORT_ERROR',request_bytes_sent=True)
        return original(method,path,query,headers,body,timeout)
    cli=StructuredResponseClient(transport=StructuredResponseTransport(exchange=exchange))
    with pytest.raises(StructuredResponseError) as raised:
        cli.claim(TASK,'sdk-test',ADDRESS,'original-key',journal_directory=tmp_path)
    assert raised.value.code=='CLAIM_OUTCOME_UNKNOWN' and raised.value.journal_handle
    j=StructuredResponseJournal.open(tmp_path,raised.value.journal_handle)
    assert cli.recover_claim(journal=j).execution_id==EXEC
    claim_calls=[x for x in v.calls if x[1].endswith('/claim')]
    assert claim_calls[0][4]==claim_calls[1][4]
    assert claim_calls[1][3]['Idempotency-Key']=='original-key'
    assert claim_calls[1][3]['X-LN-Claim-Recovery']=='1'


def test_large_v3_body_exceeds_old_limit_and_journal_stays_durable(tmp_path,fixture_pack):
    definitions=[item('entry_'+str(i)) for i in range(22)]
    cli,j,v=connected(tmp_path,fixture_pack,task(definitions))
    entries=[answer(d['item_id'],value='x'*7000) for d in definitions]
    r=cli.prepare_answer(journal=j,shared_assumptions=ASSUMPTIONS,items=entries)
    assert 16384<len(r.canonical_bytes)<=262144
    loaded=StructuredResponseJournal.open(tmp_path,j.handle)
    assert loaded.load_report().canonical_bytes==r.canonical_bytes
    assert cli.submit(journal=loaded).state=='accepted'
    assert v.calls[-1][4]==r.canonical_bytes


@pytest.mark.parametrize('payload',[
    b'{"task_id":"one","task_id":"two"}',b'{"x":NaN}',b'{"x":"\\ud800"}',b'[]',
])
def test_invalid_json_never_exposes_decoder_payload(payload):
    cli=StructuredResponseClient(transport=StructuredResponseTransport(exchange=lambda *a:ImmediateVisitRawResponse(200,{},payload)))
    with pytest.raises(StructuredResponseError,match='RESPONSE_INVALID') as raised:
        cli.get_task(TASK)
    assert raised.value.__context__ is None


@pytest.mark.parametrize('code',[301,302,307,308])
def test_redirects_are_rejected_without_following(code):
    calls=[]
    def redirect(*args):
        calls.append(args);return raw({'redirect':'https://other.example/'},code,{'Location':'https://other.example/'})
    cli=StructuredResponseClient(transport=StructuredResponseTransport(exchange=redirect))
    with pytest.raises(StructuredResponseError):cli.get_task(TASK)
    assert len(calls)==1


def test_wrong_context_is_not_accepted(tmp_path,fixture_pack):
    cli,j,v=connected(tmp_path,fixture_pack)
    cli._transport.get_context=lambda *a,**kw:dict(schema_version=c.schema('task_context'),task_id=TASK,execution_id=EXEC,context_id='ctx_other',context=None,prior=None)
    with pytest.raises(StructuredResponseError,match='RESPONSE_BINDING_INVALID'):cli.get_context(journal=j)


def test_quality_rejection_and_compensation_stay_distinct(tmp_path,fixture_pack):
    cli,j,v=connected(tmp_path,fixture_pack)
    r=cli.prepare_answer(journal=j,shared_assumptions=ASSUMPTIONS,items=[answer()])
    cli.submit(journal=j)
    s=status(r.report)
    s.update(quality={'state':'REJECTED','required_values':['0.3'],'Q':None},
             entitlement={'state':'NONE','kind':'normal','amount_atomic':'0'},analysis_exclusion_reason='quality_rejected')
    cli._transport.get_submission_status=lambda *a,**kw:s
    rejected=cli.get_submission_status(journal=j)
    assert rejected.state=='accepted' and rejected.entitlement['amount_atomic']=='0'
    s.update(quality={'state':'FAILED','required_values':None,'Q':None},
             entitlement={'state':'GRANTED','kind':'compensation','amount_atomic':'150000'},analysis_exclusion_reason='evaluation_failed')
    compensated=cli.get_submission_status(journal=j)
    assert compensated.entitlement['kind']=='compensation' and compensated.payout['state']=='NOT_STARTED'


def test_choice_unknown_namespace_reads_without_old_execution():
    from ln_church_agent.endpoint_choice_reason_client import AgentEndpointChoiceReasonClient
    from ln_church_agent.endpoint_choice_reason_transport import EndpointChoiceTransport
    p=dict(task_id=TASK,task_type='endpoint_choice_reason.v2',task_definition_version='2.1.0',
           schema_version='ln_church.agent_task.endpoint_choice_reason.v2_1',task_definition_digest=DEF)
    cli=AgentEndpointChoiceReasonClient(version='v2',transport=EndpointChoiceTransport(version='v2',exchange=lambda *a:raw(p)))
    value=cli.get_task(TASK)
    assert value.update_required and not value.supported and value.model_dump()['task_definition_version']=='2.1.0'


def test_explicit_mcp_sequence_uses_same_saved_handle(tmp_path,fixture_pack,monkeypatch):
    from ln_church_agent.integrations import mcp_structured_response as m
    v=Venue();transport=StructuredResponseTransport(exchange=v)
    monkeypatch.setattr(m,'StructuredResponseClient',lambda:StructuredResponseClient(transport=transport))
    monkeypatch.setattr(m,'_directory',lambda:tmp_path)
    class Registry:
        tools={}
        def tool(self):
            def save(f):self.tools[f.__name__]=f;return f
            return save
    reg=Registry();m.register_tools(reg);ops=reg.tools
    read=ops['structured_response_get_task'](TASK);assert not read['read_only']
    op=ops['structured_response_claim'](TASK,'sdk-test',ADDRESS,'mcp-key')
    handle=op['journal_handle'];assert handle
    assert ops['structured_response_get_context'](handle)['context_id']=='ctx_fixed'
    count=len(v.calls)
    prepared=ops['structured_response_prepare_answer'](handle,ASSUMPTIONS,[answer()])
    assert prepared['state']=='prepared' and count==len(v.calls)
    assert ops['structured_response_submit'](handle)['state']=='accepted'
    assert ops['structured_response_recover_completion'](handle)['state']=='accepted'
    assert TOKEN not in json.dumps(op)+json.dumps(prepared)
