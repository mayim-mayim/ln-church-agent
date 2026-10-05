"""Audited L7/PNC vectors on isolated SDK adapters, NOT producer pack proof."""
import copy
import json
from decimal import Decimal
from types import SimpleNamespace
import pytest
from test_v1_18_5_paid_service_trial_http_v2_contract import wire_v2
from test_v1_18_5_paid_service_trial_http_v2_purchase import V2HTTP, terms_response
from test_v1_18_5_paid_service_trial_contract import receipt_for, status_for
from ln_church_agent import paid_service_trial_contract as c
from ln_church_agent.paid_service_trial_models import model_for, parse_claim, FrozenPaidServiceTrialReport
from ln_church_agent.paid_service_trial_transport import PaidServiceTrialTransport, PaidServiceTrialRawResponse
from ln_church_agent.paid_service_trial_client import PaidServiceTrialTaskClient
from ln_church_agent.paid_service_trial import PaidServiceTrialExecutor, export_purchase_import_descriptor
from ln_church_agent.paid_service_trial_journal import PaidServiceTrialJournal
from ln_church_agent.models import PaymentPolicy


def new_wire(old, method='POST', amount='100000'):
    wire=copy.copy(old);wire.terms=copy.deepcopy(old.terms)
    wire.terms['requirements']['amount']=amount
    wire.request=c.prepare_request(dict(method=method,url=old.request['url'],body='{"x":1}' if method=='POST' else None))
    wire.task=copy.deepcopy(old.task)
    wire.task.update(schema_version='ln_church.agent_task.paid_service_trial.v3',task_type='paid_service_trial.v3',
        task_definition_version='3.0.0',request=wire.request,request_digest=c.v2_digest(wire.request),
        purchase_terms=wire.terms,purchase_terms_digest=c.purchase_terms_digest(wire.request,wire.terms,'v3'),
        listing_ends_at='2026-09-28T00:00:00.000Z',
        definition_url=c.PUBLIC_API_ORIGIN+'/agent-task-specs/paid_service_trial.v3/3.0.0/manifest.json')
    terms={k:wire.task[k] for k in ('request','request_digest','purchase_terms_digest','purchase_terms','plan_id',
        'registration_amount_atomic','capacity_total','repeat_policy','reward')}
    wire.task['terms_digest']=c.v2_digest(terms)
    wire.claim=copy.deepcopy(old.claim)
    wire.claim.update({k:wire.task[k] for k in ('task_type','task_definition_version','request','request_digest',
        'purchase_terms','purchase_terms_digest','terms_digest')})
    wire.claim['schema_version']='ln_church.agent_task_claim_response.paid_service_trial.v3'
    wire.credential=parse_claim(wire.claim)
    return wire


class Venue:
    def __init__(self, wire):
        self.wire=wire;self.calls=[];self.report=None;self.lose_response=False
    def __call__(self,method,path,query,headers,body,timeout):
        self.calls.append((method,path,query,body))
        if path=='/api/agent/tasks':
            assert 'task_type=paid_service_trial.v3' in query
            value=dict(schema_version='ln_church.agent_task_page.paid_service_trial.v3',tasks=[self.wire.task],next_cursor=None)
        elif path.endswith('/claim'):
            assert json.loads(body)['schema_version']=='ln_church.agent_task_claim_request.v1'
            value=self.wire.claim
        elif path.endswith('/status'):
            value=status_for(self.report);value['schema_version']='ln_church.task_submission_status.paid_service_trial.v3'
        elif method=='POST':
            self.report=FrozenPaidServiceTrialReport(body)
            self.report.model.require_claim(self.wire.credential)
            if self.lose_response:raise TimeoutError()
            value=receipt_for(self.report);value['schema_version']='ln_church.task_completion_receipt.paid_service_trial.v3'
        else:value=self.wire.task
        return PaidServiceTrialRawResponse(200,{},json.dumps(value).encode())


def lane(wire,tmp_path,policy=None):
    tmp_path.chmod(0o700);venue=Venue(wire)
    client=PaidServiceTrialTaskClient(version='v3',transport=PaidServiceTrialTransport(version='v3',exchange=venue),claim_directory=tmp_path)
    http=V2HTTP(wire)
    executor=PaidServiceTrialExecutor(signer=wire.signer,policy=policy or PaymentPolicy(),client=client,
        http=http,block_guard=SimpleNamespace(ready=lambda _:True),wall_time=lambda:wire.now)
    return SimpleNamespace(venue=venue,client=client,http=http,executor=executor,journal=PaidServiceTrialJournal(tmp_path,wire.credential))


@pytest.mark.parametrize('method',['GET','POST'])
def test_pnc03_client_purchase_unknown_read(wire_v2,tmp_path,method):
    w=new_wire(wire_v2,method);x=lane(w,tmp_path)
    assert x.client.list_tasks().tasks[0].listing_ends_at==w.task['listing_ends_at']
    assert x.client.get_task(w.task['task_id']).task_type=='paid_service_trial.v3'
    claim=x.client.claim_task(w.task['task_id'],'agent',w.signer.address,idempotency_key='same-key')
    x.venue.lose_response=True
    result=x.executor.execute(claim,journal=x.journal)
    assert result.state=='REPORTED' and x.http.paid==1
    assert x.http.authorization['value']==result.report.model.purchase.amount=='100000'
    before=x.journal.snapshot()
    assert before['schema_version']=='ln_church.paid_service_trial_journal.v3'
    assert before['claim']['request']['schema_version']=='ln_church.paid_service_request.v2'
    recovered=PaidServiceTrialJournal.load_claim(tmp_path,claim.task_id,claim.execution_id)
    x.executor._signer=None
    x.executor.execute(recovered,journal=PaidServiceTrialJournal(tmp_path,recovered))
    assert (x.http.paid,x.http.unpaid)==(1,2)
    assert x.journal.snapshot()['operation_id']==before['operation_id']
    assert sum(method=='GET' and path.endswith('/status') for method,path,_,_ in x.venue.calls)==1
    assert x.executor._policy._budget_total('reserved')==Decimal('.1')


@pytest.mark.parametrize('value',['1','10000','10001','20000','20001','100000',str(2**256-1)])
def test_pnc01_lossless_amounts(wire_v2,value):
    w=new_wire(wire_v2,amount=value)
    assert model_for('task','v3').model_validate(w.task).purchase_terms.requirements.amount==value
    assert w.credential.reward.amount_atomic=='20000'
    if int(value)>10000:
        with pytest.raises(ValueError):c.amount(value)


@pytest.mark.parametrize('value',['0','-1','01','+1','1.0','1e5',' 1',1,True,None,str(2**256)])
def test_pnc02_invalid_amounts(wire_v2,value):
    with pytest.raises(ValueError):new_wire(wire_v2,amount=value)


@pytest.mark.parametrize('denial',['tx','session','reserved','permission','signer'])
def test_pnc05_denied_before_sign(wire_v2,tmp_path,denial):
    w=new_wire(wire_v2);p=PaymentPolicy(max_spend_per_tx_usd=.1,max_spend_per_session_usd=.1);x=lane(w,tmp_path,p)
    if denial=='tx':p.max_spend_per_tx_usd=.01
    if denial=='session':p.max_spend_per_session_usd=.01
    if denial=='reserved':x.executor._reserve_policy(w.credential,'another-operation')
    if denial=='permission':p.allowed_schemes=[]
    class NoSigner:
        address=w.signer.address
        def generate_eip3009_payload_atomic(self,*a,**k):pytest.fail('Denied purchase reached signer')
    x.executor._signer=None if denial=='signer' else NoSigner()
    with pytest.raises(ValueError):x.executor.execute(w.credential,journal=x.journal)
    assert x.http.paid==0 and x.journal.snapshot()['report'] is None


def test_pnc05_equal_budget_pnc06_defaults(wire_v2,tmp_path):
    p=PaymentPolicy();assert (p.max_spend_per_tx_usd,p.max_spend_per_session_usd)==(5.,10.)
    x=lane(new_wire(wire_v2),tmp_path,PaymentPolicy(max_spend_per_tx_usd=.1,max_spend_per_session_usd=.1))
    x.executor.execute(x.http.wire.credential,journal=x.journal)
    assert x.http.paid==1 and x.executor._policy._budget_total('reserved')==Decimal('.1')


@pytest.mark.parametrize('field,value',[('amount','10000'),('payTo','0x'+'34'*20),('asset','0x'+'34'*20),('network','eip155:1')])
def test_pnc04_mismatch_before_sign(wire_v2,tmp_path,field,value):
    from ln_church_agent.paid_service_trial_network import PaidServiceTrialTermsError
    w=new_wire(wire_v2);x=lane(w,tmp_path);bad=copy.deepcopy(w.terms['requirements']);bad[field]=value
    x.http.fetch=lambda *a,**k:terms_response(w,conditions=[bad])
    class NoSigner:
        address=w.signer.address
        def generate_eip3009_payload_atomic(self,*a,**k):pytest.fail('Mismatch reached signer')
    x.executor._signer=NoSigner()
    with pytest.raises(PaidServiceTrialTermsError):x.executor.execute(w.credential,journal=x.journal)
    assert x.journal.snapshot()['report'] is None


@pytest.mark.parametrize('patch',[{'task_type':'paid_service_trial.v2'},{'task_definition_version':'2.0.0'},
    {'schema_version':'ln_church.agent_task_claim_response.paid_service_trial.v2'},
    {'purchase_terms_digest':'f'*64},{'request_digest':'f'*64}])
def test_cmp02_mixed_claim(wire_v2,patch):
    w=new_wire(wire_v2)
    with pytest.raises(ValueError):parse_claim(dict(w.claim,**patch))


def test_import_descriptor(wire_v2):
    w=new_wire(wire_v2);result=export_purchase_import_descriptor(w.request,'0x'+'ab'*32,w.terms,version='v3')
    assert result['schema_version']=='ln_church.paid_service_trial_sample_import_request.v3'
    assert result['request']['schema_version']=='ln_church.paid_service_request.v2'
    assert result['purchase_terms_digest']==w.claim['purchase_terms_digest']


def test_missing_producer_packs_fail_closed(monkeypatch):
    from ln_church_agent import immediate_visit_versions as iv,endpoint_choice_reason_contract as ec
    monkeypatch.setattr(c, 'V3_PACK_SHA256', {})
    monkeypatch.setattr(iv, 'V3_PACK_SHA256', {})
    monkeypatch.setattr(ec, 'V2_PACK_SHA256', {})
    for call in (lambda:c.load_contract_bundle('v3'),lambda:iv.load_pack('v3'),lambda:ec.load_contract_pack('v2')):
        with pytest.raises(ValueError,match='has not been received'):call()


def immediate_v3(value):
    value=copy.deepcopy(value)
    # Only family-owned fields; shared request/descriptor fields stay untouched.
    for key in ('schema_version','task_type','profile_id'):
        if key in value:value[key]=value[key].rsplit('.',1)[0]+'.v3'
    if 'definition_version' in value:value['definition_version']='3.0.0'
    if 'published_at' in value:
        from datetime import datetime,timedelta
        stamp=datetime.fromisoformat(value['published_at'].replace('Z','+00:00'))+timedelta(hours=168)
        value['listing_ends_at']=stamp.isoformat(timespec='milliseconds').replace('+00:00','Z')
        value['definition_url']=c.PUBLIC_API_ORIGIN+'/agent-task-specs/immediate_http_visit.v3/3.0.0/SKILL.md'
    return value


def test_instant_v3_page_claim_saved_report(tmp_path,monkeypatch):
    from test_v1_18_3_immediate_visit_contract import task_wire,claim_wire,report_wire,TASK,ADDRESS,ENDPOINT
    from test_v1_18_3_immediate_visit_client import Exchange,raw
    from ln_church_agent.immediate_visit_models import ImmediateVisitTaskPage,FrozenImmediateVisitReport
    from ln_church_agent.immediate_visit_client import AgentImmediateVisitClient
    from ln_church_agent.immediate_visit_transport import ImmediateVisitTransport
    from ln_church_agent.immediate_visit_journal import ImmediateVisitJournal
    from ln_church_agent.immediate_visit import ImmediateVisitExecutor
    from ln_church_agent import immediate_visit_versions as iv
    monkeypatch.setattr(iv,'load_pack',lambda version:{'profile.json':json.dumps(dict(profile_id='immediate_visit_utf8.v3',task_type='immediate_http_visit.v3',request_headers={'Accept':'*/*','Accept-Encoding':'identity'},user_agents={'agent':'ExternalAgent-via-LNChurch/1.0','reference':'LNChurch-Reference/1.0'})).encode()})
    page=dict(schema_version='ln_church.agent_task_page.immediate_visit.v3',tasks=[immediate_v3(task_wire())],next_cursor=None)
    ex=Exchange([raw(page),raw(immediate_v3(claim_wire()))])
    client=AgentImmediateVisitClient(version='v3',transport=ImmediateVisitTransport(version='v3',exchange=ex))
    assert client.list_tasks().tasks[0].definition_version=='3.0.0'
    claim=client.claim_task(TASK,'agent',ADDRESS,idempotency_key='key')
    assert json.loads(ex.requests[1][4])['schema_version']=='ln_church.agent_task_claim_request.immediate_visit.v3'
    tmp_path.chmod(0o700);journal=ImmediateVisitJournal(tmp_path,claim)
    report=FrozenImmediateVisitReport.from_report(immediate_v3(report_wire()))
    journal.prepare_report(claim,report)
    monkeypatch.setattr(ImmediateVisitExecutor,'_fetch',lambda *a,**k:pytest.fail('Recovery refetched target'))
    recovered=ImmediateVisitJournal.load_claim(tmp_path,TASK,claim.execution_id)
    assert ImmediateVisitExecutor(journal=ImmediateVisitJournal(tmp_path,recovered)).execute(recovered,ENDPOINT).canonical_bytes==report.canonical_bytes
    from ln_church_agent.immediate_visit_journal import _read
    assert _read(journal.path)['schema_version']=='ln_church.immediate_visit_journal.v3'
    mixed=copy.deepcopy(page);mixed['tasks'][0]['profile_id']='immediate_visit_utf8.v2'
    with pytest.raises(ValueError):ImmediateVisitTaskPage.model_validate(mixed)
    mixed=copy.deepcopy(page);mixed['tasks'][0]['listing_ends_at']=task_wire()['listing_ends_at']
    with pytest.raises(ValueError):ImmediateVisitTaskPage.model_validate(mixed)


def test_choice_v2_client_answer_read_recovery(tmp_path,monkeypatch):
    from test_endpoint_choice_reason_prepack import task,claim,receipt,status,raw,TASK,ADDRESS,SUB,DEF
    from ln_church_agent import endpoint_choice_reason_contract as ec
    from ln_church_agent.endpoint_choice_reason_models import EndpointChoiceTaskPage,FrozenEndpointChoiceReport
    from ln_church_agent.endpoint_choice_reason_client import AgentEndpointChoiceReasonClient
    from ln_church_agent.endpoint_choice_reason_transport import EndpointChoiceTransport
    from ln_church_agent.endpoint_choice_reason_journal import EndpointChoiceJournal
    from ln_church_agent.immediate_visit_journal import _read
    monkeypatch.setattr(ec,'load_contract_pack',lambda version='v1':dict(manifest={'task_definition_digest':DEF}))
    task2=task();task2.update(schema_version=ec.schema('agent_task','v2'),task_type='endpoint_choice_reason.v2',
        task_definition_version='2.0.0',listing_ends_at='2026-10-05T00:00:00Z',
        definition_url=ec.PUBLIC_API_ORIGIN+'/agent-task-specs/endpoint_choice_reason.v2/2.0.0/SKILL.md')
    task2['terms_digest']=ec.digest({k:task2[k] for k in ec.TERMS_FIELDS})
    claim2=claim();claim2.update(schema_version=ec.schema('agent_task_claim_response','v2'),task_type=task2['task_type'],
        task_definition_version='2.0.0',terms_digest=task2['terms_digest'])
    calls=[];reports=[]
    def exchange(method,path,query,headers,body,timeout):
        calls.append((method,path,body))
        if path=='/api/agent/tasks':
            assert 'task_type=endpoint_choice_reason.v2' in query
            value=dict(schema_version=ec.schema('agent_task_page','v2'),tasks=[task2],next_cursor=None)
        elif path.endswith('/claim'):
            assert json.loads(body)['schema_version']=='ln_church.agent_task_claim_request.v1'
            value=claim2
        elif path.endswith('/status'):
            value=status(reports[-1]);value.update(schema_version=ec.schema('task_submission_status','v2'),terms_digest=task2['terms_digest'])
        else:
            reports.append(FrozenEndpointChoiceReport(body));value=receipt(reports[-1])
            value.update(schema_version=ec.schema('task_completion_receipt','v2'),terms_digest=task2['terms_digest'])
        return raw(value)
    client=AgentEndpointChoiceReasonClient(version='v2',transport=EndpointChoiceTransport(version='v2',exchange=exchange))
    assert client.list_tasks().tasks[0].listing_ends_at==task2['listing_ends_at']
    tmp_path.chmod(0o700)
    kwargs=dict(task_id=TASK,agent_id='agent',reward_address=ADDRESS,idempotency_key='same',version='v2')
    journal=EndpointChoiceJournal(tmp_path,**kwargs)
    client.claim_task(journal=journal)
    client.prepare_answer(journal=journal,selected_candidate_id='c1',answer_reason='Reason specific to the question.',submission_id=SUB)
    assert client.complete_task(journal=journal).state=='accepted'
    assert client.recover_completion(journal=EndpointChoiceJournal(tmp_path,**kwargs)).state=='accepted'
    assert len(reports)==1 and calls[-1][0]=='GET'
    assert _read(journal.path)['schema_version']=='ln_church.endpoint_choice_reason_journal.v2'
    with pytest.raises(ValueError):EndpointChoiceTaskPage.model_validate(dict(schema_version=ec.schema('agent_task_page'),tasks=[task2],next_cursor=None))


def test_new_defaults_and_registration_identity(monkeypatch):
    from ln_church_agent.immediate_visit_client import AgentImmediateVisitClient
    from ln_church_agent.endpoint_choice_reason_client import AgentEndpointChoiceReasonClient
    from ln_church_agent.offer_registration import _operation_ref
    assert PaidServiceTrialTaskClient().version=='v3'
    assert AgentImmediateVisitClient().version=='v3'
    assert AgentEndpointChoiceReasonClient().version=='v2'
    envelope=dict(accepted={'asset':c.ASSET},payload={'authorization':{'from':'0x'+'ab'*20,'nonce':'0x'+'cd'*32}})
    assert _operation_ref('endpoint_choice_reason.v1',envelope)==_operation_ref('endpoint_choice_reason.v2',envelope)
    assert _operation_ref('immediate_http_visit.v2',envelope)==_operation_ref('immediate_http_visit.v3',envelope)


@pytest.mark.parametrize('family,old_version,new_version', [('immediate_http_visit','v2','v3'),('endpoint_choice_reason','v1','v2')])
def test_registration_retains_versioned_window(family,old_version,new_version,monkeypatch):
    from ln_church_agent import offer_registration as r
    from ln_church_agent import endpoint_choice_reason_contract as ec
    from test_offer_registration import request
    from datetime import datetime,timedelta,timezone
    monkeypatch.setattr(r,'load_pack',lambda version:{})
    monkeypatch.setattr(ec,'load_contract_pack',lambda version='v1':{})
    for version,hours in [(old_version,48),(new_version,168)]:
        kind=family+'.'+version
        data=request('endpoint_choice_reason.v1' if family=='endpoint_choice_reason' else kind)
        data['task_type']=kind
        assert r._request(data)['task_type']==kind
        task_id='task_'+'1'*32;op='123e4567-e89b-42d3-8456-426614174000'
        start=datetime(2026,10,1,tzinfo=timezone.utc)
        amount,capacity=r.plan(kind,data['plan_id'])
        result=dict(schema_version='ln_church.task_offer_create_response.'+('immediate_visit.'+version if family=='immediate_http_visit' else kind),
            registration_intent_id=op,task_id=task_id,task_type=kind,status='OPEN',
            task_url=c.PUBLIC_API_ORIGIN+c.task_detail_path(task_id),
            summary_url=c.PUBLIC_API_ORIGIN+'/api/agent/task-offers/'+task_id+'/summary',
            results_url=c.PUBLIC_API_ORIGIN+(c.task_detail_path(task_id)+'/results' if family=='endpoint_choice_reason' else '/agent-taskboard.html?task_id='+task_id+'&view=results'),
            published_at=start.isoformat().replace('+00:00','Z'),
            listing_ends_at=(start+timedelta(hours=hours)).isoformat().replace('+00:00','Z'),
            plan_id=data['plan_id'],registration_amount_atomic=amount,capacity_total=capacity)
        if family=='endpoint_choice_reason':result['manifest_url']=c.PUBLIC_API_ORIGIN+'/agent-task-specs/'+kind+'/'+{'v1':'1.0.0','v2':'2.0.0'}[version]+'/manifest.json'
        else:result['repeat_policy']='allow'
        assert r._success(result,kind,op,data)==result
        bad=dict(result,listing_ends_at=(start+timedelta(hours=168 if hours==48 else 48)).isoformat().replace('+00:00','Z'))
        with pytest.raises(ValueError):r._success(bad,kind,op,data)
