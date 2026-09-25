"""DC 0dbce748 §3: safe received details, legacy catch and persisted rejection."""
import copy
import json
import httpx
import pytest

from test_v1_18_5_paid_service_trial_contract import wire
from test_v1_18_5_paid_service_trial_http_v2_contract import wire_v2
from ln_church_agent import paid_service_trial_transport as t
from ln_church_agent import paid_service_trial_journal as j
from ln_church_agent.paid_service_trial_client import PaidServiceTrialTaskClient


def envelope(version='v2',code='unsupported_purchase_terms',request_id='request-original',reason='missing_payment_required'):
    value=dict(schema_version='ln_church.task_error.paid_service_trial.'+version,
        code=code,request_id=request_id,message='SYNTHETIC_PRIVATE_MESSAGE')
    if version=='v2':value['reason']=reason
    return value


@pytest.mark.parametrize('version',['v1','v2'])
@pytest.mark.parametrize('request_id,expected',[
    ('!', '!'),('r'*256,'r'*256),('r'*257,None),('',None),('has space',None),
    ('has\nnewline',None),('é',None),('\x7f',None),('~id!','~id!'),
])
def test_safe_id_does_not_change_api_outcome_and_survives_restart(wire,wire_v2,tmp_path,version,request_id,expected):
    w=wire if version=='v1' else wire_v2;calls=[]
    def exchange(*a):
        calls.append(a)
        return t.PaidServiceTrialRawResponse(400,{},json.dumps(envelope(version,request_id=request_id)).encode())
    def client():return PaidServiceTrialTaskClient(version=version,claim_directory=tmp_path,
        transport=t.PaidServiceTrialTransport(version=version,exchange=exchange))
    for operation in [lambda:client().claim_task(w.claim['task_id'],'synthetic-agent',w.claim['reward_address'],idempotency_key='original'),
                      lambda:client().recover_claim(w.claim['task_id'],idempotency_key='original')]:
        with pytest.raises(t.PaidServiceTrialError) as error:operation()
        e=error.value
        assert isinstance(e,t.PaidServiceTrialAPIError)
        assert (e.code,e.status_code,e.public_error_code)==('API_ERROR',400,'unsupported_purchase_terms')
        assert e.reason==('missing_payment_required' if version=='v2' else None)
        assert e.request_id==expected and str(e)=='API_ERROR' and e.__context__ is None
        assert 'SYNTHETIC_PRIVATE' not in repr(e)
    assert len(calls)==1
    record=j._ClaimRequest(tmp_path,version,w.claim['task_id'],'original').read()
    assert record['rejection']['request_id']==expected


def test_186_rejection_remains_readable_without_post(wire_v2,tmp_path):
    body=json.dumps(dict(schema_version='ln_church.agent_task_claim_request.v1',
        agent_id='synthetic-agent',reward_address=wire_v2.claim['reward_address']),sort_keys=True,separators=(',',':')).encode()
    record=j._ClaimRequest(tmp_path,'v2',wire_v2.claim['task_id'],'original')
    data=record.read(body);data.update(state='REJECTED',rejection=dict(code='unsupported_purchase_terms',status=400));record.save(data)
    calls=[]
    client=PaidServiceTrialTaskClient(claim_directory=tmp_path,transport=t.PaidServiceTrialTransport(exchange=lambda *a:calls.append(a)))
    with pytest.raises(t.PaidServiceTrialAPIError) as error:client.recover_claim(wire_v2.claim['task_id'],idempotency_key='original')
    assert error.value.public_error_code=='unsupported_purchase_terms' and error.value.status_code==400
    assert error.value.reason is None and error.value.request_id is None and not calls


@pytest.mark.parametrize('case,status,code,request_id',[
    ('503',503,'temporarily_unavailable','request-original'),
    ('decode',200,None,None),('dto',200,None,None),('unexpected-success',201,None,None),
    ('bad-envelope',400,None,None),('bad-code-type',400,None,None),
    ('head-timeout',None,None,None),('body-timeout',200,None,None),('encoding',200,None,None),
])
def test_actual_default_api_received_status_survives_unknown(wire_v2,tmp_path,monkeypatch,record_property,case,status,code,request_id):
    calls=[];mode=[case]
    class BrokenBody(httpx.SyncByteStream):
        def __iter__(self):
            yield b'{'
            raise httpx.ReadTimeout('SYNTHETIC_PRIVATE')
    def reply(request):
        calls.append((str(request.url),request.headers['idempotency-key'],request.content))
        if mode[0]=='head-timeout':raise httpx.ReadTimeout('SYNTHETIC_PRIVATE')
        if mode[0]=='body-timeout':return httpx.Response(200,stream=BrokenBody())
        if mode[0]=='encoding':return httpx.Response(200,headers={'content-encoding':'gzip'},stream=httpx.ByteStream(b'x'))
        value=copy.deepcopy(wire_v2.claim);actual=200
        if mode[0]=='503':value=envelope(code='temporarily_unavailable',reason=None);actual=503
        if mode[0]=='bad-envelope':value={'message':'SYNTHETIC_PRIVATE'};actual=400
        if mode[0]=='bad-code-type':value=envelope(code={'private':'SYNTHETIC_PRIVATE'});actual=400
        if mode[0]=='dto':value['unexpected']='SYNTHETIC_PRIVATE'
        if mode[0]=='unexpected-success':actual=201
        content=b'{SYNTHETIC_PRIVATE' if mode[0]=='decode' else json.dumps(value).encode()
        return httpx.Response(actual,stream=httpx.ByteStream(content))
    def pinned(address,tracker,*args):
        def handle(request):tracker.request_bytes_sent=True;return reply(request)
        return httpx.MockTransport(handle)
    monkeypatch.setattr(t,'_new_pinned_httpx_transport',pinned)
    def client():return PaidServiceTrialTaskClient(claim_directory=tmp_path,
        transport=t.PaidServiceTrialTransport(resolver=lambda *a:['8.8.8.8']))
    with pytest.raises(t.PaidServiceTrialTransportError) as error:
        client().claim_task(wire_v2.claim['task_id'],'synthetic-agent',wire_v2.claim['reward_address'],idempotency_key='original')
    e=error.value
    assert e.code=='CLAIM_OUTCOME_UNKNOWN' and e.status_code==status
    assert e.public_error_code==code and e.request_id==request_id and e.reason is None
    assert str(e)=='CLAIM_OUTCOME_UNKNOWN' and e.__context__ is None and e.__cause__ is None
    assert 'SYNTHETIC_PRIVATE' not in repr(e)
    mode[0]='success'
    claim=client().recover_claim(wire_v2.claim['task_id'],idempotency_key='original')
    assert claim._private_payload()==wire_v2.claim and calls[0]==calls[1]
    record_property('runtime',json.dumps(dict(case=case,status=status,public_code=code,request_id=request_id,
        same_request=True,api_attempts=len(calls),recovered=True,live_requests=0)))


def test_custom_dict_without_http_metadata_does_not_invent_200(wire_v2,tmp_path):
    class Adapter:
        def claim_task(self,*a,**kw):return {'unexpected':'SYNTHETIC_PRIVATE'}
    client=PaidServiceTrialTaskClient(claim_directory=tmp_path,transport=Adapter())
    with pytest.raises(t.PaidServiceTrialTransportError) as error:
        client.claim_task(wire_v2.claim['task_id'],'synthetic-agent',wire_v2.claim['reward_address'],idempotency_key='original')
    assert error.value.status_code is None and error.value.request_id is None
