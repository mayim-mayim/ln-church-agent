"""SDK self-evidence for Charter 563300b0 W2/W3/W6 and A2/3/6/7/8/10/11/13/14.

Synthetic Edge, real EIP-3009 signing/verification, actual four transports.
This does not establish DO/AWS atomicity or cross-repository integration.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import threading
import pytest
import httpx

from ln_church_agent.access_quota import (
    AccessQuotaPolicy, AccessQuotaError, ORIGIN, PURPOSE, SCHEMA, EXTENSION, ASSETS,
    request_digest,
)
from ln_church_agent.crypto.evm import LocalKeyAdapter
from ln_church_agent.task_transport import TaskTransport, TaskTransportError
from ln_church_agent.task_v2_transport import TaskV2Transport, TaskV2RawResponse, TaskV2Error
from ln_church_agent.immediate_visit_transport import ImmediateVisitTransport, ImmediateVisitRawResponse, ImmediateVisitError
from ln_church_agent.paid_service_trial_transport import PaidServiceTrialTransport, PaidServiceTrialRawResponse, PaidServiceTrialError

NOW = 1790400000
PID = 'aq_'+'1'*32
PAYTO = '0x'+'2'*40
TX = '0x'+'3'*64
BODY = b'{"agent_id":"synthetic","reward_address":"0x4444444444444444444444444444444444444444"}'
FAMILIES = ['v17','scheduled','immediate','paid']


def b64(value):
    return base64.b64encode(json.dumps(value,separators=(',',':')).encode()).decode()


def challenge(method, url, headers, body, pid=PID, network='eip155:8453'):
    req=dict(scheme='exact',network=network,asset=ASSETS[network],payTo=PAYTO,
             amount='10000',maxTimeoutSeconds=300,
             extra=dict(name='USD Coin',version='2',assetTransferMethod='eip3009',paymentFlow='upfront'))
    payload=dict(version=1,purchase_id=pid,subject='synthetic-ip-hmac',
                 request_digest=request_digest(method,url,headers,body),
                 terms=dict(req,purchased_requests=100,policy_version='1'),
                 issued_at=NOW,expires_at=NOW+300,policy_version='1')
    info=dict(purpose=PURPOSE,freeLimit=100,windowSeconds=3600,
              resetAt=datetime.fromtimestamp(NOW+3600,timezone.utc).isoformat(),
              price='0.01',currency='USDC',purchasedRequests=100,purchasedCreditsExpire=False,
              purchaseId=pid,challenge=b64(payload)+'.'+'a'*64,originDispatch='not_sent')
    wire=dict(x402Version=2,error='payment_required',resource=dict(url=url),accepts=[req],
              extensions={EXTENSION:dict(info=info,schema=dict(type='object')),
                          'payment-identifier':dict(info=dict(required=True,id=pid),schema=dict(type='object'))})
    return 402,{'PAYMENT-REQUIRED':b64(wire)},json.dumps(wire).encode()


def status(code='pending', state='PENDING', http=202, **extra):
    return http,{'Retry-After':'2'},json.dumps(dict(schema_version=SCHEMA,purpose=PURPOSE,
                      code=code,status=state,**dict({'purchase_id':PID},**extra))).encode()


def success(data=None, http=200):
    return http,{'PAYMENT-RESPONSE':b64(dict(success=True,network='eip155:8453',transaction=TX)),
                 'X-LN-Access-Quota':b64(dict(version=1,freeRemaining=0,paidRemaining=99,
                    resetAt='2026-09-26T01:00:00Z',purchaseId=PID))},json.dumps(data or {'ok':True}).encode()


class Signer:
    def __init__(self):
        # Deterministic, publicly documented synthetic seed; never a funded key.
        self.inner=LocalKeyAdapter(hashlib.sha256(b'LN access synthetic fixture only').hexdigest())
        self.calls=0
    @property
    def address(self):return self.inner.address
    def generate_eip3009_payload_atomic(self,*args,**kwargs):
        self.calls+=1
        return self.inner.generate_eip3009_payload_atomic(*args,**kwargs)


class Harness:
    def __init__(self, family, policy=None, responses=None, tweak=None):
        self.family=family;self.policy=policy or AccessQuotaPolicy(wall_time=lambda:NOW)
        self.responses=iter(responses or [success()]);self.requests=[];self.now=0.;self.tweak=tweak
        if family=='v17':
            self.transport=TaskTransport(_exchange=self.v17,_resolver=lambda *a:['8.8.8.8'],
                                         _monotonic=lambda:self.now,access_quota=self.policy)
        else:
            cls={'scheduled':TaskV2Transport,'immediate':ImmediateVisitTransport,'paid':PaidServiceTrialTransport}[family]
            self.transport=cls(exchange=self.call,monotonic=lambda:self.now,access_quota=self.policy)
    def serve(self,method,url,headers,body,remaining):
        self.requests.append((method,url,dict(headers),body,remaining))
        self.now+=1
        if not any(k.lower() in ('payment-signature','x-ln-access-recovery') for k in headers):
            raw=challenge(method,url,headers,body)
            return self.tweak(raw) if self.tweak else raw
        item=next(self.responses)
        if isinstance(item,Exception):raise item
        return item
    def v17(self,**kw):
        headers={'Content-Type':'application/json'} if kw['body'] is not None else {}
        headers.update(kw.get('access_headers',{}))
        url=str(httpx.URL(kw['url'],params=kw['params']))
        return self.serve(kw['method'],url,headers,kw['body'] or b'',kw['timeout'])
    def call(self,method,path,query,headers,body,*timeout):
        raw=self.serve(method,ORIGIN+path+('?' + query if query is not None else ''),headers,body,timeout[0] if timeout else None)
        cls={'scheduled':TaskV2RawResponse,'immediate':ImmediateVisitRawResponse,'paid':PaidServiceTrialRawResponse}[self.family]
        return cls(*raw)
    def claim(self):
        if self.family=='v17':
            return self.transport.request('POST','/api/agent/tasks/task_1/claim',json_body=json.loads(BODY),
                                          ambiguous_delivery_code='CLAIM_OUTCOME_UNKNOWN')
        if self.family=='scheduled':return self.transport.claim_task('task_1',BODY)
        return self.transport.claim_task('task_1',BODY,idempotency_key='original-key')


def approved(budget=10000):return AccessQuotaPolicy(allow=True,budget_atomic=budget,signer=Signer(),wall_time=lambda:NOW)


@pytest.mark.parametrize('family',FAMILIES)
def test_default_is_zero_spend_and_structured_conditions(family):
    p=AccessQuotaPolicy(signer=Signer(),budget_atomic=10000,wall_time=lambda:NOW)
    h=Harness(family,p)
    with pytest.raises(AccessQuotaError) as e:h.claim()
    assert e.value.code=='ACCESS_REQUIRED' and e.value.origin_not_sent
    assert e.value.terms.amount_atomic==10000 and e.value.terms.reset_at
    assert len(h.requests)==1 and p.signer.calls==p.spent_atomic==p.reserved_atomic==0
    assert e.value.__cause__ is None and e.value.__context__ is None
    assert 'challenge' not in repr(e.value.__dict__) and 'signature' not in repr(e.value.__dict__)


@pytest.mark.parametrize('family',FAMILIES)
def test_explicit_purchase_preserves_original_and_success_schema(family):
    p=approved();h=Harness(family,p)
    result=h.claim()
    assert (result.data if family=='v17' else result)=={'ok':True}
    assert p.signer.calls==1 and p.spent_atomic==10000 and p.reserved_atomic==0
    first,second=h.requests
    assert first[:2]==second[:2] and first[3]==second[3]
    for key in ('Content-Type','Idempotency-Key'):
        assert first[2].get(key)==second[2].get(key)
    envelope=json.loads(base64.b64decode(second[2]['PAYMENT-SIGNATURE']))
    assert envelope['extensions']['payment-identifier']['info']['id']==PID
    assert envelope['payload']['authorization']['validBefore']==str(NOW+300)
    assert p.snapshot(PID)['quota']['paidRemaining']==99
    if family!='scheduled':assert second[4]<first[4]  # one absolute budget


@pytest.mark.parametrize('family',FAMILIES)
def test_pending_and_loss_keep_one_proof_and_reservation(family):
    p=approved();h=Harness(family,p,[status(),OSError('PRIVATE'),success()])
    for _ in range(2):
        with pytest.raises(AccessQuotaError) as e:h.claim()
        assert e.value.code=='ACCESS_PENDING' and not e.value.origin_not_sent
        assert p.reserved_atomic==10000 and p.spent_atomic==0
    h.claim()
    assert p.signer.calls==1 and p.spent_atomic==10000
    assert len({r[2]['PAYMENT-SIGNATURE'] for r in h.requests if 'PAYMENT-SIGNATURE' in r[2]})==1
    assert len({r[3] for r in h.requests})==1


@pytest.mark.parametrize('family',FAMILIES)
def test_failed_final_only_releases_and_requires_explicit_new_operation(family):
    p=approved();h=Harness(family,p,[status('failed_final','FAILED_FINAL',409)])
    with pytest.raises(AccessQuotaError) as e:h.claim()
    assert e.value.code=='ACCESS_FAILED_FINAL' and p.reserved_atomic==p.spent_atomic==0
    with pytest.raises(AccessQuotaError):h.claim()
    assert len(h.requests)==2 and p.signer.calls==1
    p.finish_failed(PID)
    assert not p.has_operation(*('POST',h.requests[0][1],h.requests[0][2],h.requests[0][3]))


@pytest.mark.parametrize('family',FAMILIES)
@pytest.mark.parametrize('code',['result_expired','result_unavailable'])
def test_result_loss_never_releases_paid_budget(family,code):
    p=approved();h=Harness(family,p,[status(code,'PAID',410),status('failed_final','FAILED_FINAL',409)])
    with pytest.raises(AccessQuotaError) as e:h.claim()
    assert e.value.code=='ACCESS_'+code.upper() and p.spent_atomic==10000 and p.reserved_atomic==0
    with pytest.raises(AccessQuotaError) as e:h.claim()
    assert e.value.code=='ACCESS_PENDING' and p.spent_atomic==10000
    assert p.signer.calls==1


@pytest.mark.parametrize('family',FAMILIES)
def test_origin_402_not_purchased(family):
    h=Harness(family,approved(),tweak=lambda _: (402,{},b'{"error":"seller_payment"}'))
    with pytest.raises((TaskTransportError,TaskV2Error,ImmediateVisitError,PaidServiceTrialError)):
        h.claim()
    assert h.policy.signer.calls==0 and len(h.requests)==1


@pytest.mark.parametrize('field',['binding','url','purpose','origin','header','amount','network','asset','identifier'])
def test_challenge_validation_does_not_sign(field):
    def tweak(raw):
        status_,headers,body=raw;v=json.loads(body);info=v['extensions'][EXTENSION]['info']
        if field=='binding':
            payload=json.loads(base64.b64decode(info['challenge'].split('.')[0]));payload['request_digest']='0'*64
            info['challenge']=b64(payload)+'.'+'a'*64
        if field=='url':v['resource']['url']=ORIGIN+'/api/agent/tasks/wrong'
        if field=='purpose':info['purpose']='seller'
        if field=='origin':info['originDispatch']='sent'
        if field=='amount':v['accepts'][0]['amount']='20000'
        if field=='network':v['accepts'][0]['network']='eip155:137'
        if field=='asset':v['accepts'][0]['asset']=PAYTO
        if field=='identifier':v['extensions']['payment-identifier']['info']['id']='other'
        return status_,{'PAYMENT-REQUIRED':b64(v) if field!='header' else b64({})},json.dumps(v).encode()
    h=Harness('paid',approved(),tweak=tweak)
    with pytest.raises((AccessQuotaError,PaidServiceTrialError)):h.claim()
    assert h.policy.signer.calls==0


def test_shared_budget_is_atomic_across_parallel_distinct_operations():
    p=approved();barrier=threading.Barrier(2)
    def invoke(i):
        url=ORIGIN+'/api/agent/tasks/task_'+str(i)
        def send(extra,remaining):
            if not extra:
                barrier.wait()
                return challenge('GET',url,{},b'',pid='aq_'+str(i)*32)
            return status(purchase_id='aq_'+str(i)*32)
        try:p.exchange(method='GET',url=url,headers={},body=b'',send=send,deadline=20,clock=lambda:0)
        except AccessQuotaError as e:return e.code
    with ThreadPoolExecutor(2) as pool:out=list(pool.map(invoke,[1,2]))
    assert sorted(out)==['ACCESS_BUDGET_EXCEEDED','ACCESS_PENDING']
    assert p.signer.calls==1 and p.reserved_atomic==10000 and p.spent_atomic==0


@pytest.mark.parametrize('family',FAMILIES)
def test_deadline_no_hidden_retry_or_timeout_extension(family):
    p=approved();h=Harness(family,p)
    original=h.serve
    def delayed(*a):
        raw=original(*a);h.now=20.;return raw
    h.serve=delayed
    with pytest.raises((AccessQuotaError,TaskTransportError)) as e:h.claim()
    assert len(h.requests)==1 and p.signer.calls==0


def test_external_host_and_outside_routes_never_buy():
    p=approved()
    for url in ('http://kari.mayim-mayim.com/api/agent/tasks', 'https://seller.example/api/agent/tasks',
                ORIGIN+'/api/agent/tasks/task_1/completion'):
        calls=[]
        def send(extra,remaining):calls.append(extra);return 402,{},b'{}'
        assert p.exchange(method='POST',url=url,headers={},body=b'',send=send,deadline=20,clock=lambda:0)[0]==402
        assert calls==[{}]
    assert p.signer.calls==0


@pytest.mark.parametrize('family',['immediate','paid'])
def test_readonly_claim_miss_does_not_fallback_to_new_claim(family):
    h=Harness(family,approved())
    def miss(method,path,query,headers,body,*timeout):
        assert headers['X-LN-Claim-Recovery']=='1'
        h.requests.append(headers)
        cls=ImmediateVisitRawResponse if family=='immediate' else PaidServiceTrialRawResponse
        return cls(*status('claim_result_unknown'))
    h.transport._exchange=miss
    with pytest.raises(AccessQuotaError) as e:h.transport.recover_claim('task_1',BODY,idempotency_key='original-key')
    assert e.value.code=='ACCESS_PENDING' and len(h.requests)==1 and h.policy.signer.calls==0


@pytest.mark.parametrize('family',FAMILIES)
def test_free_window_explicit_resume_does_not_sign(family):
    p=AccessQuotaPolicy(wall_time=lambda:NOW);h=Harness(family,p)
    with pytest.raises(AccessQuotaError):h.claim()
    p._wall_time=lambda:NOW+3601
    def free(method,url,headers,body,remaining):
        h.requests.append((method,url,dict(headers),body,remaining))
        assert not {'PAYMENT-SIGNATURE','X-LN-Access-Challenge'} & headers.keys()
        return 200,{},b'{"ok":true}'
    h.serve=free
    h.claim()
    assert len(h.requests)==2 and p.reserved_atomic==p.spent_atomic==0
    assert h.requests[0][3]==h.requests[1][3]


@pytest.mark.parametrize('family',FAMILIES)
def test_origin_402_after_purchase_keeps_receipt_and_paid_budget(family):
    p=approved();h=Harness(family,p,[success({'error':'origin_payment'},402)])
    with pytest.raises((TaskTransportError,TaskV2Error,ImmediateVisitError,PaidServiceTrialError)):
        h.claim()
    assert p.spent_atomic==10000 and p.reserved_atomic==0
    assert p.snapshot(PID)['receipt']['transaction']==TX
    assert len(h.requests)==2


def test_two_concurrent_same_operations_reuse_one_signature_and_one_origin_fence():
    p=approved();barrier=threading.Barrier(2);origin=0;fenced=False;proofs=[]
    url=ORIGIN+'/api/agent/tasks/task_1/claim'
    def send(extra,remaining):
        nonlocal origin,fenced
        if not extra:
            barrier.wait()
            return challenge('POST',url,{},b'{}')
        proofs.append(extra['PAYMENT-SIGNATURE'])
        if not fenced:
            origin+=1;fenced=True
            return status('origin_unknown','PAID')
        return success()
    def call(_):
        try:return p.exchange(method='POST',url=url,headers={},body=b'{}',send=send,deadline=20,clock=lambda:0)
        except AccessQuotaError as e:return e.code
    with ThreadPoolExecutor(2) as pool:values=list(pool.map(call,[1,2]))
    assert origin==1 and len(set(proofs))==1 and p.signer.calls==1 and p.spent_atomic==10000
    assert 'ACCESS_PENDING' in values


# Actual public clients: the access exception must survive all parser/error
# boundaries, then the unchanged Claim schema must still create credentials.
from test_v1_18_5_paid_service_trial_contract import wire
from test_v1_18_5_paid_service_trial_http_v2_contract import wire_v2


@pytest.mark.parametrize('family',FAMILIES)
def test_public_clients_resume_same_operation_and_return_typed_claim(family,wire_v2,tmp_path):
    from ln_church_agent.task_client import AgentTaskClient
    from ln_church_agent.task_v2_client import AgentTaskV2Client
    from ln_church_agent.immediate_visit_client import AgentImmediateVisitClient
    from ln_church_agent.paid_service_trial_client import PaidServiceTrialTaskClient
    from test_v1_17_0_task_venue_sdk import _claim_response
    from test_v1_18_0_task_v2_models import _claim_payload
    from test_v1_18_3_immediate_visit_contract import claim_wire
    data={'v17':_claim_response(),'scheduled':_claim_payload(),
          'immediate':claim_wire(),'paid':wire_v2.claim}[family]
    p=AccessQuotaPolicy(wall_time=lambda:NOW);h=Harness(family,p,[status(),success(data)])
    if family=='v17':
        client=AgentTaskClient(_transport=h.transport)
        invoke=lambda:client.claim_task(data['task_id'],agent_id='synthetic',reward_address=data['reward_address'])
    elif family=='scheduled':
        client=AgentTaskV2Client(transport=h.transport)
        invoke=lambda:client.claim_task(data['task_id'],agent_id='synthetic',reward_address=data['reward_address'])
    elif family=='immediate':
        client=AgentImmediateVisitClient(transport=h.transport)
        invoke=lambda:client.claim_task(data['task_id'],'synthetic',data['reward_address'],idempotency_key='original-key')
    else:
        client=PaidServiceTrialTaskClient(transport=h.transport,claim_directory=tmp_path)
        invoke=lambda:client.claim_task(data['task_id'],'synthetic',data['reward_address'],idempotency_key='original-key')
    with pytest.raises(AccessQuotaError) as e:invoke()
    assert e.value.origin_not_sent
    p.allow=True;p.budget_atomic=10000;p.signer=Signer()
    with pytest.raises(AccessQuotaError) as e:invoke()
    assert e.value.code=='ACCESS_PENDING'
    result=invoke()
    assert result.task_id==data['task_id']
    assert len(h.requests)==3 and p.signer.calls==1 and p.spent_atomic==10000


@pytest.mark.parametrize('family',FAMILIES)
def test_real_httpx_pinning_and_same_bytes_through_access_continuation(family,monkeypatch):
    import httpcore
    import ssl
    from ln_church_agent import task_transport as v17
    from ln_church_agent import task_v2_transport as v2
    from ln_church_agent import immediate_visit_transport as im
    from ln_church_agent import paid_service_trial_transport as paid
    p=approved();requests=[];pins=[];tls=[]
    class Stream:
        def __init__(self):self.sent=bytearray();self.response=None
        def write(self,data,timeout=None):
            assert 0<timeout<=10;self.sent.extend(data)
        def read(self,max_bytes,timeout=None):
            assert 0<timeout<=20
            if self.response is None:
                head,body=bytes(self.sent).split(b'\r\n\r\n',1)
                lines=head.split(b'\r\n');method,path,_=lines[0].decode().split(' ')
                headers=dict(line.decode().split(': ',1) for line in lines[1:])
                lower={k.lower():v for k,v in headers.items()}
                assert lower['host']=='kari.mayim-mayim.com'
                assert not {'authorization','cookie','x-ln-access-origin-auth'} & lower.keys()
                requests.append((method,path,headers,body))
                raw=(challenge(method,ORIGIN+path,headers,body) if len(requests)==1 else success())
                status_,rh,rb=raw
                self.response=(('HTTP/1.1 '+str(status_)+' OK\r\nContent-Length: '+str(len(rb))+'\r\n'+
                    ''.join(k+': '+v+'\r\n' for k,v in rh.items())+'\r\n').encode()+rb)
            result,self.response=self.response[:max_bytes],self.response[max_bytes:]
            return result
        def start_tls(self,ssl_context,server_hostname=None,timeout=None):
            assert isinstance(ssl_context,ssl.SSLContext) and ssl_context.check_hostname and ssl_context.verify_mode==ssl.CERT_REQUIRED
            assert server_hostname in ('kari.mayim-mayim.com',b'kari.mayim-mayim.com')
            assert 0<timeout<=5;tls.append(server_hostname);return self
        def close(self):pass
        def get_extra_info(self,name):return None
    def connect(self,host,port,timeout=None,**kwargs):
        assert host in ('8.8.8.8',b'8.8.8.8') and port==443 and 0<timeout<=5
        pins.append(host);return Stream()
    monkeypatch.setattr(httpcore.SyncBackend,'connect_tcp',connect)
    resolver=lambda *a:['8.8.8.8']
    if family=='v17':
        t=v17.TaskTransport(access_quota=p,_resolver=resolver)
        result=t.request('POST','/api/agent/tasks/task_1/claim',json_body=json.loads(BODY))
    elif family=='scheduled':
        t=v2.TaskV2Transport(access_quota=p,resolver=resolver);result=t.claim_task('task_1',BODY)
    else:
        t=(im.ImmediateVisitTransport if family=='immediate' else paid.PaidServiceTrialTransport)(access_quota=p,resolver=resolver)
        result=t.claim_task('task_1',BODY,idempotency_key='original-key')
    assert len(pins)==len(tls)==len(requests)==2
    assert requests[0][:2]==requests[1][:2] and requests[0][3]==requests[1][3]
    assert 'payment-signature' in {k.lower() for k in requests[1][2]}
    assert p.spent_atomic==10000


@pytest.mark.parametrize('family',FAMILIES)
def test_read_only_purchase_state_uses_original_binding_without_proof(family):
    p=approved();h=Harness(family,p,[status(),status('origin_unknown','PAID')])
    with pytest.raises(AccessQuotaError):h.claim()
    with p.read_only(PID):
        with pytest.raises(AccessQuotaError) as e:h.claim()
        assert e.value.code=='ACCESS_PENDING'
    last=h.requests[-1]
    assert last[2]['X-LN-Access-Recovery']=='1' and 'PAYMENT-SIGNATURE' not in last[2]
    assert h.requests[0][0:2]==last[0:2] and h.requests[0][3]==last[3]
    assert p.spent_atomic==10000 and p.signer.calls==1


@pytest.mark.parametrize('family',FAMILIES)
def test_get_query_is_bound_and_preserved_on_purchase(family):
    p=approved();h=Harness(family,p)
    if family=='v17':h.transport.request('GET','/api/agent/tasks',params={'limit':2,'cursor':'a+b/c='})
    else:h.transport.list_tasks()
    assert h.requests[0][1]==h.requests[1][1] and '?' in h.requests[0][1]
    assert all(r[3]==b'' for r in h.requests)


@pytest.mark.parametrize('mutated',['method','url','body','content-type','key'])
def test_original_challenge_cannot_authorize_changed_request(mutated):
    p=approved();url=ORIGIN+'/api/agent/tasks/task_1/claim'
    headers={'Content-Type':'application/json','Idempotency-Key':'same-key'}
    raw=challenge('POST',url,headers,b'{}')
    method='POST';body=b'{}'
    if mutated=='method':method='GET';url=ORIGIN+'/api/agent/tasks/task_1';body=b''
    if mutated=='url':url+='?x=changed'
    if mutated=='body':body=b'{ }'
    if mutated=='content-type':headers['Content-Type']='application/json; charset=utf-8'
    if mutated=='key':headers['Idempotency-Key']='changed-key'
    with pytest.raises(AccessQuotaError):
        p.exchange(method=method,url=url,headers=headers,body=body,send=lambda *a:raw,deadline=20,clock=lambda:0)
    assert p.signer.calls==0


def test_sepolia_signing_is_explicit_and_uses_separate_chain_and_asset():
    from eth_account import Account
    from eth_account.messages import encode_typed_data
    from ln_church_agent.crypto.evm import EIP3009_TYPES, TRUSTED_EIP3009_TOKENS
    signer=Signer().inner
    p=AccessQuotaPolicy(allow=True,budget_atomic=10000,signer=signer,network='eip155:84532',wall_time=lambda:NOW)
    url=ORIGIN+'/api/agent/tasks'
    proofs=[]
    def send(extra,remaining):
        if not extra:return challenge('GET',url,{},b'',network='eip155:84532')
        proofs.append(json.loads(base64.b64decode(extra['PAYMENT-SIGNATURE'])))
        return status()
    with pytest.raises(AccessQuotaError):p.exchange(method='GET',url=url,headers={},body=b'',send=send,deadline=20,clock=lambda:0)
    wire=proofs[0];auth=wire['payload']['authorization'];message=dict(auth)
    for key in ('value','validAfter','validBefore'):message[key]=int(message[key])
    typed=encode_typed_data(domain_data=dict(name='USD Coin',version='2',chainId=84532,verifyingContract=ASSETS['eip155:84532']),
        message_types=EIP3009_TYPES,message_data=message)
    assert Account.recover_message(typed,signature=wire['payload']['signature']).lower()==signer.address.lower()
    assert wire['accepted']['network']=='eip155:84532' and wire['accepted']['asset']==ASSETS['eip155:84532']
    assert (84532,ASSETS['eip155:84532']) not in TRUSTED_EIP3009_TOKENS
