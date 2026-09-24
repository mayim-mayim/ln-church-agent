"""Deterministic same-R network/signing boundaries from HTTP Wire §§2–4."""
import base64
import copy
import json
import ssl
from types import SimpleNamespace

import pytest
from test_v1_18_5_paid_service_trial_http_v2_contract import wire_v2, V2TaskTransport
from ln_church_agent import paid_service_trial_contract as c
from ln_church_agent.models import PaymentPolicy
from ln_church_agent.paid_service_trial import PaidServiceTrialExecutor, export_purchase_import_descriptor
from ln_church_agent.paid_service_trial_client import PaidServiceTrialTaskClient
from ln_church_agent.paid_service_trial_journal import PaidServiceTrialJournal
from ln_church_agent.paid_service_trial_models import PurchaseTerms
from ln_church_agent.paid_service_trial_network import (
    PaidTrialHTTPResponse, PaidServiceTrialHTTPS, current_v2_terms, PaidServiceTrialTermsError,
)
from ln_church_agent.task_journal import JournalPersistenceError


def terms_response(wire,body=b'',conditions=None):
    envelope=dict(x402Version=2,resource={'url':wire.request['url']},
        accepts=conditions if conditions is not None else [wire.terms['requirements']])
    header=base64.b64encode(json.dumps(envelope).encode()).decode()
    return PaidTrialHTTPResponse(402,[('PAYMENT-REQUIRED',header)],body)


class V2HTTP:
    def __init__(self,wire):
        self.wire=wire;self.unpaid=0;self.paid=0;self.seen=[];self.change_after_sign=False
    def fetch(self,request,*,payment_signature=None):
        assert request==self.wire.request
        self.seen.append((copy.deepcopy(request),bool(payment_signature)))
        if payment_signature is None:
            self.unpaid+=1
            terms=copy.deepcopy(self.wire.terms['requirements'])
            if self.change_after_sign and self.unpaid==2:terms['amount']='1001'
            return terms_response(self.wire,b'<html>Pay for this item</html>',[terms])
        self.paid+=1
        payload=json.loads(base64.b64decode(payment_signature))
        assert payload['resource']=={'url':request['url']}
        self.authorization=payload['payload']['authorization']
        return PaidTrialHTTPResponse(502,[],b'private provider result')


@pytest.fixture
def lane_v2(wire_v2,tmp_path):
    wire=wire_v2;tmp_path.chmod(0o700)
    journal=PaidServiceTrialJournal(tmp_path,wire.credential)
    http=V2HTTP(wire);transport=V2TaskTransport(wire)
    client=PaidServiceTrialTaskClient(transport=transport)
    guard=SimpleNamespace(ready=lambda value:True)
    policy=PaymentPolicy(max_spend_per_tx_usd=.001,max_spend_per_session_usd=.001,allowed_hosts=['seller.example.com'])
    executor=PaidServiceTrialExecutor(signer=wire.signer,policy=policy,client=client,http=http,block_guard=guard,wall_time=lambda:wire.now)
    return SimpleNamespace(journal=journal,http=http,transport=transport,client=client,guard=guard,executor=executor,policy=policy)


def test_exact_request_survives_purchase_and_report(wire_v2,lane_v2):
    wire=wire_v2;lane=lane_v2
    result=lane.executor.execute(wire.credential,journal=lane.journal)
    assert lane.http.unpaid==2 and lane.http.paid==1
    assert all(x[0]==wire.request for x in lane.http.seen)
    assert result.report.model.request_digest==wire.claim['request_digest']
    assert result.report.model.purchase_terms_digest==wire.claim['purchase_terms_digest']
    assert 'request' not in result.report.model.wire()
    assert result.http_status==502
    saved=lane.journal.snapshot()
    assert saved['schema_version']=='ln_church.paid_service_trial_journal.v2'
    assert saved['claim']['request']==wire.request
    assert saved['claim']['request']['body'].encode()==wire.request['body'].encode()
    for forbidden in ('claim_token','signature','PAYMENT-SIGNATURE','private provider result'):
        assert forbidden not in lane.journal.path.read_text()
    lane.executor._signer=None
    lane.executor.execute(wire.credential,journal=lane.journal)
    assert lane.http.paid==1 and lane.http.unpaid==2


def test_change_during_signing_stops_paid_send(wire_v2,lane_v2):
    lane=lane_v2;lane.http.change_after_sign=True
    with pytest.raises(PaidServiceTrialTermsError):lane.executor.execute(wire_v2.credential,journal=lane.journal)
    assert lane.http.paid==0 and not lane.journal.snapshot()['paid_dispatch_reserved']
    # PREPARED is not permission to generate a replacement authorization.
    assert lane.executor.execute(wire_v2.credential,journal=lane.journal).state=='NO_DISPATCH'
    assert lane.http.unpaid==2


@pytest.mark.parametrize('stage',['prepare','reserve_paid_dispatch'])
def test_persistence_failure_sends_nothing(wire_v2,lane_v2,monkeypatch,stage):
    def fail(*args):raise JournalPersistenceError()
    monkeypatch.setattr(lane_v2.journal,stage,fail)
    with pytest.raises(JournalPersistenceError):lane_v2.executor.execute(wire_v2.credential,journal=lane_v2.journal)
    assert lane_v2.http.paid==0


@pytest.mark.parametrize('body',[b'',b'<html>Pay</html>',b'{"error":"payment needed"}',
    b'{"x402Version":2}',b'{"resource":null,"accepts":false}',b'[1,2]'])
def test_unrelated_content_with_valid_header(wire_v2,body):
    assert current_v2_terms(terms_response(wire_v2,body),wire_v2.terms,wire_v2.request).wire()==wire_v2.terms


def test_condition_sets_ignore_order_duplicates_and_optional_default(wire_v2):
    original=copy.deepcopy(wire_v2.terms['requirements'])
    explicit=copy.deepcopy(original);explicit['extra']['assetTransferMethod']='eip3009'
    extra=copy.deepcopy(original);extra['amount']='999'
    body=dict(x402Version=2,resource={'url':wire_v2.request['url'],'description':'irrelevant'},accepts=[extra,explicit,original])
    response=terms_response(wire_v2,json.dumps(body).encode(),[original,extra])
    assert current_v2_terms(response,wire_v2.terms,wire_v2.request).wire()==wire_v2.terms


@pytest.mark.parametrize('change,reason',[
    ({'status':200},'expected_402'),({'headers':[]},'missing_payment_required'),
    ({'url':'https://different.example.com/'},'resource_mismatch'),
    ({'raw_header':'not-base64'},'invalid_payment_required'),
    ({'condition':{'recipient':'0x'+'45'*20}},'conflicting_payment_terms'),
    ({'condition':{'maxAmountRequired':'999'}},'conflicting_payment_terms'),
    ({'condition':{'chainId':1}},'conflicting_payment_terms'),
    ({'condition':{'extra':{'name':'USD Coin','version':'2','chainId':1}}},'conflicting_payment_terms'),
    ({'condition':{'extra':{'recipient':'0x'+'45'*20}}},'conflicting_payment_terms'),
    ({'condition':{'extra':{'maxAmountRequired':'999'}}},'conflicting_payment_terms'),
    ({'condition':{'amount':'1001'}},'unsupported_payment_profile'),
])
def test_finite_terms_rejection(wire_v2,change,reason):
    req=copy.deepcopy(wire_v2.terms['requirements']);req.update(change.get('condition',{}))
    body=dict(x402Version=2,resource={'url':change.get('url',wire_v2.request['url'])},accepts=[req])
    header=change.get('raw_header',base64.b64encode(json.dumps(body).encode()).decode())
    response=PaidTrialHTTPResponse(change.get('status',402),change.get('headers',[('PAYMENT-REQUIRED',header)]),b'')
    with pytest.raises(PaidServiceTrialTermsError) as caught:current_v2_terms(response,wire_v2.terms,wire_v2.request)
    assert caught.value.reason==reason


@pytest.mark.parametrize('body',[
    b'{"x402Version":2,"resource":null,"accepts":[]}',
    b'{"x402Version":2,"resource":{},"accepts":[],"accepts":[]}',
])
def test_recognized_malformed_terms_not_dropped(wire_v2,body):
    with pytest.raises(PaidServiceTrialTermsError):current_v2_terms(terms_response(wire_v2,body),wire_v2.terms,wire_v2.request)


def test_unselected_malformed_condition_not_dropped(wire_v2):
    good=wire_v2.terms['requirements'];bad=dict(good,amount='not-an-amount')
    with pytest.raises(PaidServiceTrialTermsError):current_v2_terms(terms_response(wire_v2,conditions=[good,bad]),wire_v2.terms,wire_v2.request)


@pytest.mark.parametrize('method,body',[('GET',None),('POST','null'),('POST','""'),('POST','{"é":"😀"}')])
def test_actual_http_wire_identical_unpaid_and_paid(method,body):
    sent=[]
    class Socket:
        def __init__(self,*args):self.reply=b'HTTP/1.1 402 Payment Required\r\nContent-Length: 0\r\n\r\n'
        def connect(self,*args):pass
        def settimeout(self,*args):pass
        def getpeername(self):return ('8.8.8.8',443)
        def sendall(self,data):sent.append(data)
        def recv(self,n):r=self.reply[:n];self.reply=self.reply[n:];return r
        def close(self):pass
    class TLS:
        verify_mode=ssl.CERT_REQUIRED;check_hostname=True
        def wrap_socket(self,socket,**kwargs):return socket
    http=PaidServiceTrialHTTPS(resolver=lambda *args:['8.8.8.8'],socket_factory=Socket,ssl_context_factory=TLS)
    request=c.prepare_request(dict(method=method,url='https://seller.example.com/paid?x=1&x=2',body=body))
    assert http.fetch(request).complete
    assert http.fetch(request,payment_signature='YWJj').complete
    plain,paid=sent
    assert plain==paid.replace(b'PAYMENT-SIGNATURE: YWJj\r\n',b'')
    head,actual=plain.split(b'\r\n\r\n',1)
    assert head.startswith((method+' /paid?x=1&x=2 HTTP/1.1').encode())
    assert b'Cookie:' not in head and b'Authorization:' not in head
    if method=='GET':
        assert actual==b'' and b'Content-Type:' not in head and b'Content-Length:' not in head
    else:
        assert actual==request['body'].encode()
        assert b'Content-Type: application/json' in head
        assert ('Content-Length: '+str(len(actual))).encode() in head


def test_post_upload_consumes_absolute_deadline():
    clock=[0];sent=[]
    class Socket:
        def __init__(self,*args):pass
        def connect(self,*args):pass
        def settimeout(self,*args):pass
        def getpeername(self):return ('8.8.8.8',443)
        def sendall(self,data):sent.append(data);clock[0]=21
        def recv(self,n):pytest.fail('Expired upload must not start a fresh response timer')
        def close(self):pass
    class TLS:
        verify_mode=ssl.CERT_REQUIRED;check_hostname=True
        def wrap_socket(self,socket,**kwargs):return socket
    http=PaidServiceTrialHTTPS(resolver=lambda *args:['8.8.8.8'],socket_factory=Socket,ssl_context_factory=TLS,monotonic=lambda:clock[0])
    request=c.prepare_request(dict(method='POST',url='https://seller.example.com/paid',body='null'))
    assert not http.fetch(request,payment_signature='YWJj').complete
    assert len(sent)==1


def test_v2_import_no_io_uuid_optional_identity_parity(wire_v2):
    request_id='123e4567-e89b-42d3-a456-426614174000'
    result=export_purchase_import_descriptor(wire_v2.request,'0x'+'ef'*32,wire_v2.terms,import_request_id=request_id)
    assert set(result)=={'schema_version','import_request_id','request','request_digest','purchase_terms','purchase_terms_digest','transaction_hash'}
    assert result['schema_version']=='ln_church.paid_service_trial_sample_import_request.v2'
    assert result['request']==wire_v2.request and result['import_request_id']==request_id
    assert result['purchase_terms_digest']==wire_v2.claim['purchase_terms_digest']
    assert result==export_purchase_import_descriptor(wire_v2.request,'0x'+'ef'*32,wire_v2.terms,import_request_id=request_id)
    assert 'purchase' not in result
    with pytest.raises(ValueError):export_purchase_import_descriptor(wire_v2.request['url'],'0x'+'ef'*32,wire_v2.terms)


@pytest.mark.parametrize('boundary',['wallet','host','budget','sealed_block','missing_pack'])
def test_v2_guards_prevent_signing_and_paid_send(wire_v2,lane_v2,monkeypatch,boundary):
    lane=lane_v2
    class NoSigner:
        address=wire_v2.credential.reward_address
        def generate_eip3009_payload_atomic(self,*args,**kwargs):
            pytest.fail('Guard must stop before signing')
    signer=NoSigner();lane.executor._signer=signer
    if boundary=='wallet':signer.address='0x'+'45'*20
    if boundary=='host':lane.policy.allowed_hosts=['different.example.com']
    if boundary=='budget':lane.policy.max_spend_per_tx_usd=0
    if boundary=='sealed_block':lane.guard.ready=lambda value:False
    if boundary=='missing_pack':
        monkeypatch.setattr(c,'load_contract_bundle',lambda version:c._load_v2_contract_bundle())
        # This case exercises absent resources independently of producer intake.
        monkeypatch.setattr(c,'__file__',str(lane.journal.path.parent/'missing'/'contract.py'))
    if boundary=='sealed_block':
        assert lane.executor.execute(wire_v2.credential,journal=lane.journal).state=='NO_DISPATCH'
    else:
        with pytest.raises(ValueError):lane.executor.execute(wire_v2.credential,journal=lane.journal)
    assert lane.http.paid==0
    if boundary in ('wallet','missing_pack'):assert lane.http.unpaid==0


def test_invalid_saved_request_fails_before_dns(wire_v2):
    def no_dns(*args,**kwargs):pytest.fail('Invalid R reached DNS')
    from ln_church_agent.network_fetch import NetworkFetchError
    http=PaidServiceTrialHTTPS(resolver=no_dns)
    for key,value in [('method','DELETE'),('body','{}'),('body_sha256','f'*64),('url','https://localhost/')]:
        invalid=dict(wire_v2.request);invalid[key]=value
        with pytest.raises((ValueError,NetworkFetchError)):http.fetch(invalid)


@pytest.mark.parametrize('patch',[
    {'chain_id':1},{'parameters':{'amount':'999'}},
    {'contract':'0x'+'45'*20},{'token_address':'0x'+'45'*20},
    {'destination':'0x'+'45'*20},{'parameters':{'chain_id':1}},
    {'parameters':{'network':'eip155:1'}},{'parameters':{'asset':'0x'+'45'*20}},
])
@pytest.mark.parametrize('placement',['header','marked_body'])
def test_c2_recognized_conditions_reject_before_signing(wire_v2,lane_v2,patch,placement):
    bad=copy.deepcopy(wire_v2.terms['requirements']);bad.update(patch)
    body=dict(x402Version=2,resource={'url':wire_v2.request['url']},accepts=[bad])
    response=(terms_response(wire_v2,conditions=[bad]) if placement=='header'
              else terms_response(wire_v2,json.dumps(body).encode()))
    calls=[]
    def fetch(request,*,payment_signature=None):
        assert payment_signature is None,'Contradictory terms reached paid dispatch'
        calls.append(request);return response
    class NoSigner:
        address=wire_v2.credential.reward_address
        def generate_eip3009_payload_atomic(self,*args,**kwargs):pytest.fail('Contradictory terms reached signing')
    lane_v2.http.fetch=fetch;lane_v2.executor._signer=NoSigner()
    with pytest.raises(PaidServiceTrialTermsError) as caught:
        lane_v2.executor.execute(wire_v2.credential,journal=lane_v2.journal)
    assert caught.value.reason=='conflicting_payment_terms'
    assert calls==[wire_v2.request]
    assert not lane_v2.journal.snapshot()['paid_dispatch_reserved']


def test_c2_consistent_aliases_and_payment_parameters(wire_v2):
    raw=copy.deepcopy(wire_v2.terms['requirements'])
    raw.update(chain_id=8453,contract=raw['asset'],token_address=raw['asset'],destination=raw['payTo'],
        parameters={'network':raw['network'],'chainId':8453,'chain_id':8453,
            'asset':raw['asset'],'contract':raw['asset'],'token_address':raw['asset'],
            'amount':raw['amount'],'payTo':raw['payTo'],'destination':raw['payTo'],
            'description':'Unrelated seller explanation'})
    body=dict(x402Version=2,resource={'url':wire_v2.request['url']},accepts=[raw,raw])
    assert current_v2_terms(terms_response(wire_v2,json.dumps(body).encode()),wire_v2.terms,wire_v2.request).wire()==wire_v2.terms


@pytest.mark.parametrize('placement',['header','marked_body'])
def test_c2_equivalent_provider_url_compares_to_frozen_request(wire_v2,placement):
    body=dict(x402Version=2,resource={'url':'https://SELLER.example.com:443/paid?x=1'},accepts=[wire_v2.terms['requirements']])
    response=(PaidTrialHTTPResponse(402,[('PAYMENT-REQUIRED',base64.b64encode(json.dumps(body).encode()).decode())],b'')
              if placement=='header' else terms_response(wire_v2,json.dumps(body).encode()))
    original=copy.deepcopy(wire_v2.request)
    assert current_v2_terms(response,wire_v2.terms,wire_v2.request).wire()==wire_v2.terms
    assert wire_v2.request==original
    body['resource']['url']='https://SELLER.example.com:443/different?x=1'
    bad=(PaidTrialHTTPResponse(402,[('PAYMENT-REQUIRED',base64.b64encode(json.dumps(body).encode()).decode())],b'')
         if placement=='header' else terms_response(wire_v2,json.dumps(body).encode()))
    with pytest.raises(PaidServiceTrialTermsError) as caught:current_v2_terms(bad,wire_v2.terms,wire_v2.request)
    assert caught.value.reason=='resource_mismatch'


@pytest.mark.parametrize('parameters',[
    {'chain_id':'8453','amount':1000,'asset':'USDC'},
    {'chain_id':'0'*100+'8453','description':{'amount':'unrelated text'}},
])
def test_c2_equivalent_provider_parameter_representations(wire_v2,parameters):
    raw=dict(wire_v2.terms['requirements'],parameters=parameters)
    assert current_v2_terms(terms_response(wire_v2,conditions=[raw]),wire_v2.terms,wire_v2.request).wire()==wire_v2.terms


@pytest.mark.parametrize('parameters',[None,[],{'permit2':{}},{'assetTransferMethod':'permit2'}])
def test_c2_malformed_or_unsupported_parameter_conditions(wire_v2,parameters):
    raw=dict(wire_v2.terms['requirements'],parameters=parameters)
    with pytest.raises(PaidServiceTrialTermsError):current_v2_terms(terms_response(wire_v2,conditions=[raw]),wire_v2.terms,wire_v2.request)
