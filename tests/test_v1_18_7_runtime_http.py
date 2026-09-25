"""DC 0dbce748 §§2/4/5: real HTTP parser to ordinary Client/Executor/Journal.

Only sockets/TLS, synthetic signer/chain and LN API exchange are controlled.
No parser monkey-patch, response adapter, external request or real payment.
"""
import base64
import copy
import json
import multiprocessing
import ssl
from types import SimpleNamespace

import pytest
from test_v1_18_5_paid_service_trial_contract import wire
from test_v1_18_5_paid_service_trial_http_v2_contract import wire_v2
from test_v1_18_5_paid_service_trial_accepted_address import address_lane
from test_v1_18_6_issue21_claim_recovery import Server
from ln_church_agent import paid_service_trial_network as net
from ln_church_agent import paid_service_trial_contract as c
from ln_church_agent import paid_service_trial_journal as j
from ln_church_agent.network_fetch import _parse_immediate_visit_head
from ln_church_agent.paid_service_trial_client import PaidServiceTrialTaskClient
from ln_church_agent.paid_service_trial_transport import PaidServiceTrialTransport, PaidServiceTrialTransportError
from ln_church_agent.task_journal import JournalPersistenceError


def b64(value):return base64.b64encode(json.dumps(value).encode()).decode()


def wire_response(status=402,headers=(),body=b''):
    return (f'HTTP/1.1 {status} Synthetic\r\n'.encode()
        + b''.join((k+': '+v+'\r\n').encode() for k,v in headers)
        + f'Content-Length: {len(body)}\r\n\r\n'.encode()+body)


def standard_https(replies):
    trace=SimpleNamespace(sent=[],connects=[],sni=[],responses=[],remaining=list(replies))
    class Socket:
        def __init__(self,*a):self.reply=trace.remaining.pop(0)
        def connect(self,target):trace.connects.append(target)
        def getpeername(self):return ('8.8.8.8',443)
        def settimeout(self,value):assert value>0
        def sendall(self,value):trace.sent.append(value)
        def recv(self,n):
            if isinstance(self.reply,Exception):raise self.reply
            result=self.reply[:n];self.reply=self.reply[n:];return result
        def close(self):pass
    class TLS:
        verify_mode=ssl.CERT_REQUIRED
        check_hostname=True
        def wrap_socket(self,socket,**kw):trace.sni.append(kw['server_hostname']);return socket
    return net.PaidServiceTrialHTTPS(resolver=lambda *a:['8.8.8.8'],socket_factory=Socket,
        ssl_context_factory=TLS),trace


def terms(w):return dict(x402Version=2,resource={'url':w.request['url']},accepts=[w.terms['requirements']])


@pytest.mark.parametrize('name,body',[
    ('Payment-Required',b''),('PAYMENT-REQUIRED',b'<html>Pay</html>'),
    ('payment-required',b'{"message":"Pay"}'),
])
def test_standard_headers_and_ordinary_body(wire_v2,name,body):
    value=b64(terms(wire_v2))
    http,_=standard_https([wire_response(headers=[(name,value),(name,value)],body=body)])
    response=http.fetch(wire_v2.request)
    assert response.complete and [v for k,v in response.headers if k=='payment-required']==[value,value]
    assert net.current_v2_terms(response,wire_v2.terms,wire_v2.request).wire()==wire_v2.terms


@pytest.mark.parametrize('kind,reason',[
    ('missing','missing_payment_required'),('non402','expected_402'),('head-timeout','expected_402'),
    ('encoding','invalid_payment_required'),('base64','invalid_payment_required'),
    ('duplicate','conflicting_payment_terms'),('body-conflict','conflicting_payment_terms'),
    ('body-invalid','invalid_payment_required'),('framing','invalid_payment_required'),
    ('body-limit','invalid_payment_required'),('head-limit','expected_402'),
])
def test_standard_rejection_boundaries(wire_v2,kind,reason):
    value=terms(wire_v2);headers=[('Payment-Required',b64(value))];body=b'';status=402
    if kind=='missing':headers=[]
    if kind=='non402':status=200
    if kind=='encoding':headers.append(('Content-Encoding','gzip'))
    if kind=='base64':headers=[('Payment-Required','!!')]
    if kind=='duplicate':headers.append(('payment-required',b64(dict(value,accepts=[]))))
    if kind=='body-conflict':
        other=copy.deepcopy(value);other['accepts'][0]['amount']='999';body=json.dumps(other).encode()
    if kind=='body-invalid':body=b'{"x402Version":2,"resource":{},"accepts":[]}'
    if kind=='framing':headers.append(('Transfer-Encoding','chunked'))
    if kind=='body-limit':headers.append(('Content-Length',str(c.MAX_BODY_BYTES+1)))
    if kind=='head-limit':headers.append(('X-Description','x'*c.MAX_HEADER_BYTES))
    raw=TimeoutError('SYNTHETIC_PRIVATE') if kind=='head-timeout' else wire_response(status,headers,body)
    http,trace=standard_https([raw])
    with pytest.raises(net.PaidServiceTrialTermsError) as error:
        net.current_v2_terms(http.fetch(wire_v2.request),wire_v2.terms,wire_v2.request)
    assert error.value.reason==reason and len(trace.sent)==1


def test_shared_parser_default_projection_unchanged():
    raw=wire_response(headers=[('Payment-Required','abc'),('Payment-Response','def'),
        ('X-Private','secret'),('Content-Type','application/json')])
    _,old=_parse_immediate_visit_head(raw)
    _,paid=_parse_immediate_visit_head(raw,retain_payment_headers=True)
    assert old==(('content-type','application/json'),('content-length','0'))
    assert paid[:2]==(('payment-required','abc'),('payment-response','def'))
    assert not any(k=='x-private' for k,v in paid)


@pytest.mark.parametrize('mode',['normal','lost-restart','credential','journal'])
def test_claim_to_standard_http_and_resume(address_lane,monkeypatch,mode,record_property):
    lane=address_lane;server=Server(lane.w)
    original=j._write
    def exchange(method,path,query,headers,body,timeout):
        record=j._ClaimRequest(lane.tmp_path,lane.version,lane.w.claim['task_id'],'original-key').read()
        assert record['state']=='UNKNOWN' and record['body'].encode()==body
        assert record['idempotency_key']==headers['Idempotency-Key']=='original-key'
        return server.exchange(method,path,query,headers,body,timeout)
    def client():return PaidServiceTrialTaskClient(version=lane.version,claim_directory=lane.tmp_path,
        transport=PaidServiceTrialTransport(version=lane.version,exchange=exchange))
    def claim_call():return client().claim_task(lane.w.claim['task_id'],'synthetic-agent',lane.signer.address,idempotency_key='original-key')
    # Remove only fixture-created, unused initial files before this test's Claim.
    # This is synthetic setup, never recovery of a lost purchase journal.
    lane.journal.path.unlink();lane.journal.credential_path.unlink()
    if mode=='lost-restart':
        ctx=multiprocessing.get_context('fork');queue=ctx.Queue()
        def child():
            server.mode='lost'
            try:claim_call()
            except PaidServiceTrialTransportError as error:queue.put((error.code,server.original))
        process=ctx.Process(target=child);process.start();process.join(10)
        assert process.exitcode==0
        code,request=queue.get(timeout=2);assert code=='CLAIM_OUTCOME_UNKNOWN'
        server.original=request;server.allocations=1
        request_record=j._ClaimRequest(lane.tmp_path,lane.version,lane.w.claim['task_id'],'original-key')
        assert request_record.read()['state']=='UNKNOWN'
        assert not lane.journal.credential_path.exists() and not lane.journal.path.exists()
    elif mode in {'credential','journal'}:
        def fail(path,data):
            if (mode=='credential' and 'claim_token' in data or mode=='journal' and
                data.get('schema_version')=='ln_church.paid_service_trial_journal.'+lane.version):
                raise JournalPersistenceError()
            original(path,data)
        monkeypatch.setattr(j,'_write',fail)
        with pytest.raises(JournalPersistenceError):claim_call()
        monkeypatch.setattr(j,'_write',original)
        assert j._ClaimRequest(lane.tmp_path,lane.version,lane.w.claim['task_id'],'original-key').read()['state']=='RECEIVED'
    assert not lane.signer.calls and lane.http.paid==0
    # No execution ID or credential is supplied for recovery.
    claim=claim_call() if mode=='normal' else client().recover_claim(lane.w.claim['task_id'],idempotency_key='original-key')
    assert claim._private_payload()==lane.w.claim and server.allocations==1
    assert len(server.calls)==1  # child lost request is counted separately below
    lane.journal=j.PaidServiceTrialJournal(lane.tmp_path,claim)
    seller=lane.http
    raw=seller.requirements('checksum')
    value=dict(x402Version=2,resource={'url':c.target_url(claim)},accepts=[raw],
        extensions={'bazaar':{'info':{'input':{'type':'http','method':lane.method}}}})
    response=wire_response(headers=[('Payment-Required',b64(value))],body=b'{"message":"Pay"}')
    tx='0x'+'ab'*32
    paid=wire_response(200,[('Payment-Response',b64(dict(success=True,network=c.NETWORK,
        payer=lane.signer.address,transaction=tx)))],b'SYNTHETIC CONTENT')
    http,trace=standard_https([response]*(1 if lane.version=='v1' else 2)+[paid])
    lane.executor._http=http
    result=lane.executor.execute(claim,journal=lane.journal)
    assert result.state=='REPORTED' and lane.journal.snapshot()['transaction_hash']==tx
    assert result.report.model.transaction_hash==tx
    assert len(lane.signer.calls)==1
    saved=lane.journal.snapshot()
    lane.executor._signer=None
    lane.executor.execute(claim,journal=j.PaidServiceTrialJournal(lane.tmp_path,claim))
    assert len(trace.sent)==(2 if lane.version=='v1' else 3)
    assert sum(b'PAYMENT-SIGNATURE:' in x for x in trace.sent)==1
    for req in trace.sent:
        h,body=req.split(b'\r\n\r\n',1)
        assert h.startswith(lane.method.encode()+b' ') and b'HTTP/1.1' in h
        assert b'Accept: */*' in h and b'Accept-Encoding: identity' in h
        assert b'User-Agent: LNChurch-Paid-Trial/1.0' in h
        assert b'Cookie:' not in h and b'Authorization:' not in h
        assert body==(lane.target['body'].encode() if lane.version=='v2' and lane.method=='POST' else b'')
    actual=json.loads(base64.b64decode(trace.sent[-1].split(b'PAYMENT-SIGNATURE: ')[1].split(b'\r\n')[0]))
    assert actual['accepted']['asset']==raw['asset'] and actual['accepted']['payTo']==raw['payTo']
    assert set(trace.sni)=={'seller.example.com'} and all(x==('8.8.8.8',443) for x in trace.connects)
    assert lane.journal.snapshot()['report_sha256']==saved['report_sha256']
    # Only report acceptance; this synthetic header is not an independent witness.
    assert not any(x=='VERIFIED' or x=='paid_confirmed' for x in saved.values() if isinstance(x,str))
    record_property('runtime',json.dumps(dict(version=lane.version,method=lane.method,mode=mode,
        api_attempts=len(server.calls)+(mode=='lost-restart'),new_claims=server.allocations,
        same_claim=True,request_saved_before_send=True,unpaid_requests=1 if lane.version=='v1' else 2,
        paid_sends=1,restart_extra_paid_sends=0,live_payments=0)))


@pytest.mark.parametrize('kind',['invalid','conflicting','absent'])
def test_bad_locator_is_not_payment_authority(wire_v2,kind):
    value=b64(dict(success=True,network=c.NETWORK,payer=wire_v2.claim['reward_address'],transaction='0x'+'ab'*32))
    headers=[] if kind=='absent' else [('Payment-Response','!!' if kind=='invalid' else value)]
    if kind=='conflicting':headers.append(('payment-response',b64({'transaction':'0x'+'cd'*32})))
    http,_=standard_https([wire_response(200,headers)])
    response=http.fetch(wire_v2.request)
    assert response.complete and c.payment_response_locator(response.headers,payer=wire_v2.claim['reward_address']) is None
