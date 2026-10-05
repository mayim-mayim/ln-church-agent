"""SDK requester boundaries, using synthetic wallets and the fixed Hondo adapter."""
import base64
import copy
import json
import os
import pickle
import subprocess
import time
from pathlib import Path
import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data
from ln_church_agent.crypto.evm import LocalKeyAdapter
from ln_church_agent.offer_registration import (
    OfferRegistrationClient,OfferRegistrationError,RegistrationReadResult,RegistrationReadChallenge,
    DOMAIN,TYPES,PATH,READ_PATH,_resource,
)
from ln_church_agent import endpoint_choice_reason_contract as c
from ln_church_agent.immediate_visit_client import AgentImmediateVisitClient
from ln_church_agent.immediate_visit_transport import ImmediateVisitTransport,ImmediateVisitRawResponse

# Public synthetic fixture identity, never funded or used against external services.
SEED='17'*32

def request(kind='endpoint_choice_reason.v1'):
    if kind.startswith('endpoint_choice_reason.'):return dict(task_type=kind,plan_id='C5',question='Which API fits?',
        candidates=[dict(candidate_id='a',url='https://example.com/',evaluator_description='PRIVATE_SYNTHETIC_CONTEXT')],
        correct_candidate_ids=['a'],reveal_correct_set_after_answer=False)
    return dict(task_type=kind,plan_id='C50',repeat_policy='allow',urls=['https://example.com/'])


def signature(typed):
    return '0x'+Account.from_key(SEED).sign_message(encode_typed_data(full_message=typed)).signature.hex().removeprefix('0x')


class Bridge:
    def __init__(self):
        root=os.environ.get('HONDO_ROOT')
        if not root: pytest.skip('Fixed isolated Hondo source not supplied')
        env=dict(os.environ,AWS_EC2_METADATA_DISABLED='true')
        self.proc=subprocess.Popen(['node',str(Path(__file__).parent/'fixtures/v189/hondo-bridge.mjs')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
        self.calls=[]
    def send(self,value):
        self.proc.stdin.write(json.dumps(value)+'\n');self.proc.stdin.flush()
        line=self.proc.stdout.readline()
        if not line: raise AssertionError('Bridge exited: '+self.proc.stderr.read()[-3000:])
        result=json.loads(line)
        assert 'bridge_error' not in result,result
        return result
    def __call__(self,method,path,query,headers,body,timeout,**kwargs):
        self.calls.append((method,path,query,dict(headers),body))
        result=self.send(dict(method=method,path=path,query=query,headers=headers,body=body.decode()))
        if result is None: return ImmediateVisitRawResponse(404,{},b'{}')
        return ImmediateVisitRawResponse(result.get('status',result.get('statusCode')),result.get('headers',{}),
            result['body'].encode() if isinstance(result['body'],str) else json.dumps(result['body']).encode())
    def close(self):
        self.proc.stdin.close();self.proc.wait(timeout=10)
        assert self.proc.returncode==0,self.proc.stderr.read()


@pytest.fixture
def bridge():
    b=Bridge()
    try:yield b
    finally:b.close()


def client(bridge):
    return OfferRegistrationClient(transport=ImmediateVisitTransport(exchange=bridge, version='v2'),wall_time=lambda:bridge.send({'control':'counts'})['now']/1000)


def signed(cli,kind=c.TASK_TYPE):
    quote=cli.prepare_registration(request(kind));operation=quote.sign(LocalKeyAdapter(SEED))
    assert quote.sign(None) is operation
    return operation


@pytest.mark.parametrize('kind',[c.TASK_TYPE,'endpoint_choice_reason.v2','immediate_http_visit.v1','immediate_http_visit.v2','immediate_http_visit.v3'])
def test_real_registration_and_saved_response_read(kind,bridge):
    cli=client(bridge);op=signed(cli,kind)
    assert len(bridge.calls)==1 and not any(k.lower()=='payment-signature' for k in bridge.calls[0][3])
    assert op.operation_ref and op.profile
    result=cli.submit_registration(op)
    assert result['task_type']==kind and result['status']=='OPEN'
    assert cli.submit_registration(op)==result
    ch=cli.get_registration_challenge(kind,op.operation_ref,op.payer)
    proof=ch.sign(signature,now=bridge.send({'control':'counts'})['now']/1000)
    before=bridge.send({'control':'counts'})
    a=cli.read_registration(proof);b=cli.read_registration(proof)
    assert a==b and a.kind=='COMMITTED' and a.result==result and a.status is None
    after=bridge.send({'control':'counts'})
    assert before['settles']==after['settles']==1 and before['verifies']==after['verifies']==1
    for _,path,query,headers,body in bridge.calls[2:]:
        assert query is None and all(k.lower() not in ('payment-signature','x-payment') for k in headers)
    for private in [op,ch,proof]:
        assert 'PRIVATE_SYNTHETIC_CONTEXT' not in repr(private)
        with pytest.raises(TypeError):pickle.dumps(private)


@pytest.mark.parametrize('kind',[c.TASK_TYPE,'endpoint_choice_reason.v2','immediate_http_visit.v1','immediate_http_visit.v2','immediate_http_visit.v3'])
def test_response_lost_recovers_by_ref_and_replay_is_exact(kind,bridge):
    cli=client(bridge);op=signed(cli,kind);original=bridge.__call__
    def lose(*args,**kwargs):
        response=original(*args,**kwargs)
        raise OSError('SYNTHETIC private response lost')
    cli._transport._exchange=lose
    with pytest.raises(OfferRegistrationError,match='REGISTRATION_OUTCOME_UNKNOWN'):cli.submit_registration(op)
    cli._transport._exchange=bridge
    before=len(bridge.calls)
    with pytest.raises(OfferRegistrationError,match='REGISTRATION_OUTCOME_UNKNOWN'):cli.submit_registration(op)
    assert len(bridge.calls)==before
    # Fresh client with only saved nonsecret reference and explicit read signature.
    fresh=client(bridge);proof=fresh.get_registration_challenge(kind,op.operation_ref,op.payer).sign(signature)
    read=fresh.read_registration(proof)
    assert read.kind=='COMMITTED'
    assert cli.submit_registration(op,replay=True)==read.result
    paid=[call for call in bridge.calls if 'PAYMENT-SIGNATURE' in call[3]]
    assert len(paid)==2 and paid[0][3]==paid[1][3] and paid[0][4]==paid[1][4]
    assert bridge.send({'control':'counts'})['settles']==1


def test_pending_then_expired_authorization_read_and_explicit_proof_renewal(bridge):
    bridge.send({'control':'configure','confirmed':False});cli=client(bridge);op=signed(cli)
    result=cli.submit_registration(op)
    assert isinstance(result,RegistrationReadResult) and result.kind=='STATUS' and result.result is None
    ch=cli.get_registration_challenge(op.task_type,op.operation_ref,op.payer);proof=ch.sign(signature)
    assert cli.read_registration(proof).kind=='STATUS'
    bridge.send({'control':'configure','advance':301000,'confirmed':True})
    before=len(bridge.calls)
    with pytest.raises(OfferRegistrationError,match='READ_PROOF_EXPIRED'):cli.read_registration(proof)
    assert len(bridge.calls)==before
    bridge.send({'control':'reconcile','type':op.task_type,'ref':op.operation_ref})
    proof=cli.get_registration_challenge(op.task_type,op.operation_ref,op.payer).sign(signature,now=bridge.send({'control':'counts'})['now']/1000)
    assert cli.read_registration(proof).kind=='COMMITTED'
    assert bridge.send({'control':'counts'})['settles']==1


def test_wrong_payer_bad_proof_erc1271_and_unavailable(bridge):
    cli=client(bridge);op=signed(cli);cli.submit_registration(op)
    other=Account.from_key('18'*32)
    proof=cli.get_registration_challenge(op.task_type,op.operation_ref,other.address).sign(
        lambda typed:'0x'+other.sign_message(encode_typed_data(full_message=typed)).signature.hex().removeprefix('0x'))
    with pytest.raises(OfferRegistrationError,match='registration_recovery_unavailable'):cli.read_registration(proof)
    proof=cli.get_registration_challenge(op.task_type,op.operation_ref,op.payer).sign(lambda t:'0x1234')
    with pytest.raises(OfferRegistrationError,match='invalid_recovery_proof'):cli.read_registration(proof)
    bridge.send({'control':'configure','contractCode':'0x1234'})
    assert cli.read_registration(proof).kind=='COMMITTED'
    bridge.send({'control':'configure','contractValid':False})
    with pytest.raises(OfferRegistrationError,match='invalid_recovery_proof'):cli.read_registration(proof)
    bridge.send({'control':'configure','rpcFails':True})
    with pytest.raises(OfferRegistrationError,match='recovery_temporarily_unavailable'):cli.read_registration(proof)
    assert bridge.send({'control':'counts'})['settles']==1


@pytest.mark.parametrize('delta',[{'correct_candidate_ids':[]},{'repeat_policy':'allow'}, {'question':' '},
    {'candidates':[dict(candidate_id='a',url='http://example.com/')]}, {'plan_id':'C50'}])
def test_invalid_input_precedes_payment_and_network(delta):
    def no_send(*a,**k):pytest.fail('Invalid registration must not reach network')
    cli=client_no_clock=OfferRegistrationClient(transport=ImmediateVisitTransport(exchange=no_send, version='v2'))
    with pytest.raises(OfferRegistrationError):cli.prepare_registration(dict(request(),**delta))


@pytest.mark.parametrize('field,value',[('network','eip155:84532'),('amount','1000001'),('asset','0x'+'a'*40),('maxTimeoutSeconds',True),('payTo','0x'+'0'*40)])
def test_payment_terms_rejected_before_sign(field,value):
    req=dict(scheme='exact',network='eip155:8453',asset=c.ASSET,amount='1000000',payTo='0x'+'2'*40,maxTimeoutSeconds=300,extra=dict(name='USD Coin',version='2'))
    req[field]=value
    body=dict(x402Version=2,resource=_resource(c.TASK_TYPE),accepts=[req])
    raw=ImmediateVisitRawResponse(402,{'PAYMENT-REQUIRED':base64.b64encode(json.dumps(body).encode()).decode()},json.dumps(body).encode())
    cli=OfferRegistrationClient(transport=ImmediateVisitTransport(exchange=lambda *a,**k:raw, version='v2'))
    with pytest.raises(OfferRegistrationError):cli.prepare_registration(request())


@pytest.mark.parametrize('version',['v1','v2','v3'])
def test_immediate_convenience_uses_selected_version(version,bridge):
    cli=AgentImmediateVisitClient(version=version,transport=ImmediateVisitTransport(exchange=bridge, version='v2'))
    quote=cli.prepare_registration(plan_id='C50',repeat_policy='allow',urls=['https://example.com/'])
    op=quote.sign(LocalKeyAdapter(SEED))
    assert op.task_type=='immediate_http_visit.'+version
    assert cli.registration_client().submit_registration(op)['task_type']==op.task_type

@pytest.mark.parametrize('version',['v1','v2','v3'])
def test_actual_immediate_worker_preserves_original_version_and_report(version,bridge,tmp_path,monkeypatch):
    from ln_church_agent.immediate_visit_models import FrozenImmediateVisitReport
    from ln_church_agent.immediate_visit_journal import ImmediateVisitJournal
    from ln_church_agent.immediate_visit import ImmediateVisitExecutor
    cli=client(bridge);op=signed(cli,'immediate_http_visit.'+version);registered=cli.submit_registration(op)
    worker=AgentImmediateVisitClient(version=version,transport=ImmediateVisitTransport(exchange=bridge, version='v2'))
    task=worker.get_task(registered['task_id']);claim=worker.claim_task(task.task_id,'fixture',op.payer,idempotency_key='worker')
    tmp_path.chmod(0o700);journal=ImmediateVisitJournal(tmp_path,claim)
    report=FrozenImmediateVisitReport.from_report(dict(schema_version='ln_church.task_completion.immediate_visit.'+version,
        task_id=claim.task_id,execution_id=claim.execution_id,submission_id='sub_'+'b'*32,endpoint_id=claim.endpoints[0].endpoint_id,
        profile_id=claim.profile_id,observation=dict(outcome='inconclusive',reason='dns_failed',status=None,media_family=None,body_bytes=None,
        fetch_started_at=claim.claimed_at,fetch_finished_at=claim.claimed_at)))
    journal.prepare_report(claim,report)
    result=worker.complete_task(claim,report,journal=journal)
    assert result.receipt.schema_version.endswith('.'+version)
    fresh_claim=ImmediateVisitJournal.load_claim(tmp_path,claim.task_id,claim.execution_id)
    reopened=ImmediateVisitJournal(tmp_path,fresh_claim)
    monkeypatch.setattr(ImmediateVisitExecutor,'_fetch',lambda *a,**k:pytest.fail('Saved report must not refetch target'))
    assert ImmediateVisitExecutor(journal=reopened).execute(fresh_claim,claim.endpoints[0].endpoint_id).canonical_bytes==report.canonical_bytes
    # Current default client must read the original credential version.
    current=AgentImmediateVisitClient(transport=ImmediateVisitTransport(exchange=bridge, version='v2'), version='v2')
    recovered=current.recover_completion(fresh_claim,report,journal=reopened)
    assert recovered.status.schema_version.endswith('.'+version)

@pytest.mark.parametrize('part,field,value',[('domain','name','LNChurch Offer Results'),('domain','chainId',84532),
    ('message','action','pay'),('message','profile','V17_STRICT_TASK_OFFER'),('message','operationRef','0'*64),
    ('message','audience','https://example.com/'),('message','payer','0x'+'1'*40)])
def test_read_challenge_cannot_change_purpose_or_binding(part,field,value,bridge):
    cli=client(bridge);op=signed(cli)
    ch=cli.get_registration_challenge(op.task_type,op.operation_ref,op.payer)
    wire=json.loads(ch._wire);wire['typed_data'][part][field]=value
    with pytest.raises((ValueError,OfferRegistrationError)):
        RegistrationReadChallenge(wire,op.task_type,op.operation_ref,op.payer,time.time())


def test_registration_example_import_and_actual_calls(bridge):
    import importlib.util
    p=Path(__file__).resolve().parents[1]/'examples/endpoint_choice_reason_registration.py'
    spec=importlib.util.spec_from_file_location('registration_example',p);example=importlib.util.module_from_spec(spec);spec.loader.exec_module(example)
    cli=client(bridge);quote=example.prepare(cli,request());op=example.authorize_payment(quote,LocalKeyAdapter(SEED))
    result=example.submit_original(cli,op)
    proof,saved=example.begin_read_recovery(cli,task_type=op.task_type,operation_ref=op.operation_ref,payer=op.payer,read_signer=signature)
    assert saved.result==result and example.continue_read_recovery(cli,proof)==saved
    restored=cli.restore_registration(request(),op._header)
    assert restored.operation_ref==op.operation_ref and cli.submit_registration(restored)==result
    assert bridge.send({'control':'counts'})['settles']==1
