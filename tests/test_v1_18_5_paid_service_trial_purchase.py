import base64
import copy
import json
import os
from types import SimpleNamespace

import pytest
from eth_account import Account

from test_v1_18_5_paid_service_trial_contract import wire, FakeTaskTransport
from ln_church_agent import paid_service_trial_contract as c
from ln_church_agent.models import PaymentPolicy
from ln_church_agent.paid_service_trial import PaidServiceTrialExecutor, export_purchase_import_descriptor as _export_purchase_import_descriptor
from functools import partial
export_purchase_import_descriptor = partial(_export_purchase_import_descriptor, version='v1')
from ln_church_agent.paid_service_trial_client import PaidServiceTrialTaskClient
from ln_church_agent.paid_service_trial_journal import PaidServiceTrialJournal
from ln_church_agent.paid_service_trial_models import PurchaseTerms
from ln_church_agent.paid_service_trial_network import (
    PaidTrialHTTPResponse, BaseSealedBlockGuard, current_terms, normalize_requirements, PaidServiceTrialHTTPS,
)
from ln_church_agent.task_journal import JournalPersistenceError


class FakeHTTP:
    def __init__(self,wire):
        self.wire=wire;self.unpaid=0;self.paid=0;self.failure=False;self.status=200;self.header=None
        self.change=None
    def fetch(self,url,*,payment_signature=None):
        if payment_signature is None:
            self.unpaid+=1;req=copy.deepcopy(self.wire.terms['requirements'])
            if self.change:req.update(self.change)
            return PaidTrialHTTPResponse(402,[],json.dumps({'x402Version':2,'accepts':[req]}).encode())
        self.paid+=1
        payload=json.loads(base64.b64decode(payment_signature))
        self.authorization=payload['payload']['authorization']
        assert payload['resource']=={'url':self.wire.claim['endpoint']}
        assert payload['accepted']==self.wire.terms['requirements']
        assert self.authorization['from'].lower()==self.wire.claim['reward_address']
        assert self.authorization['validBefore']==str(self.wire.now+300)
        if self.failure:raise TimeoutError('private upstream text')
        headers=[] if self.header is None else [('PAYMENT-RESPONSE',self.header)]
        return PaidTrialHTTPResponse(self.status,headers,b'product is private')


@pytest.fixture
def lane(wire,tmp_path):
    tmp_path.chmod(0o700)
    journal=PaidServiceTrialJournal(tmp_path,wire.credential)
    http=FakeHTTP(wire);transport=FakeTaskTransport(wire)
    client=PaidServiceTrialTaskClient(version='v1', transport=transport)
    guard=SimpleNamespace(ready=lambda value:True)
    policy=PaymentPolicy(max_spend_per_tx_usd=.001,max_spend_per_session_usd=.001,allowed_hosts=['seller.example.com'])
    executor=PaidServiceTrialExecutor(signer=wire.signer,policy=policy,client=client,http=http,block_guard=guard,wall_time=lambda:wire.now)
    return SimpleNamespace(journal=journal,http=http,transport=transport,client=client,guard=guard,executor=executor,policy=policy)


def test_purchase_reports_without_hash_and_never_repeats(wire,lane):
    result=lane.executor.execute(wire.credential,journal=lane.journal)
    assert result.state=='REPORTED' and lane.http.paid==1
    assert result.completion.receipt_state=='accepted'
    assert result.report.model.purchase.authorization_nonce==lane.http.authorization['nonce']
    assert 'transaction_hash' not in json.loads(result.report.to_bytes())
    lane.executor.execute(wire.credential,journal=lane.journal)
    assert lane.http.paid==1 and lane.http.unpaid==1
    assert lane.policy._session_reserved_usd==.001


@pytest.mark.parametrize('status,failure',[(500,False),(403,False),(200,True)])
def test_failed_http_still_reports(wire,lane,status,failure):
    lane.http.status=status;lane.http.failure=failure
    result=lane.executor.execute(wire.credential,journal=lane.journal)
    assert result.state=='REPORTED' and len(lane.transport.posts)==1 and lane.http.paid==1
    assert result.http_outcome==('UNKNOWN' if failure else 'RESPONSE_RECEIVED')
    assert 'private upstream text' not in lane.journal.path.read_text()
    assert 'product is private' not in lane.journal.path.read_text()


def test_padded_locator_on_failed_http(wire,lane):
    lane.http.status=502
    lane.http.header=base64.b64encode(json.dumps({'transaction':'0x'+'bc'*32,'network':c.NETWORK,'success':True}).encode()).decode()
    result=lane.executor.execute(wire.credential,journal=lane.journal)
    assert result.report.model.transaction_hash=='0x'+'bc'*32
    assert result.http_status==502
    assert lane.journal.snapshot()['payload_digest']!=result.report.model.transaction_hash


def test_wrong_signer_or_unknown_claim_no_io(wire,lane):
    lane.executor._signer=SimpleNamespace(address=Account.create().address)
    with pytest.raises(ValueError):lane.executor.execute(wire.credential,journal=lane.journal)
    assert lane.http.paid==0 and lane.http.unpaid==0
    with pytest.raises(ValueError):lane.executor.execute(None,journal=lane.journal)
    assert lane.http.paid==0


@pytest.mark.parametrize('change',[
    {'amount':'1001'},{'network':'eip155:1'},{'asset':'0x'+'33'*20},
    {'payTo':'0x'+'23'*20},{'scheme':'permit2'},{'maxTimeoutSeconds':300},
    {'extra':{'name':'Evil Coin','version':'2'}},{'extra':{'name':'USD Coin','version':'2','assetTransferMethod':'permit2'}},
])
def test_terms_change_stops_before_signing(wire,lane,change):
    lane.http.change=change
    with pytest.raises(ValueError):lane.executor.execute(wire.credential,journal=lane.journal)
    assert lane.http.paid==0 and lane.journal.snapshot()['report'] is None


@pytest.mark.parametrize('body',[b'Payment required',b'{"error":"payment required"}',b''])
def test_complete_v2_header_and_irrelevant_body(wire,body):
    req=copy.deepcopy(wire.terms['requirements'])
    req['extra']['assetTransferMethod']='eip3009'
    header=base64.b64encode(json.dumps({'x402Version':2,'accepts':[req]}).encode()).decode()
    selected=PurchaseTerms.model_validate(wire.terms)
    assert current_terms(PaidTrialHTTPResponse(402,[('PAYMENT-REQUIRED',header)],body),selected)==selected


def test_header_body_conflict_or_partial_response_cannot_authorize(wire):
    req=copy.deepcopy(wire.terms['requirements'])
    header=base64.b64encode(json.dumps({'x402Version':2,'accepts':[req]}).encode()).decode()
    req['amount']='999'
    body=json.dumps({'x402Version':2,'accepts':[req]}).encode()
    selected=PurchaseTerms.model_validate(wire.terms)
    for response in (PaidTrialHTTPResponse(402,[('PAYMENT-REQUIRED',header)],body),
                     PaidTrialHTTPResponse(402,[('PAYMENT-REQUIRED',header)],b'',False)):
        with pytest.raises(ValueError):current_terms(response,selected)


@pytest.mark.parametrize('field,value',[
    ('max_spend_per_tx_usd',.0009999),('max_spend_per_session_usd',.0009999),
    ('allowed_hosts',[]),('blocked_hosts',['seller.example.com']),('allowed_networks',['eip155:1']),('allowed_schemes',[]),('allowed_assets',[]),
])
def test_policy_does_not_use_reward_to_finance_purchase(wire,lane,field,value):
    setattr(lane.policy,field,value)
    with pytest.raises(ValueError):lane.executor.execute(wire.credential,journal=lane.journal)
    assert lane.http.paid==0


@pytest.mark.parametrize('method',['prepare','reserve_paid_dispatch'])
def test_storage_fault_before_dispatch_no_spend(wire,lane,monkeypatch,method):
    def fail(*a,**k):raise JournalPersistenceError()
    monkeypatch.setattr(lane.journal,method,fail)
    with pytest.raises(JournalPersistenceError):lane.executor.execute(wire.credential,journal=lane.journal)
    assert lane.http.paid==0


def test_disk_fsync_fault_before_dispatch(wire,lane,monkeypatch):
    from ln_church_agent import immediate_visit_journal
    monkeypatch.setattr(immediate_visit_journal.os,'fsync',lambda fd:(_ for _ in ()).throw(OSError('private')))
    with pytest.raises(JournalPersistenceError):lane.executor.execute(wire.credential,journal=lane.journal)
    assert lane.http.paid==0


def test_guard_unavailable_allows_no_dispatch(wire,lane):
    lane.guard.ready=lambda _:False
    result=lane.executor.execute(wire.credential,journal=lane.journal)
    assert result.state=='NO_DISPATCH' and result.reason=='sealed_block_unavailable'
    assert lane.http.paid==0 and not lane.transport.posts


def block(timestamp):
    return dict(number='0x10',timestamp=hex(timestamp),hash='0x'+'aa'*32,parentHash='0x'+'bb'*32,
                stateRoot='0x'+'cc'*32,receiptsRoot='0x'+'dd'*32,transactionsRoot='0x'+'ee'*32,
                nonce='0x'+'00'*8,logsBloom='0x'+'00'*256,gasLimit='0x100',gasUsed='0x0',size='0x1',transactions=[])


def test_sealed_guard_exact_schedule_budget_and_no_same_second(wire):
    now=[0.0];calls=[]
    def rpc(method,params,timeout):
        calls.append((method,now[0],timeout))
        return '0x2105' if method=='eth_chainId' else block(wire.now-2)
    guard=BaseSealedBlockGuard(rpc=rpc,monotonic=lambda:now[0],sleep=lambda n:now.__setitem__(0,now[0]+n))
    assert not guard.ready(wire.claim['purchase_block_timestamp_exclusive_min'])
    assert [x[1] for x in calls[1:]]==[0,1,3,6]
    assert all(x[2]<=5 for x in calls)


@pytest.mark.parametrize('edit',[{'hash':None},{'stateRoot':None},{'nonce':'0x0'},{'transactions':None},{'number':None}])
def test_pending_flashblock_is_not_sealed(wire,edit):
    sample=block(wire.now);sample.update(edit)
    guard=BaseSealedBlockGuard(rpc=lambda m,p,t:'0x2105' if m=='eth_chainId' else sample,sleep=lambda _:None)
    assert not guard.ready(wire.claim['purchase_block_timestamp_exclusive_min'])


def test_wrong_chain_stops_block_reads(wire):
    calls=[]
    guard=BaseSealedBlockGuard(rpc=lambda m,p,t:calls.append(m) or '0x1')
    assert not guard.ready(wire.claim['purchase_block_timestamp_exclusive_min'])
    assert calls==['eth_chainId']


def test_no_default_payout_cooldown_or_wallet_fence(wire,lane,tmp_path):
    first=lane.executor.execute(wire.credential,journal=lane.journal)
    # Existing server response is sufficient for a different explicit Claim;
    # payout status does not become a client admission condition.
    from ln_church_agent.paid_service_trial_models import PaidServiceTrialClaim
    claim=PaidServiceTrialClaim.model_validate(dict(wire.claim,execution_id='next-execution'))
    lane.policy.max_spend_per_session_usd=.002
    next_journal=PaidServiceTrialJournal(tmp_path,claim)
    lane.executor.execute(claim,journal=next_journal)
    assert lane.http.paid==2


def test_import_descriptor_is_nonsecret_and_no_purchase(wire,lane):
    result=lane.executor.execute(wire.credential,journal=lane.journal)
    descriptor=export_purchase_import_descriptor(wire.claim['endpoint'],'0x'+'aa'*32,wire.terms,result.report.model.purchase)
    assert lane.http.paid==1
    assert set(descriptor)=={'schema_version','import_request_id','endpoint','purchase_terms_digest','transaction_hash','purchase'}
    assert 'signature' not in json.dumps(descriptor) and 'claim_token' not in json.dumps(descriptor)
    # Tx-only import does not run the local EOA signing validator.
    assert 'purchase' not in export_purchase_import_descriptor(wire.claim['endpoint'],'0x'+'aa'*32,wire.terms)


def test_alias_conflict_and_duplicate_json_stop(wire):
    req=copy.deepcopy(wire.terms['requirements']);req['maxAmountRequired']='999'
    with pytest.raises(ValueError):normalize_requirements(req)
    response=PaidTrialHTTPResponse(402,[],b'{"x402Version":2,"x402Version":1,"accepts":[]}')
    with pytest.raises(ValueError):current_terms(response,PurchaseTerms.model_validate(wire.terms))


def test_http_rejects_private_dns_without_connect(wire):
    calls=[]
    http=PaidServiceTrialHTTPS(resolver=lambda h,p:['127.0.0.1'],socket_factory=lambda *a:calls.append(a))
    response=http.fetch(wire.claim['endpoint'])
    assert not response.complete and calls==[]
