"""Audited address delta §§2–4: actual executor headers, durable state, no resend.

All identities and signatures in exported matcher evidence are synthetic. The
crypto validator alone is replaced for this finite transport harness; existing
purchase tests exercise the unchanged real validator with ephemeral test keys.
"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from eth_utils import to_checksum_address

from test_v1_18_5_paid_service_trial_contract import wire, FakeTaskTransport
from test_v1_18_5_paid_service_trial_http_v2_contract import wire_v2, V2TaskTransport
from ln_church_agent import paid_service_trial_contract as c
from ln_church_agent import paid_service_trial as executor_module
from ln_church_agent.crypto.evm import derive_eip3009_requirement_nonce
from ln_church_agent.models import PaymentPolicy
from ln_church_agent.paid_service_trial import PaidServiceTrialExecutor
from ln_church_agent.paid_service_trial_client import PaidServiceTrialTaskClient
from ln_church_agent.paid_service_trial_journal import PaidServiceTrialJournal
from ln_church_agent.paid_service_trial_models import parse_claim
from ln_church_agent.paid_service_trial_network import PaidTrialHTTPResponse

PATHS = [('v1','GET'), ('v2','GET'), ('v2','POST')]
PAY_TO = '0xabcdef0123456789abcdef0123456789abcdef01'
PAYER = '0x'+'11'*20
SYNTHETIC_SIGNATURE = '0x'+'00'*65


def spelling(address, form):
    if form == 'checksum': return to_checksum_address(address)
    if form == 'mixed':
        # Mix supported spellings across the pair, not an invalid checksum.
        return to_checksum_address(address) if address==c.ASSET else address.lower()
    return address.lower()


class SyntheticSigner:
    address = PAYER
    def __init__(self): self.calls=[]
    def generate_eip3009_payload_atomic(self, asset, amount, pay_to, **kw):
        payload={'authorization':{'from':PAYER,'to':pay_to,'value':amount,
            'validAfter':'0','validBefore':str(kw['valid_before']),
            'nonce':derive_eip3009_requirement_nonce(kw['requirement_hash'],kw['idempotency_key'])},
            'signature':SYNTHETIC_SIGNATURE}
        self.calls.append(copy.deepcopy(payload))
        return payload


def validate_synthetic(payload, **kw):
    assert payload['signature']==SYNTHETIC_SIGNATURE
    auth=payload['authorization']
    assert auth['from']==kw['expected_signer']==PAYER
    assert auth['to']==kw['pay_to'] and auth['value']==kw['atomic_amount']
    assert auth['nonce']==kw['expected_nonce']
    assert int(auth['validBefore'])==kw['max_valid_before']>kw['now']
    assert kw['token_address']==c.ASSET and kw['chain_id']==8453


class Seller:
    def __init__(self, lane):
        self.lane=lane;self.unpaid=0;self.paid=0;self.headers=[];self.snapshots=[]
        self.form='checksum';self.final_form=None;self.body_only=False;self.alternatives=False
        self.metadata=False;self.patch=None;self.patch_at=1;self.lose_response=False
        self.crash_final=False;self.expire_final=False;self.seen=[]
    def requirements(self, form):
        raw=copy.deepcopy(self.lane.w.terms['requirements'])
        raw.update(asset=spelling(c.ASSET,form),payTo=spelling(PAY_TO,form))
        return raw
    def fetch(self, request, *, payment_signature=None):
        l=self.lane
        assert request==l.target
        self.seen.append(copy.deepcopy(request))
        if payment_signature is None:
            self.unpaid+=1
            if self.crash_final and self.unpaid==2: raise Interrupted()
            form=self.final_form if self.unpaid==2 and self.final_form else self.form
            raw=self.requirements(form)
            if self.patch and self.unpaid==self.patch_at: raw.update(self.patch)
            options=[raw]
            if self.alternatives:
                alternative=dict(self.requirements('lower'),amount='999',payTo='0x'+'bb'*20)
                options=[alternative,raw,self.requirements('lower'),raw]
            if self.metadata:
                raw['description']='SYNTHETIC-NON-ECHO';raw['extra']['description']='SYNTHETIC-NON-ECHO'
            envelope=dict(x402Version=2,resource={'url':c.target_url(l.w.credential)},accepts=options)
            other=copy.deepcopy(envelope)
            for item in other['accepts']:
                item['asset']=item['asset'].lower();item['payTo']=item['payTo'].lower()
            if l.version=='v2': other['accepts'].reverse()
            self.final_requirements=copy.deepcopy(raw)
            self.final_options=copy.deepcopy(options)
            if self.expire_final and self.unpaid==2:l.clock=l.w.now+301
            return PaidTrialHTTPResponse(402,[] if self.body_only else [('PAYMENT-REQUIRED',
                base64.b64encode(json.dumps(envelope).encode()).decode())],
                json.dumps(envelope if self.body_only else other).encode())
        self.paid+=1;self.headers.append(payment_signature)
        actual=json.loads(base64.b64decode(payment_signature))
        snapshot=l.journal.snapshot();self.snapshots.append(snapshot)
        assert snapshot['paid_dispatch_reserved'] and snapshot['report'] is not None
        assert snapshot['payload_digest']==c.version_digest(actual,l.version)
        assert actual['payload']==l.signer.calls[0]
        assert actual['accepted']['asset']==self.final_requirements['asset']
        assert actual['accepted']['payTo']==self.final_requirements['payTo']
        if self.lose_response:raise TimeoutError('SYNTHETIC-PRIVATE-RESPONSE')
        return PaidTrialHTTPResponse(502,[],b'SYNTHETIC-PRIVATE-RESPONSE')


class Interrupted(BaseException): pass


@pytest.fixture(params=PATHS,ids=['v1-GET','v2-GET','v2-POST'])
def address_lane(request,tmp_path,monkeypatch):
    version,method=request.param
    w=request.getfixturevalue('wire' if version=='v1' else 'wire_v2')
    w.terms=copy.deepcopy(w.terms);w.terms['requirements']['payTo']=PAY_TO
    w.claim=copy.deepcopy(w.claim);w.claim['purchase_terms']=w.terms;w.claim['reward_address']=PAYER
    if version=='v2':
        w.request=c.prepare_request(dict(method=method,url=w.request['url'],body='{"x":1.25,"e\\u0301":"😀"}' if method=='POST' else None))
        w.claim.update(request=w.request,request_digest=c.v2_digest(w.request),purchase_terms_digest=c.purchase_terms_digest(w.request,w.terms))
    # Recompute the same canonical offer identity after fixture-only edits.
    public={k:copy.deepcopy(w.task[k]) for k in ('plan_id','registration_amount_atomic','capacity_total','repeat_policy','reward')}
    public['purchase_terms']=w.terms
    if version=='v1':public['endpoint']=w.claim['endpoint']
    else:public.update({k:w.claim[k] for k in ('request','request_digest','purchase_terms_digest')})
    w.claim['terms_digest']=c.version_digest(public,version)
    w.credential=parse_claim(w.claim)
    tmp_path.chmod(0o700)
    journal=PaidServiceTrialJournal(tmp_path,w.credential)
    signer=SyntheticSigner();monkeypatch.setattr(executor_module,'validate_eip3009_payload',validate_synthetic)
    transport=FakeTaskTransport(w) if version=='v1' else V2TaskTransport(w)
    client=PaidServiceTrialTaskClient(version=version,transport=transport)
    l=SimpleNamespace(w=w,version=version,method=method,journal=journal,signer=signer,
        transport=transport,client=client,clock=w.now,tmp_path=tmp_path,target=c.target_request(w.credential))
    l.http=Seller(l)
    l.executor=PaidServiceTrialExecutor(signer=signer,client=client,http=l.http,
        policy=PaymentPolicy(max_spend_per_tx_usd=.001,max_spend_per_session_usd=.001,allowed_hosts=['seller.example.com']),
        block_guard=SimpleNamespace(ready=lambda _:True),wall_time=lambda:l.clock)
    return l


def run_and_check(l, label):
    claim_before=copy.deepcopy(l.w.credential.model_dump(mode='json'))
    result=l.executor.execute(l.w.credential,journal=l.journal)
    assert result.state=='REPORTED'
    assert (l.http.unpaid,l.http.paid,len(l.signer.calls))==(1 if l.version=='v1' else 2,1,1)
    actual=json.loads(base64.b64decode(l.http.headers[0]))
    assert actual['accepted']==dict(l.w.terms['requirements'],asset=l.http.final_requirements['asset'],payTo=l.http.final_requirements['payTo'])
    assert actual['resource']=={'url':c.target_url(l.w.credential)}
    assert l.w.credential.model_dump(mode='json')==claim_before
    assert result.report.model.terms_digest==l.w.claim['terms_digest']
    assert result.report.model.purchase.payTo==PAY_TO
    assert result.report.model.purchase.authorization_nonce==actual['payload']['authorization']['nonce']
    saved=l.journal.snapshot();assert saved['payload_digest']==c.version_digest(actual,l.version)
    assert saved['payload_digest']==hashlib.sha256(base64.b64decode(l.http.headers[0])).hexdigest()
    initial_envelope=copy.deepcopy(actual)
    initial_envelope['accepted'].update(asset=spelling(c.ASSET,l.http.form),payTo=spelling(PAY_TO,l.http.form))
    initial_digest=c.version_digest(initial_envelope,l.version)
    assert (initial_digest==saved['payload_digest'])==(initial_envelope==actual)
    for marker in ('SYNTHETIC-NON-ECHO','SYNTHETIC-PRIVATE-RESPONSE',SYNTHETIC_SIGNATURE,'claim_token',spelling(PAY_TO,'checksum')):
        assert marker not in l.journal.path.read_text()
    # Reopen persisted report/reservation with no signer; do not rewrite evidence.
    reopened=PaidServiceTrialJournal(l.tmp_path,l.w.credential)
    l.executor._signer=None;l.executor.execute(l.w.credential,journal=reopened)
    assert l.http.paid==1 and len(l.signer.calls)==1
    for key in ('operation_id','payload_digest','report','report_sha256','paid_dispatch_reserved'):
        assert reopened.snapshot()[key]==saved[key]
    out=os.environ.get('LN_ACCEPTED_ADDRESS_EVIDENCE')
    if out:
        path=Path(out);path.mkdir(parents=True,exist_ok=True)
        evidence=dict(case=f'{l.version}-{l.method}-{label}',synthetic=True,
            payment_signature=l.http.headers[0],actual_envelope=actual,
            seller_requirements=l.http.final_options,request=l.target,
            canonical_terms=l.w.terms,terms_digest=l.w.claim['terms_digest'],
            request_digest=l.w.claim.get('request_digest'),purchase_terms_digest=l.w.claim.get('purchase_terms_digest'),
            stored_envelope_digest=saved['payload_digest'],report_sha256=saved['report_sha256'],
            initial_spelling_envelope_digest=initial_digest,
            terms_calls=l.http.unpaid,signer_calls=len(l.signer.calls),paid_sends=l.http.paid,
            durable_before_send=True,restart_extra_sends=0,crypto_validator='synthetic shape/identity validation; existing tests cover real validator')
        (path/(evidence['case']+'.json')).write_text(json.dumps(evidence,indent=2)+'\n')
    return actual


@pytest.mark.parametrize('form',['checksum','mixed','lower'])
def test_actual_executor_preserves_seller_pair(address_lane,form):
    l=address_lane;l.http.form=form
    run_and_check(l,form)


def test_first_matching_pair_alternatives_duplicates_body_case_order(address_lane):
    l=address_lane;l.http.alternatives=True;l.http.metadata=True
    run_and_check(l,'alternatives')


@pytest.mark.parametrize('initial,final',[('lower','checksum'),('checksum','mixed'),('mixed','lower')])
def test_final_spelling_same_signature_nonce_and_canonical_identity(address_lane,initial,final):
    l=address_lane;l.http.form=initial
    if l.version=='v2':l.http.final_form=final
    else:l.http.body_only=True
    actual=run_and_check(l,'final-'+initial+'-'+final)
    assert actual['payload']==l.signer.calls[0]


@pytest.mark.parametrize('change',[
    {'payTo':'0x'+'34'*20},{'asset':'0x'+'34'*20},{'amount':'1001'},
    {'network':'eip155:1'},{'maxTimeoutSeconds':300},
    {'extra':{'name':'Other','version':'2'}},{'recipient':'0x'+'34'*20},
    {'asset':'0x'+c.ASSET[2:].upper()},
])
def test_real_condition_changes_still_stop_before_signing(address_lane,change):
    l=address_lane;l.http.patch=change
    with pytest.raises(ValueError):l.executor.execute(l.w.credential,journal=l.journal)
    assert l.http.paid==0 and l.signer.calls==[]
    assert l.journal.snapshot()['report'] is None


@pytest.mark.parametrize('final_failure',['change','expiry','interrupt'])
def test_failed_final_check_is_prepared_and_cannot_resign(address_lane,final_failure):
    l=address_lane
    if l.version=='v1':
        # v1 has no post-sign HTTP request; expire immediately after signing.
        generate=l.signer.generate_eip3009_payload_atomic
        def expire(*a,**kw):
            result=generate(*a,**kw);l.clock=l.w.now+301;return result
        l.signer.generate_eip3009_payload_atomic=expire
    elif final_failure=='change':l.http.patch={'amount':'1001'};l.http.patch_at=2
    elif final_failure=='expiry':l.http.expire_final=True
    else:l.http.crash_final=True
    if l.version=='v2' and final_failure in ('change','interrupt'):
        with pytest.raises(ValueError if final_failure=='change' else Interrupted):
            l.executor.execute(l.w.credential,journal=l.journal)
    else:assert l.executor.execute(l.w.credential,journal=l.journal).state=='NO_DISPATCH'
    saved=l.journal.snapshot();assert saved['report'] and not saved['paid_dispatch_reserved']
    calls=l.http.unpaid
    reopened=PaidServiceTrialJournal(l.tmp_path,l.w.credential)
    l.clock=l.w.now;l.executor._signer=None
    assert l.executor.execute(l.w.credential,journal=reopened).state=='NO_DISPATCH'
    assert l.http.paid==0 and l.http.unpaid==calls and len(l.signer.calls)==1
    assert reopened.snapshot()==saved


def test_lost_paid_response_never_repeats(address_lane):
    l=address_lane;l.http.lose_response=True
    run_and_check(l,'lost-response')
