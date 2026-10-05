"""Exact producer Backend + real SDK; provider, storage and keys are synthetic.

HONDO_ROOT must contain 90b06a6c58ec76b09f7adb9b430ce34f6d2a0b71.
No producer pack loader is replaced in this lane.
"""
import json
import os
import subprocess
from pathlib import Path
from decimal import Decimal
from types import SimpleNamespace
import pytest
from test_offer_registration import Bridge, SEED
from ln_church_agent import paid_service_trial_contract as c
from ln_church_agent.crypto.evm import LocalKeyAdapter
from ln_church_agent.models import PaymentPolicy
from ln_church_agent.paid_service_trial_client import PaidServiceTrialTaskClient
from ln_church_agent.paid_service_trial_transport import PaidServiceTrialTransport, PaidServiceTrialRawResponse
from ln_church_agent.paid_service_trial_journal import PaidServiceTrialJournal
from ln_church_agent.paid_service_trial import PaidServiceTrialExecutor, export_purchase_import_descriptor
from ln_church_agent.paid_service_trial_network import PaidTrialHTTPResponse


class PaidBridge(Bridge):
    def __init__(self):
        if not os.environ.get('HONDO_ROOT'):pytest.skip('Fixed Hondo input required')
        self.proc=subprocess.Popen(['node',str(Path(__file__).parent/'fixtures/post-v1810/paid-bridge.mjs')],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
            env=dict(os.environ,AWS_EC2_METADATA_DISABLED='true'))
        self.calls=[]
    def __call__(self,*args,**kwargs):
        out=super().__call__(*args,**kwargs)
        return PaidServiceTrialRawResponse(out.status_code,out.headers,out.body)


@pytest.fixture
def paid_bridge():
    b=PaidBridge()
    try:yield b
    finally:b.close()


def make_lane(b,method,tmp_path,policy):
    setup=b.send({'control':'setup','method':method});task=setup['task'];tmp_path.chmod(0o700)
    cli=PaidServiceTrialTaskClient(version='v3',claim_directory=tmp_path,
        transport=PaidServiceTrialTransport(version='v3',exchange=b))
    assert cli.get_task(task['task_id']).task_definition_digest==c.load_contract_bundle('v3')['manifest']['task_definition_digest']
    assert cli.list_tasks().tasks[0].request.method==method
    signer=LocalKeyAdapter(SEED)
    claim=cli.claim_task(task['task_id'],'sdk',signer.address,idempotency_key='fixed-claim')
    b.send({'control':'advance','ms':2000})
    class Seller:
        def fetch(self,request,*,payment_signature=None):
            out=b.send({'control':'seller','request':request,'payment':payment_signature})
            return PaidTrialHTTPResponse(out['status'],out['headers'],out['body'].encode())
    journal=PaidServiceTrialJournal(tmp_path,claim)
    executor=PaidServiceTrialExecutor(signer=signer,policy=policy,client=cli,http=Seller(),
        block_guard=SimpleNamespace(ready=lambda _:True),wall_time=lambda:b.send({'control':'counts'})['now']/1000)
    return SimpleNamespace(setup=setup,client=cli,claim=claim,journal=journal,executor=executor)


@pytest.mark.parametrize('method',['GET','POST'])
def test_fixed_paid_sample_purchase_report_lost_read_import(method,tmp_path,paid_bridge):
    b=paid_bridge;p=PaymentPolicy(max_spend_per_tx_usd=.1,max_spend_per_session_usd=.1)
    x=make_lane(b,method,tmp_path,p)
    s=x.setup
    assert s['samplePaid']==s['feeSettles']==1
    assert s['pending']['http_outcome']=='UNKNOWN' and s['replay']['operation_ref']==s['pending']['operation_ref']
    assert s['recovered']['payment_state']=='MATCHED' and s['recovered']['purchase']['amount']=='100000'
    assert s['retained']['result']==s['registration']
    original=b.__call__
    def lost(*args,**kwargs):
        out=original(*args,**kwargs)
        if args[0]=='POST' and args[1].endswith('/completion'):raise TimeoutError('Synthetic accepted Report response lost')
        return out
    x.client._transport._exchange=lost
    result=x.executor.execute(x.claim,journal=x.journal)
    assert result.state=='REPORTED' and result.report.model.purchase.amount=='100000'
    before=x.journal.snapshot();assert before['schema_version']=='ln_church.paid_service_trial_journal.v3'
    assert before['claim']['request']['schema_version']=='ln_church.paid_service_request.v2'
    assert b.send({'control':'counts'})['agentPaid']==1
    verified=b.send({'control':'verify','execution':x.claim.execution_id})
    assert verified=={'state':'VERIFIED','bad':'MISMATCH','reason':'amount_mismatch','evaluation':'APPROVED'}
    x.client._transport._exchange=b
    status=x.client.get_submission_status(x.claim,result.report)
    assert status.evaluation.state=='APPROVED'
    reopened=PaidServiceTrialJournal(tmp_path,PaidServiceTrialJournal.load_claim(tmp_path,x.claim.task_id,x.claim.execution_id))
    x.executor._signer=None
    x.executor.execute(x.claim,journal=reopened)
    assert b.send({'control':'counts'})['agentPaid']==1 and reopened.snapshot()['operation_id']==before['operation_id']
    assert p._budget_total('reserved')==Decimal('.1')
    body=export_purchase_import_descriptor(x.setup['task']['request'],'0x'+'a'*64,x.setup['task']['purchase_terms'],version='v3')
    imported=b.send({'control':'import','body':body})
    assert imported['pending']['operation_ref'].startswith('pi3_') and imported['result']['payment_state']=='MATCHED'


@pytest.mark.parametrize('denial',['tx','session','reserved','permission','signer'])
def test_fixed_paid_budget_and_permission_before_signature(denial,tmp_path,paid_bridge):
    p=PaymentPolicy(max_spend_per_tx_usd=.1,max_spend_per_session_usd=.1)
    x=make_lane(paid_bridge,'POST',tmp_path,p)
    if denial=='tx':p.max_spend_per_tx_usd=.01
    if denial=='session':p.max_spend_per_session_usd=.01
    if denial=='reserved':x.executor._reserve_policy(x.claim,'other')
    if denial=='permission':p.allowed_schemes=[]
    class NoSigner:
        address=x.claim.reward_address
        def generate_eip3009_payload_atomic(self,*a,**k):pytest.fail('Denied purchase reached signer')
    x.executor._signer=None if denial=='signer' else NoSigner()
    with pytest.raises(ValueError):x.executor.execute(x.claim,journal=x.journal)
    assert paid_bridge.send({'control':'counts'})['agentPaid']==0
    assert x.journal.snapshot()['report'] is None
