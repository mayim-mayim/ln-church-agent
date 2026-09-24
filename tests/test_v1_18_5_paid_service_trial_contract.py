"""Requirements-derived test-only Wire examples; not a distributable pack."""
import base64
import copy
from datetime import datetime, timezone
import json
from types import SimpleNamespace

import pytest
from eth_account import Account

from ln_church_agent import paid_service_trial_contract as c
from ln_church_agent.crypto.evm import LocalKeyAdapter
from ln_church_agent.paid_service_trial_models import (
    PaidServiceTrialClaim, PaidServiceTrialTask, PurchaseTerms,
    PaidServiceTrialSubmissionStatus, FrozenPaidServiceTrialReport,
)
from ln_church_agent.paid_service_trial_transport import (
    PaidServiceTrialTransport, PaidServiceTrialRawResponse, PaidServiceTrialAPIError,
    PaidServiceTrialTransportError,
)
from ln_church_agent.paid_service_trial_client import PaidServiceTrialTaskClient


@pytest.fixture
def wire(monkeypatch):
    signer=LocalKeyAdapter(Account.create().key.hex())
    terms={'x402_version':2,'authorization_method':'EIP-3009','requirements':{
        'scheme':'exact','network':'eip155:8453','asset':c.ASSET,'amount':'1000',
        'payTo':'0x'+'12'*20,'maxTimeoutSeconds':900,'extra':{'name':'USD Coin','version':'2'}}}
    reward={'network':c.NETWORK,'asset':'USDC','asset_address':c.ASSET,'amount_atomic':'20000'}
    public={'endpoint':'https://seller.example.com/paid','purchase_terms':terms,'plan_id':'C40',
            'registration_amount_atomic':'1000000','capacity_total':40,'repeat_policy':'ALLOW_REPEAT','reward':reward}
    # No fixture bytes/hashes are installed into the formal contract directory.
    definition_digest='d'*64
    monkeypatch.setattr(c,'load_contract_bundle',lambda version='v1':{'manifest':{'task_definition_digest':definition_digest}})
    task=dict(public,schema_version=c.TASK_SCHEMA_VERSION,task_id='Case.Task~X',task_type=c.TASK_TYPE,
              task_definition_version='1.0.0',task_definition_digest=definition_digest,terms_digest=c.digest(public),
              status='OPEN',published_at='2026-09-21T00:00:00.000Z',listing_ends_at='2026-09-23T00:00:00.000Z',
              capacity_reserved=0,capacity_consumed=0,capacity_available=40,definition_url=c.DEFINITION_URL,
              summary_url=c.PUBLIC_API_ORIGIN+'/api/agent/task-offers/Case.Task~X/summary',
              results_url=c.PUBLIC_API_ORIGIN+'/api/agent/task-offers/Case.Task~X/execution-summaries')
    claim={k:task[k] for k in ('task_id','task_type','task_definition_version','task_definition_digest','terms_digest','endpoint','purchase_terms','repeat_policy','reward')}
    claim.update(schema_version='ln_church.agent_task_claim_response.paid_service_trial.v1',
                 execution_id='execution~opaque',claim_token=base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('='),
                 reward_address=signer.address.lower(),reward_address_control_verified=False,
                 claim_accepted_at='2026-09-21T00:00:00.000Z',report_deadline='2026-09-21T00:10:00.000Z',
                 purchase_block_timestamp_exclusive_min='1789948800')
    return SimpleNamespace(signer=signer,terms=terms,task=task,claim=claim,
                           credential=PaidServiceTrialClaim.model_validate(claim),now=1789948802)


def report_for(wire):
    claim=wire.claim
    data={k:claim[k] for k in ('task_id','task_type','task_definition_version','task_definition_digest','terms_digest','execution_id')}
    data.update(schema_version='ln_church.task_completion.paid_service_trial.v1',submission_id='sub_'+'a'*32,
                purchase={'network':c.NETWORK,'asset':c.ASSET,'payer':claim['reward_address'],
                          'authorization_nonce':'0x'+'ab'*32,'payTo':wire.terms['requirements']['payTo'],
                          'amount':'1000','validAfter':'0','validBefore':str(wire.now+300)})
    return FrozenPaidServiceTrialReport.from_dict(data)


def receipt_for(report):
    data=json.loads(report.to_bytes())
    return dict(schema_version='ln_church.task_completion_receipt.paid_service_trial.v1',
                **{k:data[k] for k in ('task_id','execution_id','submission_id','terms_digest')},
                report_sha256=report.report_sha256,receipt_state='accepted',
                received_at='2026-09-21T00:00:05.000Z',verification_deadline='2026-09-21T01:00:05.000Z',
                status_url=c.PUBLIC_API_ORIGIN+c.task_status_path(data['task_id'],data['submission_id']))


def status_for(report):
    data=receipt_for(report);data.pop('receipt_state');data.pop('status_url')
    data.update(schema_version='ln_church.task_submission_status.paid_service_trial.v1',
                purchase_verification={'state':'PENDING','reason':'receipt_pending','transaction_hash':None,'transaction_url':None,'verified_at':None},
                evaluation={'state':'PENDING','approved_amount_atomic':None,'evaluated_at':None},
                payout={'state':'not_applicable','transaction_hash':None,'transaction_url':None,'confirmed_paid_amount_atomic':'0','paid_confirmed_at':None},
                updated_at='2026-09-21T00:00:06.000Z')
    return data


class FakeTaskTransport:
    def __init__(self,wire):
        self.wire=wire;self.posts=[];self.reads=0;self.accepted=None;self.events=[]
        self.lose_response=False;self.fail_posts=False;self.conflict=False
    def close(self):pass
    def list_tasks(self,**kwargs):
        return {'schema_version':'ln_church.agent_task_page.paid_service_trial.v1','tasks':[self.wire.task],'next_cursor':None}
    def get_task(self,*args,**kwargs):return self.wire.task
    def claim_task(self,*args,**kwargs):return self.wire.claim
    def post_completion_bytes(self,task,token,submission,body,**kwargs):
        self.events.append('POST');self.posts.append((body,kwargs))
        if self.conflict:raise PaidServiceTrialAPIError('report_conflict',status_code=409)
        if self.fail_posts:raise PaidServiceTrialTransportError('TIMEOUT')
        self.accepted=FrozenPaidServiceTrialReport(body)
        if self.lose_response:raise PaidServiceTrialTransportError('TIMEOUT')
        return receipt_for(self.accepted)
    def get_submission_status(self,*args,**kwargs):
        self.events.append('GET');self.reads+=1
        if self.accepted is None:raise PaidServiceTrialAPIError('not_found',status_code=404)
        return status_for(self.accepted)


def test_exact_task_and_claim_roundtrips(wire):
    assert PaidServiceTrialTask.model_validate(wire.task).public_terms()['capacity_total']==40
    assert PaidServiceTrialClaim.model_validate(wire.credential)._private_payload()==wire.claim
    assert 'claim_token' not in wire.credential.model_dump()
    assert wire.claim['claim_token'] not in repr(wire.credential)
    terms=PurchaseTerms.model_validate(wire.terms)
    assert PurchaseTerms.model_validate(terms).wire()==wire.terms


@pytest.mark.parametrize('edit',[
    {'capacity_available':39},{'capacity_total':50},{'extra':'forbidden'},
    {'listing_ends_at':'2026-09-23T00:00:00.001Z'},{'terms_digest':'a'*64},
    {'capacity_reserved':False},{'definition_url':'https://evil.example.com/manifest.json'},
])
def test_reject_invalid_closed_task(wire,edit):
    with pytest.raises(ValueError):PaidServiceTrialTask.model_validate(dict(wire.task,**edit))


@pytest.mark.parametrize('edit',[
    {'report_deadline':'2026-09-21T00:10:00Z'}, {'reward_address_control_verified':0},
    {'purchase_block_timestamp_exclusive_min':'1789948801'}, {'execution_id':'bad/id'},
])
def test_claim_binding(wire,edit):
    with pytest.raises(ValueError):PaidServiceTrialClaim.model_validate(dict(wire.claim,**edit))


def test_report_locator_is_separate_and_null_rejected(wire):
    report=report_for(wire);new=report.supplement('0x'+'ff'*32)
    assert new.report_sha256==report.report_sha256
    assert new.submission_id==report.submission_id
    assert 'transaction_hash' not in json.loads(report.to_bytes())
    with pytest.raises(ValueError):FrozenPaidServiceTrialReport.from_dict(dict(json.loads(report.to_bytes()),transaction_hash=None))
    with pytest.raises(ValueError):FrozenPaidServiceTrialReport(report.to_bytes().replace(b'"amount":"1000"',b'"amount":"1000","amount":"1"'))


@pytest.mark.parametrize('encoding',[base64.b64encode,base64.urlsafe_b64encode])
def test_padded_settlement_locator(wire,encoding):
    value={'success':True,'transaction':'0x'+'aB'*32,'network':c.NETWORK,'payer':wire.signer.address}
    encoded=encoding(json.dumps(value).encode()).decode()
    assert c.payment_response_locator([('PaYmEnT-ReSpOnSe',encoded)],payer=wire.signer.address)=='0x'+'ab'*32


@pytest.mark.parametrize('raw',[
    b'[]',b'{"transaction":"x","transaction":"y"}',b'{"network":"eip155:1","transaction":"0x'+b'ab'*32+b'"}',
    b'{"transactionHash":"0x'+b'ab'*32+b'"}',
])
def test_invalid_locator_never_becomes_payment_failure(wire,raw):
    value=base64.b64encode(raw).decode()
    assert c.payment_response_locator([('payment-response',value)],payer=wire.signer.address) is None


def test_duplicate_headers_and_overlong_locator(wire):
    assert c.payment_response_locator([('payment-response','a'),('PAYMENT-RESPONSE','b')],payer=wire.signer.address) is None
    assert c.payment_response_locator([('payment-response','a'*32769)],payer=wire.signer.address) is None


def test_receipt_verification_approval_and_payout_distinct(wire):
    report=report_for(wire);pending=status_for(report)
    assert PaidServiceTrialSubmissionStatus.model_validate(pending).evaluation.approved_amount_atomic is None
    pending['purchase_verification'].update(state='VERIFIED',reason=None)
    pending['evaluation'].update(state='APPROVED',approved_amount_atomic='20000',evaluated_at='2026-09-21T00:00:07.000Z')
    pending['payout'].update(state='ambiguous',transaction_hash='0x'+'cd'*32,transaction_url='https://basescan.org/tx/0x'+'cd'*32)
    result=PaidServiceTrialSubmissionStatus.model_validate(pending)
    assert result.payout.confirmed_paid_amount_atomic=='0'
    pending['payout']['confirmed_paid_amount_atomic']='20000'
    with pytest.raises(ValueError):PaidServiceTrialSubmissionStatus.model_validate(pending)


def test_exact_free_and_private_routes(wire,tmp_path):
    seen=[]
    def exchange(method,path,query,headers,body,timeout):
        seen.append((method,path,query,headers,body))
        value=wire.task if path.endswith(wire.task['task_id']) else wire.claim
        if path=='/api/agent/tasks':value={'schema_version':'ln_church.agent_task_page.paid_service_trial.v1','tasks':[wire.task],'next_cursor':None}
        return PaidServiceTrialRawResponse(200,{},json.dumps(value).encode())
    client=PaidServiceTrialTaskClient(version='v1', transport=PaidServiceTrialTransport(version='v1', exchange=exchange),claim_directory=tmp_path)
    client.list_tasks();client.get_task(wire.task['task_id']);client.claim_task(wire.task['task_id'],'agent',wire.signer.address,idempotency_key='same-claim')
    assert seen[0][2]=='task_type=paid_service_trial.v1&task_schema_version=ln_church.agent_task.paid_service_trial.v1&limit=25'
    assert seen[1][2]=='task_schema_version=ln_church.agent_task.paid_service_trial.v1'
    assert json.loads(seen[2][4])=={'schema_version':'ln_church.agent_task_claim_request.v1','agent_id':'agent','reward_address':wire.signer.address.lower()}
    assert all('PAYMENT-SIGNATURE' not in x[3] for x in seen)


@pytest.fixture
def mock_bundle(tmp_path, monkeypatch):
    """API §9 test pack, never installed as a distributable Backend artifact."""
    import hashlib
    from pathlib import Path
    root = tmp_path / 'contracts' / 'v185-paid-service-trial'
    root.mkdir(parents=True)
    monkeypatch.setattr(c, '__file__', str(tmp_path / 'paid_service_trial_contract.py'))
    fixture = (Path(__file__).parent / 'fixtures/v185-paid-service-trial/semantic-contract.json').read_bytes()
    wire_bytes = b'{"test_only":"Wire placeholder; not a formal pack"}'
    definition = {
        'schema_version': 'ln_church.agent_task_definition.paid_service_trial.v1',
        'task_type': 'paid_service_trial.v1', 'task_definition_version': '1.0.0',
        'semantic_contract_sha256': hashlib.sha256(fixture).hexdigest(),
        'wire_contract_sha256': hashlib.sha256(wire_bytes).hexdigest(),
        'reward': {'network': 'eip155:8453', 'asset': 'USDC', 'asset_address': c.ASSET, 'amount_atomic': '20000'},
        'plans': [{'plan_id': name, 'registration_amount_atomic': fee, 'capacity_total': count}
                  for name, fee, count in [('C40', '1000000', 40), ('C400', '10000000', 400), ('C4000', '100000000', 4000)]],
        'listing_duration_ms': 172800000, 'report_window_ms': 600000, 'verification_window_ms': 3600000,
        'repeat_policies': ['ALLOW_REPEAT', 'ONCE_PER_OFFER_REWARD_ADDRESS'],
        'purchase_profile': {'x402_version': 2, 'scheme': 'exact', 'authorization_method': 'EIP-3009',
                             'network': 'eip155:8453', 'asset': c.ASSET, 'http_method': 'GET',
                             'minimum_amount_atomic': '1', 'maximum_amount_atomic': '10000'},
        'guides': {'worker': 'SKILL.md', 'requester': 'requester-guide.md'},
    }
    resources = {'SKILL.md': b'# Test-only Agent Guide\n', 'definition.json': c.jcs_canonical_bytes(definition),
                 'requester-guide.md': b'# Test-only Requester Guide\n',
                 'v18-5-paid-service-trial-contract-v1.json': fixture, 'wire-contract.json': wire_bytes}
    desc = {'schema_version': 'ln_church.task_definition_source_bundle.v1',
            'source_repository': 'mayim-mayim/LN_Church',
            'basis_commit': '7fb401a9c2ba420b36566af068649d6a81d20515',
            'basis_tree': 'f8975740fecd58c70574b211044c9a0f5a5990ef',
            'specification_repository': 'mayim-mayim/LN_Church_Development-Charter',
            'specification_commit': '0f15a177b52221e21fa40f851d648afc929d6e3d',
            'architecture_commit': '4bf3532bd09468df87d93e5a0fcada96d7f7b808',
            'task_type': 'paid_service_trial.v1', 'task_definition_version': '1.0.0',
            'profile_id': 'paid_service_trial_base_usdc_eip3009.v1',
            'fixture_blob': 'ce68b83fc3ef1dd14c15910f39bd3a3fb98e9f87',
            'fixture_sha256': hashlib.sha256(fixture).hexdigest()}
    manifest = {'schema_version': 'ln_church.agent_task_source_bundle_manifest.v1',
                'source_repository': 'mayim-mayim/LN_Church', 'task_type': 'paid_service_trial.v1',
                'task_definition_version': '1.0.0',
                'task_definition_digest_algorithm': 'sha256-rfc8785-jcs-descriptor-lowercase-hex-v1',
                'descriptor': desc}

    def save():
        entries = []
        for name, raw in sorted(resources.items()):
            (root / name).write_bytes(raw)
            entries.append({'path': c.ARTIFACT_PREFIX + name, 'mode': '100644',
                            'blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
                            'sha256': hashlib.sha256(raw).hexdigest()})
        desc['source_bundle_entries'] = entries
        manifest['components'] = {e['path']: {'sha256': e['sha256']} for e in entries}
        write_manifest()

    def write_manifest():
        manifest['task_definition_digest'] = c.digest(desc)
        (root / 'manifest.json').write_bytes(c.jcs_canonical_bytes(manifest))

    save()
    return SimpleNamespace(root=root, manifest=manifest, desc=desc, resources=resources,
                           definition=definition, save=save, write_manifest=write_manifest)


def test_skill_bundle_resolves_fixture_and_wire_by_path(mock_bundle):
    bundle = c.load_contract_bundle()
    assert list(bundle['resources']) == ['SKILL.md', 'definition.json', 'requester-guide.md',
                                        'v18-5-paid-service-trial-contract-v1.json', 'wire-contract.json']
    assert bundle['definition']['guides'] == {'worker': 'SKILL.md', 'requester': 'requester-guide.md'}
    assert bundle['manifest']['descriptor']['specification_commit'] == '0f15a177b52221e21fa40f851d648afc929d6e3d'


@pytest.mark.parametrize('change', ['old_spec', 'old_skill_spec', 'old_architecture', 'old_fixture_pin',
                                  'wrong_basis', 'old_name', 'old_reference',
                                  'wrong_wire', 'unsorted', 'mode', 'blob', 'sha256',
                                  'component', 'digest', 'tamper', 'fixture'])
def test_skill_bundle_rejects_identity_mismatch(mock_bundle, change):
    b = mock_bundle
    if change == 'old_spec':
        b.desc['specification_commit'] = '3a7b600a303bba27901103640cc39b7ec06aa959'
    elif change == 'old_skill_spec':
        b.desc['specification_commit'] = '874772266c8505d4c3c405d0f56b64a5302bb728'
    elif change == 'old_architecture':
        b.desc['architecture_commit'] = '1a9c4c7f62971a618d7e3acc11bcb855146e8c45'
    elif change == 'old_fixture_pin':
        b.desc['fixture_blob'] = 'a27a7456d906a943a3d098adbc3b7b3bcd586d16'
    elif change == 'wrong_basis':
        b.desc['basis_commit'] = 'be0f818674b1ee0bb2f9aa4bee02ad985b298508'
    elif change == 'old_name':
        b.resources['worker-guide.md'] = b.resources.pop('SKILL.md'); b.save()
    elif change in ('old_reference', 'wrong_wire'):
        if change == 'old_reference': b.definition['guides']['worker'] = 'worker-guide.md'
        else: b.definition['wire_contract_sha256'] = b.desc['fixture_sha256']
        b.resources['definition.json'] = c.jcs_canonical_bytes(b.definition); b.save()
    elif change == 'unsorted':
        b.desc['source_bundle_entries'].reverse()
    elif change in ('mode', 'blob', 'sha256'):
        b.desc['source_bundle_entries'][0][change] = {'mode': '100755', 'blob': '0'*40, 'sha256': '0'*64}[change]
    elif change == 'component':
        b.manifest['components'][c.ARTIFACT_PREFIX + 'SKILL.md']['sha256'] = '0'*64
    elif change == 'fixture':
        b.resources['v18-5-paid-service-trial-contract-v1.json'] += b'\n'; b.save()
        e = b.desc['source_bundle_entries'][3]
        b.desc.update(fixture_blob=e['blob'], fixture_sha256=e['sha256'])
    b.write_manifest()
    if change == 'digest':
        b.manifest['task_definition_digest'] = '0'*64
        (b.root / 'manifest.json').write_bytes(c.jcs_canonical_bytes(b.manifest))
    if change == 'tamper': (b.root / 'SKILL.md').write_bytes(b'changed')
    with pytest.raises(ValueError, match='unavailable or invalid'):
        c.load_contract_bundle()


def test_corrected_fixture_identity_and_definition_version(mock_bundle):
    import hashlib
    bundle = c.load_contract_bundle()
    raw = bundle['resources']['v18-5-paid-service-trial-contract-v1.json']
    assert len(raw) == 21407
    assert hashlib.sha256(raw).hexdigest() == '4c46c6c5ac959f1562ae18be2d3b0965483d46659c3cc844549346d1460a0fb3'
    assert json.loads(raw)['contract_version'] == '1.0.1'
    assert bundle['definition']['task_definition_version'] == '1.0.0'
    assert bundle['manifest']['descriptor']['architecture_commit'] == '4bf3532bd09468df87d93e5a0fcada96d7f7b808'
