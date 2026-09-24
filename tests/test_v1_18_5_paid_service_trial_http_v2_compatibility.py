"""Original v1 identities and public/private SDK boundaries survive HTTP v2."""
import hashlib
import json
from pathlib import Path

import pytest
from test_v1_18_5_paid_service_trial_contract import wire
from test_v1_18_5_paid_service_trial_purchase import lane
from test_v1_18_5_paid_service_trial_http_v2_contract import wire_v2, report_for_v2
from ln_church_agent import paid_service_trial_contract as c
from ln_church_agent.paid_service_trial_client import PaidServiceTrialTaskClient
from ln_church_agent.paid_service_trial_models import PaidServiceTrialClaimV2, FrozenPaidServiceTrialReport
from ln_church_agent.paid_service_trial_journal import PaidServiceTrialJournal
from ln_church_agent.task_journal import JournalError

_FORMAL_LOADER = c.load_contract_bundle
PACK = Path(c.__file__).parent/'contracts'
V1_HASHES = {
    'SKILL.md':'b874e7765338f732a697501f8e7ea79ecdb3766b958d7a10647f7ee0b75045fb',
    'definition.json':'c3ff8399624dfd65305aa5b6a21b86f026768ee3801723f377676c42781e271c',
    'requester-guide.md':'c8562b806aeabea1196e4ddf90318d1e8e48b2e4ceb2ebc70178f8ac0051cd0b',
    'v18-5-paid-service-trial-contract-v1.json':'4c46c6c5ac959f1562ae18be2d3b0965483d46659c3cc844549346d1460a0fb3',
    'wire-contract.json':'385e16636f7ca97c6734198fa2928c9b10a9648fcda73efb9b0b7897f6e750c5',
    'manifest.json':'6d64e1118f87b28410f020b15956f4812859a5ab1641e5951322d1f1ef818809',
}


def test_exact_v1_pack_and_original_loader_provenance():
    for name,sha in V1_HASHES.items():assert hashlib.sha256((PACK/'v185-paid-service-trial'/name).read_bytes()).hexdigest()==sha
    bundle=c.load_contract_bundle('v1')
    assert bundle['manifest']['task_definition_digest']=='f9464a5b2ca01c38df971b74b3d855be7e0fc1dd2f09d8b526d5e74539c85095'
    assert bundle['manifest']['descriptor']['specification_commit']=='0f15a177b52221e21fa40f851d648afc929d6e3d'


def test_actual_fixed_backend_v2_pack():
    bundle=c.load_contract_bundle('v2')
    assert bundle['manifest']['task_definition_digest']=='08723b869949844b04319bd395ba5f6f91c1aa9155e710929f1dc4168895da14'
    assert bundle['definition']['task_definition_version']=='2.0.0'
    assert bundle['definition']['purchase_profile']['http_methods']==['GET','POST']
    assert bundle['manifest']['descriptor']['specification_commit']=='1e2946f150c3f69f1fae718f570faa4248b1a653'


def test_v1_journal_paths_and_saved_recovery_with_v2_default_client(wire,lane,tmp_path):
    result=lane.executor.execute(wire.credential,journal=lane.journal)
    expected=c.digest([c.TASK_TYPE,wire.claim['task_id'],wire.claim['execution_id']])
    assert lane.journal.path.name==expected+'.json'
    assert lane.journal.snapshot()['schema_version']=='ln_church.paid_service_trial_journal.v1'
    assert 'claim' not in lane.journal.snapshot()  # original ordinary format
    saved=PaidServiceTrialJournal.load_claim(tmp_path,wire.claim['task_id'],wire.claim['execution_id'])
    client=PaidServiceTrialTaskClient(transport=lane.transport)  # default v2
    reply=client.recover_completion(saved,result.report,journal=lane.journal)
    assert reply.schema_version=='ln_church.task_submission_status.paid_service_trial.v1'
    assert lane.http.paid==1


def test_v2_corrupt_saved_request_fails_before_recovery(wire_v2,tmp_path):
    from ln_church_agent.immediate_visit_journal import _read,_write
    tmp_path.chmod(0o700)
    journal=PaidServiceTrialJournal(tmp_path,wire_v2.credential)
    data=_read(journal.path);data['claim']['request']['body']='{}';_write(journal.path,data)
    with pytest.raises(JournalError):PaidServiceTrialJournal.load_claim(tmp_path,wire_v2.claim['task_id'],wire_v2.claim['execution_id'])


def test_report_cannot_replace_original_request_digest(wire_v2):
    report=report_for_v2(wire_v2)
    for key in ('request_digest','purchase_terms_digest'):
        data=report.model.wire();data[key]='f'*64
        bad=FrozenPaidServiceTrialReport.from_dict(data)
        with pytest.raises(ValueError):bad.model.require_claim(wire_v2.credential)
    supplemented=report.supplement('0x'+'ab'*32)
    assert supplemented.report_sha256==report.report_sha256
    assert supplemented.model.purchase==report.model.purchase


def test_v2_public_request_does_not_disclose_private_claim(wire_v2):
    model=PaidServiceTrialClaimV2.model_validate(wire_v2.claim)
    public=model.model_dump(mode='json')
    assert public['request']==wire_v2.request
    assert 'claim_token' not in public and wire_v2.claim['claim_token'] not in repr(model)
    with pytest.raises(TypeError):__import__('pickle').dumps(model)


def test_unknown_version_never_falls_back():
    for version in ('v3',None,1,'2.0.0'):
        with pytest.raises(ValueError):PaidServiceTrialTaskClient(version=version)
        with pytest.raises(ValueError):c.load_contract_bundle(version)


@pytest.mark.parametrize('name', ['SKILL.md','definition.json','requester-guide.md',
    'v18-5-paid-service-trial-contract-v2.json','wire-contract.json','manifest.json'])
def test_each_formal_v2_resource_is_pinned(name,tmp_path,monkeypatch):
    import shutil
    source=PACK/'v185-paid-service-trial-v2'
    target=tmp_path/'contracts'/'v185-paid-service-trial-v2'
    shutil.copytree(source,target)
    resource=target/name;resource.write_bytes(resource.read_bytes()+b' ')
    monkeypatch.setattr(c,'__file__',str(tmp_path/'contract.py'))
    with pytest.raises(ValueError,match='unavailable or invalid'):c.load_contract_bundle('v2')


def test_self_consistent_replacement_manifest_cannot_rebind_v2(tmp_path,monkeypatch):
    import shutil
    target=tmp_path/'contracts'/'v185-paid-service-trial-v2'
    shutil.copytree(PACK/'v185-paid-service-trial-v2',target)
    resource=target/'SKILL.md';raw=resource.read_bytes()+b'\nChanged guide\n';resource.write_bytes(raw)
    manifest=json.loads((target/'manifest.json').read_bytes())
    entry=manifest['descriptor']['source_bundle_entries'][0]
    entry['sha256']=hashlib.sha256(raw).hexdigest()
    entry['blob']=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    manifest['components'][entry['path']]['sha256']=entry['sha256']
    manifest['task_definition_digest']=c.v2_digest(manifest['descriptor'])
    (target/'manifest.json').write_text(json.dumps(manifest))
    monkeypatch.setattr(c,'__file__',str(tmp_path/'contract.py'))
    with pytest.raises(ValueError,match='unavailable or invalid'):c.load_contract_bundle('v2')


@pytest.mark.parametrize('method',['GET','POST'])
def test_formal_pack_execution_and_saved_recovery(wire_v2,tmp_path,monkeypatch,method):
    from types import SimpleNamespace
    from ln_church_agent.models import PaymentPolicy
    from ln_church_agent.paid_service_trial import PaidServiceTrialExecutor
    from test_v1_18_5_paid_service_trial_http_v2_contract import V2TaskTransport
    from test_v1_18_5_paid_service_trial_http_v2_purchase import V2HTTP
    # Undo only the test DTO's stand-in loader. This route must use real pack bytes.
    monkeypatch.setattr(c,'load_contract_bundle',_FORMAL_LOADER)
    bundle=c.load_contract_bundle('v2');wire=wire_v2
    request=c.prepare_request(dict(method=method,url=wire.request['url'],
        body=wire.request['body'] if method=='POST' else None))
    wire.request=request
    wire.task.update(request=request,request_digest=c.v2_digest(request),
        purchase_terms_digest=c.purchase_terms_digest(request,wire.terms),
        task_definition_digest=bundle['manifest']['task_definition_digest'])
    fields=('request','request_digest','purchase_terms','purchase_terms_digest','plan_id',
        'registration_amount_atomic','capacity_total','repeat_policy','reward')
    wire.task['terms_digest']=c.v2_digest({k:wire.task[k] for k in fields})
    for key in ('request','request_digest','purchase_terms_digest','task_definition_digest','terms_digest'):
        wire.claim[key]=wire.task[key]
    wire.credential=PaidServiceTrialClaimV2.model_validate(wire.claim)
    client=PaidServiceTrialTaskClient(transport=V2TaskTransport(wire))
    http=V2HTTP(wire);tmp_path.chmod(0o700)
    journal=PaidServiceTrialJournal(tmp_path,wire.credential)
    executor=PaidServiceTrialExecutor(signer=wire.signer,
        policy=PaymentPolicy(max_spend_per_tx_usd=.001,max_spend_per_session_usd=.001,allowed_hosts=['seller.example.com']),
        client=client,http=http,block_guard=SimpleNamespace(ready=lambda value:True),wall_time=lambda:wire.now)
    result=executor.execute(wire.credential,journal=journal)
    assert result.report.model.task_definition_digest==bundle['manifest']['task_definition_digest']
    assert result.report.model.request_digest==wire.claim['request_digest']
    assert http.paid==1
    saved=PaidServiceTrialJournal.load_claim(tmp_path,wire.claim['task_id'],wire.claim['execution_id'])
    restarted=PaidServiceTrialJournal(tmp_path,saved);executor._signer=None
    executor.execute(saved,journal=restarted)
    assert http.paid==1 and http.unpaid==2
