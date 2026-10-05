"""Published API and DC-fixed producer resource compatibility for 1.18.11."""
import hashlib
import importlib
import json
import subprocess
import sys
from pathlib import Path
import pytest
from test_immediate_visit_fixed_pack import MAPPED
from ln_church_agent import immediate_visit_versions as iv, paid_service_trial_contract as pc, endpoint_choice_reason_contract as ec
from ln_church_agent.immediate_visit_models import FrozenImmediateVisitReport
from ln_church_agent.offer_registration import _request

PACK=iv.load_pack('v3')
ROWS=[r for r in json.loads(PACK['wire-fixtures.json'])['fixtures'] if r['schema'] in {*MAPPED,'registration.schema.json','submission.schema.json'}]

@pytest.mark.parametrize('row',ROWS,ids=lambda r:r['id'])
def test_instant_v3_producer_wire(row):
    from jsonschema import Draft202012Validator
    Draft202012Validator(json.loads(PACK[row['schema']])).validate(row['value'])
    if row['schema'] in MAPPED:assert MAPPED[row['schema']].model_validate(row['value']).schema_version.endswith('.v3')
    elif row['schema']=='registration.schema.json':assert _request(row['value'])==row['value']
    else:assert json.loads(FrozenImmediateVisitReport.from_report(row['value']).canonical_bytes)==row['value']


def test_three_fixed_descriptor_digests_and_versions():
    expected=['070780402e97d8b2840ecc91ce66bc42aa1ef529aebfbbb2a0ab7845f24b9a41','5ada2a522eb7d3eb500c1e893c8e7387814882a334930d48ca5ae2bebdc2a6e5','c777eb006645196e9bbd1c6b6cf410f628a5580cb8e20ee32f2ae4f96afb8de7']
    manifests=[json.loads(PACK['manifest.json']),pc.load_contract_bundle('v3')['manifest'],ec.load_contract_pack('v2')['manifest']]
    for m,d in zip(manifests,expected):assert m['task_definition_digest']==d
    for m in manifests:assert m['task_definition_digest']==pc.v2_digest(m['descriptor'])
    assert hashlib.sha256(ec.load_contract_pack('v2')['resources']['evaluation-profile.json']).hexdigest()==ec.PACK_SHA256['evaluation-profile.json']


@pytest.mark.parametrize('module,pin,loader',[(iv,'V3_PACK_SHA256',lambda:iv.load_pack('v3')),(pc,'V3_PACK_SHA256',lambda:pc.load_contract_bundle('v3')),(ec,'V2_PACK_SHA256',lambda:ec.load_contract_pack('v2'))])
def test_modified_pack_refused(module,pin,loader,monkeypatch):
    wrong=dict(getattr(module,pin));wrong['definition.json']='0'*64
    monkeypatch.setattr(module,pin,wrong)
    with pytest.raises(ValueError):loader()


def test_v3_public_types_lazy_and_explicit_imports():
    source='''import sys
import ln_church_agent as sdk
assert 'ln_church_agent.paid_service_trial_models' not in sys.modules
from ln_church_agent import PaidServiceTrialTaskV3, PaidServiceTrialClaimV3, PaidServiceTrialReportV3, PaidServiceTrialCompletionReceiptV3, PaidServiceTrialSubmissionStatusV3
from ln_church_agent import PaidServiceTrialTaskV2, PaidServiceRequest
assert PaidServiceTrialTaskV3 is not PaidServiceTrialTaskV2
for suffix in ['Task','Claim','Report','CompletionReceipt','SubmissionStatus']:
 name='PaidServiceTrial'+suffix+'V3'
 assert name in sdk.__all__ and sdk._V18_LAZY_EXPORTS[name]==('paid_service_trial_models',name)
'''
    subprocess.run([sys.executable,'-c',source],check=True)
