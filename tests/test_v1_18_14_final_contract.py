"""Fixed B4 pack and final closed DTO/terms guards, without provider calls."""
import copy
import hashlib
import json
from pathlib import Path

import pytest

from ln_church_agent import structured_response_contract as c
from ln_church_agent import endpoint_choice_reason_contract as ec
from ln_church_agent.structured_response_models import StructuredResponseTask
from ln_church_agent.endpoint_choice_reason_models import EndpointChoiceV21Evaluation
from test_v1_18_14_structured_response_prepack import task


def supported_task():
    value=task()
    value['task_definition_digest']=c.load_contract_pack()['manifest']['task_definition_digest']
    value['terms_digest']=c.digest({k:value[k] for k in c._TERM_FIELDS if k in value})
    return value


def test_fixed_definition_and_profile_bindings():
    pack=c.load_contract_pack()
    assert pack['manifest']['task_definition_digest']=='4d2b8f711b2273fba5215bbcfd767df1145d30a91ee9ea5711437e791616b274'
    assert c.digest(json.loads(pack['resources']['evaluation-profile.json']))=='ed3ae5c6d632e93bec2d25f22098c8f653c730a4787f550f832f977a844c8fbb'
    assert ec.load_contract_pack('v2_1')['manifest']['task_definition_digest']=='4d7cb9d024ae41f60898146e4dbcd7ea3be63a33a9e8c0d01696192abe8f1b56'


@pytest.mark.parametrize('key',['canonical_context_id','order_id','private_binding_id','unexpected_token'])
def test_supported_task_rejects_non_contract_fields(key):
    value=supported_task();value[key]='must-not-leak'
    with pytest.raises(ValueError) as caught:StructuredResponseTask(value)
    assert 'must-not-leak' not in str(caught.value)


@pytest.mark.parametrize('key',['title','description','context_id','participation','reward'])
def test_public_terms_changes_cannot_keep_old_digest(key):
    value=supported_task()
    if key in {'title','description','context_id'}:value[key]='changed'
    elif key=='participation':value[key]={'mode':'EXCLUDE','source_task_id':None,'source_visibility':'withheld_for_blind'}
    else:value[key]=dict(value[key],normal_amount_atomic='140000')
    with pytest.raises(ValueError):StructuredResponseTask(value)


@pytest.mark.parametrize('q,coefficient,basis,amount',[
    ('0.3','0','QUALITY_REJECTED','0'),
    ('0.31','0.31','SCORE_PROPORTIONAL','31000'),
    ('0.7','1','FULL_REWARD_LINE','100000'),
])
def test_v21_quality_boundary_keeps_v3_boundary_separate(q,coefficient,basis,amount):
    parsed=EndpointChoiceV21Evaluation.model_validate(dict(state='GRADED',is_correct=True,q=q,
        applied_coefficient=coefficient,reward_basis=basis,base_amount_atomic='100000',
        approved_amount_atomic=amount,evaluated_at='2026-10-14T00:00:00.000Z'))
    assert parsed.approved_amount_atomic==amount


def test_legacy_pack_bytes_still_match_embedded_pins():
    for version in ('v1','v2'):assert ec.load_contract_pack(version)['manifest']['task_definition_version']=={'v1':'1.0.0','v2':'2.0.0'}[version]


def test_answered_explanation_quality_is_not_a_local_structural_gate():
    value=supported_task()
    result=c.validate_answer({'must':'','volume':'','outcome':''},[
        {'item_id':'answer_1','status':'answered','value':'My answer','reason':''}],value['items'])
    assert result['items'][0]['reason']==''


def test_capacity_snapshot_cannot_disagree_with_rpah():
    value=supported_task();value['capacity_quality_pending']=1
    with pytest.raises(ValueError):StructuredResponseTask(value)


@pytest.mark.parametrize('change', ['b3_digest', 'unknown_digest', 'unknown_tuple'])
def test_unmirrored_identity_is_read_only_before_claim(change, tmp_path):
    from ln_church_agent.structured_response_client import StructuredResponseClient
    from ln_church_agent.structured_response_transport import StructuredResponseError, StructuredResponseTransport
    from test_v1_18_14_structured_response_prepack import raw, ADDRESS
    value = supported_task()
    if change == 'unknown_tuple':
        value['task_definition_version'] = '99.0.0'
    else:
        value['task_definition_digest'] = ('1d86750f0fdf7421553c230d45b6dc3f687cb2710010b77f521adf5c6721a7b6'
            if change == 'b3_digest' else 'f' * 64)
    calls = []
    def exchange(method, path, query, headers, body, timeout):
        calls.append(method)
        assert method == 'GET'
        return raw(value)
    client = StructuredResponseClient(transport=StructuredResponseTransport(exchange=exchange))
    parsed = client.get_task(value['task_id'])
    assert not parsed.supported and parsed.update_required
    with pytest.raises(StructuredResponseError) as caught:
        client.claim(value['task_id'], 's2-unknown', ADDRESS, 's2-unknown-' + change,
            journal_directory=tmp_path)
    assert caught.value.code == 'UNSUPPORTED_TUPLE'
    assert calls == ['GET', 'GET']
