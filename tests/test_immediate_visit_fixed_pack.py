"""Fixed Hondo normative fixture checks, without replacing pack bytes or digests."""
import json
import pytest
from jsonschema import Draft202012Validator
from ln_church_agent.immediate_visit_versions import load_v2_pack,agent_user_agent
from ln_church_agent.immediate_visit_models import ImmediateVisitTask,ImmediateVisitTaskPage,ImmediateVisitCompletionReceipt,ImmediateVisitSubmissionStatus,FrozenImmediateVisitReport
from ln_church_agent.offer_registration import _request,plan
from test_v1_18_3_immediate_visit_transport import Harness

PACK=load_v2_pack()
FIXTURES=json.loads(PACK['wire-fixtures.json'])['fixtures']
MAPPED={'task.schema.json':ImmediateVisitTask,'page.schema.json':ImmediateVisitTaskPage,
        'receipt.schema.json':ImmediateVisitCompletionReceipt,'result.schema.json':ImmediateVisitSubmissionStatus}
ROWS=[x for x in FIXTURES if x['schema'] in {*MAPPED,'registration.schema.json','submission.schema.json'}]

@pytest.mark.parametrize('row',ROWS,ids=lambda x:x['id'])
def test_normative_v2_wire_dtos(row):
    Draft202012Validator(json.loads(PACK[row['schema']])).validate(row['value'])
    if row['schema'] in MAPPED:
        obj=MAPPED[row['schema']].model_validate(row['value'])
        assert obj.schema_version.endswith('.v2')
    elif row['schema']=='registration.schema.json':
        validated=_request(row['value']);assert validated==row['value']
        expected=row['expected_economics'];assert plan(validated['task_type'],validated['plan_id'])==(expected['registration_amount_atomic'],expected['capacity_total'])
    else:
        frozen=FrozenImmediateVisitReport.from_report(row['value']);assert json.loads(frozen.canonical_bytes)==row['value']


def test_exact_pack_role_ua_reaches_actual_connector():
    profile=json.loads(PACK['profile.json']);h=Harness(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1\r\n\r\nx')
    h.connector.fetch_immediate_visit('https://example.com/a',profile_id='immediate_visit_utf8.v2')
    wire=h.sockets[0][1].requests[0]
    assert wire.count(b'User-Agent:')==1 and ('User-Agent: '+profile['user_agents']['agent']+'\r\n').encode() in wire
    assert profile['user_agents']['reference'].encode() not in wire
    assert agent_user_agent('immediate_visit_utf8.v1')!='ExternalAgent-via-LNChurch/1.0'


_PROFILE_VECTORS=json.loads(PACK['profile-fixtures.json'])['vectors']

@pytest.mark.parametrize('vector',_PROFILE_VECTORS,ids=lambda v:v['id'])
def test_fixed_v2_profile_vectors(vector):
    from ln_church_agent import immediate_visit_profile as profile
    body=bytes.fromhex(vector['body_hex'])
    result=profile.analyze_response(vector['status'],(('Content-Type',vector['content_type']),),body)
    assert result['outcome']==vector['expected_outcome']
    if result['outcome']=='inconclusive':
        assert result['reason']==vector['expected_reason']
        assert 'structure_sha256' not in result and 'body_sha256' not in result
    else:
        assert result['structure_sha256']==vector['expected_structure_sha256']
        assert result['body_sha256']==vector['expected_body_sha256']
        text=body.decode('utf-8').removeprefix('\ufeff')
        structure=profile._extract_structure(text,result['media_family'])
        assert structure==vector['expected_structure']
        assert profile.jcs_bytes(structure)==vector['expected_jcs_utf8'].encode()
