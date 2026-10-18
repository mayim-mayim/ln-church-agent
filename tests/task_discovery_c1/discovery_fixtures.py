"""Synthetic wire examples derived from audited Charter 87a1027f §§2-3/4.1.

These are SDK self-check fixtures, not Backend output or integration evidence.
The twelve independent rows repeat the specification's tuples intentionally.
"""
import base64
import json
from urllib.parse import urlencode

ORIGIN = 'https://kari.mayim-mayim.com'
NOW = '2026-10-17T07:30:00.000Z'
END = '2026-10-24T07:30:00.000Z'
ROWS = [
 ('payment_surface_discovery.v1', '1.0.0', 'ln_church.agent_task.v1', 'none'),
 ('scheduled_http_get_batch.v1', '1.0.0', 'ln_church.agent_task.v2', 'schema'),
 ('immediate_http_visit.v1', '1.0.0', 'ln_church.agent_task.immediate_visit.v1', 'none'),
 ('immediate_http_visit.v2', '2.0.0', 'ln_church.agent_task.immediate_visit.v2', 'none'),
 ('immediate_http_visit.v3', '3.0.0', 'ln_church.agent_task.immediate_visit.v3', 'none'),
 ('paid_service_trial.v1', '1.0.0', 'ln_church.agent_task.paid_service_trial.v1', 'schema'),
 ('paid_service_trial.v2', '2.0.0', 'ln_church.agent_task.paid_service_trial.v2', 'schema'),
 ('paid_service_trial.v3', '3.0.0', 'ln_church.agent_task.paid_service_trial.v3', 'schema'),
 ('endpoint_choice_reason.v1', '1.0.0', 'ln_church.agent_task.endpoint_choice_reason.v1', 'both'),
 ('endpoint_choice_reason.v2', '2.0.0', 'ln_church.agent_task.endpoint_choice_reason.v2', 'both'),
 ('endpoint_choice_reason.v2', '2.1.0', 'ln_church.agent_task.endpoint_choice_reason.v2_1', 'both'),
 ('structured_response.v3', '3.0.0', 'ln_church.agent_task.structured_response.v3', 'both'),
]

# Existing formal Definition identities; provenance is checked by c3 tests.
DIGESTS = [
 '9e5d340f746c957ac9e9363c0af8ef72f0fe2bc8ea4bc4b55d1f7006b5448406',
 '24c90c221a111881cfcd455811b7de568c93f7be6950744f05423c42e3e4f22d',
 '25996fb28b531a8892ef39c9e98899d94a31bef2628ddeb437b0e8fd673b6e43',
 '3ef4d211aa66ef7972e5c4fd861d5afd83219759e2eaebf926694936bd5a532f',
 '070780402e97d8b2840ecc91ce66bc42aa1ef529aebfbbb2a0ab7845f24b9a41',
 'f9464a5b2ca01c38df971b74b3d855be7e0fc1dd2f09d8b526d5e74539c85095',
 '08723b869949844b04319bd395ba5f6f91c1aa9155e710929f1dc4168895da14',
 '5ada2a522eb7d3eb500c1e893c8e7387814882a334930d48ca5ae2bebdc2a6e5',
 'a74586b704dd87eb819780481ad7347ce9fcdfdaa4684726da32e4e1ed9e1d93',
 'c777eb006645196e9bbd1c6b6cf410f628a5580cb8e20ee32f2ae4f96afb8de7',
 '4d7cb9d024ae41f60898146e4dbcd7ea3be63a33a9e8c0d01696192abe8f1b56',
 '4d2b8f711b2273fba5215bbcfd767df1145d30a91ee9ea5711437e791616b274',
]

def cursor(after=END+'#task_11'):
    raw=json.dumps({'generation':'v1','after':after},separators=(',',':')).encode()
    return 'td1.'+base64.urlsafe_b64encode(raw).rstrip(b'=').decode()

def candidate(index=11):
    kind, version, schema, selector=ROWS[index]
    task_id='task_'+str(index)
    params={}
    if selector=='both': params['task_type']=kind
    if selector!='none': params['task_schema_version']=schema
    return dict(task_id=task_id,task_type=kind,task_schema_version=schema,
        task_definition_version=version,task_definition_digest=DIGESTS[index],
        title='Public recruiting candidate',summary='Read the official Guide before choosing a client.',
        recruitment_state='candidate',capacity_available=3,claim_before=END,
        scheduled_at='2026-10-24T08:00:00.000Z' if index==1 else None,
        eligibility='check_task_details',detail_url=ORIGIN+'/api/agent/tasks/'+task_id+('?' + urlencode(params) if params else ''),
        definition_url=ORIGIN+'/agent-task-specs/'+kind+'/'+version+'/'+((DIGESTS[index]+'/') if index==0 else '')+'SKILL.md',
        projection_updated_at=NOW)

def page(indices=(11,), *, continuation=False, more=False):
    return dict(schema_version='ln_church.task_discovery_page.v1',
        selection='recruiting_candidates',coverage='all_supported_families',
        checked_at=NOW,page_scope='continuation' if continuation else 'initial',
        tasks=[candidate(i) for i in indices],next_cursor=cursor() if more else None,
        empty_reason=None if indices else 'no_candidates_observed_in_range',
        claim_authority='task_claim_endpoint')

